from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote

import pytest

from kodesec_scanner import external
from kodesec_scanner.source_io import SourceEvidenceError, SourceTextReader

TEXT = 'resource "aws_security_group" "open" {}\n'


def projected(path: Path, cwd: Path) -> str:
    return quote(('/' + os.path.relpath(path, cwd)).replace('/..', '').lstrip('/'))


def document(uri: str) -> dict:
    return {'runs': [{'columnKind': 'unicodeCodePoints', 'results': [{
        'ruleId': 'CKV_AWS_24', 'level': 'error', 'message': {'text': 'Public fixture'},
        'locations': [{'physicalLocation': {'artifactLocation': {'uri': uri},
            'region': {'startLine': 1, 'endLine': 1}}}]}]}]}


def roots(tmp_path):
    source = tmp_path / 'source'
    cwd = tmp_path / 'scratch/checkov'
    source.mkdir()
    cwd.mkdir(parents=True)
    return source, cwd


def parse(tmp_path, source, cwd, uri):
    native = tmp_path / 'native.sarif'
    native.write_text(json.dumps(document(uri)))
    return external._parse_sarif(native, 'checkov', source, checkov_cwd=cwd)


@pytest.mark.parametrize('relative', ['main.tf', 'infra/main.tf', 'space name.tf',
                                    'unicode-😀.tf', 'literal%20name.tf', 'colon:name.tf'])
def test_checkov_owned_cwd_projection_maps_exact_unique_source(tmp_path, relative):
    source, cwd = roots(tmp_path)
    target = source / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(TEXT)
    parsed = parse(tmp_path, source, cwd, projected(target, cwd))
    assert parsed.integrity.as_dict()['complete']
    assert [finding.file_path for finding in parsed.findings] == [relative]
    assert parsed.findings[0].code_snippet.rstrip("\n") == TEXT.rstrip('\n')


@pytest.mark.parametrize('uri', ['main.tf', '../source/main.tf', '%2e%2e/source/main.tf',
    'https://example.invalid/main.tf', 'file:///source/main.tf', '/source/main.tf',
    'source/missing.tf', 'source/space%2520name.tf'])
def test_checkov_context_never_guesses_or_falls_back_for_native_paths(tmp_path, uri):
    source, cwd = roots(tmp_path)
    (source / 'main.tf').write_text(TEXT)
    (source / 'space name.tf').write_text(TEXT)
    parsed = parse(tmp_path, source, cwd, uri)
    assert parsed.findings == []
    assert parsed.integrity.dropped_reason_counts == {'unresolved_checkov_source_path': 1}


def test_checkov_separator_erasure_collision_never_selects_unrelated_file(tmp_path):
    source, cwd = roots(tmp_path)
    (source / 'dir').mkdir()
    erased = source / 'dir/..foo.tf'
    ordinary = source / 'dirfoo.tf'
    erased.write_text(TEXT)
    ordinary.write_text(TEXT)
    assert projected(erased, cwd) == projected(ordinary, cwd)
    parsed = parse(tmp_path, source, cwd, projected(erased, cwd))
    assert parsed.findings == []
    assert parsed.integrity.dropped_reason_counts == {'ambiguous_checkov_source_path': 1}


def test_checkov_unique_erased_name_retains_its_exact_original_path(tmp_path):
    source, cwd = roots(tmp_path)
    (source / 'dir').mkdir()
    target = source / 'dir/..foo.tf'
    target.write_text(TEXT)
    parsed = parse(tmp_path, source, cwd, projected(target, cwd))
    assert parsed.integrity.as_dict()['complete']
    assert [finding.file_path for finding in parsed.findings] == ['dir/..foo.tf']


def test_checkov_nonregular_collision_is_refused(tmp_path):
    source, cwd = roots(tmp_path)
    (source / 'dir').mkdir()
    (source / 'dir/..foo.tf').symlink_to(source / 'dirfoo.tf')
    ordinary = source / 'dirfoo.tf'
    ordinary.write_text(TEXT)
    parsed = parse(tmp_path, source, cwd, projected(ordinary, cwd))
    assert parsed.findings == []
    assert parsed.integrity.dropped_reason_counts == {'ambiguous_checkov_source_path': 1}


def test_lookup_and_source_read_share_the_open_root_descriptor(tmp_path):
    source, _cwd = roots(tmp_path)
    (source / 'main.tf').write_text('original\n')
    with SourceTextReader(source, 1024) as reader:
        source.rename(tmp_path / 'retained-source')
        source.mkdir()
        (source / 'main.tf').write_text('replacement\n')
        lookup = reader.projected_path_lookup({'main.tf'}, lambda relative: relative, 10, lambda: None)
        assert lookup == {'main.tf': 'main.tf'}
        assert reader.read_document(lookup['main.tf']).text == 'original\n'


def test_lookup_prunes_unrelated_repository_administration_tree(tmp_path, monkeypatch):
    source, cwd = roots(tmp_path)
    (source / 'main.tf').write_text(TEXT)
    (source / '.git/objects').mkdir(parents=True)
    (source / '.git/objects/unrelated').write_text('unused')
    administration_inode = (source / '.git').stat().st_ino
    original = os.listdir
    def listdir(descriptor):
        assert os.fstat(descriptor).st_ino != administration_inode
        return original(descriptor)
    monkeypatch.setattr(os, 'listdir', listdir)
    parsed = parse(tmp_path, source, cwd, projected(source / 'main.tf', cwd))
    assert parsed.integrity.as_dict()['complete']


def test_lookup_enforces_metadata_bound_and_cancellation(tmp_path):
    source, _cwd = roots(tmp_path)
    for name in ('a.tf', 'b.tf', 'c.tf'):
        (source / name).write_text(TEXT)
    with SourceTextReader(source, 1024) as reader:
        with pytest.raises(SourceEvidenceError, match='producer_path_lookup_limit'):
            reader.projected_path_lookup({'a.tf'}, lambda relative: relative, 2, lambda: None)
        control = external.ExecutionControl.with_timeout(10)
        control.cancel_event.set()
        with pytest.raises(external.RunCancelled):
            reader.projected_path_lookup({'a.tf'}, lambda relative: relative, 10, control.checkpoint)


def test_lookup_detects_directory_mutation_during_enumeration(tmp_path, monkeypatch):
    source, _cwd = roots(tmp_path)
    (source / 'main.tf').write_text(TEXT)
    original = os.listdir
    def listdir(descriptor):
        result = original(descriptor)
        (source / 'late.tf').write_text(TEXT)
        return result
    monkeypatch.setattr(os, 'listdir', listdir)
    with SourceTextReader(source, 1024) as reader:
        with pytest.raises(SourceEvidenceError, match='producer_path_lookup_changed'):
            reader.projected_path_lookup({'main.tf'}, lambda relative: relative, 10, lambda: None)


def test_other_sarif_producers_keep_original_path_contract(tmp_path):
    source, cwd = roots(tmp_path)
    (source / 'main.tf').write_text(TEXT)
    native = tmp_path / 'native.sarif'
    native.write_text(json.dumps(document('main.tf')))
    parsed = external._parse_sarif(native, 'gitleaks', source, checkov_cwd=cwd)
    assert parsed.integrity.as_dict()['complete']
    assert parsed.findings[0].file_path == 'main.tf'


def test_checkov_wrapper_supplies_actual_owned_cwd_to_strict_parser(tmp_path, monkeypatch):
    source, _cwd = roots(tmp_path)
    (source / 'main.tf').write_text(TEXT)
    scratch = tmp_path / 'owned-scratch'
    scratch.mkdir()
    def invoke(scanner, command, cwd, timeout, raw, env, **kwargs):
        assert scanner == 'checkov'
        assert cwd == raw == scratch / 'checkov'
        (raw / 'results_sarif.sarif').write_text(json.dumps(document(projected(source / 'main.tf', cwd))))
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(external, '_invoke_run_command', invoke)
    result = external.run_external_tool('checkov', source, scratch, tmp_path / 'publish',
        tmp_path / 'cache', 10, control=external.ExecutionControl.with_timeout(10))
    assert result.status == 'completed'
    assert result.parse_integrity['complete']
    assert result.findings[0].file_path == 'main.tf'
