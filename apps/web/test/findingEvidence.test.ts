import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import type { Finding } from '../src/api.ts';
import { findingEvidenceMetadata, findingEvidenceMetadataKey, findingEvidencePresentation,
  offenderColumnSegments, preserveFindingEvidence } from '../src/findingEvidence.ts';

const finding = (update: Partial<Finding> = {}): Finding => ({
  id: 7, scan_id: 3, scan_finding_number: 2, display_id: 'S3-F002', scanner: 'opengrep',
  rule_id: 'javascript.lang.audit.dynamic-code', severity: 'high', file_path: 'src/app.ts',
  message: 'Dynamic code execution can consume untrusted input. Review the input boundary.',
  fingerprint: 'fixture', suppressed: false, lifecycle_status: 'open', gate_exempt: false,
  gate_effect: 'blocking', occurrence_count: 1, is_repeat: false, revision: 1, ...update,
});

test('result types distinguish mixed scanner evidence without inventing missing package fields', () => {
  for (const [scanner, rule_id, metadata_json, kind] of [
    ['opengrep', 'code-rule', {}, 'code'], ['bearer', 'code-rule', {}, 'code'],
    ['sast-lite', 'code-rule', {}, 'code'], ['gitleaks', 'token-rule', {}, 'secret'],
    ['trufflehog', 'token-rule', { verified: true }, 'secret'], ['checkov', 'CKV_FIXTURE', {}, 'configuration'],
    ['grype', 'CVE-2026-1234', {}, 'dependency'], ['trivy', 'CVE-2026-1234', {}, 'dependency'],
    ['trivy', 'GHSA-abcd-abcd-abcd', {}, 'dependency'], ['trivy', 'other', { tags: ['license'] }, 'license'],
    ['trivy', 'other', { tags: ['secret'] }, 'secret'], ['trivy', 'other', {}, 'unknown'],
    ['unknown-scanner', 'CVE-2026-1234', {}, 'unknown'],
  ] as const) {
    const result = findingEvidencePresentation(finding({ scanner, rule_id, metadata_json }));
    assert.equal(result.kind, kind);
    assert.equal(result.verifiedSecret, scanner === 'trufflehog');
    assert.equal('packageVersion' in result, false);
  }
  assert.equal(findingEvidencePresentation(finding()).title, 'Dynamic code execution can consume untrusted input.');
  assert.equal(findingEvidencePresentation(finding({ metadata_json: { rule_name: 'Avoid dynamic execution' } })).title,
    'Avoid dynamic execution');
  assert.equal(findingEvidencePresentation(finding({ message: 'x'.repeat(4000) })).title, 'Code issue');
  assert.equal(findingEvidencePresentation(finding({ scanner: 'trufflehog', metadata_json: { verified: 'true' } })).verifiedSecret, false);
});

test('Trivy structured messages have concise titles without changing their evidence', () => {
  const message = 'Artifact: app.py Type:  Secret AWS Access Key ID Severity: CRITICAL Match: [REDACTED]';
  const input = finding({ scanner: 'trivy', rule_id: 'aws-access-key-id', message, metadata_json: { tags: ['secret'] } });
  assert.equal(findingEvidencePresentation(input).title, 'AWS Access Key ID');
  assert.equal(input.message, message);
  assert.equal(findingEvidencePresentation({ ...input, message: 'Artifact: package.lock\nType: npm\nSeverity: HIGH' }).title, 'Secret exposure');
  assert.equal(findingEvidencePresentation({ ...input, message: 'Artifact: unsupported scanner layout' }).title, 'Secret exposure');
  assert.equal(findingEvidencePresentation({ ...input, metadata_json: { rule_name: 'Readable scanner title' } }).title, 'Readable scanner title');
});

test('review projection retains only bounded admitted metadata through lifecycle reconciliation', () => {
  const detail = finding({ code_snippet: 'redacted source', metadata_json: { rule_name: 'Readable rule', tags: ['security'],
    snippet_start_line: 20, snippet_column_start: 900, snippet_truncated: true, snippet_line_truncated: true,
    message_truncated: true, verified: true, raw_payload: 'must not reach the UI', help_uri: 'javascript:unsafe' } });
  const summary = finding({ revision: 2, lifecycle_status: 'fixed', suppressed: true, gate_effect: 'excluded' });
  const merged = preserveFindingEvidence(summary, detail);
  assert.equal(merged.revision, 2);
  assert.equal(merged.lifecycle_status, 'fixed');
  assert.equal(merged.code_snippet, 'redacted source');
  assert.equal(merged.metadata_json?.snippet_column_start, 900);
  assert.equal(merged.metadata_json?.snippet_line_truncated, true);
  assert.equal(merged.metadata_json?.raw_payload, undefined);
  assert.equal(merged.metadata_json?.help_uri, undefined);
  assert.notEqual(findingEvidenceMetadataKey(detail), findingEvidenceMetadataKey(finding()));
  for (const key of ['rule_name', 'tags', 'verified', 'snippet_start_line', 'snippet_column_start',
    'snippet_truncated', 'snippet_line_truncated', 'message_truncated']) {
    assert.notEqual(findingEvidenceMetadataKey(detail), findingEvidenceMetadataKey({ metadata_json: { ...detail.metadata_json, [key]: undefined } }), key);
  }
  assert.deepEqual(findingEvidenceMetadata({ metadata_json: { rule_name: 'x'.repeat(241),
    tags: ['x'.repeat(161)], snippet_start_line: Infinity, snippet_column_start: '3', verified: 1 } }), {});
});

test('offender columns use UTF-16 end-exclusive ranges and retain whitespace geometry', () => {
  assert.deepEqual(offenderColumnSegments({ lines: ['\t😀eval(value);'], firstLine: 8,
    startLine: 8, endLine: 8, startColumn: 4, endColumn: 8 }),
  [{ lineIndex: 0, prefix: '\t😀', text: 'eval' }]);
  assert.deepEqual(offenderColumnSegments({ lines: ['first(value,', '\tother', 'last)'], firstLine: 8,
    startLine: 8, endLine: 10, startColumn: 7, endColumn: 5 }),
  [{ lineIndex: 0, prefix: 'first(', text: 'value,' }, { lineIndex: 1, prefix: '', text: '\tother' },
    { lineIndex: 2, prefix: '', text: 'last' }]);
  assert.deepEqual(offenderColumnSegments({ lines: ['eval(value)'], firstLine: 8,
    startLine: 8, endLine: 8, startColumn: 900, endColumn: 904, columnOrigin: 900 }),
  [{ lineIndex: 0, prefix: '', text: 'eval' }]);
});

test('invalid, absent and uncaptured column ranges fall back to line evidence', () => {
  const input = { lines: ['😀call()'], firstLine: 8, startLine: 8, endLine: 8, startColumn: 3, endColumn: 7 };
  for (const update of [{ startColumn: undefined }, { startColumn: 3.2 }, { endColumn: 1 },
    { startLine: 10, endLine: 11 }, { startColumn: 900 }, { startColumn: 2 }, { endColumn: 2 },
    { columnOrigin: 0 }, { endLine: 7 }]) {
    assert.deepEqual(offenderColumnSegments({ ...input, ...update }), [], JSON.stringify(update));
  }
});

test('Trivy titles recognize actual and compact messages without category metadata', () => {
  const cases = JSON.parse(readFileSync(new URL('../../../extensions/vscode/test/fixtures/finding-titles.json', import.meta.url), 'utf8'));
  for (const entry of cases) {
    for (const message of [entry.message, entry.message.replaceAll('\n', ' '), entry.message.replaceAll('\n', '\r\n')]) {
      const input = finding({ scanner: 'trivy', rule_id: 'fixture-rule', message, metadata_json: undefined });
      const result = findingEvidencePresentation(input);
      assert.equal(result.kind, entry.kind);
      assert.equal(result.title, entry.title);
      assert.equal(input.message, message);
    }
  }
  const unknown = finding({ scanner: 'trivy', rule_id: 'unknown', message: 'Artifact: unsupported layout' });
  assert.equal(findingEvidencePresentation(unknown).kind, 'unknown');
  assert.equal(findingEvidencePresentation(unknown).title, 'Scanner finding');
});
