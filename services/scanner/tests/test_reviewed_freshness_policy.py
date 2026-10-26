"""Reviewed-data age warnings do not hide integrity failures or hard expiry."""
from datetime import timedelta

import pytest

from kodesec_scanner import cache_manifest
from kodesec_scanner.preparation_budget import timestamp
from test_updater import TOOLS, RULES, _data_candidate


@pytest.fixture(autouse=True)
def validated_content(monkeypatch):
    monkeypatch.setattr(cache_manifest, 'receipt_matches_installed_content', lambda *_: True)


@pytest.mark.parametrize('age,state,warn', [
    (timedelta(days=7, microseconds=-1), 'ready', False),
    (timedelta(days=7), 'ready', True),
    (timedelta(days=14, microseconds=-1), 'ready', True),
    (timedelta(days=14), 'stale', False),
])
def test_refresh_warning_and_hard_validity_boundaries(age, state, warn):
    requirement = next(r for r in TOOLS.value.tool('trivy').requirements if r.id == 'trivy-db')
    updated = cache_manifest._parse_utc(cache_manifest.locked_intrinsic_updated_at(requirement), 'updated')
    generation = _data_candidate(updated_at=timestamp(updated),
                                 expires_at=timestamp(updated + timedelta(days=14)))
    requirement = next(r for r in TOOLS.value.tool('trivy').requirements if r.id == 'trivy-db')
    facet = cache_manifest._component_readiness([requirement], generation,
        expected_tool_id='trivy', expected_tool_lock_sha256=TOOLS.sha256,
        expected_rules_lock_sha256=RULES.sha256, now=updated + age)
    assert facet.state == state
    assert facet.ready is (state == 'ready')
    assert bool(facet.reason and facet.reason.startswith('Refresh due:')) is warn


def test_warning_does_not_hide_invalid_component_identity():
    requirement = next(r for r in TOOLS.value.tool('trivy').requirements if r.id == 'trivy-db')
    updated = cache_manifest._parse_utc(cache_manifest.locked_intrinsic_updated_at(requirement), 'updated')
    generation = _data_candidate(updated_at=timestamp(updated),
                                 expires_at=timestamp(updated + timedelta(days=14)))
    receipt = generation.manifest.components[0]
    receipt.source_sha256 = '0' * 64
    requirement = next(r for r in TOOLS.value.tool('trivy').requirements if r.id == 'trivy-db')
    facet = cache_manifest._component_readiness([requirement], generation,
        expected_tool_id='trivy', expected_tool_lock_sha256=TOOLS.sha256,
        expected_rules_lock_sha256=RULES.sha256, now=updated + timedelta(days=8))
    assert facet.state == 'invalid' and not facet.ready
    assert not facet.reason.startswith('Refresh due:')


def test_refresh_warning_cannot_override_invalid_content(monkeypatch):
    monkeypatch.setattr(cache_manifest, 'receipt_matches_installed_content', lambda *_: False)
    requirement = next(r for r in TOOLS.value.tool('trivy').requirements if r.id == 'trivy-db')
    updated = cache_manifest._parse_utc(cache_manifest.locked_intrinsic_updated_at(requirement), 'updated')
    generation = _data_candidate(updated_at=timestamp(updated),
                                 expires_at=timestamp(updated + timedelta(days=14)))
    requirement = next(r for r in TOOLS.value.tool('trivy').requirements if r.id == 'trivy-db')
    facet = cache_manifest._component_readiness([requirement], generation,
        expected_tool_id='trivy', expected_tool_lock_sha256=TOOLS.sha256,
        expected_rules_lock_sha256=RULES.sha256, now=updated + timedelta(days=8))
    assert facet.state == 'invalid' and not facet.ready


@pytest.mark.parametrize('tool_id,component_id', [('trivy', 'trivy-db'), ('trivy', 'trivy-java-db'), ('grype', 'grype-db')])
def test_intrinsic_receipt_cannot_rebase_the_locked_publisher_timestamp(tool_id, component_id):
    requirement = next(r for r in TOOLS.value.tool(tool_id).requirements if r.id == component_id)
    updated = cache_manifest._parse_utc(cache_manifest.locked_intrinsic_updated_at(requirement), 'updated')
    receipt = _data_candidate(component_id=component_id, updated_at=timestamp(updated),
                             expires_at=timestamp(updated + timedelta(days=14))).manifest.components[0]
    assert cache_manifest.receipt_matches_freshness_contract(receipt, requirement)
    receipt.updated_at = timestamp(updated + timedelta(days=3))
    receipt.expires_at = timestamp(updated + timedelta(days=17))
    assert not cache_manifest.receipt_matches_freshness_contract(receipt, requirement)
