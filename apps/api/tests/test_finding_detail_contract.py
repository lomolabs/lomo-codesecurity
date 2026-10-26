from __future__ import annotations

import json
from pathlib import Path

from kodesec_api.schemas import FindingDetailOut


CONTRACT_FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "extensions"
    / "vscode"
    / "test"
    / "fixtures"
    / "contracts"
    / "finding-detail.json"
)


def test_vscode_finding_detail_fixture_matches_api_schema() -> None:
    payload = json.loads(CONTRACT_FIXTURE.read_text(encoding="utf-8"))
    assert set(payload) == set(FindingDetailOut.model_fields)
    assert FindingDetailOut.model_validate(payload).model_dump(mode="json") == payload
