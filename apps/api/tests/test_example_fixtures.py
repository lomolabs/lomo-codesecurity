"""Protect the bounded third-party import; never execute fixture code."""

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def test_terragoat_import_matches_pinned_provenance_and_preserves_upstream() -> None:
    fixture = ROOT / "examples/third-party/terragoat"
    manifest = json.loads((fixture / "provenance.json").read_text())
    assert manifest["commit"] == "729f8da62c6a85ce4af5ad3d123de97776d954c4"
    assert manifest["license"] == "Apache-2.0"
    assert {item["path"] for item in manifest["files"]} == {
        "LICENSE", "terraform/aws/s3.tf", "terraform/aws/ecr.tf", "terraform/aws/consts.tf",
    }
    for item in manifest["files"]:
        payload = (fixture / item["path"]).read_bytes()
        assert len(payload) == item["size_bytes"] < 12_000
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        if item["path"].endswith(".tf"):
            warning, payload = payload.split(b"\n\n", 1)
            assert b"DO NOT run Terraform" in warning
            assert manifest["commit"].encode() in warning
            if not item["path"].endswith("s3.tf"):
                payload = payload[:-1]  # These two upstream files lack a final LF.
        assert hashlib.sha256(payload).hexdigest() == item["upstream_sha256"]
    assert len(list(fixture.rglob("*.tf"))) == 3


def test_example_workspace_has_only_two_portable_scan_sources_and_no_tasks() -> None:
    workspace = ROOT / "examples/security-demo.code-workspace"
    data = json.loads(workspace.read_text())
    assert set(data) == {"folders"}
    assert [item["path"] for item in data["folders"]] == ["vulnerable-demo", "third-party/terragoat"]
    for item in data["folders"]:
        assert not Path(item["path"]).is_absolute()
        assert (workspace.parent / item["path"]).is_dir()
