from __future__ import annotations

import os
from pathlib import Path
import tempfile

os.environ.setdefault(
    "KODESEC_SCRATCH_DIR",
    str(Path(tempfile.mkdtemp(prefix="kodesec-health-test-")) / "scratch"),
)

import pytest
from fastapi.testclient import TestClient

from kodesec_scanner import main as scanner


@pytest.mark.parametrize("root_count", [1, 15, 64])
def test_health_response_is_independent_of_source_inventory(monkeypatch, root_count):
    roots = [f"/owned/{'nested/' * 100}repository-{index}" for index in range(root_count)]
    monkeypatch.setattr(scanner.settings, "allowed_roots", ",".join(roots))
    # Health must not initialize cache verification or resolve scanner binaries.
    monkeypatch.setattr(scanner, "_runtime_verifier", lambda: pytest.fail("health probed scanner data"))
    response = TestClient(scanner.app).get("/healthz")
    assert response.status_code == 200
    assert len(response.content) <= 4096  # Existing Settings health-response bound.
    assert response.json() == {
        "ok": True,
        "version": scanner.__version__,
        "engine": "kodesec-worker",
    }
    assert all(root.encode() not in response.content for root in roots)
