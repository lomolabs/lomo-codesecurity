from __future__ import annotations

import ast
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

SCANNER_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = SCANNER_ROOT / "kodesec_scanner"
PROOF_LOCK = SCANNER_ROOT / "maintainer-proof-requirements.lock"
BUILD_LOCK = SCANNER_ROOT / "build-requirements.lock"
EXPECTED = {
    "annotated-types": "0.8.0",
    "pydantic": "2.13.4",
    "pydantic-core": "2.46.4",
    "pydantic-settings": "2.15.0",
    "python-dotenv": "1.2.2",
    "typing-extensions": "4.16.0",
    "typing-inspection": "0.4.4",
}
CORE_IMPORT_FILES = (
    "trivy_db_lock_candidate.py",
    "cache_manifest.py",
    "tools.py",
    "updater.py",
)


def _requirements(path: Path) -> dict[str, tuple[str, frozenset[str]]]:
    text = path.read_text(encoding="utf-8")
    starts = list(
        re.finditer(r"(?m)^([a-z0-9][a-z0-9-]*)==([^\s\\]+)\s*\\?\s*$", text)
    )
    parsed: dict[str, tuple[str, frozenset[str]]] = {}
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        hashes = frozenset(
            re.findall(r"--hash=sha256:([0-9a-f]{64})", text[match.end() : end])
        )
        parsed[match.group(1)] = (match.group(2), hashes)
    return parsed


def test_python314_maintainer_lock_is_exact_hash_bound_import_closure() -> None:
    proof = _requirements(PROOF_LOCK)
    build = _requirements(BUILD_LOCK)

    assert {name: version for name, (version, _hashes) in proof.items()} == EXPECTED
    assert all(len(hashes) >= 2 for _version, hashes in proof.values())
    assert proof == {name: build[name] for name in EXPECTED}
    forbidden_sources = r"(?m)^\s*(?:--index-url|--extra-index-url|-e\s|https?://)"
    assert not re.search(forbidden_sources, PROOF_LOCK.read_text())

    project = tomllib.loads((SCANNER_ROOT / "pyproject.toml").read_text())
    assert "pydantic==2.13.4" in project["project"]["dependencies"]

    external: set[str] = set()
    for filename in CORE_IMPORT_FILES:
        tree = ast.parse((PACKAGE_ROOT / filename).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = {alias.name.split(".", 1)[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots = {node.module.split(".", 1)[0]}
            else:
                continue
            external.update(root for root in roots if root not in sys.stdlib_module_names)
    assert external == {"pydantic"}


@pytest.mark.parametrize("omit_settings", [False, True])
def test_candidate_entrypoint_imports_with_only_locked_dependencies(omit_settings: bool) -> None:
    # A fresh interpreter prevents an already imported runtime dependency from
    # hiding an incomplete maintainer lock. Exercise the actual CLI entrypoint,
    # including transitive relative imports omitted by the static inventory.
    modules = {name.replace("-", "_") for name in _requirements(PROOF_LOCK)}
    modules.remove("python_dotenv")
    modules.add("dotenv")
    if omit_settings:
        modules.remove("pydantic_settings")
    scripts = SCANNER_ROOT.parents[1] / "scripts"
    program = f'''
import importlib.abc
import importlib.util
import sys
import sysconfig
from pathlib import Path

sysconfig.get_config_vars()
scripts = Path({str(scripts)!r})
allowed = {modules!r} | {{"kodesec_scanner"}}
class LockedImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        root = fullname.split(".", 1)[0]
        if root in sys.stdlib_module_names or root in allowed or (scripts / (root + ".py")).is_file():
            return None
        raise ImportError("outside maintainer dependency lock: " + fullname)

sys.meta_path.insert(0, LockedImports())
spec = importlib.util.spec_from_file_location("maintainer_entrypoint", scripts / "trivy-db-lock-candidate.py")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
core = module._candidate_core()
assert Path(core.__file__).resolve() == Path({str(PACKAGE_ROOT / 'trivy_db_lock_candidate.py')!r}).resolve()
'''
    result = subprocess.run(
        [sys.executable, "-I", "-c", program],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if omit_settings:
        assert result.returncode != 0
        assert "outside maintainer dependency lock: pydantic_settings" in result.stderr
    else:
        assert result.returncode == 0, result.stderr
