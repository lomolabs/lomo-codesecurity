from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import stat
import subprocess
import sys
import tomllib
from uuid import uuid4

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
INIT = REPO_ROOT / "scripts" / "init-runtime.sh"
ROTATE = REPO_ROOT / "scripts" / "rotate-auth.sh"
LOOPBACK_URL = REPO_ROOT / "scripts" / "validate-loopback-url.py"
NORMALIZE_RUNTIME_PAYLOAD = REPO_ROOT / "apps" / "api" / "normalize-runtime-payload.sh"
BOOTSTRAP_GITEA = REPO_ROOT / "scripts" / "bootstrap-gitea.sh"
RESTORE = REPO_ROOT / "scripts" / "restore.sh"
COMPOSE_BUILD = REPO_ROOT / "scripts" / "compose-build.sh"
RUNTIME_COMPOSE = REPO_ROOT / "scripts" / "runtime-compose.py"
SOURCE_PROVENANCE = REPO_ROOT / "scripts" / "source_provenance.py"
SECRET_KEYS = {
    "POSTGRES_PASSWORD",
    "KODESEC_INSTALLATION_SECRET",
    "KODESEC_BOOTSTRAP_TOKEN",
    "KODESEC_ADVISOR_GRANT_SECRET",
    "GRAFANA_ADMIN_PASSWORD",
    "GITEA_SECRET_KEY",
    "GITEA_INTERNAL_TOKEN",
    "GITEA_TEST_PASSWORD",
}


def test_control_image_pins_bases_and_installs_only_the_locked_graph() -> None:
    dockerfile = (REPO_ROOT / "apps/api/Dockerfile").read_text(encoding="utf-8")
    assert dockerfile.startswith(
        "FROM node:22-alpine@sha256:"
        "c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 "
        "AS web-build\n"
    )
    assert (
        "FROM python:3.12-slim@sha256:"
        "229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36\n"
        in dockerfile
    )
    lock_copy = (
        "COPY apps/api/requirements-production.lock ./requirements-production.lock"
    )
    locked_install = (
        "pip install --disable-pip-version-check --only-binary=:all: \\\n"
        "        --require-hashes -r requirements-production.lock"
    )
    project_install = (
        "pip install --disable-pip-version-check --no-build-isolation --no-deps ."
    )
    assert lock_copy in dockerfile
    assert locked_install in dockerfile
    assert project_install in dockerfile
    assert dockerfile.index(lock_copy) < dockerfile.index(
        "COPY apps/api/pyproject.toml"
    )
    assert dockerfile.index(locked_install) < dockerfile.index(project_install)
    assert "RUN pip install ." not in dockerfile


def test_standard_image_builds_bind_exact_clean_git_provenance(tmp_path: Path) -> None:
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    compose = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    control = (REPO_ROOT / "apps" / "api" / "Dockerfile").read_text(encoding="utf-8")
    scanner = (REPO_ROOT / "services" / "scanner" / "Dockerfile").read_text(
        encoding="utf-8"
    )

    assert makefile.count("scripts/compose-build.sh $(COMPOSE)") == 5
    assert compose.count("KODESEC_SOURCE_COMMIT: ${KODESEC_SOURCE_COMMIT:-}") == 2
    assert compose.count("KODESEC_SOURCE_TREE: ${KODESEC_SOURCE_TREE:-}") == 2
    assert compose.count("KODESEC_SOURCE_KIND: ${KODESEC_SOURCE_KIND:-git}") == 2
    assert compose.count("KODESEC_SOURCE_DIGEST: ${KODESEC_SOURCE_DIGEST:-}") == 2
    for dockerfile, role in ((control, "control"), (scanner, "scanner")):
        assert 'test "${#KODESEC_SOURCE_COMMIT}" -eq 40' in dockerfile
        assert 'test "${#KODESEC_SOURCE_TREE}" -eq 40' in dockerfile
        assert 'LABEL org.opencontainers.image.revision="${KODESEC_SOURCE_COMMIT}"' in dockerfile
        assert 'dev.lomo.kodesec.source-tree="${KODESEC_SOURCE_TREE}"' in dockerfile
        assert 'dev.lomo.kodesec.source-kind="${KODESEC_SOURCE_KIND}"' in dockerfile
        assert 'dev.lomo.kodesec.source-digest="${KODESEC_SOURCE_DIGEST}"' in dockerfile
        assert (
            f'dev.lomo.kodesec.build-identity="{role}:'
            '${KODESEC_SOURCE_COMMIT}${KODESEC_SOURCE_DIGEST:+source-sha256}:'
            '${KODESEC_SOURCE_TREE}${KODESEC_SOURCE_DIGEST}"'
        ) in dockerfile
        # A commit-only change must not invalidate dependency downloads or
        # source compilation: source identity is bound after the runtime payload.
        provenance_start = dockerfile.index("ARG KODESEC_SOURCE_COMMIT")
        assert provenance_start > dockerfile.rindex("COPY ")
        assert provenance_start > dockerfile.rindex("pip install ")
        assert provenance_start > dockerfile.rindex("RUN install -d ")
        assert provenance_start < dockerfile.index("\nUSER kodesec\n")

    checkout = tmp_path / "checkout"
    (checkout / "scripts").mkdir(parents=True)
    (checkout / "apps" / "api").mkdir(parents=True)
    for script in (COMPOSE_BUILD, SOURCE_PROVENANCE):
        shutil.copy2(script, checkout / "scripts" / script.name)
        (checkout / "scripts" / script.name).chmod(0o755)
    source = checkout / "apps" / "api" / "source.py"
    source.write_text("print('clean')\n", encoding="utf-8")
    subprocess.run(["git", "init", "--quiet"], cwd=checkout, check=True)
    subprocess.run(
        ["git", "config", "user.email", "provenance-test@invalid"],
        cwd=checkout,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Provenance Test"], cwd=checkout, check=True
    )
    subprocess.run(
        [
            "git",
            "add",
            "scripts/compose-build.sh",
            "scripts/source_provenance.py",
            "apps/api/source.py",
        ],
        cwd=checkout,
        check=True,
    )
    subprocess.run(["git", "commit", "--quiet", "-m", "fixture"], cwd=checkout, check=True)
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=checkout,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"],
        cwd=checkout,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    capture = checkout / "capture.sh"
    capture.write_text(
        "#!/bin/sh\n"
        "printf 'commit=%s\\ntree=%s\\nargument=%s\\n' "
        '"$KODESEC_SOURCE_COMMIT" "$KODESEC_SOURCE_TREE" "$1"\n',
        encoding="utf-8",
    )
    capture.chmod(0o755)

    exact = subprocess.run(
        [str(checkout / "scripts" / COMPOSE_BUILD.name), str(capture), "build"],
        cwd=checkout,
        text=True,
        capture_output=True,
        check=False,
    )
    assert exact.returncode == 0, exact.stderr
    assert f"commit={commit}" in exact.stdout
    assert f"tree={tree}" in exact.stdout
    assert "argument=build" in exact.stdout

    (checkout / "docs").mkdir()
    (checkout / "docs" / "operator-note.md").write_text(
        "not an image input\n", encoding="utf-8"
    )
    unrelated = subprocess.run(
        [str(checkout / "scripts" / COMPOSE_BUILD.name), str(capture), "build"],
        cwd=checkout,
        text=True,
        capture_output=True,
        check=False,
    )
    assert unrelated.returncode == 0, unrelated.stderr

    source.write_text("print('dirty')\n", encoding="utf-8")
    refused = subprocess.run(
        [str(checkout / "scripts" / COMPOSE_BUILD.name), str(capture), "build"],
        cwd=checkout,
        text=True,
        capture_output=True,
        check=False,
    )
    assert refused.returncode == 2
    assert "dirty image-build inputs" in refused.stderr
    assert "apps/api/source.py" in refused.stderr
    assert "argument=build" not in refused.stdout


def test_control_image_installs_ssh_client_for_advisor_connector() -> None:
    dockerfile = (REPO_ROOT / "apps/api/Dockerfile").read_text(encoding="utf-8")
    ssh_install = (
        "RUN apt-get update && apt-get install -y --no-install-recommends \\\n"
        "    openssh-client \\\n"
        "    && rm -rf /var/lib/apt/lists/*"
    )
    assert ssh_install in dockerfile
    assert dockerfile.index(ssh_install) < dockerfile.index("USER kodesec")


def test_control_runtime_payload_is_readable_after_restrictive_checkout(
    tmp_path: Path,
) -> None:
    dockerfile = (REPO_ROOT / "apps/api/Dockerfile").read_text(encoding="utf-8")
    normalizer_copy = (
        "COPY apps/api/normalize-runtime-payload.sh "
        "/tmp/normalize-runtime-payload.sh"
    )
    normalizer_run = "RUN /bin/sh /tmp/normalize-runtime-payload.sh /app"
    payload_copies = (
        "COPY apps/api/kodesec_api ./kodesec_api",
        "COPY services/advisor_connector ./advisor_connector",
        "COPY --from=web-build /web/dist ./static",
    )
    assert normalizer_copy in dockerfile
    assert all(copy in dockerfile for copy in payload_copies)
    assert max(dockerfile.index(copy) for copy in payload_copies) < dockerfile.index(
        normalizer_run
    )
    assert dockerfile.index(normalizer_copy) < dockerfile.index(normalizer_run)
    assert dockerfile.index(normalizer_run) < dockerfile.index("\nUSER kodesec\n")

    runtime_root = tmp_path / "app"
    previous_umask = os.umask(0o077)
    try:
        for relative in (
            "kodesec_api/nested/module.py",
            "advisor_connector/__init__.py",
            "static/assets/app.js",
        ):
            path = runtime_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("immutable runtime payload\n", encoding="utf-8")
        sentinel = runtime_root / "private-build-sentinel"
        sentinel.write_text("unchanged\n", encoding="utf-8")
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE((runtime_root / "kodesec_api").stat().st_mode) == 0o700
    assert stat.S_IMODE(
        (runtime_root / "kodesec_api/nested/module.py").stat().st_mode
    ) == 0o600
    assert stat.S_IMODE(sentinel.stat().st_mode) == 0o600

    subprocess.run(
        ["/bin/sh", str(NORMALIZE_RUNTIME_PAYLOAD), str(runtime_root)],
        check=True,
        capture_output=True,
        text=True,
    )

    for relative in (
        "kodesec_api",
        "kodesec_api/nested",
        "advisor_connector",
        "static",
        "static/assets",
    ):
        assert stat.S_IMODE((runtime_root / relative).stat().st_mode) == 0o555
    for relative in (
        "kodesec_api/nested/module.py",
        "advisor_connector/__init__.py",
        "static/assets/app.js",
    ):
        assert stat.S_IMODE((runtime_root / relative).stat().st_mode) == 0o444
    assert stat.S_IMODE(sentinel.stat().st_mode) == 0o600


def test_source_snapshot_mountpoint_is_private_and_owned_in_both_images() -> None:
    for relative in ("apps/api/Dockerfile", "services/scanner/Dockerfile"):
        dockerfile = (REPO_ROOT / relative).read_text(encoding="utf-8")
        source_layout = dockerfile.index("/data/source-snapshots")
        generations_layout = dockerfile.index("/data/source-snapshots/generations")
        assert "install -d -o 1000 -g 1000 -m 0700" in dockerfile[:source_layout]
        assert source_layout < generations_layout < dockerfile.index("\nUSER kodesec\n")


def test_fresh_source_snapshot_volume_round_trips_between_built_images() -> None:
    control_image = os.environ.get("KODESEC_TEST_CONTROL_IMAGE")
    scanner_image = os.environ.get("KODESEC_TEST_SCANNER_IMAGE")
    if not control_image or not scanner_image:
        pytest.skip("set exact built control and scanner image tags for the volume regression")
    volume = f"lomo-source-snapshot-test-{uuid4().hex}"
    common = [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
    ]
    subprocess.run(
        ["docker", "volume", "create", volume],
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        scanner_mount = f"type=volume,source={volume},target=/data/source-snapshots,readonly"
        subprocess.run(
            [
                *common,
                "--mount", scanner_mount,
                "--entrypoint", "python",
                scanner_image,
                "-c",
                "import os,stat; "
                "root=os.stat('/data/source-snapshots'); "
                "generations=os.stat('/data/source-snapshots/generations'); "
                "assert (root.st_uid,root.st_gid,stat.S_IMODE(root.st_mode))==(1000,1000,0o700); "
                "assert (generations.st_uid,generations.st_gid,stat.S_IMODE(generations.st_mode))==(1000,1000,0o700)",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        control_program = (
            "import base64,hashlib; from types import SimpleNamespace; "
            "from kodesec_api.schemas import SourceSnapshotCreate; "
            "from kodesec_api.source_snapshots import store_source_snapshot; "
            "content=b\"print('volume fixture')\\n\"; "
            "payload=SourceSnapshotCreate.model_validate({'source_id':'a'*64,'name':'volume-fixture','files':["
            "{'path':'app.py','content_base64':base64.b64encode(content).decode('ascii'),"
            "'sha256':hashlib.sha256(content).hexdigest(),'size_bytes':len(content)}]}); "
            "digest,_,_,_=store_source_snapshot(SimpleNamespace(source_snapshot_dir='/data/source-snapshots'),payload); "
            "print(digest)"
        )
        sealed = subprocess.run(
            [
                *common,
                "--mount", f"type=volume,source={volume},target=/data/source-snapshots",
                "--entrypoint", "python",
                control_image,
                "-c", control_program,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        digest = sealed.stdout.strip()
        assert re.fullmatch(r"[0-9a-f]{64}", digest)
        scanner_program = (
            "from pathlib import Path; from kodesec_scanner import main; "
            f"digest='{digest}'; "
            "repo=main._ensure_allowed(Path('/data/source-snapshots/generations')/digest/'source'); "
            "main._ensure_snapshot_binding(repo,digest); "
            "logical,content=main._read_target_file(repo,'app.py'); "
            "assert logical.name=='app.py' and content==b\"print('volume fixture')\\n\""
        )
        subprocess.run(
            [
                *common,
                "--mount", scanner_mount,
                "--env", "KODESEC_ALLOWED_ROOTS=/data/source-snapshots/generations",
                "--env", "KODESEC_SOURCE_SNAPSHOT_DIR=/data/source-snapshots",
                "--env", "KODESEC_SCRATCH_DIR=/run/kodesec-scratch",
                "--tmpfs", "/run/kodesec-scratch:rw,nosuid,nodev,size=512m,uid=1000,gid=1000,mode=0700",
                "--entrypoint", "python",
                scanner_image,
                "-c", scanner_program,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        subprocess.run(
            ["docker", "volume", "rm", volume],
            check=True,
            capture_output=True,
            text=True,
        )


def test_control_image_production_lock_is_hashed_and_excludes_test_dependencies() -> (
    None
):
    lock = (REPO_ROOT / "apps/api/requirements-production.lock").read_text(
        encoding="utf-8"
    )
    assert "--hash=sha256:" in lock
    assert re.search(r"^[a-z0-9][a-z0-9._-]*==[^ ]+", lock, flags=re.MULTILINE)
    assert re.search(r"^pytest==", lock, flags=re.MULTILINE) is None
    assert re.search(r"^iniconfig==", lock, flags=re.MULTILINE) is None
    assert re.search(r"^pluggy==", lock, flags=re.MULTILINE) is None
    assert re.search(r"^kodesec-api(?:==|\s*@)", lock, flags=re.MULTILINE) is None
    assert "make api-requirements-lock" in lock.splitlines()[1]
    assert re.search(r"^setuptools==75\.6\.0", lock, flags=re.MULTILINE)
    assert "-e ." not in lock
    assert "/private/tmp" not in lock

    project = tomllib.loads(
        (REPO_ROOT / "apps/api/pyproject.toml").read_text(encoding="utf-8")
    )
    direct_dependencies = project["project"]["dependencies"]
    expected = {
        re.match(r"^([A-Za-z0-9._-]+)", dependency)
        .group(1)
        .lower()
        .replace("_", "-"): dependency.split("==", 1)[1]
        for dependency in direct_dependencies
    }
    locked = {
        match.group(1).lower().replace("_", "-"): match.group(2)
        for match in re.finditer(
            r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)==([^ ;\\]+)",
            lock,
            flags=re.MULTILINE,
        )
    }
    assert {name: locked.get(name) for name in expected} == expected
    for name in expected:
        assert len(re.findall(rf"^{re.escape(name)}==", lock, flags=re.MULTILINE)) == 1
    assert locked["setuptools"] == "75.6.0"

    patterns = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert "!apps/api/requirements-production.lock" in patterns
    assert patterns.index("!apps/api/requirements-production.lock") > patterns.index(
        "apps/api/requirements-test.txt"
    )


def test_shared_test_lock_covers_both_service_dependency_declarations() -> None:
    lock = (REPO_ROOT / "apps/api/requirements-test.txt").read_text(encoding="utf-8")
    locked = {
        match.group(1).lower().replace("_", "-"): match.group(2)
        for match in re.finditer(
            r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)==([^ ;\\]+)", lock, flags=re.MULTILINE
        )
    }
    expected: dict[str, str] = {}
    for service in ("apps/api", "services/scanner"):
        project = tomllib.loads(
            (REPO_ROOT / service / "pyproject.toml").read_text(encoding="utf-8")
        )["project"]
        for dependency in (
            project["dependencies"] + project["optional-dependencies"]["test"]
        ):
            match = re.fullmatch(r"([A-Za-z0-9._-]+)(?:\[[^]]+\])?==([^ ;]+)", dependency)
            assert match is not None, f"Unpinned shared test dependency: {dependency}"
            name, version = match.group(1).lower().replace("_", "-"), match.group(2)
            assert name not in expected or expected[name] == version
            expected[name] = version
    assert {name: locked.get(name) for name in expected} == expected


def test_api_dependency_lock_targets_are_frozen_and_fail_on_drift() -> None:
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    for target in ("api-requirements-lock:", "api-requirements-lock-check:"):
        assert target in makefile
    assert (
        makefile.count("for api_platform in x86_64-manylinux2014 aarch64-manylinux2014")
        == 2
    )
    assert makefile.count("apps/api/pyproject.toml apps/api/build-requirements.in") == 2
    api_targets = makefile[
        makefile.index("api-requirements-lock:") : makefile.index(
            "scanner-requirements-lock:"
        )
    ]
    assert api_targets.count("--python-version 3.12 --python-platform") == 2
    assert api_targets.count("--generate-hashes --no-emit-package kodesec-api") == 2
    assert (
        api_targets.count("--custom-compile-command 'make api-requirements-lock'") == 2
    )
    assert (
        api_targets.count(
            'cmp "$$lock_tmp/x86_64-manylinux2014.lock" \\\n'
            '\t      "$$lock_tmp/aarch64-manylinux2014.lock"'
        )
        == 2
    )
    assert (
        'cmp "$$lock_tmp/x86_64-manylinux2014.lock" \\\n'
        "\t      apps/api/requirements-production.lock"
    ) in makefile

    test_recipe = makefile[makefile.index("test:") : makefile.index("test-postgres:")]
    assert "cd apps/api && env -i" in test_recipe
    for name in ("HOME", "USER", "LOGNAME", "PATH", "TMPDIR"):
        assert f'{name}="$${{{name}' in test_recipe


def test_scanner_root_build_context_includes_only_its_locked_inputs() -> None:
    dockerfile = (REPO_ROOT / "services/scanner/Dockerfile").read_text(encoding="utf-8")
    sources = {
        match.group(1)
        for match in re.finditer(r"^COPY (?!\-\-from=)([^ ]+) ", dockerfile, flags=re.MULTILINE)
    }
    expected = {
        "services/scanner/pyproject.toml",
        "services/scanner/kodesec_scanner",
        "scanner-tools.lock.json",
        "scanner-rules.lock.json",
        "services/scanner/rules/opengrep",
        "tests/scanner-runtime/fixtures/opengrep",
        "tests/scanner-runtime/fixtures/bearer/rules-canary",
    }
    assert expected <= sources
    assert all((REPO_ROOT / source).exists() for source in sources)

    patterns = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    for required in (
        "!services",
        "!services/scanner",
        "!services/scanner/**",
        "!tests",
        "!tests/scanner-runtime",
        "!tests/scanner-runtime/**",
    ):
        assert required in patterns
    assert patterns.index("!services") > patterns.index("services")
    assert patterns.index("!tests") > patterns.index("tests")


def test_control_root_build_context_includes_the_advisor_connector() -> None:
    dockerfile = (REPO_ROOT / "apps/api/Dockerfile").read_text(encoding="utf-8")
    assert "COPY services/advisor_connector ./advisor_connector" in dockerfile

    patterns = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    for required in (
        "!services",
        "!services/advisor_connector",
        "!services/advisor_connector/**",
    ):
        assert required in patterns
    assert patterns.index("!services/advisor_connector") > patterns.index("services/*")


def _init(state_dir: Path, **extra: str) -> subprocess.CompletedProcess[str]:
    environment = {
        **os.environ,
        "KODESEC_STATE_DIR": str(state_dir),
        "KODESEC_RUNTIME_ENV": str(state_dir / "runtime.env"),
        **extra,
    }
    return subprocess.run(
        [str(INIT)],
        cwd=REPO_ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )


def _values(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


def test_restore_quiesces_and_restarts_durable_worker() -> None:
    content = RESTORE.read_text(encoding="utf-8")
    assert "stop api-ingress worker api scanner scanner-updater gitea" in content
    assert "compose up -d scanner scanner-updater advisor-connector worker api api-ingress" in content


def _rotate(state_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(ROTATE)],
        cwd=REPO_ROOT,
        env={
            **os.environ,
            "KODESEC_STATE_DIR": str(state_dir),
            "KODESEC_RUNTIME_ENV": str(state_dir / "runtime.env"),
        },
        text=True,
        capture_output=True,
        check=False,
    )


def test_runtime_init_is_private_random_quiet_and_idempotent(tmp_path: Path) -> None:
    first_state = tmp_path / "first"
    initialized = _init(first_state)
    assert initialized.returncode == 0, initialized.stderr
    runtime_env = first_state / "runtime.env"
    first_owner = first_state / "first-owner-browser-v1.json"
    assert stat.S_IMODE(first_state.stat().st_mode) == 0o700
    assert stat.S_IMODE(runtime_env.stat().st_mode) == 0o600
    assert stat.S_IMODE(first_owner.stat().st_mode) == 0o600

    values = _values(runtime_env)
    assert SECRET_KEYS <= values.keys()
    assert "KODESEC_IDE_PAIRING_TOKEN" not in values
    assert all(len(values[key]) >= 43 for key in SECRET_KEYS)
    assert values["KODESEC_REPO_ROOT"] == str(REPO_ROOT.resolve())
    assert values["KODESEC_ALLOWED_ROOTS"] == str(REPO_ROOT.resolve())
    assert re.fullmatch(r"[a-f0-9]{12}", values["KODESEC_INSTALLATION_ID"])
    assert values["COMPOSE_PROJECT_NAME"] == (
        f"lomo-code-security-{values['KODESEC_INSTALLATION_ID']}"
    )
    assert values["KODESEC_CONTROL_IMAGE"] == (
        f"lomo-kodesec-control:{values['KODESEC_INSTALLATION_ID']}"
    )
    assert values["KODESEC_SCANNER_IMAGE"] == (
        f"lomo-kodesec-scanner:{values['KODESEC_INSTALLATION_ID']}"
    )
    first_owner_payload = json.loads(first_owner.read_text(encoding="utf-8"))
    assert first_owner_payload == {
        "bootstrap_token": values["KODESEC_BOOTSTRAP_TOKEN"],
        "control_origin": "http://127.0.0.1:8080",
        "installation_id": values["KODESEC_INSTALLATION_ID"],
        "v": 1,
    }
    output = initialized.stdout + initialized.stderr
    assert all(values[key] not in output for key in SECRET_KEYS)

    auth_info = subprocess.run(
        [str(REPO_ROOT / "scripts" / "auth-info.sh")],
        cwd=REPO_ROOT,
        env={
            **os.environ,
            "KODESEC_STATE_DIR": str(first_state),
            "KODESEC_RUNTIME_ENV": str(runtime_env),
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert auth_info.returncode == 0, auth_info.stderr
    assert "Browser bootstrap URL" in auth_info.stdout
    assert values["KODESEC_BOOTSTRAP_TOKEN"] in auth_info.stdout
    assert "pairing" not in auth_info.stdout.lower()

    before = hashlib.sha256(runtime_env.read_bytes()).digest()
    first_owner_before = hashlib.sha256(first_owner.read_bytes()).digest()
    repeated = _init(first_state)
    assert repeated.returncode == 0
    assert hashlib.sha256(runtime_env.read_bytes()).digest() == before
    assert hashlib.sha256(first_owner.read_bytes()).digest() == first_owner_before

    second_state = tmp_path / "second"
    assert _init(second_state).returncode == 0
    second_values = _values(second_state / "runtime.env")
    assert all(values[key] != second_values[key] for key in SECRET_KEYS)
    assert values["COMPOSE_PROJECT_NAME"] != second_values["COMPOSE_PROJECT_NAME"]
    assert values["KODESEC_INSTALLATION_ID"] != second_values["KODESEC_INSTALLATION_ID"]
    assert values["KODESEC_CONTROL_IMAGE"] != second_values["KODESEC_CONTROL_IMAGE"]
    assert values["KODESEC_SCANNER_IMAGE"] != second_values["KODESEC_SCANNER_IMAGE"]
    second_first_owner = json.loads(
        (second_state / "first-owner-browser-v1.json").read_text(encoding="utf-8")
    )
    assert second_first_owner["bootstrap_token"] == second_values["KODESEC_BOOTSTRAP_TOKEN"]
    assert second_first_owner["bootstrap_token"] != first_owner_payload["bootstrap_token"]

    rotated = _rotate(first_state)
    assert rotated.returncode == 0, rotated.stderr
    rotated_values = _values(runtime_env)
    assert rotated_values["KODESEC_BOOTSTRAP_TOKEN"] != values["KODESEC_BOOTSTRAP_TOKEN"]
    assert rotated_values["KODESEC_INSTALLATION_ID"] == values["KODESEC_INSTALLATION_ID"]
    assert not first_owner.exists()
    unchanged = SECRET_KEYS - {"KODESEC_BOOTSTRAP_TOKEN"}
    assert all(rotated_values[key] == values[key] for key in unchanged)
    assert all(rotated_values[key] not in rotated.stdout + rotated.stderr for key in SECRET_KEYS)


def test_first_owner_identity_survives_run_scoped_compose_names(tmp_path: Path) -> None:
    state = tmp_path / "run-scoped"
    initialized = _init(state)
    assert initialized.returncode == 0, initialized.stderr
    runtime_env = state / "runtime.env"
    values = _values(runtime_env)
    original_installation_id = values["KODESEC_INSTALLATION_ID"]
    rewritten = runtime_env.read_text(encoding="utf-8")
    rewritten = re.sub(
        r"(?m)^COMPOSE_PROJECT_NAME=.*$",
        "COMPOSE_PROJECT_NAME=lomo-foreground-217-0123456789ab",
        rewritten,
    )
    rewritten = re.sub(
        r"(?m)^KODESEC_CONTROL_IMAGE=.*$",
        "KODESEC_CONTROL_IMAGE=lomo-kodesec-control:foreground-217-aabbccddeeff",
        rewritten,
    )
    rewritten = re.sub(
        r"(?m)^KODESEC_SCANNER_IMAGE=.*$",
        "KODESEC_SCANNER_IMAGE=lomo-kodesec-scanner:foreground-217-0123456789ab",
        rewritten,
    )
    rewritten = re.sub(r"(?m)^CONTROL_PORT=.*$", "CONTROL_PORT=8180", rewritten)
    runtime_env.write_text(rewritten, encoding="utf-8")
    runtime_env.chmod(0o600)

    published = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "publish-first-owner-bootstrap.py"),
            str(state),
            str(runtime_env),
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert published.returncode == 0, published.stderr
    payload = json.loads(
        (state / "first-owner-browser-v1.json").read_text(encoding="utf-8")
    )
    assert payload["installation_id"] == original_installation_id
    assert payload["control_origin"] == "http://127.0.0.1:8180"
    runtime_before = runtime_env.read_bytes()
    artifact_before = (state / "first-owner-browser-v1.json").read_bytes()
    repeated = _init(state)
    assert repeated.returncode == 0, repeated.stderr
    assert runtime_env.read_bytes() == runtime_before
    assert (state / "first-owner-browser-v1.json").read_bytes() == artifact_before
    repeated_values = _values(runtime_env)
    assert repeated_values["KODESEC_INSTALLATION_ID"] == original_installation_id
    assert repeated_values["KODESEC_BOOTSTRAP_TOKEN"] == values["KODESEC_BOOTSTRAP_TOKEN"]

@pytest.mark.parametrize("role,path", [("control", "apps/api/Dockerfile"), ("scanner", "services/scanner/Dockerfile")])
def test_image_provenance_shell_and_labels_accept_only_typed_source_identities(tmp_path: Path, role: str, path: str) -> None:
    provenance_type = runpy.run_path(str(SOURCE_PROVENANCE))["SourceProvenance"]
    dockerfile = (REPO_ROOT / path).read_text(encoding="utf-8")
    boundary = dockerfile.split("ARG KODESEC_SOURCE_COMMIT", 1)[1]
    validation = boundary.split("RUN ", 1)[1].split("\nLABEL ", 1)[0].replace("\\\n", "")
    validation = validation.replace("/usr/local/share/kodesec/build-identity", '"$KODESEC_TEST_BUILD_IDENTITY"')
    label_block = boundary.split("\nLABEL ", 1)[1].split("\n\n", 1)[0]
    labels = re.findall(r'([a-zA-Z0-9_.-]+)="([^"]*)"', label_block)
    label_command = "\n".join(f"printf '%s\\n' \"{value}\"" for _, value in labels)
    for index, provenance in enumerate((provenance_type("a" * 40, "b" * 40), provenance_type.snapshot("c" * 64))):
        identity_file = tmp_path / f"identity-{index}"
        environment = {**os.environ, **dict(provenance.build_args()), "KODESEC_TEST_BUILD_IDENTITY": str(identity_file)}
        valid = subprocess.run(["/bin/sh", "-c", validation], env=environment, capture_output=True, text=True, check=False)
        assert valid.returncode == 0, valid.stderr
        resolved = subprocess.run(["/bin/sh", "-ec", label_command], env=environment, capture_output=True, text=True, check=True)
        assert dict(zip((key for key, _ in labels), resolved.stdout.splitlines(), strict=True)) == provenance.labels(role)
        if role == "scanner":
            assert identity_file.read_text() == provenance.build_identity(role) + "\n"
            assert stat.S_IMODE(identity_file.stat().st_mode) == 0o444
    invalid_inputs = [
        {"KODESEC_SOURCE_KIND": "unknown"},
        {"KODESEC_SOURCE_KIND": ""},
        {"KODESEC_SOURCE_DIGEST": "c" * 64},
        {"KODESEC_SOURCE_COMMIT": "A" * 40},
        {"KODESEC_SOURCE_TREE": "b" * 39},
        {"KODESEC_SOURCE_KIND": "source-sha256", "KODESEC_SOURCE_DIGEST": "c" * 64},
        {"KODESEC_SOURCE_KIND": "source-sha256", "KODESEC_SOURCE_COMMIT": "", "KODESEC_SOURCE_TREE": "", "KODESEC_SOURCE_DIGEST": ""},
        {"KODESEC_SOURCE_KIND": "source-sha256", "KODESEC_SOURCE_COMMIT": "", "KODESEC_SOURCE_TREE": "", "KODESEC_SOURCE_DIGEST": "c" * 63},
        {"KODESEC_SOURCE_KIND": "source-sha256", "KODESEC_SOURCE_COMMIT": "", "KODESEC_SOURCE_TREE": "", "KODESEC_SOURCE_DIGEST": "C" * 64},
    ]
    for index, changes in enumerate(invalid_inputs):
        identity_file = tmp_path / f"refused-{index}"
        environment = {**os.environ, **dict(provenance_type("a" * 40, "b" * 40).build_args()),
                       **changes, "KODESEC_TEST_BUILD_IDENTITY": str(identity_file)}
        refused = subprocess.run(["/bin/sh", "-c", validation], env=environment, capture_output=True, text=True, check=False)
        assert refused.returncode != 0
        assert not identity_file.exists()


@pytest.mark.parametrize("key", ["KODESEC_SOURCE_COMMIT", "KODESEC_SOURCE_TREE", "KODESEC_SOURCE_KIND", "KODESEC_SOURCE_DIGEST"])
def test_runtime_compose_refuses_build_provenance_in_runtime_before_docker(tmp_path: Path, key: str) -> None:
    state = tmp_path / "state"
    assert _init(state).returncode == 0
    runtime = state / "runtime.env"
    with runtime.open("a", encoding="utf-8") as stream:
        stream.write(f"{key}=synthetic-build-only-value\n")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "docker-invoked"
    docker = fake_bin / "docker"
    docker.write_text(f"#!{sys.executable}\nfrom pathlib import Path\nPath({str(marker)!r}).touch()\n")
    docker.chmod(0o755)
    result = subprocess.run([sys.executable, str(RUNTIME_COMPOSE), str(runtime), "config"],
                            env={**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"},
                            capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert "must not supply image-build source provenance" in result.stderr
    assert "synthetic-build-only-value" not in result.stderr
    assert not marker.exists()


def test_runtime_compose_launcher_removes_ambient_product_overrides(tmp_path: Path) -> None:
    state = tmp_path / "state"
    initialized = _init(state)
    assert initialized.returncode == 0, initialized.stderr
    runtime_env = state / "runtime.env"
    values = _values(runtime_env)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker = fake_bin / "docker"
    inspected = [
        "KODESEC_REPO_ROOT",
        "KODESEC_ALLOWED_ROOTS",
        "KODESEC_CONTROL_IMAGE",
        "POSTGRES_IMAGE",
        "KODESEC_WORKER_LEASE_SECONDS",
        "WORKER_MEMORY_LIMIT",
        "COMPOSE_PROJECT_NAME",
        "COMPOSE_FILE",
        "COMPOSE_ENV_FILES",
        "COMPOSE_PATH_SEPARATOR",
        "COMPOSE_PROFILES",
        "COMPOSE_PARALLEL_LIMIT",
        "COMPOSE_PROGRESS",
        "KODESEC_SOURCE_COMMIT",
        "KODESEC_SOURCE_TREE",
        "KODESEC_SOURCE_KIND",
        "KODESEC_SOURCE_DIGEST",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
    ]
    docker.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        f"keys = {inspected!r}\n"
        "print(json.dumps({'arguments': sys.argv[1:], "
        "'environment': {key: os.environ.get(key) for key in keys}}))\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    poisoned = {
        **os.environ,
        "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
        "KODESEC_REPO_ROOT": "/Users",
        "KODESEC_ALLOWED_ROOTS": "/Users",
        "KODESEC_CONTROL_IMAGE": "unreviewed:latest",
        "POSTGRES_IMAGE": "unreviewed-postgres:latest",
        "KODESEC_WORKER_LEASE_SECONDS": "999999",
        "WORKER_MEMORY_LIMIT": "64g",
        "COMPOSE_PROJECT_NAME": "wrong-project",
        "COMPOSE_FILE": "/owner/compose.yml",
        "COMPOSE_ENV_FILES": "/owner/.env",
        "COMPOSE_PATH_SEPARATOR": ";",
        "COMPOSE_PROFILES": "all",
        "COMPOSE_PARALLEL_LIMIT": "99",
        "COMPOSE_PROGRESS": "json",
        "KODESEC_SOURCE_COMMIT": "a" * 40,
        "KODESEC_SOURCE_TREE": "b" * 40,
        "KODESEC_SOURCE_KIND": "git",
        "KODESEC_SOURCE_DIGEST": "",
        "DOCKER_HOST": "unix:///run/owner-docker.sock",
        "DOCKER_CONTEXT": "owner-context",
    }
    result = subprocess.run(
        [
            sys.executable,
            str(RUNTIME_COMPOSE),
            str(runtime_env),
            "config",
            "--format",
            "json",
        ],
        cwd=REPO_ROOT,
        env=poisoned,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    frozen_runtime = payload["arguments"][4]
    assert Path(frozen_runtime).parent.parent == state
    assert not Path(frozen_runtime).exists()
    assert payload["arguments"] == [
        "compose",
        "--project-name",
        values["COMPOSE_PROJECT_NAME"],
        "--env-file",
        frozen_runtime,
        "--file",
        str(REPO_ROOT / "docker-compose.yml"),
        "config",
        "--format",
        "json",
    ]
    preserved = {
        "KODESEC_SOURCE_COMMIT",
        "KODESEC_SOURCE_TREE",
        "KODESEC_SOURCE_KIND",
        "KODESEC_SOURCE_DIGEST",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
    }
    for key in set(inspected) - preserved:
        assert payload["environment"][key] is None
    assert payload["environment"]["KODESEC_SOURCE_COMMIT"] == "a" * 40
    assert payload["environment"]["KODESEC_SOURCE_TREE"] == "b" * 40
    assert payload["environment"]["KODESEC_SOURCE_KIND"] == "git"
    assert payload["environment"]["KODESEC_SOURCE_DIGEST"] == ""
    assert payload["environment"]["DOCKER_HOST"] == "unix:///run/owner-docker.sock"
    assert payload["environment"]["DOCKER_CONTEXT"] == "owner-context"

    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert 'COMPOSE := $(PYTHON) "$(REPO_ROOT)/scripts/runtime-compose.py" "$(RUNTIME_ENV)"' in makefile
    assert "docker compose --env-file $(RUNTIME_ENV)" not in makefile

    spaced_repo = tmp_path / "clone with spaces"
    (spaced_repo / "scripts").mkdir(parents=True)
    shutil.copy2(REPO_ROOT / "Makefile", spaced_repo / "Makefile")
    shutil.copy2(RUNTIME_COMPOSE, spaced_repo / "scripts" / "runtime-compose.py")
    shutil.copy2(REPO_ROOT / "scripts/source_roots.py", spaced_repo / "scripts/source_roots.py")
    shutil.copy2(REPO_ROOT / "docker-compose.yml", spaced_repo / "docker-compose.yml")
    via_make = subprocess.run(
        [
            "make",
            "--no-print-directory",
            "-f",
            str(spaced_repo / "Makefile"),
            "status",
            f"PYTHON={sys.executable}",
            f"RUNTIME_ENV={runtime_env}",
        ],
        cwd=spaced_repo,
        env=poisoned,
        text=True,
        capture_output=True,
        check=False,
    )
    assert via_make.returncode == 0, via_make.stderr
    make_payload = json.loads(via_make.stdout.splitlines()[-1])
    make_frozen_runtime = make_payload["arguments"][4]
    assert Path(make_frozen_runtime).parent.parent == state
    assert not Path(make_frozen_runtime).exists()
    assert make_payload["arguments"] == [
        "compose",
        "--project-name",
        values["COMPOSE_PROJECT_NAME"],
        "--env-file",
        make_frozen_runtime,
        "--file",
        str(spaced_repo / "docker-compose.yml"),
        "ps",
    ]

    symlink = tmp_path / "runtime-symlink.env"
    symlink.symlink_to(runtime_env)
    rejected_symlink = subprocess.run(
        [sys.executable, str(RUNTIME_COMPOSE), str(symlink), "config"],
        cwd=REPO_ROOT,
        env=poisoned,
        text=True,
        capture_output=True,
        check=False,
    )
    assert rejected_symlink.returncode != 0
    assert "must not be a symbolic link" in rejected_symlink.stderr

    hardlink = tmp_path / "runtime-hardlink.env"
    os.link(runtime_env, hardlink)
    rejected_hardlink = subprocess.run(
        [sys.executable, str(RUNTIME_COMPOSE), str(hardlink), "config"],
        cwd=REPO_ROOT,
        env=poisoned,
        text=True,
        capture_output=True,
        check=False,
    )
    assert rejected_hardlink.returncode != 0
    assert "single-link regular file" in rejected_hardlink.stderr


def test_runtime_init_rejects_missing_current_fields_without_mutation(tmp_path: Path) -> None:
    state = tmp_path / "missing-current-fields"
    assert _init(state).returncode == 0
    runtime_env = state / "runtime.env"
    runtime_env.write_text(
        "\n".join(
            line
            for line in runtime_env.read_text(encoding="utf-8").splitlines()
            if not line.startswith("KODESEC_SCANNER_IMAGE=")
        )
        + "\n",
        encoding="utf-8",
    )
    runtime_env.chmod(0o600)
    before = runtime_env.read_bytes()

    rejected = _init(state)
    assert rejected.returncode != 0
    assert "does not match the current format" in rejected.stderr
    assert "missing fields: KODESEC_SCANNER_IMAGE" in rejected.stderr
    assert "KODESEC_SCANNER_IMAGE" in rejected.stderr
    assert runtime_env.read_bytes() == before
    assert stat.S_IMODE(runtime_env.stat().st_mode) == 0o600


def test_runtime_init_rejects_noncurrent_or_invalid_cookie_retention_without_mutation(
    tmp_path: Path,
) -> None:
    noncurrent_state = tmp_path / "noncurrent-session-contract"
    assert _init(noncurrent_state).returncode == 0
    noncurrent_runtime = noncurrent_state / "runtime.env"
    noncurrent_runtime.write_bytes(
        noncurrent_runtime.read_text(encoding="utf-8")
        .replace("KODESEC_RUNTIME_CONFIG_VERSION=1\n", "")
        .rstrip("\n")
        .replace("\n", "\r\n")
        .encode("utf-8")
    )
    noncurrent_runtime.chmod(0o600)
    noncurrent_bytes = noncurrent_runtime.read_bytes()

    rejected = _init(noncurrent_state)
    assert rejected.returncode != 0
    assert "does not match the current format" in rejected.stderr
    assert "KODESEC_RUNTIME_CONFIG_VERSION" in rejected.stderr
    assert noncurrent_runtime.read_bytes() == noncurrent_bytes

def test_runtime_init_rejects_symlink_and_open_permissions(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    target = tmp_path / "target"
    target.write_text("not-runtime-data", encoding="utf-8")
    (state / "runtime.env").symlink_to(target)
    assert _init(state).returncode == 2
    assert target.read_text(encoding="utf-8") == "not-runtime-data"

    (state / "runtime.env").unlink()
    (state / "runtime.env").write_text("partial=true\n", encoding="utf-8")
    (state / "runtime.env").chmod(0o644)
    result = _init(state)
    assert result.returncode == 2
    assert "mode 0600" in result.stderr

    (state / "runtime.env").chmod(0o600)
    result = _init(state)
    assert result.returncode != 0
    assert "missing generated secret fields" in result.stderr


def test_runtime_init_rejects_ancestor_symlink_into_source_and_hardlinks(tmp_path: Path) -> None:
    source_alias = tmp_path / "source-alias"
    source_alias.symlink_to(REPO_ROOT / ".kodesec-test", target_is_directory=True)
    refused = source_alias / f"ancestor-symlink-{tmp_path.name}"
    result = _init(refused)
    assert result.returncode == 2
    assert "Runtime secrets must live outside the source tree" in result.stderr
    assert not refused.exists()

    state = tmp_path / "hardlink-state"
    state.mkdir()
    original = tmp_path / "runtime-hardlink"
    original.write_text("not-a-runtime-environment\n", encoding="utf-8")
    original.chmod(0o600)
    os.link(original, state / "runtime.env")
    result = _init(state)
    assert result.returncode == 2
    assert "must not have hard links" in result.stderr


def test_auth_helpers_reject_hard_linked_runtime_configuration(tmp_path: Path) -> None:
    state = tmp_path / "state"
    assert _init(state).returncode == 0
    runtime_env = state / "runtime.env"
    linked = tmp_path / "runtime-linked.env"
    os.link(runtime_env, linked)
    environment = {
        **os.environ,
        "KODESEC_STATE_DIR": str(state),
        "KODESEC_RUNTIME_ENV": str(runtime_env),
    }
    for script in (REPO_ROOT / "scripts" / "auth-info.sh", ROTATE):
        result = subprocess.run(
            [str(script)],
            cwd=REPO_ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 2
        assert "single-link" in result.stderr


def test_gitea_smoke_refuses_destructive_workdir_outside_owned_state(tmp_path: Path) -> None:
    state = tmp_path / "state"
    assert _init(state).returncode == 0
    unsafe = tmp_path / "unsafe"
    repo = unsafe / "repo"
    repo.mkdir(parents=True)
    sentinel = repo / "owner-data"
    sentinel.write_text("preserve", encoding="utf-8")
    result = subprocess.run(
        [str(BOOTSTRAP_GITEA), "--smoke"],
        cwd=REPO_ROOT,
        env={
            **os.environ,
            "KODESEC_STATE_DIR": str(state),
            "KODESEC_RUNTIME_ENV": str(state / "runtime.env"),
            "GITEA_TEST_DIR": str(unsafe),
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert "dedicated gitea-smoke directory" in result.stderr
    assert sentinel.read_text(encoding="utf-8") == "preserve"


def test_runtime_init_works_from_archive_without_git_metadata(tmp_path: Path) -> None:
    archive = tmp_path / "archive"
    (archive / "scripts").mkdir(parents=True)
    shutil.copy2(INIT, archive / "scripts" / INIT.name)
    shutil.copy2(
        REPO_ROOT / "scripts" / "publish-first-owner-bootstrap.py",
        archive / "scripts" / "publish-first-owner-bootstrap.py",
    )
    shutil.copy2(REPO_ROOT / ".env.example", archive / ".env.example")
    assert not (archive / ".git").exists()
    state = tmp_path / "archive-state"
    result = subprocess.run(
        ["/bin/sh", str(archive / "scripts" / INIT.name)],
        cwd=archive,
        env={
            **os.environ,
            "KODESEC_STATE_DIR": str(state),
            "KODESEC_RUNTIME_ENV": str(state / "runtime.env"),
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert stat.S_IMODE((state / "runtime.env").stat().st_mode) == 0o600
    assert stat.S_IMODE((state / "first-owner-browser-v1.json").stat().st_mode) == 0o600


def test_runtime_init_rejects_source_tree_without_explicit_test_scope(tmp_path: Path) -> None:
    refused = REPO_ROOT / ".kodesec-test" / f"runtime-init-refused-{tmp_path.name}"
    result = _init(refused)
    assert result.returncode == 2
    assert not refused.exists()

    allowed = REPO_ROOT / ".kodesec-test" / f"runtime-init-{tmp_path.name}"
    try:
        result = _init(allowed, KODESEC_ALLOW_TEST_STATE="1")
        assert result.returncode == 0, result.stderr
        assert stat.S_IMODE((allowed / "runtime.env").stat().st_mode) == 0o600
    finally:
        if allowed.exists():
            shutil.rmtree(allowed)


def test_runtime_init_refuses_symlink_advisor_authorization_directory(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    target = tmp_path / "outside-auth"
    state.mkdir(mode=0o700)
    target.mkdir(mode=0o700)
    (state / "advisor-auth").symlink_to(target, target_is_directory=True)
    result = _init(state)
    assert result.returncode != 0
    assert "non-symlink" in result.stderr
    assert not (state / "runtime.env").exists()


def test_runtime_init_owner_directory_check_is_btrfs_compatible() -> None:
    source = INIT.read_text(encoding="utf-8")
    owner_directory_check = source.split('auth = state / "advisor-auth"', 1)[1].split(
        "PY\nstate_dir=", 1
    )[0]
    assert "metadata.st_nlink" not in owner_directory_check
    for invariant in (
        "os.lstat(auth)",
        "stat.S_ISDIR(metadata.st_mode)",
        "stat.S_ISLNK(metadata.st_mode)",
        "stat.S_IMODE(metadata.st_mode) != 0o700",
        "metadata.st_uid != os.getuid()",
        "auth.resolve(strict=True).parent != state.resolve(strict=True)",
    ):
        assert invariant in owner_directory_check


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
        ("http://localhost:3000/", "http://localhost:3000"),
        ("http://[::1]:8443", "http://[::1]:8443"),
    ],
)
def test_operator_loopback_url_validator_accepts_exact_origins(value: str, expected: str) -> None:
    result = subprocess.run(
        [str(LOOPBACK_URL), value],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected


@pytest.mark.parametrize(
    "value",
    [
        "https://127.0.0.1:8080",
        "http://127.0.0.1",
        "http://user:pass@127.0.0.1:8080",
        "http://127.0.0.1:8080/api",
        "http://127.0.0.1:8080?token=value",
        "http://192.0.2.1:8080",
        "file:///tmp/socket",
    ],
)
def test_operator_loopback_url_validator_rejects_credential_egress(value: str) -> None:
    result = subprocess.run(
        [str(LOOPBACK_URL), value],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert "refusing non-loopback URL" in result.stderr


def test_rendered_compose_has_one_loopback_core_origin(tmp_path: Path) -> None:
    if not shutil_which("docker"):
        pytest.skip("Docker Compose CLI is not installed")
    state = tmp_path / "state"
    assert _init(state).returncode == 0
    runtime_env = state / "runtime.env"
    runtime_env.write_text(
        runtime_env.read_text(encoding="utf-8").replace("CONTROL_PORT=8080", "CONTROL_PORT=18080"),
        encoding="utf-8",
    )
    command = [
        "docker",
        "compose",
        "--env-file",
        str(runtime_env),
        "config",
        "--format",
        "json",
    ]
    rendered = subprocess.run(command, cwd=REPO_ROOT, text=True, capture_output=True, check=True)
    config = json.loads(rendered.stdout)
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    restore = RESTORE.read_text(encoding="utf-8")
    assert (
        "up -d --build postgres scanner scanner-updater advisor-connector worker api api-ingress"
        in makefile
    )
    assert "up -d scanner scanner-updater advisor-connector worker api api-ingress" in restore
    assert set(config["services"]) == {
        "api",
        "api-ingress",
        "advisor-connector",
        "schema-init",
        "postgres",
        "scanner",
        "scanner-updater",
        "worker",
    }
    for service_name in (
        "postgres",
        "scanner",
        "scanner-updater",
        "api",
        "api-ingress",
        "worker",
        "advisor-connector",
    ):
        assert config["services"][service_name]["restart"] == "unless-stopped"
    assert config["services"]["schema-init"]["restart"] == "no"
    assert config["services"]["schema-init"]["command"] == [
        "python",
        "-m",
        "kodesec_api.schema_init",
    ]
    published = [
        (name, port)
        for name, service in config["services"].items()
        for port in service.get("ports", [])
    ]
    assert len(published) == 1
    assert published[0][0] == "api-ingress"
    assert published[0][1]["host_ip"] == "127.0.0.1"
    assert int(published[0][1]["published"]) == 18080
    assert int(published[0][1]["target"]) == 8080
    assert "web" not in config["services"]
    api_environment = config["services"]["api"]["environment"]
    worker_environment = config["services"]["worker"]["environment"]
    assert api_environment["KODESEC_CONTROL_ORIGINS"] == "http://127.0.0.1:18080"
    assert api_environment["KODESEC_INTERNAL_HOSTS"] == "api:8080,127.0.0.1:8080"
    assert api_environment["KODESEC_ALLOWED_ROOTS"] == str(REPO_ROOT.resolve())
    assert api_environment["KODESEC_SOURCE_SNAPSHOT_DIR"] == "/data/source-snapshots"
    assert worker_environment["KODESEC_SOURCE_SNAPSHOT_DIR"] == "/data/source-snapshots"
    assert api_environment["KODESEC_OLLAMA_ALLOWED_HOSTS"] == ""
    assert (
        worker_environment["KODESEC_OLLAMA_ALLOWED_HOSTS"]
        == api_environment["KODESEC_OLLAMA_ALLOWED_HOSTS"]
    )
    assert api_environment["KODESEC_SCANNER_TOOLS_TIMEOUT"] == "45"
    assert config["services"]["schema-init"]["image"] == config["services"]["api"]["image"]
    assert config["services"]["schema-init"]["environment"] == {
        "DATABASE_URL": config["services"]["schema-init"]["environment"]["DATABASE_URL"],
        "KODESEC_ARTIFACT_DIR": "/data/artifacts",
    }
    schema_init_artifacts = next(
        mount
        for mount in config["services"]["schema-init"]["volumes"]
        if mount["target"] == "/data/artifacts"
    )
    assert schema_init_artifacts["type"] == "volume"
    assert config["services"]["worker"]["image"] == config["services"]["api"]["image"]
    assert config["services"]["api"]["image"] == _values(runtime_env)["KODESEC_CONTROL_IMAGE"]
    assert config["services"]["scanner"]["image"] == _values(runtime_env)["KODESEC_SCANNER_IMAGE"]
    assert config["services"]["scanner"]["build"]["context"] == str(REPO_ROOT.resolve())
    assert (
        config["services"]["scanner"]["build"]["dockerfile"]
        == "services/scanner/Dockerfile"
    )
    assert config["services"]["scanner-updater"]["image"] == config["services"]["scanner"]["image"]
    scanner_mount = next(
        mount
        for mount in config["services"]["scanner"]["volumes"]
        if mount.get("type") == "bind"
    )
    assert scanner_mount["source"] == str(REPO_ROOT.resolve())
    assert scanner_mount["target"] == str(REPO_ROOT.resolve())
    assert scanner_mount["read_only"] is True
    scanner_service = config["services"]["scanner"]
    scanner_environment = scanner_service["environment"]
    assert scanner_environment["KODESEC_ARTIFACT_DIR"] == "/data/artifacts"
    assert scanner_environment["KODESEC_SOURCE_SNAPSHOT_DIR"] == "/data/source-snapshots"
    assert scanner_environment["KODESEC_ALLOWED_ROOTS"] == (
        f"{REPO_ROOT.resolve()},/data/source-snapshots/generations"
    )
    assert scanner_environment["KODESEC_SCRATCH_DIR"] == "/run/kodesec-scratch"
    assert scanner_environment["KODESEC_TOOL_CACHE_DIR"] == "/data/tool-cache"
    assert "KODESEC_OPENGREP_RULES_PATH" not in scanner_environment
    cache_mount = next(
        mount for mount in scanner_service["volumes"] if mount["target"] == "/data/tool-cache"
    )
    assert cache_mount["type"] == "volume"
    assert cache_mount["source"] == "scanner_cache"
    assert cache_mount["read_only"] is True
    source_snapshot_mounts = {
        service_name: next(
            mount
            for mount in config["services"][service_name]["volumes"]
            if mount["target"] == "/data/source-snapshots"
        )
        for service_name in ("api", "worker", "scanner")
    }
    assert all(
        mount["type"] == "volume" and mount["source"] == "source_snapshots"
        for mount in source_snapshot_mounts.values()
    )
    assert source_snapshot_mounts["api"].get("read_only", False) is False
    assert source_snapshot_mounts["worker"]["read_only"] is True
    assert source_snapshot_mounts["scanner"]["read_only"] is True
    assert all(mount["target"] != "/run/kodesec-scratch" for mount in scanner_service["volumes"])
    scratch_mounts = scanner_service["tmpfs"]
    scratch = next(item for item in scratch_mounts if item.startswith("/run/kodesec-scratch:"))
    assert len(scratch_mounts) == 2
    assert any(item.startswith("/tmp:") and "size=64m" in item for item in scratch_mounts)
    for option in ("rw", "nosuid", "nodev", "size=512m", "uid=1000", "gid=1000", "mode=0700"):
        assert option in scratch

    for service_name in (
        "api",
        "api-ingress",
        "schema-init",
        "scanner",
        "scanner-updater",
        "worker",
        "advisor-connector",
    ):
        service = config["services"][service_name]
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert any(item.startswith("/tmp:") for item in service["tmpfs"])
    assert any(
        item.startswith("/tmp:") and "size=160m" in item
        for item in config["services"]["api"]["tmpfs"]
    )
    assert config["services"]["api"]["pull_policy"] == "never"
    assert "ports" not in config["services"]["api"]
    assert config["services"]["api"]["healthcheck"]["test"] == [
        "CMD",
        "python",
        "-I",
        "-m",
        "kodesec_api.http_health",
    ]
    assert "advisor=" not in " ".join(config["services"]["api"]["healthcheck"]["test"])
    assert "extra_hosts" not in config["services"]["api"]

    internal_networks = {name for name, network in config["networks"].items() if network.get("internal")}
    assert len(internal_networks) == 5
    private_network = next(
        name for name in internal_networks if name in scanner_service["networks"]
    )
    updater_control = next(
        name for name in internal_networks
        if name in config["services"]["scanner-updater"]["networks"]
    )
    advisor_control = next(
        name for name in internal_networks
        if name in config["services"]["advisor-connector"]["networks"]
    )
    ingress_control = next(
        name for name in internal_networks
        if name in config["services"]["api-ingress"]["networks"]
    )
    component_observation = next(
        name
        for name in internal_networks
        if name in config["services"]["api"]["networks"]
        and name not in {private_network, ingress_control, updater_control}
    )
    external_networks = {
        name for name, network in config["networks"].items() if not network.get("internal")
    }
    updater_egress = next(
        name
        for name in external_networks
        if name in config["services"]["scanner-updater"]["networks"]
    )
    advisor_egress = next(
        name for name in external_networks
        if name in config["services"]["advisor-connector"]["networks"]
    )
    ingress_network = next(
        name for name in external_networks
        if name in config["services"]["api-ingress"]["networks"]
    )
    assert external_networks == {updater_egress, advisor_egress, ingress_network}
    assert all(
        service_name == "api-ingress" or ingress_network not in service["networks"]
        for service_name, service in config["services"].items()
    )
    assert set(scanner_service["networks"]) == {private_network}
    assert set(config["services"]["postgres"]["networks"]) == {private_network}
    assert set(config["services"]["schema-init"]["networks"]) == {private_network}
    assert private_network in config["services"]["worker"]["networks"]
    assert set(config["services"]["worker"]["networks"]) == {
        private_network,
        updater_control,
        advisor_control,
    }
    assert advisor_control not in config["services"]["api"]["networks"]
    assert "advisor-connector" not in config["services"]["api"].get("depends_on", {})
    assert "advisor-connector" not in config["services"]["worker"].get("depends_on", {})
    assert "extra_hosts" not in config["services"]["worker"]
    assert "ports" not in config["services"]["worker"]
    assert "KODESEC_INSTALLATION_SECRET" not in config["services"]["worker"]["environment"]
    assert config["services"]["worker"]["environment"]["KODESEC_ADVISOR_GRANT_SECRET"]
    assert config["services"]["worker"]["environment"]["SCANNER_UPDATER_URL"] == "http://scanner-updater:8092"
    assert config["services"]["api"]["environment"]["SCANNER_UPDATER_URL"] == "http://scanner-updater:8092"
    assert {
        name for name, service in config["services"].items()
        if updater_control in service["networks"]
    } == {"api", "worker", "scanner-updater"}
    assert config["services"]["worker"]["command"] == ["python", "-m", "kodesec_api.worker"]
    assert config["services"]["worker"]["healthcheck"]["test"] == [
        "CMD",
        "python",
        "-m",
        "kodesec_api.worker_health",
    ]
    assert set(config["services"]["api"]["networks"]) == {
        component_observation,
        private_network,
        ingress_control,
        updater_control,
    }
    assert "KODESEC_ADVISOR_CONNECTOR_URL" not in config["services"]["api"]["environment"]
    assert (
        config["services"]["worker"]["environment"]["KODESEC_ADVISOR_CONNECTOR_URL"]
        == "http://advisor-connector:8093"
    )
    assert all(
        service_name in {"api", "api-ingress"}
        or ingress_control not in service["networks"]
        for service_name, service in config["services"].items()
    )
    assert all(
        config["networks"][name].get("internal") is True
        for service_name in ("api", "worker")
        for name in config["services"][service_name]["networks"]
    )

    ingress = config["services"]["api-ingress"]
    assert ingress["image"] == config["services"]["api"]["image"]
    assert set(ingress["networks"]) == {ingress_control, ingress_network}
    assert ingress.get("environment", {}) == {}
    assert "volumes" not in ingress
    assert ingress["pids_limit"] == 32
    assert ingress["user"] == "1000:1000"
    assert ingress["ulimits"] == {
        "nofile": {"soft": 256, "hard": 256},
    }
    assert ingress["depends_on"] == {
        "api": {"condition": "service_healthy", "required": True}
    }
    assert ingress["command"] == [
        "python",
        "-I",
        "-m",
        "kodesec_api.ingress",
        "--listen-host",
        "0.0.0.0",
        "--listen-port",
        "8080",
        "--target-host",
        "api",
        "--target-port",
        "8080",
    ]
    assert ingress["healthcheck"]["test"] == [
        "CMD",
        "python",
        "-I",
        "-m",
        "kodesec_api.http_health",
    ]

    connector = config["services"]["advisor-connector"]
    assert set(connector["networks"]) == {advisor_control, advisor_egress}
    assert "ports" not in connector
    assert connector["read_only"] is True
    assert connector["cap_drop"] == ["ALL"]
    assert connector["security_opt"] == ["no-new-privileges:true"]
    assert connector["pids_limit"] == 64
    assert any(
        item.startswith("/tmp:")
        and "uid=" in item
        and "gid=" in item
        and "mode=0700" in item
        for item in connector["tmpfs"]
    )
    assert connector["environment"] == {
        "KODESEC_ADVISOR_AUTH_DIR": "/run/kodesec-advisor-auth",
        "KODESEC_ADVISOR_DIRECT_HOSTS": "",
        "KODESEC_ADVISOR_GRANT_SECRET": _values(runtime_env)["KODESEC_ADVISOR_GRANT_SECRET"],
        "KODESEC_ADVISOR_LOCAL_URL": "http://host.docker.internal:11434",
    }
    assert len(connector["volumes"]) == 1
    assert connector["volumes"][0]["target"] == "/run/kodesec-advisor-auth"
    assert connector["volumes"][0]["read_only"] is True
    assert all(
        forbidden not in json.dumps(connector)
        for forbidden in (
            "DATABASE_URL",
            "KODESEC_ARTIFACT_DIR",
            "KODESEC_ALLOWED_ROOTS",
            "KODESEC_INSTALLATION_SECRET",
            "/var/run/docker.sock",
            "runtime.env",
        )
    )

    updater = config["services"]["scanner-updater"]
    assert updater["cpus"] == 2
    assert updater["mem_limit"] == str(4 * 1024**3)
    assert updater["memswap_limit"] == str(4 * 1024**3)
    assert updater["pids_limit"] == 256
    assert set(updater["networks"]) == {updater_control, updater_egress}
    assert "ports" not in updater
    assert "extra_hosts" not in updater
    assert set(updater["environment"]) == {
        "KODESEC_RULES_LOCK_PATH",
        "KODESEC_TOOL_CACHE_DIR",
        "KODESEC_TOOL_LOCK_PATH",
        "KODESEC_UPDATER_MAX_ACTIVE",
        "KODESEC_UPDATER_SCRATCH_DIR",
        "KODESEC_UPDATER_SHUTDOWN_WAIT_SECONDS",
    }
    assert updater["environment"]["KODESEC_TOOL_CACHE_DIR"] == "/data/tool-cache"
    assert updater["command"] == [
        "uvicorn",
        "kodesec_scanner.updater_main:app",
        "--host",
        "0.0.0.0",
        "--port",
        "8092",
    ]
    assert len(updater["volumes"]) == 1
    updater_cache = updater["volumes"][0]
    assert updater_cache["type"] == "volume"
    assert updater_cache["source"] == "scanner_cache"
    assert updater_cache["target"] == "/data/tool-cache"
    assert updater_cache.get("read_only", False) is False
    assert all(
        forbidden not in json.dumps(updater)
        for forbidden in (
            "DATABASE_URL",
            "KODESEC_ARTIFACT_DIR",
            "KODESEC_ALLOWED_ROOTS",
            "KODESEC_INSTALLATION_SECRET",
            "OLLAMA_BASE_URL",
            "/var/run/docker.sock",
        )
    )

    full_command = [
        "docker",
        "compose",
        "--env-file",
        str(runtime_env),
        "--profile",
        "*",
        "config",
        "--format",
        "json",
    ]
    full_rendered = subprocess.run(
        full_command,
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    full_config = json.loads(full_rendered.stdout)
    assert set(full_config["services"]) == {
        "adminer",
        "api",
        "api-ingress",
        "advisor-connector",
        "gitea",
        "grafana",
        "schema-init",
        "postgres",
        "prometheus",
        "scanner",
        "scanner-updater",
        "worker",
    }
    monitoring_services = {
        name
        for name, service in full_config["services"].items()
        if "monitoring" in service.get("profiles", [])
    }
    assert monitoring_services == {"grafana", "prometheus"}
    expected_monitoring_mounts = {
        "prometheus": {
            (
                "bind",
                str((REPO_ROOT / "infra/prometheus/prometheus.yml").resolve()),
                "/etc/prometheus/prometheus.yml",
                True,
            ),
            ("volume", "prometheus_data", "/prometheus", False),
        },
        "grafana": {
            ("volume", "grafana_data", "/var/lib/grafana", False),
            (
                "bind",
                str((REPO_ROOT / "infra/grafana/provisioning").resolve()),
                "/etc/grafana/provisioning",
                True,
            ),
            (
                "bind",
                str((REPO_ROOT / "infra/grafana/dashboards").resolve()),
                "/var/lib/grafana/dashboards",
                True,
            ),
        },
    }
    for name in monitoring_services:
        service = full_config["services"][name]
        assert service.get("privileged", False) is False
        assert service.get("cap_add", []) == []
        assert service.get("devices", []) == []
        assert service.get("pid") != "host"
        assert service.get("ipc") != "host"
        assert service.get("uts") != "host"
        assert service.get("network_mode") != "host"
        assert service.get("cgroup") != "host"
        assert {
            (
                mount["type"],
                mount["source"],
                mount["target"],
                bool(mount.get("read_only", False)),
            )
            for mount in service.get("volumes", [])
        } == expected_monitoring_mounts[name]
    full_internal = next(
        name
        for name, network in full_config["networks"].items()
        if network.get("internal") and name in full_config["services"]["postgres"]["networks"]
    )
    full_control = next(
        name
        for name, network in full_config["networks"].items()
        if not network.get("internal")
        and name in full_config["services"]["prometheus"]["networks"]
    )
    assert set(full_config["services"]["prometheus"]["networks"]) == {
        full_internal,
        full_control,
    }
    assert set(full_config["services"]["adminer"]["networks"]) == {
        full_internal,
        full_control,
    }
    full_component_observation = next(
        name
        for name, network in full_config["networks"].items()
        if network.get("internal")
        and name in full_config["services"]["api"]["networks"]
        and name not in {full_internal, ingress_control, updater_control}
    )
    assert {
        service_name
        for service_name, service in full_config["services"].items()
        if full_component_observation in service["networks"]
    } == {"api", "gitea", "grafana"}
    for service in ("gitea", "grafana"):
        assert set(full_config["services"][service]["networks"]) == {
            full_component_observation,
            full_control,
        }


def shutil_which(command: str) -> str | None:
    from shutil import which

    return which(command)
