#!/usr/bin/env python3
"""Source-only, repeatable local startup using the existing product boundaries."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile

from source_provenance import (
    CONTROL_IMAGE_INPUT_PATHS, SCANNER_IMAGE_INPUT_PATHS, STANDARD_BUILD_CONTROLLER_PATHS,
    STANDARD_BUILD_INPUT_PATHS, BUILD_IDENTITY_LABEL,
    SourceProvenance, SourceProvenanceError, resolve_source_provenance, source_inputs_match,
)
from source_roots import configured_source_roots, validated_source_root
from scanner_build_contract import SCANNER_FROM_DIRECTIVES, SCANNER_RUNTIME_BASE_IMAGE

REPO = Path(__file__).resolve().parent.parent
CORE = ("postgres", "scanner", "scanner-updater", "advisor-connector", "worker", "api", "api-ingress")
GIB = 1024 ** 3
EXTENSION_ID = "lomo-dev.code-security"
MAX_VSIX = 2 * 1024 ** 2
IMAGE_REUSE_INPUTS = {
    "control": (*CONTROL_IMAGE_INPUT_PATHS, *STANDARD_BUILD_CONTROLLER_PATHS, "scripts/runtime-compose.py"),
    "scanner": (*SCANNER_IMAGE_INPUT_PATHS, *STANDARD_BUILD_CONTROLLER_PATHS, "scripts/runtime-compose.py"),
}
EXTENSION_REUSE_INPUTS = ("extensions/vscode", "Makefile")
STORAGE_PROBE_LABEL = "dev.lomo.kodesec.storage-probe"
STORAGE_PROBE_PROGRAM = (
    "import json,os; s=os.statvfs('/'); "
    "print(json.dumps({'available_bytes':s.f_bavail*s.f_frsize,"
    "'total_bytes':s.f_blocks*s.f_frsize}))"
)


class StartupError(RuntimeError):
    """An actionable failure, without runtime secrets or subprocess output."""


class PrerequisiteReport:
    """Only allowlisted observations, never raw command output or runtime values."""

    def __init__(self):
        self.checks = []
        self.current = "startup"

    def begin(self, name):
        self.current = name

    def passed(self, **observed):
        self.checks.append({"id": self.current, "status": "passed", **observed})

    def result(self, error=None):
        checks = list(self.checks)
        if error:
            checks.append({"id": self.current, "status": "failed",
                "code": getattr(error, "code", self.current + "_failed"), "message": str(error)})
        return {"schema_version": 1, "status": "failed" if error else "passed", "checks": checks,
            "storage_probe": {"temporary_container": True, "contains_source": False,
                "pulls_images": False, "scope": "selected local Docker engine"},
            "recheck": "Correct the failed prerequisite, then rerun the same command with --check --json."}


def prerequisite(options, name, **observed):
    report = getattr(options, "prerequisite_report", None)
    if report:
        report.begin(name)
        if observed:
            report.passed(**observed)


def detected_version(arguments):
    """Version commands are advisory metadata after the actual prerequisite check."""
    result = command(arguments, optional=True, timeout=10)
    # Do not expose executable output, paths, daemon diagnostics or environment.
    match = re.search(rb"(?<![0-9.])([0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?)(?![0-9.])", result.stdout[:1024])
    return match.group(1).decode("ascii") if result.returncode == 0 and match else None


class StorageAdmissionError(StartupError):
    """Fixed storage boundary codes; no daemon output is public error text."""

    def __init__(self, code):
        messages = {
            "engine_storage_probe_missing": "Docker storage cannot be measured until the source-pinned Python base is present. Run normal startup once to prepare that dependency; --check does not pull images.",
            "engine_storage_probe_invalid": "Docker storage probe identity or capacity metadata could not be verified. No application initialization or build was admitted; check the selected local engine and retry.",
            "engine_storage_probe_failed": "The isolated Docker storage measurement could not complete. Check the local engine and retry; no application data was deleted.",
            "engine_storage_cleanup_failed": "Temporary Docker probe creation or cleanup could not be verified. Inspect Docker's containers labeled dev.lomo.kodesec.storage-probe before retrying; no other container was removed.",
        }
        if code not in messages:
            raise ValueError("invalid storage admission code")
        self.code = code
        super().__init__(messages[code])


class StorageCapacityError(StartupError):
    code = "engine_storage_capacity"

    def __init__(self, minimum, available, *, building):
        super().__init__(f"Docker's measured build-layer filesystem needs at least {minimum // GIB} GiB free for this {'build' if building else 'restart'}; {available / GIB:.2f} GiB is available. Free capacity deliberately in the selected local engine; no images, caches or volumes were pruned.")


def command(arguments, *, environment=None, capture=True, timeout=30, optional=False):
    try:
        result = subprocess.run(
            arguments, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise StartupError("A required startup command could not complete. Check the selected executable and service, then rerun.") from error
    if result.returncode and not optional:
        raise StartupError("A startup step failed. No installation state was deleted; correct the reported prerequisite and rerun.")
    if capture and len(result.stdout) > 1024 ** 2:
        raise StartupError("A startup command returned more metadata than allowed.")
    return result


def vm_workflow_timeout(seconds):
    """Extra D-020 headroom for new VM actions, not bounded metadata probes."""
    return (seconds * 13 + 9) // 10 if platform.system() == "Linux" else seconds


def docker_engine_info(docker, environment, *, wait_seconds=0, show_progress=True):
    """Allow cold WSL startup to settle within one read-only readiness clock."""
    arguments = [docker, "info", "--format",
        '{"os":{{json .OSType}},"architecture":{{json .Architecture}}}']
    if not wait_seconds:
        return command(arguments, environment=environment)
    deadline = time.monotonic() + wait_seconds
    announced = False
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise StartupError(
                f"Docker in WSL did not become ready within {wait_seconds} seconds. "
                "Keep this terminal open, check Docker/containerd in the selected distro, "
                "and collect diagnostics with make support-bundle before retrying.")
        try:
            result = command(arguments, environment=environment, timeout=min(30, remaining))
        except StartupError:
            if show_progress and not announced:
                print("Waiting for Docker in WSL to finish starting…", flush=True)
                announced = True
            time.sleep(min(1, max(0, deadline - time.monotonic())))
        else:
            if time.monotonic() < deadline:
                return result


def executable(name):
    path = shutil.which(name)
    if not path:
        raise StartupError(f"Required executable is unavailable: {name}. Install it or select its explicit path, then rerun.")
    # A supported tool may dispatch on argv[0] (for example OrbStack's docker
    # symlink points to docker-tools). Validate the target, but execute the
    # selected entry point rather than changing its command identity.
    Path(path).resolve(strict=True)
    return str(Path(path).absolute())


def node_build_preflight():
    # Locked cheerio/undici require >=20.18.1; brace-expansion/lru-cache
    # further restrict the supported majors to 20 or >=22.
    message = "Extension source builds require Node.js 20.18.1 or newer on 20.x, or Node.js 22 or newer, with npm. Select a supported stable Node.js on PATH and rerun; no runtime, build or editor action was started."
    try:
        node = executable("node")
        result = command([node, "--version"], timeout=10)
    except StartupError:
        raise StartupError(message) from None
    version = re.fullmatch(rb"v(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\r?\n?", result.stdout)
    if not version:
        raise StartupError(message)
    major, minor, patch = map(int, version.groups())
    if not (major == 20 and (minor, patch) >= (18, 1) or major >= 22):
        raise StartupError(message)
    return node


def default_state():
    return Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))) / "lomo-kodesec"


def local_docker_environment(docker):
    environment = dict(os.environ)
    if environment.get("DOCKER_HOST") and not environment.get("DOCKER_CONTEXT"):
        endpoint = environment["DOCKER_HOST"]
    else:
        args = [docker, "context", "inspect"]
        if environment.get("DOCKER_CONTEXT"):
            args.append(environment["DOCKER_CONTEXT"])
        endpoint = json.loads(command([*args, "--format", "{{json .Endpoints.docker.Host}}"], environment=environment).stdout)
    if not isinstance(endpoint, str) or not endpoint.startswith("unix:///"):
        raise StartupError("Select a local Unix-socket Docker engine before source startup. Remote Docker contexts are refused; source was not sent to another host.")
    socket_path = Path(endpoint[len("unix://"):])
    if not stat.S_ISSOCK(socket_path.stat().st_mode):
        raise StartupError("The selected local Docker socket is unavailable. Start Docker and rerun.")
    # Pin the selected transport for every read/build/start; do not change the
    # account's Docker context or follow a later global context switch.
    environment.pop("DOCKER_CONTEXT", None)
    environment["DOCKER_HOST"] = endpoint
    # Buildx has its own selection, independent of the Docker context. The
    # reserved engine-backed default builder is also explicit on the build argv.
    environment["BUILDX_BUILDER"] = "default"
    environment.pop("BUILDKIT_HOST", None)
    return environment


def local_builder_preflight(docker, environment):
    endpoint = json.loads(command([docker, "context", "inspect", "default", "--format",
        "{{json .Endpoints.docker.Host}}"], environment=environment).stdout)
    if endpoint != environment["DOCKER_HOST"]:
        raise StartupError("Docker's default builder context does not resolve to the selected local engine. Select a matching local Docker engine; no context or builder was changed.")
    result = command([docker, "buildx", "inspect", "default"], environment=environment, optional=True)
    if result.returncode:
        raise StartupError("The local engine's default Buildx builder is unavailable. Start or update Docker/Buildx; no builder was created or changed.")
    # `buildx inspect` has no JSON option. Admit only its fixed public identity
    # fields; do not load/contact every account builder through `buildx ls`.
    lines = result.stdout.decode("utf-8", errors="strict").splitlines()
    if lines.count("Nodes:") != 1 or any(re.match(r"\s*Error\s*:", line) for line in lines):
        raise StartupError("The local Buildx builder could not be verified; no source build was started.")
    split = lines.index("Nodes:")

    def field(section, name):
        return [line.split(":", 1)[1].strip() for line in section if line.startswith(name + ":")]

    if (field(lines[:split], "Name") != ["default"] or field(lines[:split], "Driver") != ["docker"]
            or field(lines[split + 1:], "Name") != ["default"]
            or field(lines[split + 1:], "Endpoint") != ["default"]
            or field(lines[split + 1:], "Status") != ["running"]):
        raise StartupError("Source builds require the selected local engine's single default docker-driver builder. Remote, multi-node, container, or unverified builders are not used; no global selection was changed.")


def private_directory(path):
    if path.is_symlink():
        raise StartupError("The selected state/profile directory must not be a symbolic link.")
    if path.exists():
        item = path.stat()
        if not stat.S_ISDIR(item.st_mode) or item.st_uid != os.getuid() or item.st_mode & 0o077:
            raise StartupError("The selected state/profile directory must be owned by this account and mode 0700; no permissions were changed.")


def private_bytes(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        item = os.fstat(fd)
        if not stat.S_ISREG(item.st_mode) or item.st_uid != os.getuid() or stat.S_IMODE(item.st_mode) != 0o600 or item.st_nlink != 1 or item.st_size > limit:
            raise StartupError("A startup receipt has unsafe ownership, permissions, or size.")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            return stream.read(limit + 1)
    finally:
        os.close(fd)


def read_runtime(path):
    spec = importlib.util.spec_from_file_location("lomo_start_runtime", REPO / "scripts/runtime-compose.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    values = module.read_runtime(path)
    installation = values.get("KODESEC_INSTALLATION_ID", "")
    if not re.fullmatch(r"[a-f0-9]{12}", installation) or any(values.get(key) != expected for key, expected in (
        ("COMPOSE_PROJECT_NAME", f"lomo-code-security-{installation}"),
        ("KODESEC_CONTROL_IMAGE", f"lomo-kodesec-control:{installation}"),
        ("KODESEC_SCANNER_IMAGE", f"lomo-kodesec-scanner:{installation}"),
    )):
        raise StartupError("The runtime installation/image identities do not match. Use the existing runtime recovery guidance; no new identity was generated.")
    try:
        port = int(values["CONTROL_PORT"])
        if not 1 <= port <= 65535:
            raise ValueError()
    except (ValueError, KeyError) as error:
        raise StartupError("The runtime control port is invalid.") from error
    for source in configured_source_roots(values.get("KODESEC_REPO_ROOT", ""), values.get("KODESEC_ALLOWED_ROOTS", "")):
        validated_source_root(source)
    return values


def inspect_image(docker, reference, *, environment=None):
    result = command([docker, "image", "inspect", reference, "--format",
        '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}},"labels":{{json .Config.Labels}}}'], optional=True, environment=environment)
    if result.returncode:
        return None
    try:
        return json.loads(result.stdout)
    except (ValueError, UnicodeError) as error:
        raise StartupError("Docker returned invalid image identity metadata.") from error


def image_matches(image, provenance, role, architecture):
    if not isinstance(image, dict) or not isinstance(image.get("labels"), dict):
        return False
    try:
        observed = SourceProvenance.from_labels(image["labels"])
    except SourceProvenanceError:
        return False
    return bool(isinstance(image, dict) and isinstance(image.get("id"), str)
        and re.fullmatch(r"sha256:[a-f0-9]{64}", image["id"])
        and image.get("os") == "linux" and image.get("architecture") == architecture
        and observed == provenance
        and image["labels"].get(BUILD_IDENTITY_LABEL) == provenance.build_identity(role))


def reusable_image_source(image, current, role, architecture):
    labels = image.get("labels") if isinstance(image, dict) else None
    if not isinstance(labels, dict):
        return None
    try:
        original = SourceProvenance.from_labels(labels)
    except SourceProvenanceError:
        return None
    if not image_matches(image, original, role, architecture):
        return None
    return original if source_inputs_match(REPO, original, current, IMAGE_REUSE_INPUTS[role]) else None


def reusable_extension_source(candidate, current, bound):
    """Shared POSIX/Windows package reuse: actual bytes plus original inputs."""
    if not isinstance(bound, dict):
        return None
    try:
        original = SourceProvenance.from_record({key: value for key, value in bound.items()
            if key not in {"vsix_sha256", "version"}})
    except SourceProvenanceError:
        return None
    try:
        digest = hashlib.sha256(read_vsix_bytes(candidate)).hexdigest()
    except (OSError, StartupError):
        return None
    if digest != bound.get("vsix_sha256"):
        return None
    return (original, digest) if source_inputs_match(REPO, original, current, EXTENSION_REUSE_INPUTS) else None


def port_preflight(docker, port, project, *, environment=None):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            # Closed connections may retain this local port in TIME_WAIT.
            # SO_REUSEADDR permits a restart, not a second active listener.
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(("127.0.0.1", port))
            return
        except OSError:
            pass
    if project:
        result = command([docker, "ps", "--filter", f"label=com.docker.compose.project={project}",
            "--filter", "label=com.docker.compose.service=api-ingress", "--format", "{{.ID}}"], environment=environment)
        ids = result.stdout.decode().splitlines()
        if len(ids) == 1 and re.fullmatch(r"[a-f0-9]{12,64}", ids[0]):
            result = command([docker, "inspect", ids[0], "--format", "{{json .NetworkSettings.Ports}}"], environment=environment)
            ports = json.loads(result.stdout)
            if ports == {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]}:
                return
    raise StartupError(f"Loopback port {port} is occupied by another or unverified service. Stop that exact service or choose another runtime port; nothing was stopped automatically.")


def disk_preflight(paths, *, building):
    minimum = (32 if building else 2) * GIB
    devices = set()
    for path in paths:
        while not path.exists():
            path = path.parent
        device = path.stat().st_dev
        if device in devices:
            continue
        devices.add(device)
        if shutil.disk_usage(path).free < minimum:
            raise StartupError(f"Startup needs at least {minimum // GIB} GiB free on the source/state host filesystem for this {'build' if building else 'restart'}. Free space deliberately; no caches or volumes were deleted.")


def storage_probe_image(docker, architecture, environment, *, allow_pull):
    # Reuse the scanner's clean, source-pinned build dependency. This is not a
    # second mutable helper-image channel or a downloaded product release.
    with (REPO / "services/scanner/Dockerfile").open() as source:
        stages = tuple(line.strip() for line in source if line.strip().startswith("FROM "))
    if stages != SCANNER_FROM_DIRECTIVES:
        raise StorageAdmissionError("engine_storage_probe_invalid")
    reference = SCANNER_RUNTIME_BASE_IMAGE
    args = [docker, "image", "inspect", reference, "--format",
        '{"id":{{json .Id}},"digests":{{json .RepoDigests}},"os":{{json .Os}},"architecture":{{json .Architecture}},"size":{{json .Size}},"volumes":{{json (index .Config "Volumes")}}}']
    result = command(args, environment=environment, optional=True)
    if result.returncode:
        if not allow_pull:
            raise StorageAdmissionError("engine_storage_probe_missing")
        print("Preparing the source-pinned Python storage probe. This initial dependency allocation precedes the engine capacity measurement; no application build has started…", flush=True)
        command([docker, "pull", "--platform", f"linux/{architecture}", reference], environment=environment, timeout=vm_workflow_timeout(180))
        result = command(args, environment=environment)
    try:
        facts = json.loads(result.stdout)
    except (ValueError, UnicodeError) as error:
        raise StorageAdmissionError("engine_storage_probe_invalid") from error
    digest_reference = "python@" + reference.split("@", 1)[1]
    if (not isinstance(facts, dict) or set(facts) != {"id", "digests", "os", "architecture", "size", "volumes"}
            or not isinstance(facts["id"], str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", facts["id"])
            or not isinstance(facts["digests"], list) or digest_reference not in facts["digests"]
            or facts["os"] != "linux" or facts["architecture"] != architecture
            or type(facts["size"]) is not int or not 0 < facts["size"] <= 512 * 1024 ** 2
            or facts["volumes"] not in (None, {})):
        raise StorageAdmissionError("engine_storage_probe_invalid")
    return facts["id"]


def remove_storage_probe(docker, name, nonce, image_id, environment):
    try:
        result = command([docker, "container", "inspect", name, "--format",
            '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"owner":{{json (index .Config.Labels "dev.lomo.kodesec.storage-probe")}}}'],
            environment=environment, optional=True, timeout=10)
    except StartupError as error:
        raise StorageAdmissionError("engine_storage_cleanup_failed") from error
    try:
        facts = json.loads(result.stdout) if result.returncode == 0 else None
    except (ValueError, UnicodeError):
        facts = None
    if (not isinstance(facts, dict) or set(facts) != {"id", "name", "image", "owner"}
            or not isinstance(facts["id"], str) or not re.fullmatch(r"[a-f0-9]{64}", facts["id"])
            or facts["name"] != "/" + name or facts["owner"] != nonce or facts["image"] != image_id):
        raise StorageAdmissionError("engine_storage_cleanup_failed")
    # A timeout may leave our diagnostic running. Only its freshly reverified
    # immutable ID may be removed; never a project, image, volume, or name glob.
    try:
        result = command([docker, "container", "rm", "--force", facts["id"]],
            environment=environment, optional=True, timeout=10)
    except StartupError as error:
        raise StorageAdmissionError("engine_storage_cleanup_failed") from error
    if result.returncode:
        raise StorageAdmissionError("engine_storage_cleanup_failed")


def engine_disk_preflight(docker, architecture, environment, *, building, allow_pull):
    image_id = storage_probe_image(docker, architecture, environment, allow_pull=allow_pull)
    nonce = uuid.uuid4().hex
    name = "lomo-storage-probe-" + nonce
    try:
        created = command([docker, "container", "create", "--pull=never", "--name", name,
            "--label", f"{STORAGE_PROBE_LABEL}={nonce}", "--network", "none", "--read-only",
            "--user", "65534:65534", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
            "--pids-limit", "16", "--memory", "32m", "--memory-swap", "32m", "--cpus", "0.25",
            "--log-driver", "none", "--ipc", "none", "--restart", "no", "--entrypoint", "python3",
            image_id, "-I", "-B", "-c", STORAGE_PROBE_PROGRAM], environment=environment, timeout=10)
        container_id = created.stdout.decode("ascii").strip()
        if not re.fullmatch(r"[a-f0-9]{64}", container_id):
            raise StorageAdmissionError("engine_storage_probe_invalid")
        measured = command([docker, "container", "start", "--attach", container_id], environment=environment, timeout=15)
        facts = json.loads(measured.stdout)
        if (not isinstance(facts, dict) or set(facts) != {"available_bytes", "total_bytes"}
                or any(type(value) is not int for value in facts.values())
                or not 0 <= facts["available_bytes"] <= facts["total_bytes"] < 2 ** 63
                or facts["total_bytes"] == 0):
            raise StorageAdmissionError("engine_storage_probe_invalid")
    except StorageAdmissionError:
        raise
    except (StartupError, ValueError, UnicodeError) as error:
        raise StorageAdmissionError("engine_storage_probe_failed") from error
    finally:
        # Also reconcile creation that timed out after the daemon allocated the
        # named probe but before its ID reached this process.
        remove_storage_probe(docker, name, nonce, image_id, environment)
    minimum = (32 if building else 2) * GIB
    if facts["available_bytes"] < minimum:
        raise StorageCapacityError(minimum, facts["available_bytes"], building=building)
    return facts


def editor_arguments(options):
    result = []
    for flag, value in (("--user-data-dir", options.user_data_dir), ("--extensions-dir", options.extensions_dir)):
        if value:
            result.extend((flag, str(value)))
    return result + ["--profile", options.profile]


def read_vsix_bytes(path, expected_sha256=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        item = os.fstat(stream.fileno())
        if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1 or not 0 < item.st_size <= MAX_VSIX:
            raise StartupError("The packaged extension is missing or unsafe. Rerun the source package step.")
        content = stream.read(MAX_VSIX + 1)
    if len(content) != item.st_size or len(content) > MAX_VSIX:
        raise StartupError("The packaged extension changed during its bounded read.")
    if expected_sha256 is not None and hashlib.sha256(content).hexdigest() != expected_sha256:
        raise StartupError("The packaged extension changed after its source binding was admitted. No replacement was attributed to the original source.")
    return content


def vsix_payload(path, expected_sha256=None):
    # Parse the same bounded bytes whose digest was admitted, not a second path
    # open which could consume a later convenience-package replacement.
    with zipfile.ZipFile(io.BytesIO(read_vsix_bytes(path, expected_sha256))) as archive:
        if len(archive.infolist()) > 16 or sum(row.file_size for row in archive.infolist()) > MAX_VSIX:
            raise StartupError("The packaged extension exceeds its fixed size bound.")
        payload = {}
        for row in archive.infolist():
            if not row.filename.startswith("extension/"):
                continue
            name = row.filename[len("extension/"):]
            if not name or Path(name).is_absolute() or ".." in Path(name).parts or name in payload:
                raise StartupError("The packaged extension has an invalid member path.")
            payload[name] = archive.read(row)
    if "package.json" not in payload or "dist/extension.js" not in payload:
        raise StartupError("The packaged extension has no production payload.")
    return payload


def installed_extension_matches(location, payload):
    """Do not infer the installed bits from version or a previous launch receipt."""
    if not location.is_absolute() or location.is_symlink() or not location.is_dir():
        return False
    for name, expected in payload.items():
        path = location / name
        if any(part.is_symlink() for part in (path, *path.parents) if part != location.parent):
            return False
        if not path.is_file() or path.stat().st_size > MAX_VSIX:
            return False
        actual = path.read_bytes()
        if name == "package.json":
            try:
                actual_manifest = json.loads(actual)
                expected_manifest = json.loads(expected)
                # VS Code alone appends installation metadata to the source manifest.
                actual_manifest.pop("__metadata", None)
                if actual_manifest != expected_manifest:
                    return False
            except (ValueError, UnicodeError):
                return False
        elif actual != expected:
            return False
    return True


def write_receipt(path, payload):
    fd, temporary = tempfile.mkstemp(prefix=".launch-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(payload, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def editor_binding(options, state, values):
    """An explicit data directory must not adopt a different running installation."""
    directory = options.user_data_dir
    if not directory:
        return
    if directory == state or state in directory.parents or directory in state.parents:
        raise StartupError("The editor user-data and runtime directories must be separate, non-overlapping directories.")
    marker = directory / ".lomo-installation-v1.json"
    if not directory.exists() or not any(directory.iterdir()):
        return
    if not marker.exists() and not marker.is_symlink():
        raise StartupError("The selected editor user-data directory is non-empty and has no installation binding. Choose an empty isolated directory, or use the existing profile's manual installation workflow; it was not adopted.")
    observed = json.loads(private_bytes(marker, 4096))
    expected = editor_binding_payload(options, state, values) if values else None
    if observed != expected:
        raise StartupError("The selected editor user-data directory belongs to another runtime/profile. Reuse its original runtime or choose a fresh isolated directory.")


def editor_binding_payload(options, state, values):
    return {"v": 1, "installation_id": values["KODESEC_INSTALLATION_ID"], "state_dir": str(state), "profile": options.profile}


def claim_editor_binding(options, state, values):
    editor_binding(options, state, values)
    directory = options.user_data_dir
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    marker = directory / ".lomo-installation-v1.json"
    try:
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        editor_binding(options, state, values)
        return
    with os.fdopen(descriptor, "w") as stream:
        json.dump(editor_binding_payload(options, state, values), stream, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def ensure_extension(options, environment, provenance, previous):
    manifest = json.loads((REPO / "extensions/vscode/package.json").read_bytes())
    candidate = REPO / ".kodesec-test/vscode" / f"code-security-{manifest['version']}.vsix"
    bound = previous.get("extension", {})
    admitted = reusable_extension_source(candidate, provenance, bound)
    if admitted is None:
        print("Building the extension from these exact source inputs…", flush=True)
        command([options.make, "-C", str(REPO), "vscode-package"], capture=False, timeout=vm_workflow_timeout(900), environment=environment)
        if resolve_source_provenance(REPO, included_paths=EXTENSION_REUSE_INPUTS) != provenance:
            raise SourceProvenanceError("source_changed_during_startup")
        admitted = (provenance, hashlib.sha256(read_vsix_bytes(candidate)).hexdigest())
    package_source, admitted_digest = admitted
    payload = vsix_payload(candidate, admitted_digest)
    identity = json.loads(payload["package.json"])
    if f"{identity.get('publisher')}.{identity.get('name')}" != EXTENSION_ID:
        raise StartupError("The extension package identity does not match Lomo CodeSecurity.")
    install_env = dict(environment, VSCODE_CLI=options.code, VSCODE_PROFILE=options.profile,
        VSCODE_PROFILE_WORKSPACE=str(options.workspace.resolve(strict=True)))
    for key, value in (("VSCODE_USER_DATA_DIR", options.user_data_dir), ("VSCODE_EXTENSIONS_DIR", options.extensions_dir)):
        install_env.pop(key, None)
        if value:
            install_env[key] = str(value)

    def matches():
        inspected = command([options.node, str(REPO / "extensions/vscode/scripts/install.mjs"), "--inspect-installed"], environment=install_env)
        observed = json.loads(inspected.stdout)
        if observed == {"status": "missing"}:
            return False
        if not isinstance(observed, dict) or set(observed) != {"status", "identity", "location"} \
                or observed["status"] != "verified" or observed["identity"] != f"{EXTENSION_ID}@{identity['version']}" \
                or not isinstance(observed["location"], str):
            raise StartupError("VS Code returned invalid installed-extension evidence; no profile was reset.")
        return installed_extension_matches(Path(observed["location"]), payload)

    if not matches():
        read_vsix_bytes(candidate, admitted_digest)
        print("Installing the exact source-built extension in the selected profile…", flush=True)
        command([options.node, str(REPO / "extensions/vscode/scripts/install.mjs")], capture=False, timeout=vm_workflow_timeout(120), environment=install_env)
        if not matches():
            raise StartupError("VS Code did not expose the exact installed extension payload. Check the selected profile and extensions directory, then retry; no pairing was reset.")
    read_vsix_bytes(candidate, admitted_digest)
    return {**package_source.to_record(),
        "vsix_sha256": admitted_digest, "version": identity["version"]}


def launch(options):
    prerequisite(options, "python")
    if sys.version_info[:2] < (3, 12):
        raise StartupError("Python 3.12 or newer is required. Install it for this account and rerun with that interpreter.")
    prerequisite(options, "python", version=platform.python_version(), minimum="3.12")
    prerequisite(options, "platform")
    if os.name != "posix" or platform.system() not in {"Darwin", "Linux"}:
        raise StartupError("This source launcher supports macOS and Linux/WSL backends. Native Windows editor orchestration is not implemented here.")
    wsl = platform.system() == "Linux" and "microsoft" in platform.release().lower()
    # D-020 adds 30% to the existing VM startup allowances. Select once from
    # the host; source content and callers cannot extend an admitted command.
    build_timeout, health_wait_timeout, start_timeout = (
        (9360, 468, 546) if wsl else
        (4680, 234, 273) if platform.system() == "Linux" else
        (3600, 180, 210)
    )
    if wsl and not options.browser_only:
        raise StartupError("WSL backend startup is available with --browser-only. Native Windows editor installation/opening needs the separate supported Windows workflow; it is not inferred from a WSL code wrapper.")
    if options.publish_windows_owner and not wsl:
        raise StartupError("--publish-windows-owner is available only inside WSL.")
    prerequisite(options, "platform", system=platform.system(), wsl=wsl)
    prerequisite(options, "state_paths")
    state = options.state_dir.absolute()
    private_directory(state)
    state = state.resolve()
    runtime = state / "runtime.env"
    if state == REPO or REPO in state.parents:
        raise StartupError("Runtime state must be outside the source checkout.")
    if not options.browser_only and state != default_state().resolve() and not options.user_data_dir:
        raise StartupError("A custom runtime requires an explicit isolated --user-data-dir, so an existing editor cannot inherit another installation. Alternatively choose --browser-only.")
    for value in (options.user_data_dir, options.extensions_dir):
        if value:
            if not value.is_absolute() or any(ord(char) < 32 or ord(char) == 127 for char in str(value)):
                raise StartupError("Editor directories must be explicit absolute paths without control characters.")
            private_directory(value)
    if options.user_data_dir:
        options.user_data_dir = options.user_data_dir.resolve()
    if options.extensions_dir:
        options.extensions_dir = options.extensions_dir.resolve()
    if not options.profile or options.profile.strip() != options.profile or len(options.profile) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in options.profile):
        raise StartupError("Select one non-empty editor profile name without control characters.")
    prerequisite(options, "state_paths", validated=True)
    prerequisite(options, "make")
    options.make = executable("make")
    prerequisite(options, "make", available=True,
        **({"version": detected_version([options.make, "--version"])} if options.check else {}))
    prerequisite(options, "docker")
    options.docker = executable("docker")
    environment = local_docker_environment(options.docker)
    prerequisite(options, "docker", available=True, transport="local-unix-socket",
        **({"version": detected_version([options.docker, "--version"])} if options.check else {}))
    prerequisite(options, "compose")
    compose_version = command([options.docker, "compose", "version"], optional=True, environment=environment)
    if compose_version.returncode:
        raise StartupError("Docker Compose is unavailable. Install the docker compose plugin before starting; no runtime was changed.")
    compose_match = re.search(rb"v?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", compose_version.stdout[:1024])
    prerequisite(options, "compose", available=True, version=compose_match.group(1).decode("ascii") if compose_match else None)
    prerequisite(options, "docker_engine")
    engine_started = time.monotonic() if wsl else None
    info = docker_engine_info(options.docker, environment,
        wait_seconds=health_wait_timeout if wsl else 0,
        show_progress=not (options.check and getattr(options, "json", False)))
    if engine_started is not None:
        # Extra cold-start waiting consumes the existing backend allowance.
        # The Windows parent's 10,140-second ceiling stays authoritative.
        build_timeout -= math.ceil(max(0, time.monotonic() - engine_started - 30))
    facts = json.loads(info.stdout)
    architecture = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"}.get(facts.get("architecture"))
    if facts.get("os") != "linux" or architecture is None:
        raise StartupError("A running Linux-container Docker engine on amd64 or arm64 is required. The launcher does not change Docker settings.")
    prerequisite(options, "docker_engine", os="linux", architecture=architecture)
    included = [*STANDARD_BUILD_INPUT_PATHS, ".env.example", "scripts/start-lomo.py", "scripts/runtime-compose.py",
        "scripts/init-runtime.sh", "scripts/source_roots.py", "scripts/authorize-source.py", "scripts/publish-first-owner-bootstrap.py"]
    if options.publish_windows_owner:
        included.extend(("scripts/publish-windows-first-owner.py", "scripts/publish-windows-first-owner.ps1", "scripts/windows-installer-storage.ps1"))
    if not options.browser_only:
        prerequisite(options, "extension_build")
        included.append("extensions/vscode")
        options.code, options.node = executable(options.code), node_build_preflight()
        executable("npm")
        code_path = Path(options.code).resolve(strict=True)
        if platform.system() == "Darwin":
            apps = [parent for parent in code_path.parents if parent.name.endswith(".app")]
            if not apps:
                raise StartupError("On macOS select the VS Code CLI inside its signed application bundle.")
            if command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(apps[0])], optional=True).returncode:
                raise StartupError("The selected VS Code application has an invalid signature. Reinstall or repair that exact application; no security bypass was applied. Backend-only startup remains available with --browser-only.")
        version = command([options.code, "--version"]).stdout.decode().splitlines()
        minimum = re.fullmatch(r"\^(\d+)\.(\d+)\.(\d+)", json.loads((REPO / "extensions/vscode/package.json").read_bytes())["engines"]["vscode"])
        observed = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version[0] if version else "")
        if not minimum or not observed or tuple(map(int, observed.groups())) < tuple(map(int, minimum.groups())):
            raise StartupError("The selected VS Code version does not meet the extension's current engine requirement.")
        prerequisite(options, "extension_build", vscode_version=version[0], node_version=detected_version([options.node, "--version"]) if options.check else None)
    prerequisite(options, "reviewed_source")
    provenance = resolve_source_provenance(REPO, included_paths=included)
    prerequisite(options, "reviewed_source", kind=provenance.kind,
        **({"git_version": detected_version([executable("git"), "--version"])} if options.check and provenance.kind == "git" else {}))
    prerequisite(options, "existing_installation")
    values = read_runtime(runtime) if runtime.exists() or runtime.is_symlink() else None
    if not options.browser_only:
        editor_binding(options, state, values)
    if values and not options.browser_only and int(values["CONTROL_PORT"]) != 8080:
        raise StartupError("Automatic editor startup currently requires the default 8080 control origin. Use --browser-only and configure the selected editor's API origin explicitly; no profile settings were changed.")
    if values is None and state.exists() and any(state.iterdir()):
        raise StartupError("The selected state directory is non-empty but has no runtime. Use the original runtime; no installation was recreated.")
    previous = {}
    receipt = state / "source-launch.json"
    if receipt.exists() or receipt.is_symlink():
        previous = json.loads(private_bytes(receipt, 16384))
        if not isinstance(previous, dict):
            raise StartupError("The existing startup receipt is invalid.")
        wanted = {"profile": options.profile, "user_data_dir": str(options.user_data_dir) if options.user_data_dir else None, "extensions_dir": str(options.extensions_dir) if options.extensions_dir else None}
        if not options.browser_only and previous.get("editor") not in (None, wanted):
            raise StartupError("This runtime is bound to different editor profile paths. Reuse its recorded paths; manage additional editors through normal member enrollment.")
    images = {role: inspect_image(options.docker, values[f"KODESEC_{role.upper()}_IMAGE"], environment=environment) if values else None for role in ("control", "scanner")}
    image_sources = {role: reusable_image_source(image, provenance, role, architecture) for role, image in images.items()}
    needed = [role for role, original in image_sources.items() if original is None]
    building = bool(needed)
    prerequisite(options, "existing_installation", build_required=building)
    prerequisite(options, "buildx")
    if building:
        local_builder_preflight(options.docker, environment)
    prerequisite(options, "buildx", required=building,
        **({"version": detected_version([options.docker, "buildx", "version"])} if options.check and building else {}))
    prerequisite(options, "control_port")
    port_preflight(options.docker, int(values["CONTROL_PORT"]) if values else 8080, values["COMPOSE_PROJECT_NAME"] if values else None, environment=environment)
    prerequisite(options, "control_port", available=True)
    prerequisite(options, "host_storage")
    disk_preflight((REPO, state), building=building)
    prerequisite(options, "host_storage", minimum_free_bytes=(32 if building else 2) * GIB)
    prerequisite(options, "docker_storage")
    capacity = engine_disk_preflight(options.docker, architecture, environment, building=building, allow_pull=not options.check)
    prerequisite(options, "docker_storage", available_bytes=capacity["available_bytes"],
        total_bytes=capacity["total_bytes"], minimum_free_bytes=(32 if building else 2) * GIB,
        temporary_probe_removed=True)
    if options.check:
        if not getattr(options, "json", False):
            print(f"Preflight passed; source images {'need one build' if building else 'match and can be reused'}. Docker build-layer filesystem has {capacity['available_bytes'] / GIB:.2f} GiB available. The temporary source-free probe was removed; separate cache-volume capacity is checked when preparing scanners.")
        return
    environment.update(KODESEC_STATE_DIR=str(state), KODESEC_RUNTIME_ENV=str(runtime))
    command(["/bin/sh", str(REPO / "scripts/init-runtime.sh")], environment=environment, capture=False)
    values = read_runtime(runtime)
    if not options.browser_only and int(values["CONTROL_PORT"]) != 8080:
        raise StartupError("The initialized runtime does not use the editor's default 8080 origin. Use --browser-only and explicitly configure the editor origin; no editor was installed or opened.")
    port_preflight(options.docker, int(values["CONTROL_PORT"]), values["COMPOSE_PROJECT_NAME"], environment=environment)
    if not options.browser_only and options.user_data_dir:
        # Recheck after initialization before claiming an empty directory. Never
        # manufacture this marker in a previously used, unbound editor profile.
        claim_editor_binding(options, state, values)
    if options.publish_windows_owner:
        command([sys.executable, str(REPO / "scripts/publish-windows-first-owner.py"), str(state), str(runtime)], environment=environment, capture=False)
    compose = [sys.executable, str(REPO / "scripts/runtime-compose.py"), str(runtime)]
    if building:
        local_builder_preflight(options.docker, environment)
        print("Building the lean stack once from these exact source inputs…", flush=True)
        targets = [target for role, target in (("scanner", "scanner"), ("control", "schema-init")) if role in needed]
        command(["/bin/sh", str(REPO / "scripts/compose-build.sh"), *compose, "build", "--builder", "default", *targets], environment=environment, capture=False, timeout=build_timeout)
        for role in needed:
            images[role] = inspect_image(options.docker, values[f"KODESEC_{role.upper()}_IMAGE"], environment=environment)
            if not image_matches(images[role], provenance, role, architecture):
                raise StartupError("A source build did not produce the required matching images. No success receipt was written; rerun after correcting the failed build.")
            image_sources[role] = provenance
        # A successful build may consume most of its headroom. Do not start the
        # database/services until their smaller restart reserve still exists.
        disk_preflight((REPO, state), building=False)
        engine_disk_preflight(options.docker, architecture, environment, building=False, allow_pull=False)
    if resolve_source_provenance(REPO, included_paths=included) != provenance:
        raise SourceProvenanceError("source_changed_during_startup")
    for role, expected in images.items():
        observed = inspect_image(options.docker, values[f"KODESEC_{role.upper()}_IMAGE"], environment=environment)
        if not isinstance(observed, dict) or observed.get("id") != expected["id"] \
                or not image_matches(observed, image_sources[role], role, architecture):
            raise StartupError("A selected image changed before startup. No service was started with an unverified replacement; rerun to inspect the exact source again.")
    print("Starting the existing installation without rebuilding or removing its data…", flush=True)
    command([*compose, "up", "-d", "--no-build", "--wait", "--wait-timeout", str(health_wait_timeout), *CORE], environment=environment, capture=False, timeout=start_timeout)
    payload = {"v": 1, **provenance.to_record(),
        "installation_id": values["KODESEC_INSTALLATION_ID"], "images": {role: image["id"] for role, image in images.items()},
        "image_sources": {role: {**original.to_record(), "id": images[role]["id"]}
            for role, original in image_sources.items()}}
    if options.browser_only:
        # Do not forget the previously bound editor when starting just its backend.
        for key in ("editor", "extension"):
            if key in previous:
                payload[key] = previous[key]
    else:
        for path in (options.user_data_dir, options.extensions_dir):
            if path:
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload["extension"] = ensure_extension(options, environment, provenance, previous)
        payload["editor"] = {"profile": options.profile, "user_data_dir": str(options.user_data_dir) if options.user_data_dir else None, "extensions_dir": str(options.extensions_dir) if options.extensions_dir else None}
    write_receipt(receipt, payload)
    if options.browser_only:
        print(f"Backend ready at http://127.0.0.1:{values['CONTROL_PORT']}. In your existing VS Code profile, install lomo-dev.code-security and run CodeSecurity: Connect / Review IDE Access. For browser-only pairing, use make auth-info with this same STATE_DIR. No bootstrap value was opened or printed here.")
    else:
        command([options.code, *editor_arguments(options), "--new-window", str(options.workspace.resolve(strict=True))], environment=environment, capture=False)
        print("VS Code opened in the selected persistent profile. Use CodeSecurity's dashboard to authorize source and prepare scanners. Startup health is not scanner-readiness or release acceptance.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=default_state())
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--browser-only", dest="browser_only", action="store_true", help="Alias for the default backend-only startup; preserve existing editor profiles.")
    mode.add_argument("--source-vsix", dest="browser_only", action="store_false", help="Explicit development/QA mode: build and install a source VSIX into the selected persistent profile, then open it.")
    parser.set_defaults(browser_only=True)
    parser.add_argument("--check", action="store_true", help="Check prerequisites with one temporary source-free storage probe from a cached pinned base; do not pull, initialize, build, install, or open an editor.")
    parser.add_argument("--json", action="store_true", help="With --check, emit a versioned prerequisite report and exit nonzero on failure.")
    parser.add_argument("--code", default="code", help="Exact VS Code CLI executable (not the application bundle).")
    parser.add_argument("--profile", default="Lomo CodeSecurity")
    parser.add_argument("--user-data-dir", type=Path)
    parser.add_argument("--extensions-dir", type=Path)
    parser.add_argument("--workspace", type=Path, default=REPO / "examples/vulnerable-demo")
    parser.add_argument("--publish-windows-owner", action="store_true", help="Explicit WSL-only existing first-owner handoff; does not install/open native VS Code.")
    options = parser.parse_args()
    if options.json and not options.check:
        parser.error("--json requires --check")
    options.prerequisite_report = PrerequisiteReport() if options.check else None
    try:
        if not options.browser_only and not (options.workspace.is_dir() or (
            options.workspace.suffix == ".code-workspace" and options.workspace.is_file())):
            raise StartupError("Choose an existing workspace folder or .code-workspace file.")
        launch(options)
        if options.json:
            print(json.dumps(options.prerequisite_report.result(), sort_keys=True))
    except (StartupError, SourceProvenanceError) as error:
        if options.json:
            print(json.dumps(options.prerequisite_report.result(error), sort_keys=True))
            raise SystemExit(1) from None
        raise SystemExit(str(error)) from None
    except (OSError, ValueError, UnicodeError, zipfile.BadZipFile) as error:
        message = "Startup metadata could not be validated. Check the selected paths and prerequisite services; any completed backend state was retained for a later retry."
        if options.json:
            print(json.dumps(options.prerequisite_report.result(StartupError(message)), sort_keys=True))
            raise SystemExit(1) from None
        raise SystemExit(message) from None


if __name__ == "__main__":
    main()
