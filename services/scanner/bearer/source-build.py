#!/usr/bin/env python3
"""Pinned Bearer source builder; Docker/build receipt integration owns dispatch."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import signal
import subprocess
import tarfile
import time

HERE = Path(__file__).resolve().parent
FORBIDDEN = (b"github.com/bearer/bearer/pkg/scanner/phaseprobe", b"LOMO_PRIVATE_BEARER_PHASES", b"lomo-private-bearer-phase", b"RuleWorkChild", b"BeginRuleCPUProfile")
MAX_LOG_BYTES = 16 * 1024 * 1024
TESTS = (
    ("./pkg/commands/process/settings", "^(TestFileTimeoutPlatform|TestScanTimeout)"),
    ("./pkg/commands/process/filelist/timeout", "^TestFileTimeout"),
    ("./pkg/languages/python/detectors/object", "^TestSubscript"),
    ("./pkg/languages/python/detectors", "TestPythonObjects|TestPythonString"),
    ("./pkg/languages/python", "TestSubscript|TestDatatypes|TestFlow"),
    ("./pkg/scanner/ast/tree", "^TestQueryResultsTraceGuard"),
    ("./pkg/scanner/ast/query", "^TestStatementPairs"),
    ("./pkg/scanner/cache", "^TestCacheEviction"),
    ("./pkg/scanner/ruleset", "^TestEmptyScan"),
    ("./pkg/scanner/detectorset", "^(TestEmptyScanGuard|TestEmptyResult|TestLiveDetectorCycle|TestQueryAbsence)"),
    ("./pkg/scanner/detectors/customrule/filters", "^(TestPatternAll|TestNestedAll)"),
    ("./pkg/scanner/rulescanner", "^(TestReal|TestTraceGate|TestCancellationAtTraversalBoundary|TestQueryAbsence)"),
    ("./pkg/scanner/detectors/customrule", "^(TestTraceGate|TestQueryAbsence)"),
)


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def digest(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), "regular_input_required")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load_lock() -> dict:
    raw = (HERE / "source.lock.json").read_bytes()
    require(len(raw) <= 64 * 1024, "source_lock_size")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate_source_lock_key")
            result[key] = value
        return result
    lock = json.loads(raw, object_pairs_hook=unique)
    require(lock["schema_version"] == 1 and lock["kind"] == "bearer-source-build", "source_lock_schema")
    require(lock["source"]["commit"] == "814948ecc198a743b13a75a6bfd4688514285220", "source_commit")
    require(lock["output"]["version"] == "2.1.0+lomo.1", "modified_version")
    require(lock["output"]["platforms"] == ["linux/amd64", "linux/arm64"], "source_platforms")
    for relative, expected in lock["inputs"].items():
        require(relative in {"source-build.py", "lomo.patch", "LICENSE.txt", "NOTICE", "test_source_build.py"}, "unknown_recipe_input")
        require(digest(HERE / relative) == expected, "recipe_input_digest:" + relative)
    require(set(lock["inputs"]) == {"source-build.py", "lomo.patch", "LICENSE.txt", "NOTICE", "test_source_build.py"}, "recipe_input_closure")
    return lock


def safe_archive_members(archive: tarfile.TarFile, prefix: str, file_count: int, total_bytes: int):
    members = archive.getmembers()
    require(len(members) <= 4096, "archive_member_bound")
    names = set()
    files = 0
    total = 0
    for member in members:
        path = PurePosixPath(member.name)
        require(not path.is_absolute() and ".." not in path.parts and path.parts and path.parts[0] == prefix, "archive_containment")
        require(member.name == str(path) and member.name not in names, "archive_duplicate_or_noncanonical")
        names.add(member.name)
        require(member.isfile() or member.isdir(), "archive_links_or_special_files")
        require(member.size >= 0 and member.size <= 40 * 1024 * 1024, "archive_file_bound")
        if member.isfile():
            require(len(path.parts) > 1, "archive_root_file")
            files += 1
            total += member.size
            require(files <= file_count and total <= total_bytes, "archive_aggregate_bound")
    require(files == file_count and total == total_bytes, "archive_inventory")
    return members


def verify_source(root: Path, lock: dict, *, patched: bool) -> None:
    require(root.is_dir() and root.resolve() == root.absolute() and not root.is_symlink(), "canonical_source_root")
    for name in ("go.mod", "go.sum", "LICENSE.txt"):
        require(digest(root / name) == lock["source"]["file_sha256"][name], "source_input_digest:" + name)
    for row in lock["patch_files"]:
        relative = PurePosixPath(row["path"])
        require(not relative.is_absolute() and ".." not in relative.parts, "patch_path")
        target = root / str(relative)
        require(target.resolve().is_relative_to(root), "patch_path_containment")
        expected = row["after_sha256"] if patched else row["before_sha256"]
        if expected is None:
            require(not target.exists() and not target.is_symlink(), "patch_added_path_present")
        else:
            require(digest(target) == expected, "patch_file_digest:" + str(relative))
    if patched:
        for target in root.rglob("*.go"):
            if target.name.endswith("_test.go"):
                continue
            require(not target.is_symlink() and target.is_file(), "source_link")
            require(not any(token in target.read_bytes() for token in FORBIDDEN), "private_probe_in_source")


def command(argv: list[str], root: Path, logs: Path, name: str, deadline: float, env: dict | None = None) -> bytes:
    require(time.monotonic() < deadline, "build_clock_expired")
    logs.mkdir(parents=True, exist_ok=True)
    stdout = logs / (name + ".stdout")
    stderr = logs / (name + ".stderr")
    failure = None
    with stdout.open("xb") as out, stderr.open("xb") as err:
        process = subprocess.Popen(argv, cwd=root, env=env, stdout=out, stderr=err, start_new_session=True)
        try:
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    failure = "build_clock_expired"
                    break
                if stdout.stat().st_size > MAX_LOG_BYTES or stderr.stat().st_size > MAX_LOG_BYTES:
                    failure = "command_output_bound"
                    break
                time.sleep(0.02)
        finally:
            if failure is not None or process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=3)
        # A reaped parent alone does not establish child-process terminality.
        group_deadline = time.monotonic() + 3
        while True:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                break
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                break
            require(time.monotonic() < group_deadline, "owned_process_group_not_terminal")
            time.sleep(0.02)
        require(failure is None, failure or "command_failed")
        require(process.returncode == 0, "command_failed:" + name)
    require(stdout.stat().st_size <= MAX_LOG_BYTES and stderr.stat().st_size <= MAX_LOG_BYTES, "command_output_bound")
    return stdout.read_bytes()


def prepare(archive_path: Path, root: Path, logs: Path, lock: dict) -> None:
    require(archive_path.stat().st_size == lock["source"]["archive_bytes"] and digest(archive_path) == lock["source"]["archive_sha256"], "source_archive_digest")
    require(not root.exists() and not root.is_symlink() and root.parent.resolve() == root.parent.absolute(), "fresh_source_destination")
    with tarfile.open(archive_path, "r:gz") as archive:
        members = safe_archive_members(archive, "bearer-" + lock["source"]["commit"], lock["source"]["file_count"], lock["source"]["source_bytes"])
        root.mkdir(mode=0o755)
        for member in members:
            parts = PurePosixPath(member.name).parts[1:]
            if not parts:
                continue
            target = root.joinpath(*parts)
            if member.isdir():
                target.mkdir(mode=0o755, parents=True, exist_ok=True)
            else:
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                with archive.extractfile(member) as source, target.open("xb") as destination:
                    while block := source.read(1024 * 1024):
                        destination.write(block)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
    verify_source(root, lock, patched=False)
    deadline = time.monotonic() + 60
    command(["git", "apply", "--check", str(HERE / "lomo.patch")], root, logs, "patch-check", deadline, build_environment(online=False))
    command(["git", "apply", str(HERE / "lomo.patch")], root, logs, "patch-apply", deadline, build_environment(online=False))
    verify_source(root, lock, patched=True)
    (root / "LOMO-MODIFICATIONS").write_bytes((HERE / "NOTICE").read_bytes())


def build_environment(*, online: bool) -> dict:
    # Entire compiler environment is explicit. Inherited Go/cache helpers,
    # module switches, tool overrides and dynamic-loader variables cannot enter.
    return {
        "PATH": "/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root", "TMPDIR": "/tmp", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
        "CGO_ENABLED": "1", "GOTOOLCHAIN": "local", "GOWORK": "off", "GOENV": "off",
        "GOFLAGS": "-mod=readonly -trimpath -buildvcs=false", "GO111MODULE": "on",
        "GOMAXPROCS": "2", "GOPATH": "/go", "GOMODCACHE": "/go/pkg/mod", "GOCACHE": "/go/cache",
        "CC": "gcc", "CXX": "g++", "AR": "ar", "PKG_CONFIG": "pkg-config",
        "GOPROXY": "https://proxy.golang.org" if online else "off",
        "GOSUMDB": "sum.golang.org" if online else "off",
    }


def verify_test_events(raw: bytes, root: Path, package: str, pattern: str) -> None:
    require(type(raw) is bytes and 0 < len(raw) <= MAX_LOG_BYTES, "semantic_test_log_bound")
    selected = set()
    for source in (root / package.removeprefix("./")).glob("*_test.go"):
        for name in re.findall(r"^func (Test\w+)\(", source.read_text(), flags=re.MULTILINE):
            if re.search(pattern, name):
                selected.add(name)
    require(bool(selected), "no_semantic_tests_selected")
    expected_package = "github.com/bearer/bearer/" + package.removeprefix("./")
    started, passed = set(), set()
    package_started = package_passed = False
    known_warning = False
    for line in raw.splitlines():
        require(0 < len(line) <= 65536, "semantic_test_event_bound")
        event = json.loads(line)
        require(type(event) is dict, "semantic_test_event_shape")
        action, name = event.get("Action"), event.get("Test")
        if action == "build-output":
            output = event.get("Output")
            require(not package_started and not known_warning and
                    event.keys() == {"ImportPath", "Action", "Output"} and
                    event["ImportPath"] == "github.com/smacker/go-tree-sitter/yaml" and
                    type(output) is str and len(output.encode()) == 708 and
                    hashlib.sha256(output.encode()).hexdigest() == "6ce38392b092c4a7714eec1d47e15c30c68883166058f9ddada5c2e7010012a9",
                    "unknown_compiler_build_event")
            known_warning = True
            continue
        require(event.get("Package") == expected_package and not package_passed,
                "semantic_test_package_identity_or_terminal")
        require(action in {"start", "run", "pause", "cont", "output", "pass"} and
                (name is None or type(name) is str), "semantic_test_failure_skip_or_action")
        if action == "start":
            require(not package_started and name is None, "duplicate_package_start")
            package_started = True
            continue
        require(package_started, "semantic_event_without_package_start")
        if name is not None:
            require(name.split("/", 1)[0] in selected and name not in passed,
                    "unknown_or_already_terminal_test")
        if action == "run":
            require(name is not None and name not in started and
                    ("/" not in name or name.rsplit("/", 1)[0] in started), "semantic_test_duplicate_or_orphan_run")
            started.add(name)
        elif action == "pass":
            if name is None:
                require(started == passed and {x for x in started if "/" not in x} == selected,
                        "semantic_test_set_incomplete")
                package_passed = True
            else:
                require(name in started, "semantic_test_pass_without_run")
                require(all(x in passed for x in started if x.startswith(name + "/")), "nested_test_not_terminal")
                passed.add(name)
        elif name is not None:
            require(name in started, "semantic_test_output_without_run")
    require(package_started and package_passed, "semantic_test_package_not_terminal")
    return {"package": expected_package, "top_tests": sorted(selected), "started_tests": sorted(started), "passed_tests": sorted(passed), "skipped_tests": 0}


def verify_binary(binary: Path, symbols: bytes, deps: bytes) -> None:
    require(binary.is_file() and not binary.is_symlink() and binary.stat().st_size <= 128 * 1024 * 1024, "binary_bound")
    require(not any(token in symbols or token in deps for token in FORBIDDEN), "private_probe_in_linked_dependencies")
    with binary.open("rb") as stream:
        previous = b""
        while block := stream.read(1024 * 1024):
            combined = previous + block
            require(not any(token in combined for token in FORBIDDEN), "private_probe_in_binary")
            previous = combined[-max(map(len, FORBIDDEN)):]


def run_build(root: Path, output: Path, lock: dict, *, dependencies: bool) -> None:
    verify_source(root, lock, patched=True)
    require(not output.exists() and not output.is_symlink() and output.parent.resolve() == output.parent.absolute(), "fresh_output_destination")
    require(platform.system() == "Linux" and platform.machine() in {"aarch64", "x86_64"}, "native_linux_build_only")
    architecture = "arm64" if platform.machine() == "aarch64" else "amd64"
    output.mkdir(mode=0o755)
    logs = output / "logs"
    deadline = time.monotonic() + 900
    env = build_environment(online=dependencies)
    observed = json.loads(command(["go", "env", "-json", "GOVERSION", "GOOS", "GOARCH", "CGO_ENABLED"], root, logs, "go-env", deadline, env))
    require(observed == {"GOVERSION": lock["toolchain"]["go_version"], "GOOS": "linux", "GOARCH": architecture, "CGO_ENABLED": "1"}, "native_toolchain_identity")
    if dependencies:
        command(["go", "mod", "download"], root, logs, "go-mod-download", deadline, env)
        command(["go", "mod", "verify"], root, logs, "go-mod-verify", deadline, env)
        verify_source(root, lock, patched=True)
        return
    command(["go", "mod", "verify"], root, logs, "go-mod-verify", deadline, env)
    semantic_tests = []
    for index, (package, pattern) in enumerate(TESTS):
        raw = command(["go", "test", "-json", package, "-run", pattern, "-count=1"], root, logs, "test-" + str(index), deadline, env)
        semantic_tests.append(verify_test_events(raw, root, package, pattern))
    deps = command(["go", "list", "-deps", "./cmd/bearer"], root, logs, "go-deps", deadline, env)
    binary = output / "bearer"
    flags = "-w -buildid= -X github.com/bearer/bearer/cmd/bearer/build.Version=" + lock["output"]["version"] + " -X github.com/bearer/bearer/cmd/bearer/build.CommitSHA=" + lock["source"]["commit"]
    command(["go", "build", "-ldflags=" + flags, "-o", str(binary), "./cmd/bearer"], root, logs, "go-build", deadline, env)
    symbols = command(["go", "tool", "nm", str(binary)], root, logs, "go-symbols", deadline, env)
    verify_binary(binary, symbols, deps)
    command(["go", "version", "-m", str(binary)], root, logs, "build-info", deadline, env)
    command(["readelf", "--file-header", "--program-headers", "--dynamic", str(binary)], root, logs, "elf", deadline, env)
    verify_source(root, lock, patched=True)
    receipt = {"schema_version": 1, "kind": "bearer-source-build-output", "source_commit": lock["source"]["commit"], "source_archive_sha256": lock["source"]["archive_sha256"], "source_lock_sha256": digest(HERE / "source.lock.json"), "inputs": lock["inputs"], "toolchain": lock["toolchain"], "go_env": observed, "semantic_tests": semantic_tests, "platform": "linux/" + architecture, "version": lock["output"]["version"], "binary_sha256": digest(binary), "binary_bytes": binary.stat().st_size, "private_probes_absent": True, "logs": {str(p.relative_to(output)): digest(p) for p in sorted(logs.iterdir())}}
    (output / "build.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    for name in ("LICENSE.txt", "NOTICE"):
        (output / name).write_bytes((HERE / name).read_bytes())
        (output / name).chmod(0o444)
    binary.chmod(0o755)
    (output / "build.json").chmod(0o444)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "dependencies", "build"))
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    lock = load_lock()
    if args.action == "prepare":
        require(args.archive is not None, "archive_required")
        prepare(args.archive, args.source, args.output, lock)
    else:
        require(args.archive is None, "unexpected_archive")
        run_build(args.source, args.output, lock, dependencies=args.action == "dependencies")


if __name__ == "__main__":
    main()
