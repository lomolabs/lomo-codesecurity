from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("bearer_source_build", HERE / "source-build.py")
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


class SourceBuildContractTests(unittest.TestCase):
    def test_exact_recipe_closure_and_distinct_unobserved_version(self):
        lock = BUILD.load_lock()
        self.assertEqual(lock["output"], {"version": "2.1.0+lomo.1", "platforms": ["linux/amd64", "linux/arm64"]})
        self.assertNotIn("binary_sha256", lock["output"])
        self.assertIn("TestFileTimeoutPlatformAssignment", (HERE / "lomo.patch").read_text())
        self.assertIn("TestFileTimeoutInvalidFactorFailsClosed", (HERE / "lomo.patch").read_text())
        self.assertIn("TestFileTimeoutOverflowFailsClosed", (HERE / "lomo.patch").read_text())
        self.assertIn("TestScanTimeoutKeepsIndependentCap", (HERE / "lomo.patch").read_text())
        self.assertIn("TestScanTimeout", dict(BUILD.TESTS)["./pkg/commands/process/settings"])
        self.assertEqual(len(lock["patch_files"]), 37)
        self.assertIn("pkg/languages/python/detectors/object/projection_test.go", {x["path"] for x in lock["patch_files"]})
        self.assertIn("TestRealEmptyMemoDifferentialFindingsAndActualReuse", (HERE / "lomo.patch").read_text())
        self.assertIn("TestRealMemoNegativeAliasOutsideWarmSubtree", (HERE / "lomo.patch").read_text())
        self.assertIn("TestPatternAllDoesNotHideOuterCancellationBeforeDeadChild", (HERE / "lomo.patch").read_text())
        self.assertIn("TestStatementPairsNativeDifferential", (HERE / "lomo.patch").read_text())
        for name in ("TestQueryAbsenceBoundReferenceDifferential", "TestQueryAbsencePreservesReachableVariableErrors",
                     "TestQueryAbsenceDepthCycleActiveAndUnknownFences", "TestQueryAbsenceUnknownQueryFallback"):
            self.assertIn(name, (HERE / "lomo.patch").read_text())
        for package in ("./pkg/scanner/rulescanner", "./pkg/scanner/detectorset", "./pkg/scanner/detectors/customrule"):
            self.assertIn("TestQueryAbsence", dict(BUILD.TESTS)[package])
        self.assertIn(("./pkg/scanner/ast/query", "^TestStatementPairs"), BUILD.TESTS)
        self.assertNotIn("phaseprobe", (HERE / "lomo.patch").read_text())

    def archive(self, rows):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as archive:
            for name, kind, content in rows:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.size = len(content) if kind == tarfile.REGTYPE else 0
                archive.addfile(member, io.BytesIO(content) if kind == tarfile.REGTYPE else None)
        raw.seek(0)
        return tarfile.open(fileobj=raw)

    def test_archive_accepts_exact_regular_inventory(self):
        with self.archive([("root", tarfile.DIRTYPE, b""), ("root/file", tarfile.REGTYPE, b"abc")]) as archive:
            self.assertEqual(len(BUILD.safe_archive_members(archive, "root", 1, 3)), 2)

    def test_archive_refuses_links_escape_duplicates_and_inventory_changes(self):
        for rows in (
            [("root/link", tarfile.SYMTYPE, b"")],
            [("root/link", tarfile.LNKTYPE, b"")],
            [("root/../escape", tarfile.REGTYPE, b"abc")],
            [("/root/file", tarfile.REGTYPE, b"abc")],
            [("other/file", tarfile.REGTYPE, b"abc")],
            [("root/file", tarfile.REGTYPE, b"abc"), ("root/file", tarfile.REGTYPE, b"abc")],
            [("root/file", tarfile.REGTYPE, b"more")],
        ):
            with self.subTest(rows=rows), self.archive(rows) as archive, self.assertRaises(ValueError):
                BUILD.safe_archive_members(archive, "root", 1, 3)

    def test_prepare_changed_archive_never_creates_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "archive"
            archive.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "source_archive_digest"):
                BUILD.prepare(archive, root / "source", root / "logs", BUILD.load_lock())
            self.assertFalse((root / "source").exists())

    def test_binary_refuses_probe_marker_across_read_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "bearer"
            binary.write_bytes(b"x" * (1024 * 1024 - 5) + b"LOMO_PRIVATE_BEARER_PHASES")
            with self.assertRaisesRegex(ValueError, "private_probe_in_binary"):
                BUILD.verify_binary(binary, b"safe", b"safe")
            binary.write_bytes(b"production")
            for symbols, dependencies in ((b"github.com/bearer/bearer/pkg/scanner/phaseprobe.Start", b""), (b"", b"RuleWorkChild")):
                with self.assertRaisesRegex(ValueError, "private_probe_in_linked"):
                    BUILD.verify_binary(binary, symbols, dependencies)
            BUILD.verify_binary(binary, b"production", b"production")

    def test_offline_environment_refuses_injected_flags_and_toolchain_download(self):
        prior = dict(os.environ)
        try:
            os.environ.update(GOCACHEPROG="/bad", AR="/bad", PKG_CONFIG="/bad", LD_PRELOAD="/bad", DYLD_INSERT_LIBRARIES="/bad", GO111MODULE="off", GOPATH="/bad", GIT_CONFIG_COUNT="2", GOFLAGS="-tags=unsafe", GOTOOLCHAIN="auto", GOOS="darwin", GOARCH="arm64", GOWORK="/bad", CGO_CFLAGS="-include /bad")
            env = BUILD.build_environment(online=False)
            self.assertEqual(env["GOTOOLCHAIN"], "local")
            self.assertEqual(env["GOENV"], "off")
            self.assertEqual(env["GOPROXY"], "off")
            self.assertEqual(env["GOFLAGS"], "-mod=readonly -trimpath -buildvcs=false")
            self.assertNotIn("GOARCH", env)
            self.assertNotIn("CGO_CFLAGS", env)
            self.assertNotIn("GOCACHEPROG", env)
            self.assertNotIn("LD_PRELOAD", env)
            self.assertNotIn("DYLD_INSERT_LIBRARIES", env)
            self.assertNotIn("GIT_CONFIG_COUNT", env)
            self.assertEqual(env["GO111MODULE"], "on")
            self.assertEqual(env["AR"], "ar")
            self.assertEqual(env["PKG_CONFIG"], "pkg-config")
            self.assertEqual(env["GOPATH"], "/go")
        finally:
            os.environ.clear()
            os.environ.update(prior)

    def test_command_separates_json_stdout_from_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = BUILD.command([sys.executable, "-c", "import sys;print('{\"ok\":true}');print('diagnostic',file=sys.stderr)"], root, root / "logs", "separate", time.monotonic() + 3)
            self.assertEqual(json.loads(raw), {"ok": True})
            self.assertEqual((root / "logs/separate.stderr").read_text(), "diagnostic\n")

    def test_command_deadline_terminates_its_real_owned_child_group(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pid_path = root / "child.pid"
            script = """import pathlib,signal,subprocess,sys,time
child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])
pathlib.Path(sys.argv[1]).write_text(str(child.pid))
def stop(*args):
 child.wait(timeout=2)
 sys.exit(0)
signal.signal(signal.SIGTERM,stop)
time.sleep(30)
"""
            with self.assertRaisesRegex(ValueError, "build_clock_expired"):
                BUILD.command([sys.executable, "-c", script, str(pid_path)], root, root / "logs", "deadline", time.monotonic() + 0.3)
            child = int(pid_path.read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(child, 0)

    def test_decoder_rejects_missing_skipped_and_failed_semantic_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "pkg"
            package.mkdir()
            (package / "checks_test.go").write_text("func TestRealOne(t *testing.T) {}\nfunc TestRealTwo(t *testing.T) {}\n")
            rows = [{"Action": "start"}, {"Action": "run", "Test": "TestRealOne"},
                    {"Action": "run", "Test": "TestRealOne/child"}, {"Action": "pass", "Test": "TestRealOne/child"},
                    {"Action": "pass", "Test": "TestRealOne"}, {"Action": "run", "Test": "TestRealTwo"},
                    {"Action": "pass", "Test": "TestRealTwo"}, {"Action": "pass"}]
            for row in rows:
                row["Package"] = "github.com/bearer/bearer/pkg"
            def raw(value):
                return b"\n".join(json.dumps(x).encode() for x in value)
            summary = BUILD.verify_test_events(raw(rows), root, "./pkg", "^TestReal")
            self.assertEqual(summary["started_tests"], summary["passed_tests"])
            self.assertEqual(summary["skipped_tests"], 0)
            self.assertIn("TestRealOne/child", summary["passed_tests"])
            for changed in (rows[1:], [rows[0], *rows[2:]], rows[:3] + rows[4:],
                            [rows[0], rows[1], rows[1], *rows[2:]],
                            [rows[0], {"Action": "pass", "Test": "TestRealOne", "Package": "github.com/bearer/bearer/pkg"}, *rows[2:]],
                            [rows[0], {"Action": "skip", "Test": "TestRealOne/child", "Package": "github.com/bearer/bearer/pkg"}],
                            [rows[0], {"Action": "fail", "Package": "github.com/bearer/bearer/pkg"}],
                            rows + [rows[1]]):
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    BUILD.verify_test_events(raw(changed), root, "./pkg", "^TestReal")
            with self.assertRaisesRegex(ValueError, "semantic_test_log_bound"):
                BUILD.verify_test_events(b" " * (BUILD.MAX_LOG_BYTES + 1), root, "./pkg", "^TestReal")
            with self.assertRaisesRegex(ValueError, "semantic_test_event_bound"):
                BUILD.verify_test_events(b" " * 65537, root, "./pkg", "^TestReal")


if __name__ == "__main__":
    unittest.main()
