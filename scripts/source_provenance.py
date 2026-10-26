#!/usr/bin/env python3
"""Identify clean Git sources or local authored build inputs, never publisher trust."""

from __future__ import annotations

from dataclasses import dataclass
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Mapping, Sequence


FULL_GIT_OBJECT = re.compile(r"[0-9a-f]{40}\Z")
OCI_REVISION_LABEL = "org.opencontainers.image.revision"
SOURCE_TREE_LABEL = "dev.lomo.kodesec.source-tree"
BUILD_IDENTITY_LABEL = "dev.lomo.kodesec.build-identity"
SOURCE_COMMIT_ARG = "KODESEC_SOURCE_COMMIT"
SOURCE_TREE_ARG = "KODESEC_SOURCE_TREE"
SOURCE_KIND_ARG = "KODESEC_SOURCE_KIND"
SOURCE_DIGEST_ARG = "KODESEC_SOURCE_DIGEST"
SOURCE_KIND_LABEL = "dev.lomo.kodesec.source-kind"
SOURCE_DIGEST_LABEL = "dev.lomo.kodesec.source-digest"
SOURCE_SNAPSHOT_KIND = "source-sha256"
FULL_SHA256 = re.compile(r"[0-9a-f]{64}\Z")

CONTROL_IMAGE_INPUT_PATHS: tuple[str, ...] = (
    ".dockerignore",
    "apps/api",
    "apps/web",
    "services/advisor_connector",
)
SCANNER_IMAGE_INPUT_PATHS: tuple[str, ...] = (
    ".dockerignore",
    "scanner-rules.lock.json",
    "scanner-tools.lock.json",
    "services/scanner",
    "tests/scanner-runtime",
)
STANDARD_BUILD_CONTROLLER_PATHS: tuple[str, ...] = (
    "Makefile",
    "docker-compose.yml",
    "scripts/compose-build.sh",
    "scripts/source_provenance.py",
)
STANDARD_BUILD_INPUT_PATHS: tuple[str, ...] = tuple(
    sorted(
        {
            *CONTROL_IMAGE_INPUT_PATHS,
            *SCANNER_IMAGE_INPUT_PATHS,
            *STANDARD_BUILD_CONTROLLER_PATHS,
        },
        key=lambda value: value.encode("utf-8"),
    )
)

# Every normal launcher, image builder and extension packager uses this same
# snapshot universe. This is a local BUILD INPUT identity, not an archive hash,
# upstream revision, signature, or an inferred historical dependency graph.
SNAPSHOT_BUILD_INPUT_PATHS: tuple[str, ...] = (
    ".dockerignore", ".env.example", "Makefile", "docker-compose.yml",
    "scanner-rules.lock.json", "scanner-tools.lock.json", "apps/api", "apps/web",
    "services/advisor_connector", "services/scanner", "tests/scanner-runtime",
    "extensions/vscode", "scripts",
)
SNAPSHOT_GENERATED_DIRECTORIES = frozenset({
    "apps/api/.venv", "apps/api/.pytest_cache", "apps/api/build", "apps/api/dist",
    "apps/api/kodesec_api.egg-info", "apps/web/node_modules", "apps/web/dist",
    "apps/web/.vite", "apps/web/coverage", "apps/web/test-results", "apps/web/playwright-report",
    "services/scanner/.venv", "services/scanner/.pytest_cache", "services/scanner/build",
    "services/scanner/dist", "services/scanner/kodesec_scanner.egg-info",
    "extensions/vscode/node_modules", "extensions/vscode/dist", "extensions/vscode/coverage",
    "extensions/vscode/.vscode-test", "extensions/vscode/test-results",
    "tests/scanner-runtime/.pytest_cache",
})
MAX_SNAPSHOT_ENTRIES = 20_000
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
MAX_SNAPSHOT_FILE_BYTES = 32 * 1024 * 1024
MAX_SNAPSHOT_DEPTH = 32


class SourceProvenanceError(RuntimeError):
    """The selected local source identity could not be established safely."""


@dataclass(frozen=True)
class SourceProvenance:
    commit: str | None = None
    tree: str | None = None
    kind: str = "git"
    digest: str | None = None

    def __post_init__(self) -> None:
        if self.kind == SOURCE_SNAPSHOT_KIND:
            if self.commit is not None or self.tree is not None or not isinstance(self.digest, str) \
                    or FULL_SHA256.fullmatch(self.digest) is None:
                raise SourceProvenanceError("source_snapshot_identity_invalid")
        elif self.kind != "git" or self.digest is not None or not isinstance(self.commit, str) \
                or not isinstance(self.tree, str) or FULL_GIT_OBJECT.fullmatch(self.commit) is None \
                or FULL_GIT_OBJECT.fullmatch(self.tree) is None:
            raise SourceProvenanceError("source_git_identity_invalid")

    @classmethod
    def snapshot(cls, digest: str) -> SourceProvenance:
        return cls(kind=SOURCE_SNAPSHOT_KIND, digest=digest)

    def to_record(self) -> dict[str, str]:
        if self.kind == "git":
            return {"commit": self.commit, "tree": self.tree}
        return {"kind": self.kind, "digest": self.digest}

    @classmethod
    def from_record(cls, value: object) -> SourceProvenance:
        if isinstance(value, dict) and set(value) == {"commit", "tree"}:
            return cls(value["commit"], value["tree"])
        if isinstance(value, dict) and set(value) == {"kind", "digest"} \
                and value["kind"] == SOURCE_SNAPSHOT_KIND:
            return cls.snapshot(value["digest"])
        raise SourceProvenanceError("source_record_invalid")

    @classmethod
    def from_labels(cls, labels: Mapping[str, str]) -> SourceProvenance:
        if not isinstance(labels, Mapping):
            raise SourceProvenanceError("source_labels_invalid")
        kind = labels.get(SOURCE_KIND_LABEL, "git")
        if kind == SOURCE_SNAPSHOT_KIND and labels.get(OCI_REVISION_LABEL) == "" \
                and labels.get(SOURCE_TREE_LABEL) == "":
            return cls.snapshot(labels.get(SOURCE_DIGEST_LABEL))
        if kind == "git" and labels.get(SOURCE_DIGEST_LABEL, "") == "":
            return cls(labels.get(OCI_REVISION_LABEL), labels.get(SOURCE_TREE_LABEL))
        raise SourceProvenanceError("source_labels_invalid")

    def build_identity(self, role: str) -> str:
        if role not in {"control", "scanner"}:
            raise SourceProvenanceError("source_build_role_invalid")
        return f"{role}:{self.commit}:{self.tree}" if self.kind == "git" \
            else f"{role}:{SOURCE_SNAPSHOT_KIND}:{self.digest}"

    def build_args(self) -> tuple[tuple[str, str], ...]:
        return (
            (SOURCE_KIND_ARG, self.kind), (SOURCE_DIGEST_ARG, self.digest or ""),
            (SOURCE_COMMIT_ARG, self.commit or ""), (SOURCE_TREE_ARG, self.tree or ""),
        )

    def labels(self, role: str) -> dict[str, str]:
        if role not in {"control", "scanner"}:
            raise SourceProvenanceError("source_build_role_invalid")
        return {
            OCI_REVISION_LABEL: self.commit or "",
            SOURCE_TREE_LABEL: self.tree or "",
            SOURCE_KIND_LABEL: self.kind,
            SOURCE_DIGEST_LABEL: self.digest or "",
            BUILD_IDENTITY_LABEL: self.build_identity(role),
        }


def _snapshot(root: Path, included_paths: Sequence[str]) -> SourceProvenance:
    scopes = sorted(set(SNAPSHOT_BUILD_INPUT_PATHS) | set(included_paths), key=lambda value: value.encode("utf-8"))
    scopes = [path for path in scopes if not any(path.startswith(parent + "/") for parent in scopes if parent != path)]
    digest = hashlib.sha256(b"lomo-authored-build-inputs/v1\n")
    entries = 0
    total_bytes = 0

    def stamp(metadata):
        return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
                metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)

    def visit(parent_fd: int, name: str, relative: str, depth: int) -> None:
        nonlocal entries, total_bytes
        entries += 1
        if entries > MAX_SNAPSHOT_ENTRIES or depth > MAX_SNAPSHOT_DEPTH:
            raise SourceProvenanceError("source_snapshot_entry_bound")
        if not name or name in {".", "..", ".git"} or "\\" in name \
                or any(ord(char) < 32 or ord(char) == 127 for char in name):
            raise SourceProvenanceError("source_snapshot_path_invalid")
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode) or not (stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode)):
            raise SourceProvenanceError("source_snapshot_entry_unsafe")
        if relative in SNAPSHOT_GENERATED_DIRECTORIES:
            if not stat.S_ISDIR(before.st_mode):
                raise SourceProvenanceError("source_snapshot_generated_directory_invalid")
            return
        if stat.S_ISDIR(before.st_mode):
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            try:
                if stamp(os.fstat(fd)) != stamp(before):
                    raise SourceProvenanceError("source_snapshot_changed")
                children = []
                with os.scandir(fd) as iterator:
                    for entry in iterator:
                        children.append(entry.name)
                        if entries + len(children) > MAX_SNAPSHOT_ENTRIES:
                            raise SourceProvenanceError("source_snapshot_entry_bound")
                for child in sorted(children, key=lambda value: value.encode("utf-8")):
                    child_relative = f"{relative}/{child}"
                    # Python creates these exact cache directories while loading
                    # the launcher. Only ordinary bytecode files may be omitted.
                    if name == "__pycache__":
                        entries += 1
                        info = os.stat(child, dir_fd=fd, follow_symlinks=False)
                        if not re.fullmatch(r"[^/\\]+\.cpython-[0-9]+(?:\.opt-[0-9]+)?\.pyc", child) \
                                or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                            raise SourceProvenanceError("source_snapshot_python_cache_invalid")
                        continue
                    visit(fd, child, child_relative, depth + 1)
                if stamp(os.fstat(fd)) != stamp(before):
                    raise SourceProvenanceError("source_snapshot_changed")
            finally:
                os.close(fd)
        else:
            if before.st_nlink != 1 or before.st_size > MAX_SNAPSHOT_FILE_BYTES:
                raise SourceProvenanceError("source_snapshot_file_unsafe")
            total_bytes += before.st_size
            if total_bytes > MAX_SNAPSHOT_BYTES:
                raise SourceProvenanceError("source_snapshot_byte_bound")
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
            try:
                if stamp(os.fstat(fd)) != stamp(before):
                    raise SourceProvenanceError("source_snapshot_changed")
                file_digest = hashlib.sha256()
                observed_bytes = 0
                while chunk := os.read(fd, 64 * 1024):
                    observed_bytes += len(chunk)
                    if observed_bytes > before.st_size:
                        raise SourceProvenanceError("source_snapshot_changed")
                    file_digest.update(chunk)
                if observed_bytes != before.st_size or stamp(os.fstat(fd)) != stamp(before):
                    raise SourceProvenanceError("source_snapshot_changed")
                record = [relative, before.st_mode & 0o111, observed_bytes, file_digest.hexdigest()]
                digest.update(json.dumps(record, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n")
            finally:
                os.close(fd)
        if stamp(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)) != stamp(before):
            raise SourceProvenanceError("source_snapshot_changed")

    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            root_before = os.fstat(root_fd)
            for scope in scopes:
                parent_fd = os.dup(root_fd)
                ancestors = []
                try:
                    parts = scope.split("/")
                    for parent in parts[:-1]:
                        before = os.stat(parent, dir_fd=parent_fd, follow_symlinks=False)
                        next_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
                        if stamp(os.fstat(next_fd)) != stamp(before):
                            os.close(next_fd)
                            raise SourceProvenanceError("source_snapshot_changed")
                        ancestors.append((os.dup(parent_fd), parent, before))
                        os.close(parent_fd)
                        parent_fd = next_fd
                    visit(parent_fd, parts[-1], scope, len(parts))
                    for ancestor_fd, name, before in ancestors:
                        if stamp(os.stat(name, dir_fd=ancestor_fd, follow_symlinks=False)) != stamp(before):
                            raise SourceProvenanceError("source_snapshot_changed")
                finally:
                    os.close(parent_fd)
                    for ancestor_fd, _, _ in ancestors:
                        os.close(ancestor_fd)
            if stamp(os.fstat(root_fd)) != stamp(root_before) or \
                    stamp(os.stat(root, follow_symlinks=False)) != stamp(root_before):
                raise SourceProvenanceError("source_snapshot_changed")
        finally:
            os.close(root_fd)
    except (OSError, UnicodeError) as exc:
        raise SourceProvenanceError("source_snapshot_unavailable_or_unsafe") from exc
    return SourceProvenance.snapshot(digest.hexdigest())


def _git(repo_root: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ("git", "-C", str(repo_root), *arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise SourceProvenanceError("source_git_unavailable") from exc
    if completed.returncode != 0 or completed.stderr:
        raise SourceProvenanceError("source_git_command_failed")
    try:
        return completed.stdout.decode("utf-8", errors="strict").rstrip("\n")
    except UnicodeError as exc:
        raise SourceProvenanceError("source_git_output_invalid") from exc


def resolve_source_provenance(
    repo_root: Path,
    included_paths: Sequence[str] = STANDARD_BUILD_INPUT_PATHS,
) -> SourceProvenance:
    if not included_paths or any(
        not isinstance(path, str) or not path or path.startswith("/") or "\\" in path
        or any(part in {"", ".", "..", ".git"} for part in path.split("/"))
        or any(ord(char) < 32 or ord(char) == 127 for char in path)
        for path in included_paths
    ):
        raise SourceProvenanceError("source_provenance_paths_invalid")
    try:
        if repo_root.is_symlink():
            raise SourceProvenanceError("source_root_unsafe")
        root = repo_root.resolve(strict=True)
        if not root.is_dir():
            raise SourceProvenanceError("source_root_unsafe")
    except OSError as exc:
        raise SourceProvenanceError("source_root_unavailable") from exc
    # Never interpret a broken checkout, linked worktree, ambient Git override,
    # or an archive nested inside another checkout as independent snapshot input.
    # Absence is established before invoking Git; command failures cannot trigger
    # a weaker fallback path.
    git_context = any(os.path.lexists(parent / ".git") for parent in (root, *root.parents)) \
        or any(name in os.environ for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE")) \
        or all((root / name).exists() for name in ("HEAD", "objects", "refs"))
    if not git_context:
        return _snapshot(root, included_paths)
    observed_root = Path(_git(root, "rev-parse", "--show-toplevel")).resolve(strict=True)
    if observed_root != root:
        raise SourceProvenanceError("source_git_root_mismatch")
    provenance = SourceProvenance(
        commit=_git(root, "rev-parse", "--verify", "HEAD^{commit}"),
        tree=_git(root, "rev-parse", "--verify", "HEAD^{tree}"),
    )
    dirt = _git(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--",
        *included_paths,
    )
    if dirt:
        raise SourceProvenanceError(f"dirty image-build inputs:\n{dirt}")
    return provenance


def source_inputs_match(
    repo_root: Path,
    original: SourceProvenance,
    current: SourceProvenance,
    included_paths: Sequence[str],
) -> bool:
    """Compare inputs without rewriting artifact provenance.

    A missing historical object is not evidence of equality. Current source
    drift or dirt remains a refusal, including untracked included files. The
    comparison uses immutable object IDs and includes file modes/adds/deletes;
    no branch name, external diff driver, or working-tree content is trusted.
    """
    if resolve_source_provenance(repo_root, included_paths) != current:
        raise SourceProvenanceError("source_changed_during_startup")
    if original.kind != "git" or current.kind != "git":
        # Snapshots are conservative: only the exact combined build-input
        # identity can be reused, never inferred historical per-role equality.
        return original == current
    try:
        original_tree = _git(repo_root, "rev-parse", "--verify", f"{original.commit}^{{tree}}")
    except SourceProvenanceError:
        return False
    if original_tree != original.tree:
        return False
    return not _git(
        repo_root, "diff", "--raw", "--no-renames", "--no-ext-diff", "--no-textconv",
        original.tree, current.tree, "--", *included_paths,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print the explicit source identity record")
    parser.add_argument("--scope", action="append", help="Included relative input path (repeatable)")
    parser.add_argument("--exec", dest="command", nargs=argparse.REMAINDER,
                        help="Run one build command with the verified source build arguments")
    args = parser.parse_args(argv)
    if args.command is not None and (not args.command or args.json):
        parser.error("--exec requires a command and cannot be combined with --json")
    root = Path(__file__).resolve().parents[1]
    scopes = tuple(args.scope) if args.scope else STANDARD_BUILD_INPUT_PATHS
    try:
        provenance = resolve_source_provenance(root, scopes)
        if args.command is not None:
            identity = f"{provenance.commit}:{provenance.tree}" if provenance.kind == "git" \
                else f"{SOURCE_SNAPSHOT_KIND}:{provenance.digest}"
            print(f"CodeSecurity local build source: {identity}", file=sys.stderr, flush=True)
            environment = os.environ.copy()
            environment.update(provenance.build_args())
            try:
                result = subprocess.run(args.command, env=environment, check=False)
            except OSError as exc:
                raise SourceProvenanceError("source_build_command_unavailable") from exc
            if result.returncode:
                return result.returncode if result.returncode > 0 else 128 - result.returncode
            # This diagnoses concurrent changes; it cannot undo command effects.
            if resolve_source_provenance(root, scopes) != provenance:
                raise SourceProvenanceError("source_changed_during_build")
            return 0
    except SourceProvenanceError as exc:
        print(f"CodeSecurity image provenance failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(provenance.to_record(), sort_keys=True) if args.json else
          f"{provenance.commit}:{provenance.tree}" if provenance.kind == "git" else
          f"{SOURCE_SNAPSHOT_KIND}:{provenance.digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
