"""Host-owned narrow source roots shared by authorization and Compose startup."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import unicodedata


MAX_SOURCE_ROOT_BYTES = 4096
MAX_SOURCE_ROOTS = 32
MAX_RUNTIME_BYTES = 64 * 1024
_BASE_BROAD_ROOTS = {
    "/", "/Users", "/home", "/Volumes", "/private", "/private/tmp",
    "/private/var/tmp", "/tmp", "/var", "/var/tmp", "/usr", "/etc",
    "/opt", "/mnt", "/media", "/root",
}
_MAC_DATA = "/System/Volumes/Data"
BROAD_SOURCE_ROOTS = _BASE_BROAD_ROOTS | {_MAC_DATA} | {
    f"{_MAC_DATA}{root}" for root in _BASE_BROAD_ROOTS if root != "/"
}
# A bind at these targets could shadow the scanner runtime or its private data.
_RESERVED_TARGETS = (
    "/bin", "/sbin", "/usr", "/lib", "/lib64", "/etc", "/proc", "/sys",
    "/dev", "/run", "/data", "/app",
)


class SourceRootError(ValueError):
    """An exact source authorization cannot safely become a Compose bind."""


def _compose_literal_path(value: str) -> bool:
    return (
        value == value.strip()
        and len(value.encode("utf-8")) <= MAX_SOURCE_ROOT_BYTES
        and not any(
            unicodedata.category(character) in {"Cc", "Cf", "Cs"}
            or character in {"$", "'", '"', "#", "\\", ","}
            for character in value
        )
    )


def _check_scope(value: str) -> None:
    lexical = os.path.normpath(value)
    if lexical in BROAD_SOURCE_ROOTS or lexical == Path.home().as_posix():
        raise SourceRootError("Refusing a broad source root; choose one repository or a narrow development tree.")
    if any(PurePosixPath(lexical).is_relative_to(root) for root in _RESERVED_TARGETS):
        raise SourceRootError("The selected source root would shadow a protected scanner runtime path.")


def validated_source_root(selected: str) -> Path:
    if not selected or "\x00" in selected:
        raise SourceRootError("The selected source root is empty or contains NUL.")
    if any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in selected):
        raise SourceRootError("The selected source root contains an unsafe control or formatting character.")
    if not _compose_literal_path(selected):
        raise SourceRootError("The selected source root contains characters that cannot be serialized literally through the Compose environment file.")
    source = Path(selected)
    if not source.is_absolute():
        raise SourceRootError("The selected source root must be an absolute path.")
    _check_scope(selected)
    try:
        canonical = source.resolve(strict=True)
    except OSError as error:
        raise SourceRootError(f"The selected source root cannot be resolved: {type(error).__name__}.") from error
    if not canonical.is_dir():
        raise SourceRootError("The selected source root must be an existing directory.")
    canonical_text = canonical.as_posix()
    if not _compose_literal_path(canonical_text):
        raise SourceRootError("The resolved source root contains characters that cannot be serialized literally through the Compose environment file.")
    _check_scope(canonical_text)
    if canonical_text in {Path(root).resolve(strict=False).as_posix() for root in BROAD_SOURCE_ROOTS}:
        raise SourceRootError("Refusing a broad source root; choose one repository or a narrow development tree.")
    return canonical


def configured_source_roots(primary: str, serialized: str) -> list[str]:
    """Validate persisted identities without requiring removed/offline sources.

    Only owner authorization resolves directories. Runtime teardown must still
    work when a previously approved source has been removed or disconnected.
    Compose never creates missing bind sources.
    """
    roots = serialized.split(",")
    if not 1 <= len(roots) <= MAX_SOURCE_ROOTS or len(set(roots)) != len(roots):
        raise SourceRootError("Configure between one and 32 distinct narrow source roots.")
    if primary != roots[0]:
        raise SourceRootError("KODESEC_REPO_ROOT must be the first configured source root.")
    for root in roots:
        if (
            not root.startswith("/") or not _compose_literal_path(root)
            or str(PurePosixPath(root)) != root or ".." in PurePosixPath(root).parts
        ):
            raise SourceRootError("Configured source roots must be canonical literal absolute paths.")
        _check_scope(root)
    return roots
