"""Verify native source-build evidence before sealing the installed tool manifest."""
from __future__ import annotations

import hashlib
import platform
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .cache_manifest import (
    BinarySourceBuildLock, LockValidationError, _decode_json_object,
    _read_bounded_regular_file,
)


BUILD_ROOT = Path("/usr/local/share/kodesec/builds")
_INPUTS = {"source-build.py", "lomo.patch", "LICENSE.txt", "NOTICE", "test_source_build.py"}
_PACKAGES = (
    "pkg/commands/process/settings", "pkg/commands/process/filelist/timeout",
    "pkg/languages/python/detectors/object", "pkg/languages/python/detectors",
    "pkg/languages/python", "pkg/scanner/ast/tree", "pkg/scanner/ast/query", "pkg/scanner/cache",
    "pkg/scanner/ruleset", "pkg/scanner/detectorset",
    "pkg/scanner/detectors/customrule/filters", "pkg/scanner/rulescanner",
    "pkg/scanner/detectors/customrule",
)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class SemanticTestReceipt(_StrictModel):
    package: str = Field(max_length=160)
    top_tests: list[str] = Field(min_length=1, max_length=1024)
    started_tests: list[str] = Field(min_length=1, max_length=4096)
    passed_tests: list[str] = Field(min_length=1, max_length=4096)
    skipped_tests: int = Field(ge=0, le=0)

    @model_validator(mode="after")
    def validate_terminality(self) -> "SemanticTestReceipt":
        if any(names != sorted(set(names)) for names in (
            self.top_tests, self.started_tests, self.passed_tests
        )):
            raise ValueError("source-build test names must be unique and sorted")
        if self.started_tests != self.passed_tests or self.top_tests != [
            name for name in self.started_tests if "/" not in name
        ]:
            raise ValueError("source-build tests must all reach a passed terminal event")
        if any(not name.startswith("Test") or len(name) > 1024 for name in self.started_tests):
            raise ValueError("source-build test name is invalid")
        return self


class SourceBuildReceipt(_StrictModel):
    schema_version: Literal[1]
    kind: Literal["bearer-source-build-output"]
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_archive_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_lock_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    inputs: dict[str, str] = Field(min_length=5, max_length=5)
    toolchain: dict[str, str | bool] = Field(min_length=3, max_length=3)
    go_env: dict[str, str] = Field(min_length=4, max_length=4)
    semantic_tests: list[SemanticTestReceipt] = Field(min_length=len(_PACKAGES), max_length=len(_PACKAGES))
    platform: Literal["linux/amd64", "linux/arm64"]
    version: str = Field(min_length=1, max_length=64)
    binary_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    binary_bytes: int = Field(gt=0, le=128 * 1024 * 1024)
    private_probes_absent: bool
    logs: dict[str, str] = Field(min_length=1, max_length=64)

    @field_validator("schema_version", mode="before")
    @classmethod
    def strict_version(cls, value: int) -> int:
        if type(value) is not int:
            raise ValueError("source-build schema version must be an integer")
        return value

    @model_validator(mode="after")
    def validate_proof(self) -> "SourceBuildReceipt":
        if set(self.inputs) != _INPUTS or any(not _DIGEST.fullmatch(v) for v in self.inputs.values()):
            raise ValueError("source-build recipe input closure differs")
        packages = ["github.com/bearer/bearer/" + package for package in _PACKAGES]
        if [item.package for item in self.semantic_tests] != packages:
            raise ValueError("source-build semantic package coverage differs")
        steps = {"go-env", "go-mod-verify", "go-deps", "go-build", "go-symbols", "build-info", "elf"}
        steps.update(f"test-{index}" for index in range(len(_PACKAGES)))
        expected_logs = {f"logs/{step}.{stream}" for step in steps for stream in ("stdout", "stderr")}
        if set(self.logs) != expected_logs or any(not _DIGEST.fullmatch(v) for v in self.logs.values()):
            raise ValueError("source-build evidence log closure differs")
        if not self.private_probes_absent:
            raise ValueError("private diagnostic probes are forbidden in the production build")
        return self


def _native_platform() -> str:
    architecture = {"aarch64": "arm64", "x86_64": "amd64"}.get(platform.machine())
    if platform.system() != "Linux" or architecture is None:
        raise LockValidationError("source-build verification requires a supported native Linux runtime")
    return "linux/" + architecture


def verify_source_build_metadata(
    locked: BinarySourceBuildLock, *, binary_sha256: str, binary_bytes: int,
    root: Path | None = None,
) -> dict[str, str]:
    """Bind reviewed recipe, observed native compiler, output bytes and notices.

    The generated receipt records output identity; its digest is not substituted
    for a prebuilt release artifact. Compiler-image admission is owned by the
    maintained image builder, outside this in-image verification step.
    """
    directory = (BUILD_ROOT if root is None else root) / "bearer"
    recipe_raw = _read_bounded_regular_file(directory / "source.lock.json", 64 * 1024, "source-build recipe")
    if hashlib.sha256(recipe_raw).hexdigest() != locked.recipe_sha256:
        raise LockValidationError("source-build recipe digest differs from the reviewed tool lock")
    recipe = _decode_json_object(recipe_raw, "source-build recipe")
    receipt_raw = _read_bounded_regular_file(directory / "build.json", 1024 * 1024, "source-build receipt")
    receipt = SourceBuildReceipt.model_validate(_decode_json_object(receipt_raw, "source-build receipt"))
    observed_platform = _native_platform()
    if (
        recipe.get("kind") != locked.kind or recipe.get("schema_version") != 1
        or receipt.source_lock_sha256 != locked.recipe_sha256
        or receipt.version != locked.output_version
        or recipe.get("output") != {"platforms": locked.platforms, "version": locked.output_version}
        or receipt.platform != observed_platform
        or receipt.inputs != recipe.get("inputs")
        or receipt.toolchain != recipe.get("toolchain")
        or receipt.source_commit != recipe.get("source", {}).get("commit")
        or receipt.source_archive_sha256 != recipe.get("source", {}).get("archive_sha256")
        or receipt.go_env != {
            "GOVERSION": receipt.toolchain.get("go_version"), "GOOS": "linux",
            "GOARCH": observed_platform.split("/")[1], "CGO_ENABLED": "1",
        }
        or receipt.toolchain.get("cgo_enabled") is not True
    ):
        raise LockValidationError("source-build receipt does not match the reviewed native recipe")
    # Runtime supplies the existing stat-bound observed digest. Never re-read
    # the large binary merely to revalidate the small recipe/receipt closure.
    if (type(binary_bytes) is not int or binary_bytes != receipt.binary_bytes
            or binary_sha256 != receipt.binary_sha256):
        raise LockValidationError("source-built binary differs from its output receipt")
    for name in ("LICENSE.txt", "NOTICE"):
        raw = _read_bounded_regular_file(directory / name, 64 * 1024, "source-build notice")
        if hashlib.sha256(raw).hexdigest() != receipt.inputs[name]:
            raise LockValidationError("source-build license or modification notice differs")
    return {
        "kind": locked.kind,
        "recipe_sha256": locked.recipe_sha256,
        "receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
        "platform": receipt.platform,
        "binary_sha256": receipt.binary_sha256,
    }


def verify_source_build(
    locked: BinarySourceBuildLock, binary: Path, *, root: Path | None = None,
) -> dict[str, str]:
    """Build-time byte verification sharing the runtime metadata validator."""
    binary_raw = _read_bounded_regular_file(binary, 128 * 1024 * 1024, "source-built binary")
    return verify_source_build_metadata(
        locked, binary_sha256=hashlib.sha256(binary_raw).hexdigest(),
        binary_bytes=len(binary_raw), root=root,
    )
