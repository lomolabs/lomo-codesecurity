from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    allowed_roots: str = Field("/workspace/source", alias="KODESEC_ALLOWED_ROOTS")
    max_files: int = Field(5000, ge=1, alias="KODESEC_MAX_FILES")
    max_file_bytes: int = Field(1_048_576, ge=1, alias="KODESEC_MAX_FILE_BYTES")
    artifact_dir: str = Field("/data/artifacts", alias="KODESEC_ARTIFACT_DIR")
    source_snapshot_dir: str = Field(
        "/data/source-snapshots", alias="KODESEC_SOURCE_SNAPSHOT_DIR"
    )
    scratch_dir: str = Field("/run/kodesec-scratch", alias="KODESEC_SCRATCH_DIR")
    tool_cache_dir: str = Field("/data/tool-cache", alias="KODESEC_TOOL_CACHE_DIR")
    tool_lock_path: str = Field(
        "/usr/local/share/kodesec/locks/scanner-tools.lock.json",
        alias="KODESEC_TOOL_LOCK_PATH",
    )
    rules_lock_path: str = Field(
        "/usr/local/share/kodesec/locks/scanner-rules.lock.json",
        alias="KODESEC_RULES_LOCK_PATH",
    )
    # The host supplies the installation lane; requests cannot select a budget.
    scan_platform: Literal["mac", "linux", "windows"] = Field(
        "mac", alias="KODESEC_SCAN_PLATFORM"
    )
    external_tool_timeout: int = Field(300, ge=1, le=3600, alias="KODESEC_EXTERNAL_TOOL_TIMEOUT")
    external_tool_nice: int = Field(10, ge=0, le=19, alias="KODESEC_EXTERNAL_TOOL_NICE")
    run_deadline_seconds: int = Field(1800, ge=1, le=86400, alias="KODESEC_RUN_DEADLINE_SECONDS")
    run_result_retention_seconds: int = Field(
        1800,
        ge=1,
        le=3600,
        alias="KODESEC_RUN_RESULT_RETENTION_SECONDS",
    )
    run_result_max_records: int = Field(4, ge=1, le=8, alias="KODESEC_RUN_RESULT_MAX_RECORDS")
    run_result_max_findings: int = Field(
        50_000,
        ge=10_000,
        le=50_000,
        alias="KODESEC_RUN_RESULT_MAX_FINDINGS",
    )
    run_result_max_item_bytes: int = Field(
        32 * 1024,
        ge=32 * 1024,
        le=32 * 1024,
        alias="KODESEC_RUN_RESULT_MAX_ITEM_BYTES",
    )
    run_result_max_page_bytes: int = Field(
        4 * 1024 * 1024,
        ge=4 * 1024 * 1024,
        le=4 * 1024 * 1024,
        alias="KODESEC_RUN_RESULT_MAX_PAGE_BYTES",
    )
    run_result_max_run_bytes: int = Field(
        336 * 1024 * 1024,
        ge=336 * 1024 * 1024,
        le=336 * 1024 * 1024,
        alias="KODESEC_RUN_RESULT_MAX_RUN_BYTES",
    )
    run_result_max_total_bytes: int = Field(
        384 * 1024 * 1024,
        ge=384 * 1024 * 1024,
        le=384 * 1024 * 1024,
        alias="KODESEC_RUN_RESULT_MAX_TOTAL_BYTES",
    )
    max_active_runs: int = Field(1, ge=1, le=2, alias="KODESEC_MAX_ACTIVE_RUNS")
    process_termination_grace_seconds: float = Field(
        5.0,
        ge=0.05,
        le=30.0,
        alias="KODESEC_PROCESS_TERMINATION_GRACE_SECONDS",
    )
    shutdown_wait_seconds: float = Field(10.0, ge=0.1, le=60.0, alias="KODESEC_SHUTDOWN_WAIT_SECONDS")

    @model_validator(mode="after")
    def default_platform_run_deadline(self) -> "Settings":
        # Explicit run budgets are absolute, including qualification deadlines.
        if "run_deadline_seconds" not in self.model_fields_set:
            self.run_deadline_seconds = {"mac": 1800, "linux": 4680, "windows": 7020}[self.scan_platform]
        return self

    @property
    def allowed_root_list(self) -> list[str]:
        return [item.strip().rstrip("/") or "/" for item in self.allowed_roots.split(",") if item.strip()]

    @property
    def run_result_dir(self) -> Path:
        return Path(self.scratch_dir) / "run-results"

    def validate_storage_boundaries(self) -> None:
        configured = {
            "artifact": Path(self.artifact_dir),
            "source snapshot": Path(self.source_snapshot_dir),
            "scratch": Path(self.scratch_dir),
            "tool cache": Path(self.tool_cache_dir),
        }
        if any(not path.is_absolute() for path in configured.values()):
            raise RuntimeError("scanner artifact, scratch, and tool-cache paths must be absolute")
        resolved = {name: path.resolve(strict=False) for name, path in configured.items()}
        result_dir = self.run_result_dir.resolve(strict=False)
        if result_dir.parent != resolved["scratch"] or result_dir.name != "run-results":
            raise RuntimeError("scanner result storage must be the fixed private scratch child")
        items = list(resolved.items())
        for index, (first_name, first) in enumerate(items):
            for second_name, second in items[index + 1:]:
                if first == second or first in second.parents or second in first.parents:
                    raise RuntimeError(f"scanner {first_name} and {second_name} paths must be separate")


class UpdaterSettings(BaseSettings):
    """Fixed, source-blind updater configuration.

    No setting accepts an upstream URL, source checkout, database credential,
    or executable. Network locations and embedded paths come exclusively from
    the strictly validated scanner locks.
    """

    model_config = SettingsConfigDict(env_file=None, extra="ignore")
    data_catalog_mode: Literal["source-reviewed/bundled", "signed"] = Field(
        "source-reviewed/bundled", alias="KODESEC_SCANNER_DATA_CATALOG_MODE"
    )

    tool_cache_dir: str = Field("/data/tool-cache", alias="KODESEC_TOOL_CACHE_DIR")
    scratch_dir: str = Field(
        "/run/kodesec-updater",
        alias="KODESEC_UPDATER_SCRATCH_DIR",
    )
    tool_lock_path: str = Field(
        "/usr/local/share/kodesec/locks/scanner-tools.lock.json",
        alias="KODESEC_TOOL_LOCK_PATH",
    )
    rules_lock_path: str = Field(
        "/usr/local/share/kodesec/locks/scanner-rules.lock.json",
        alias="KODESEC_RULES_LOCK_PATH",
    )
    max_active: int = Field(1, ge=1, le=2, alias="KODESEC_UPDATER_MAX_ACTIVE")
    max_pending: int = Field(8, ge=1, le=32, alias="KODESEC_UPDATER_MAX_PENDING")
    request_timeout_seconds: float = Field(
        30.0,
        ge=1.0,
        le=300.0,
        alias="KODESEC_UPDATER_REQUEST_TIMEOUT_SECONDS",
    )
    shutdown_wait_seconds: float = Field(
        10.0,
        ge=0.1,
        le=60.0,
        alias="KODESEC_UPDATER_SHUTDOWN_WAIT_SECONDS",
    )

    @property
    def allowed_hosts(self) -> frozenset[str]:
        return frozenset(
            {
                "scanner-updater:8092",
                "127.0.0.1:8092",
                "localhost:8092",
                "[::1]:8092",
            }
        )

    def validate_boundaries(self) -> None:
        cache = Path(self.tool_cache_dir)
        scratch = Path(self.scratch_dir)
        locks = (Path(self.tool_lock_path), Path(self.rules_lock_path))
        if not cache.is_absolute() or not scratch.is_absolute() or any(
            not path.is_absolute() for path in locks
        ):
            raise RuntimeError("updater cache, scratch, and lock paths must be absolute")
        cache_resolved = cache.resolve(strict=False)
        scratch_resolved = scratch.resolve(strict=False)
        if (
            cache_resolved == scratch_resolved
            or cache_resolved in scratch_resolved.parents
            or scratch_resolved in cache_resolved.parents
        ):
            raise RuntimeError("updater cache and scratch paths must be separate")
        for lock in locks:
            resolved = lock.resolve(strict=False)
            if resolved == cache_resolved or cache_resolved in resolved.parents:
                raise RuntimeError("updater locks may not reside in the writable cache")
            if resolved == scratch_resolved or scratch_resolved in resolved.parents:
                raise RuntimeError("updater locks may not reside in updater scratch")


@lru_cache
def get_settings() -> Settings:
    return Settings()


@lru_cache
def get_updater_settings() -> UpdaterSettings:
    return UpdaterSettings()
