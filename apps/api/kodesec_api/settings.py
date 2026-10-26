from functools import lru_cache
from pathlib import Path
from typing import Literal
import re
from urllib.parse import urlsplit

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = Field(
        "",
        alias="DATABASE_URL",
    )
    scanner_url: str = Field("http://localhost:8091", alias="SCANNER_URL")
    scanner_updater_url: str = Field(
        "http://scanner-updater:8092",
        alias="SCANNER_UPDATER_URL",
    )
    preparation_platform: Literal["mac", "linux", "windows"] = Field(
        "mac", alias="KODESEC_PREPARATION_PLATFORM"
    )
    scanner_tools_timeout: float = Field(12.0, alias="KODESEC_SCANNER_TOOLS_TIMEOUT")
    artifact_dir: str = Field("/data/artifacts", alias="KODESEC_ARTIFACT_DIR")
    source_snapshot_dir: str = Field(
        "/data/source-snapshots", alias="KODESEC_SOURCE_SNAPSHOT_DIR"
    )
    allowed_roots: str = Field("/workspace/source", alias="KODESEC_ALLOWED_ROOTS")

    ai_mode: str = Field("auto", alias="KODESEC_AI_MODE")
    ollama_base_url: str = Field("http://localhost:11434", alias="OLLAMA_BASE_URL")
    ollama_allowed_hosts: str = Field("", alias="KODESEC_OLLAMA_ALLOWED_HOSTS")
    ollama_model: str = Field("qwen3:8b", alias="OLLAMA_MODEL")
    ollama_model_digest: str = Field("", alias="OLLAMA_MODEL_DIGEST")
    ollama_thinking: bool = Field(False, alias="KODESEC_OLLAMA_THINKING")
    advisor_connector_url: str = Field(
        "http://advisor-connector:8093",
        alias="KODESEC_ADVISOR_CONNECTOR_URL",
    )
    advisor_direct_hosts: str = Field("", alias="KODESEC_ADVISOR_DIRECT_HOSTS")
    advisor_ssh_provider_ids: str = Field(
        "", alias="KODESEC_ADVISOR_SSH_PROVIDER_IDS"
    )
    advisor_grant_secret: str = Field(
        "", alias="KODESEC_ADVISOR_GRANT_SECRET"
    )
    auto_triage_limit: int = Field(5, alias="KODESEC_AUTO_TRIAGE_LIMIT")
    worker_lease_seconds: int = Field(30, ge=10, le=300, alias="KODESEC_WORKER_LEASE_SECONDS")
    worker_heartbeat_seconds: float = Field(10.0, ge=1.0, le=60.0, alias="KODESEC_WORKER_HEARTBEAT_SECONDS")
    worker_poll_seconds: float = Field(0.5, ge=0.05, le=30.0, alias="KODESEC_WORKER_POLL_SECONDS")
    worker_liveness_seconds: float = Field(10.0, ge=5.0, le=60.0, alias="KODESEC_WORKER_LIVENESS_SECONDS")
    worker_scanner_request_seconds: float = Field(
        5.0,
        ge=0.5,
        le=30.0,
        alias="KODESEC_WORKER_SCANNER_REQUEST_SECONDS",
    )
    worker_scanner_page_read_seconds: float = Field(
        30.0,
        ge=1.0,
        le=120.0,
        alias="KODESEC_WORKER_SCANNER_PAGE_READ_SECONDS",
    )
    worker_scanner_admission_wait_seconds: float = Field(
        1800.0,
        ge=60.0,
        le=3600.0,
        alias="KODESEC_WORKER_SCANNER_ADMISSION_WAIT_SECONDS",
    )
    worker_updater_request_seconds: float = Field(
        10.0,
        ge=0.5,
        le=60.0,
        alias="KODESEC_WORKER_UPDATER_REQUEST_SECONDS",
    )
    worker_cancel_wait_seconds: float = Field(
        30.0,
        ge=1.0,
        le=120.0,
        alias="KODESEC_WORKER_CANCEL_WAIT_SECONDS",
    )
    worker_max_findings: int = Field(50_000, ge=10_000, le=50_000, alias="KODESEC_WORKER_MAX_FINDINGS")
    worker_max_artifacts: int = Field(128, ge=128, le=128, alias="KODESEC_WORKER_MAX_ARTIFACTS")

    installation_id: str = Field("", alias="KODESEC_INSTALLATION_ID")
    installation_secret: str = Field("", alias="KODESEC_INSTALLATION_SECRET")
    bootstrap_token: str = Field("", alias="KODESEC_BOOTSTRAP_TOKEN")
    control_origins: str = Field(
        "http://127.0.0.1:8080",
        alias="KODESEC_CONTROL_ORIGINS",
    )
    internal_hosts: str = Field("api:8080,127.0.0.1:8080", alias="KODESEC_INTERNAL_HOSTS")
    static_dir: str | None = Field(None, alias="KODESEC_STATIC_DIR")
    @property
    def allowed_root_list(self) -> list[str]:
        return [item.strip() for item in self.allowed_roots.split(",") if item.strip()]

    @property
    def control_origin_list(self) -> list[str]:
        return [item.strip().rstrip("/") for item in self.control_origins.split(",") if item.strip()]

    @property
    def internal_host_list(self) -> list[str]:
        return [item.strip().lower() for item in self.internal_hosts.split(",") if item.strip()]

    @property
    def ollama_allowed_host_list(self) -> frozenset[str]:
        from .local_url import parse_declared_ollama_hosts

        return parse_declared_ollama_hosts(self.ollama_allowed_hosts)

    @property
    def advisor_direct_host_list(self) -> frozenset[str]:
        from .advisor.providers import exact_host_set

        return exact_host_set(self.advisor_direct_hosts.split(","))

    @property
    def advisor_ssh_provider_id_list(self) -> frozenset[str]:
        from .advisor.providers import MAX_PROVIDERS, PROVIDER_ID

        values = {
            item.strip()
            for item in self.advisor_ssh_provider_ids.split(",")
            if item.strip()
        }
        if len(values) > MAX_PROVIDERS or any(
            PROVIDER_ID.fullmatch(item) is None for item in values
        ):
            raise ValueError(
                "KODESEC_ADVISOR_SSH_PROVIDER_IDS must contain at most eight exact provider ids"
            )
        return frozenset(values)

    def validate_security_material(self) -> None:
        self.validate_database_configuration()
        required = {
            "KODESEC_INSTALLATION_SECRET": self.installation_secret,
            "KODESEC_BOOTSTRAP_TOKEN": self.bootstrap_token,
        }
        missing = [name for name, value in required.items() if len(value) < 43]
        if missing:
            raise RuntimeError(f"missing or weak generated security material: {', '.join(missing)}; run make init")
        if re.fullmatch(r"[a-f0-9]{12}", self.installation_id) is None:
            raise RuntimeError("KODESEC_INSTALLATION_ID must be the generated 12-character installation identity; run make init")
        if len(self.control_origin_list) != 1:
            raise RuntimeError("KODESEC_CONTROL_ORIGINS must contain exactly one loopback origin")
        if set(self.internal_host_list) != {"api:8080", "127.0.0.1:8080"}:
            raise RuntimeError("KODESEC_INTERNAL_HOSTS must contain only the fixed health and metrics hosts")
        from .schemas import normalize_project_repo_path

        roots = self.allowed_roots.split(",")
        if not 1 <= len(roots) <= 32 or len(set(roots)) != len(roots):
            raise RuntimeError("KODESEC_ALLOWED_ROOTS must contain one to 32 distinct absolute source roots")
        for root in roots:
            try:
                canonical = normalize_project_repo_path(root)
            except ValueError as error:
                raise RuntimeError("KODESEC_ALLOWED_ROOTS must contain canonical absolute source roots") from error
            if canonical != root:
                raise RuntimeError("KODESEC_ALLOWED_ROOTS must contain canonical absolute source roots")
            if canonical in {"/", "/Users", "/home", "/Volumes"}:
                raise RuntimeError("KODESEC_ALLOWED_ROOTS is too broad; choose project-scoped source roots")
        snapshot_path = Path(self.source_snapshot_dir)
        snapshot_root = snapshot_path.resolve(strict=False)
        source_roots = [Path(root).resolve(strict=False) for root in roots]
        artifact_root = Path(self.artifact_dir).resolve(strict=False)
        if (
            not snapshot_path.is_absolute()
            or ".." in snapshot_path.parts
            or snapshot_root.name != "source-snapshots"
            or any(
                snapshot_root == source_root
                or snapshot_root in source_root.parents
                or source_root in snapshot_root.parents
                for source_root in source_roots
            )
            or snapshot_root == artifact_root
            or snapshot_root in artifact_root.parents
            or artifact_root in snapshot_root.parents
        ):
            raise RuntimeError(
                "KODESEC_SOURCE_SNAPSHOT_DIR must be a separate absolute dedicated source-snapshots root"
            )
        for origin in self.control_origin_list:
            parsed = urlsplit(origin)
            if (
                parsed.scheme != "http"
                or (parsed.hostname or "").lower() not in {"127.0.0.1", "::1", "localhost"}
                or parsed.username is not None
                or parsed.password is not None
                or not parsed.port
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
            ):
                raise RuntimeError(f"control origin is not an exact loopback HTTP origin: {origin}")
        self.validate_ollama_configuration()

    def validate_ollama_configuration(self) -> None:
        from .advisor.providers import MODEL_DIGEST
        from .local_url import normalize_local_ollama_url

        try:
            normalize_local_ollama_url(self.ollama_base_url, self.ollama_allowed_host_list)
        except ValueError as exc:
            raise RuntimeError(
                "OLLAMA_BASE_URL must target a default local host or an exact operator-declared host"
            ) from exc
        if self.ollama_model_digest and MODEL_DIGEST.fullmatch(
            self.ollama_model_digest.strip().lower()
        ) is None:
            raise RuntimeError("OLLAMA_MODEL_DIGEST must be an exact lowercase SHA-256 digest")
        connector = urlsplit(self.advisor_connector_url)
        if (
            connector.scheme != "http"
            or (connector.hostname or "").lower()
            not in {"advisor-connector", "127.0.0.1", "localhost", "::1"}
            or connector.username is not None
            or connector.password is not None
            or connector.port != 8093
            or connector.path not in {"", "/"}
            or connector.query
            or connector.fragment
        ):
            raise RuntimeError(
                "KODESEC_ADVISOR_CONNECTOR_URL must be the fixed private connector endpoint"
            )
        try:
            self.advisor_direct_host_list
            self.advisor_ssh_provider_id_list
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc

    def validate_database_configuration(self) -> None:
        database_url = self.database_url.strip()
        if not database_url:
            raise RuntimeError("DATABASE_URL is required; run make init")
        if "://kodesec:kodesec@" in database_url.lower():
            raise RuntimeError("DATABASE_URL contains the removed predictable development credential; run make init")

    def validate_worker_configuration(self) -> None:
        """Fail closed when recovery timing cannot renew a lease safely."""

        self.validate_database_configuration()
        self.validate_ollama_configuration()
        if not 43 <= len(self.advisor_grant_secret) <= 256:
            raise RuntimeError(
                "KODESEC_ADVISOR_GRANT_SECRET must be a dedicated generated worker-to-connector secret"
            )
        if self.worker_heartbeat_seconds * 2 >= self.worker_lease_seconds:
            raise RuntimeError(
                "KODESEC_WORKER_HEARTBEAT_SECONDS must be less than half "
                "KODESEC_WORKER_LEASE_SECONDS"
            )
        scanner = urlsplit(self.scanner_url)
        if (
            scanner.scheme != "http"
            or (scanner.hostname or "").lower()
            not in {"scanner", "127.0.0.1", "localhost", "::1"}
            or scanner.username is not None
            or scanner.password is not None
            or scanner.port != 8091
            or scanner.path not in {"", "/"}
            or scanner.query
            or scanner.fragment
        ):
            raise RuntimeError("SCANNER_URL must be the fixed internal scanner endpoint")
        updater = urlsplit(self.scanner_updater_url)
        if (
            updater.scheme != "http"
            or (updater.hostname or "").lower()
            not in {"scanner-updater", "127.0.0.1", "localhost", "::1"}
            or updater.username is not None
            or updater.password is not None
            or updater.port != 8092
            or updater.path not in {"", "/"}
            or updater.query
            or updater.fragment
        ):
            raise RuntimeError(
                "SCANNER_UPDATER_URL must be the fixed internal updater endpoint"
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()
