from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Mapping

from . import __version__
from .data_catalog import generation_locks
from .cache_manifest import (
    CacheValidationError,
    CacheVerification,
    LoadedDocument,
    LockValidationError,
    ReadinessFacet,
    ResolvedGeneration,
    RulesLockFile,
    RuntimeComponentSnapshot,
    ToolReadiness,
    ToolLockEntry,
    ToolLockFile,
    evaluate_tool_readiness,
    load_rules_lock,
    load_tool_lock,
    resolve_active_generation_cached,
    runtime_components_from_resolved,
)


TOOL_MANIFEST_PATH = Path(
    os.environ.get(
        "KODESEC_TOOL_MANIFEST_PATH",
        "/usr/local/share/kodesec/tool-manifest.json",
    )
)
BUILD_IDENTITY_PATH = Path("/usr/local/share/kodesec/build-identity")

# OpenGrep's release executable is a small self-extracting launcher. Its native
# core must live in the immutable image rather than being materialized in a
# writable/noexec request or cache mount on first use.
OPENGREP_HOME_PATH = Path("/usr/local/share/kodesec/opengrep-home")
OPENGREP_CORE_PATH = (
    OPENGREP_HOME_PATH
    / ".cache"
    / "opengrep"
    / "v1.27.0"
    / "opengrep.bin"
)
OPENGREP_EXECUTABLE_PATH = OPENGREP_CORE_PATH.with_name("opengrep")
# Address the reviewed configuration relative to its immutable component root.
# OpenGrep incorporates absolute configuration paths into SARIF rule IDs; a
# relative entrypoint keeps IDs stable across generation IDs and hosts.
OPENGREP_RULE_ENTRYPOINT = "rules.yml"

EXTERNAL_TOOL_VERSIONS: dict[str, str] = {
    "trivy": "0.73.0",
    "gitleaks": "8.30.1",
    "opengrep": "1.27.0",
    "bearer": "2.1.0+lomo.1",
    "grype": "0.117.0",
    "checkov": "3.3.10",
    "trufflehog": "3.96.0",
    "syft": "1.51.0",
}

TOOL_VERSION_COMMANDS: dict[str, list[str]] = {
    "trivy": ["trivy", "--version"],
    "gitleaks": ["gitleaks", "version"],
    "opengrep": ["opengrep", "--experimental", "--version"],
    "bearer": ["bearer", "version"],
    "grype": ["grype", "version"],
    "checkov": ["checkov", "--version"],
    "trufflehog": ["trufflehog", "--version"],
    "syft": ["syft", "version"],
}

TOOL_ADAPTER_ARGUMENTS: dict[str, list[str]] = {
    "trivy": [
        "trivy", "fs", "--format", "sarif", "--output", "$OUTPUT", "--scanners",
        "vuln,secret,misconfig", "--cache-dir", "$CACHE", "--offline-scan",
        "--skip-db-update", "--skip-java-db-update", "--skip-check-update",
        "--disable-telemetry", "--skip-version-check", "$SOURCE",
    ],
    "gitleaks": [
        "gitleaks", "dir", "$SOURCE", "--report-format", "sarif", "--report-path",
        "$OUTPUT", "--exit-code", "0", "--no-banner",
    ],
    "opengrep": [
        "opengrep", "scan", "--config", "$RULES", "--sarif", "--output", "$OUTPUT",
        "$SOURCE",
    ],
    "bearer": [
        "bearer", "scan", "$SOURCE", "--format", "jsonv2", "--output", "$OUTPUT",
        "--disable-version-check", "--disable-default-rules", "--external-rule-dir", "$RULES",
    ],
    "grype": ["grype", "sbom:$SYFT_SBOM", "-o", "sarif", "--file", "$OUTPUT"],
    "checkov": [
        "checkov", "-d", "$SOURCE", "--framework", "kubernetes,dockerfile,terraform",
        "--output", "sarif", "--output-file-path", "$OUTPUT_DIRECTORY", "--skip-download",
        "--soft-fail",
    ],
    "trufflehog": [
        "trufflehog", "filesystem", "$SOURCE", "--json", "--no-update", "--no-verification",
    ],
    "syft": ["syft", "dir:$SOURCE", "-o", "cyclonedx-json=$OUTPUT"],
}

TOOL_ADAPTER_SUPPLEMENTAL_ARGUMENTS: dict[str, list[list[str]]] = {
    "trivy": [[
        "trivy", "rootfs", "--format", "sarif", "--output", "$OUTPUT",
        "--scanners", "vuln", "--pkg-types", "library", "--parallel", "1",
        "--cache-dir", "$CACHE", "--offline-scan", "--skip-db-update",
        "--skip-java-db-update", "--skip-check-update", "--disable-telemetry",
        "--skip-version-check", "$SOURCE",
    ]],
    "gitleaks": [],
    "opengrep": [],
    "bearer": [],
    "grype": [],
    "checkov": [],
    "trufflehog": [],
    "syft": [],
}

TOOL_ADAPTER_ENVIRONMENTS: dict[str, dict[str, str]] = {
    "trivy": {},
    "gitleaks": {},
    "opengrep": {
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
        "SEMGREP_SEND_METRICS": "off",
    },
    "bearer": {"BEARER_TELEMETRY_ENABLED": "false"},
    "grype": {
        "GRYPE_CHECK_FOR_APP_UPDATE": "false",
        "GRYPE_DB_AUTO_UPDATE": "false",
        "GRYPE_DB_CACHE_DIR": "$CACHE",
    },
    "checkov": {"CHECKOV_SKIP_FRAMEWORK_DOWNLOADS": "true"},
    "trufflehog": {},
    "syft": {"SYFT_CHECK_FOR_APP_UPDATE": "false"},
}

TOOL_ADAPTER_OUTPUT_FORMATS: dict[str, str] = {
    "trivy": "sarif",
    "gitleaks": "sarif",
    "opengrep": "sarif",
    "bearer": "jsonv2",
    "grype": "sarif",
    "checkov": "sarif",
    "trufflehog": "jsonl",
    "syft": "cyclonedx-json",
}


@dataclass(frozen=True)
class ScannerRuntimeContext:
    """One fail-closed lock, generation, and readiness decision.

    A scan must not authorize tools from one ``active.json`` revision and then
    resolve component roots from a later revision.  The context therefore owns
    the exact validated generation used by both readiness and runtime input
    resolution.  Invalid lock/cache state is represented by absent documents
    plus an all-invalid readiness map rather than by a second read attempt.
    """

    tools: LoadedDocument[ToolLockFile] | None
    rules: LoadedDocument[RulesLockFile] | None
    resolved: ResolvedGeneration | None
    runtime_by_id: Mapping[str, Mapping[str, Any]]
    readiness_by_id: Mapping[str, ToolReadiness]

    @property
    def generation_id(self) -> str | None:
        if (
            self.resolved is None
            or self.resolved.state != "ready"
            or self.resolved.generation is None
        ):
            return None
        return self.resolved.generation.manifest.generation_id

    def resolve_components(self, component_ids: list[str]) -> RuntimeComponentSnapshot:
        if self.tools is None or self.rules is None or self.resolved is None:
            raise CacheValidationError("scanner runtime context is invalid")
        return runtime_components_from_resolved(
            self.resolved,
            self.tools,
            self.rules,
            component_ids,
        )


@dataclass(frozen=True)
class ScannerToolsSnapshot:
    """Tool readiness and the exact validated generation used to derive it."""

    tools: list[dict[str, Any]]
    active_generation: str | None
    cache_verification: CacheVerification | None = None


def validate_runtime_lock_contract(tools: ToolLockFile) -> None:
    """Bind reviewed tool identities to this image's runtime constants."""

    if {tool.id for tool in tools.tools} != set(EXTERNAL_TOOL_VERSIONS):
        raise LockValidationError("runtime tool catalog differs from the curated image")
    for tool in tools.tools:
        if tool.version != EXTERNAL_TOOL_VERSIONS[tool.id]:
            raise LockValidationError("runtime tool version differs from the image pin")
        if tool.binary.version_command != TOOL_VERSION_COMMANDS[tool.id]:
            raise LockValidationError("runtime tool version command differs from its lock")
        if tool.adapter.arguments != TOOL_ADAPTER_ARGUMENTS[tool.id]:
            raise LockValidationError("runtime adapter arguments differ from its lock")
        if (
            tool.adapter.supplemental_arguments
            != TOOL_ADAPTER_SUPPLEMENTAL_ARGUMENTS[tool.id]
        ):
            raise LockValidationError(
                "runtime supplemental adapter arguments differ from its lock"
            )
        if tool.adapter.environment != TOOL_ADAPTER_ENVIRONMENTS[tool.id]:
            raise LockValidationError("runtime adapter environment differs from its lock")
        if tool.adapter.output_format != TOOL_ADAPTER_OUTPUT_FORMATS[tool.id]:
            raise LockValidationError("runtime adapter output format differs from its lock")


SCANNER_TOOLS: tuple[dict[str, str], ...] = (
    {
        "id": "secrets-lite",
        "name": "Internal Secrets Lite",
        "category": "secrets",
        "version": __version__,
        "latest_version": __version__,
        "lifecycle": "internal-lite",
        "source": "internal",
        "output_format": "normalized",
        "description": "Built-in fallback checks for common token patterns, private keys, high-entropy material, and sensitive assignments.",
    },
    {
        "id": "sast-lite",
        "name": "Internal SAST Lite",
        "category": "sast",
        "version": __version__,
        "latest_version": __version__,
        "lifecycle": "internal-lite",
        "source": "internal",
        "output_format": "normalized",
        "description": "Built-in fallback checks for a small set of risky code patterns such as shell execution, eval, formatted SQL, and weak token randomness.",
    },
    {
        "id": "iac-lite",
        "name": "Internal IaC Lite",
        "category": "iac",
        "version": __version__,
        "latest_version": __version__,
        "lifecycle": "internal-lite",
        "source": "internal",
        "output_format": "normalized",
        "description": "Built-in fallback checks for a small set of Kubernetes, Terraform, and Docker hardening risks.",
    },
    {
        "id": "trivy",
        "name": "Trivy",
        "category": "dependency/iac",
        "version": EXTERNAL_TOOL_VERSIONS["trivy"],
        "latest_version": EXTERNAL_TOOL_VERSIONS["trivy"],
        "lifecycle": "industry-tool",
        "source": "external",
        "output_format": "sarif",
        "description": "Aqua Security Trivy filesystem scanner for vulnerabilities, IaC misconfigurations, secrets, and license signals.",
    },
    {
        "id": "gitleaks",
        "name": "Gitleaks",
        "category": "secrets",
        "version": EXTERNAL_TOOL_VERSIONS["gitleaks"],
        "latest_version": EXTERNAL_TOOL_VERSIONS["gitleaks"],
        "lifecycle": "industry-tool",
        "source": "external",
        "output_format": "sarif",
        "description": "Gitleaks secret scanner using its native detector rules and SARIF output.",
    },
    {
        "id": "opengrep",
        "name": "OpenGrep",
        "category": "sast",
        "version": EXTERNAL_TOOL_VERSIONS["opengrep"],
        "latest_version": EXTERNAL_TOOL_VERSIONS["opengrep"],
        "lifecycle": "industry-tool",
        "source": "external",
        "output_format": "sarif",
        "description": "OpenGrep semantic/static-analysis scanner using pinned local rules for offline-ready SARIF output.",
    },
    {
        "id": "bearer",
        "name": "Bearer",
        "category": "sast/privacy",
        "version": EXTERNAL_TOOL_VERSIONS["bearer"],
        "latest_version": EXTERNAL_TOOL_VERSIONS["bearer"],
        "lifecycle": "industry-tool",
        "source": "external",
        "output_format": "jsonv2",
        "description": "Bearer code scanner for security, privacy, and data-flow risks in supported languages.",
    },
    {
        "id": "grype",
        "name": "Grype",
        "category": "dependency",
        "version": EXTERNAL_TOOL_VERSIONS["grype"],
        "latest_version": EXTERNAL_TOOL_VERSIONS["grype"],
        "lifecycle": "industry-tool",
        "source": "external",
        "output_format": "sarif",
        "description": "Anchore Grype vulnerability scanner for packages and container/dependency metadata.",
    },
    {
        "id": "checkov",
        "name": "Checkov",
        "category": "iac",
        "version": EXTERNAL_TOOL_VERSIONS["checkov"],
        "latest_version": EXTERNAL_TOOL_VERSIONS["checkov"],
        "lifecycle": "industry-tool",
        "source": "external",
        "output_format": "sarif",
        "description": "Checkov IaC scanner for Terraform, Kubernetes, Dockerfile, GitHub Actions, and cloud configuration risks.",
    },
    {
        "id": "trufflehog",
        "name": "TruffleHog",
        "category": "secrets",
        "version": EXTERNAL_TOOL_VERSIONS["trufflehog"],
        "latest_version": EXTERNAL_TOOL_VERSIONS["trufflehog"],
        "lifecycle": "industry-tool",
        "source": "external",
        "output_format": "jsonl",
        "description": "TruffleHog verified/structured secret scanner with JSONL output.",
    },
    {
        "id": "syft",
        "name": "Syft",
        "category": "sbom",
        "version": EXTERNAL_TOOL_VERSIONS["syft"],
        "latest_version": EXTERNAL_TOOL_VERSIONS["syft"],
        "lifecycle": "industry-tool",
        "source": "external",
        "output_format": "cyclonedx-json",
        "description": "Anchore Syft SBOM generator. It stores CycloneDX artifacts and does not emit security findings directly.",
    },
)

def scanner_tool_ids() -> set[str]:
    return {item["id"] for item in SCANNER_TOOLS}


def internal_tool_ids() -> set[str]:
    return {item["id"] for item in SCANNER_TOOLS if item.get("source") == "internal"}


def external_tool_ids() -> set[str]:
    return {item["id"] for item in SCANNER_TOOLS if item.get("source") == "external"}


def normalize_version(value: str | None) -> str:
    return (value or "").strip().removeprefix("v")


def versions_from_output(output: str) -> tuple[str, ...]:
    return tuple(
        match.group(0)
        for match in re.finditer(
            r"v?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?",
            output,
        )
    )


def version_output_matches(output: str, expected: str) -> bool:
    normalized_expected = normalize_version(expected)
    return any(normalize_version(item) == normalized_expected for item in versions_from_output(output))


def binary_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


@lru_cache(maxsize=64)
def _binary_sha256_for_stat(
    path: str,
    device: int,
    inode: int,
    size: int,
    modified_ns: int,
) -> str:
    # The scanner image root filesystem is read-only. The complete stat tuple
    # prevents stale reuse if a development/runtime executable is replaced.
    del device, inode, size, modified_ns
    return binary_sha256(Path(path))


def observed_binary_sha256(path: Path) -> str:
    stat = path.stat()
    return _binary_sha256_for_stat(
        str(path),
        stat.st_dev,
        stat.st_ino,
        stat.st_size,
        stat.st_mtime_ns,
    )


def scanner_package_identity() -> str:
    """Bind the executing adapter code without Docker access or image tags.

    Immutable installed Python sources are small; executable hashes reuse the
    existing stat-keyed observer so a changed development build cannot inherit
    a previous build's successful immutable-tree evidence.
    """
    root = Path(__file__).parent
    files = sorted(root.rglob("*.py"))
    if not files or len(files) > 256:
        raise ValueError("scanner package source inventory is invalid")
    digest = hashlib.sha256()
    for source in files:
        if source.is_symlink() or source.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("scanner package source is not immutable bounded code")
        digest.update(source.relative_to(root).as_posix().encode() + b"\0")
        digest.update(observed_binary_sha256(source).encode() + b"\0")
    return digest.hexdigest()


def _runtime_identity(tool_id: str, *binary_digests: str) -> str | None:
    # Provenance is supplied by the existing clean-source build boundary and
    # covers Dockerfile + dependency locks too, not only wrapper executables.
    # An unverified developer runtime stays scannable but cannot authorize Git.
    try:
        if BUILD_IDENTITY_PATH.is_symlink() or BUILD_IDENTITY_PATH.stat().st_size > 100:
            return None
        build = BUILD_IDENTITY_PATH.read_text(encoding="ascii").strip()
        if not re.fullmatch(r"scanner:(?:[0-9a-f]{40}:[0-9a-f]{40}|source-sha256:[0-9a-f]{64})", build):
            return None
        package = scanner_package_identity()
    except (OSError, UnicodeError, ValueError):
        return None
    return hashlib.sha256("\0".join((tool_id, build, package, *binary_digests)).encode()).hexdigest()


@lru_cache(maxsize=1)
def _verified_tool_manifest() -> dict[str, Any]:
    try:
        payload = json.loads(TOOL_MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        return {}
    tools = payload.get("tools")
    return tools if isinstance(tools, dict) else {}


def tool_runtime_state(tool_id: str, *, locked_tool: ToolLockEntry | None = None) -> dict[str, Any]:
    meta = next((item for item in SCANNER_TOOLS if item["id"] == tool_id), None)
    if not meta:
        return {"id": tool_id, "available": False, "status": "unknown"}
    if meta.get("source") == "internal":
        return {"id": tool_id, "available": True, "installed_version": __version__, "status": "ready",
            "runtime_identity": _runtime_identity(tool_id)}

    command = TOOL_VERSION_COMMANDS.get(tool_id)
    binary = command[0] if command else tool_id
    path = shutil.which(binary)
    if not path:
        return {"id": tool_id, "available": False, "status": "missing", "installed_version": None}
    manifest = _verified_tool_manifest().get(tool_id)
    if not isinstance(manifest, dict):
        return {
            "id": tool_id,
            "available": False,
            "status": "unverified",
            "installed_version": None,
        }
    expected = str(meta.get("version") or "")
    installed = str(manifest.get("installed_version") or "")
    manifest_path = manifest.get("path")
    manifest_digest = manifest.get("sha256")
    resolved_path = Path(path).resolve(strict=False)
    if (
        not installed
        or normalize_version(installed) != normalize_version(expected)
        or not isinstance(manifest_path, str)
        or Path(manifest_path).resolve(strict=False) != resolved_path
        or not isinstance(manifest_digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", manifest_digest)
    ):
        return {
            "id": tool_id,
            "available": False,
            "status": "version_mismatch",
            "installed_version": installed or None,
        }
    try:
        observed_digest = observed_binary_sha256(resolved_path)
    except OSError:
        return {
            "id": tool_id,
            "available": False,
            "status": "missing",
            "installed_version": None,
        }
    if observed_digest != manifest_digest:
        return {
            "id": tool_id,
            "available": False,
            "status": "binary_changed",
            "installed_version": installed,
        }
    source_identity: tuple[str, ...] = ()
    if tool_id == "bearer":
        try:
            declared = manifest.get("source_build")
            if locked_tool is None:
                # Standalone /tools and updater observations use the configured
                # lock. Runtime contexts pass their exact generation-selected
                # lock below rather than falling back to the default file.
                from .settings import get_settings
                configured = Path(get_settings().tool_lock_path)
                # Historical stock developer installs did not need a local
                # lock file. Only that exact stock version without source-build
                # metadata retains this compatibility; modified builds refuse.
                if not (expected == "2.1.0" and declared is None
                        and not configured.exists() and not configured.is_symlink()):
                    locked_tool = load_tool_lock(configured).value.tool(tool_id)
            source_lock = locked_tool.binary.source_build if locked_tool is not None else None
            if source_lock is not None:
                from .source_build import verify_source_build_metadata
                proof = verify_source_build_metadata(
                    source_lock, binary_sha256=observed_digest,
                    binary_bytes=resolved_path.stat().st_size,
                )
                if declared != proof:
                    raise LockValidationError("installed source-build manifest differs")
                source_identity = (proof["recipe_sha256"], proof["receipt_sha256"])
            elif declared is not None or "+lomo." in expected:
                raise LockValidationError("source-build manifest is absent from the current tool lock")
        except (OSError, ValueError, KeyError, AttributeError):
            return {
                "id": tool_id, "available": False, "status": "unverified",
                "installed_version": installed,
            }
    if tool_id == "opengrep":
        runtime_components = manifest.get("runtime_components")
        core = (
            runtime_components.get("opengrep_core")
            if isinstance(runtime_components, dict)
            else None
        )
        core_path = core.get("path") if isinstance(core, dict) else None
        core_digest = core.get("sha256") if isinstance(core, dict) else None
        expected_core_path = OPENGREP_CORE_PATH.resolve(strict=False)
        if (
            not isinstance(core_path, str)
            or Path(core_path).resolve(strict=False) != expected_core_path
            or not isinstance(core_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", core_digest)
        ):
            return {
                "id": tool_id,
                "available": False,
                "status": "unverified",
                "installed_version": installed,
            }
        try:
            if OPENGREP_CORE_PATH.is_symlink() or not OPENGREP_CORE_PATH.is_file():
                raise FileNotFoundError(OPENGREP_CORE_PATH)
            if OPENGREP_CORE_PATH.stat().st_mode & 0o111 == 0:
                raise PermissionError(OPENGREP_CORE_PATH)
            observed_core_digest = observed_binary_sha256(expected_core_path)
        except OSError:
            return {
                "id": tool_id,
                "available": False,
                "status": "missing",
                "installed_version": installed,
            }
        try:
            executable_target = OPENGREP_EXECUTABLE_PATH.resolve(strict=True)
        except OSError:
            return {
                "id": tool_id,
                "available": False,
                "status": "missing",
                "installed_version": installed,
            }
        if (
            not OPENGREP_EXECUTABLE_PATH.is_symlink()
            or executable_target != expected_core_path
        ):
            return {
                "id": tool_id,
                "available": False,
                "status": "unverified",
                "installed_version": installed,
            }
        if observed_core_digest != core_digest:
            return {
                "id": tool_id,
                "available": False,
                "status": "binary_changed",
                "installed_version": installed,
            }
    return {
        "id": tool_id,
        "available": True,
        "status": "ready",
        "installed_version": installed,
        "runtime_identity": _runtime_identity(tool_id, observed_digest,
            *([observed_core_digest] if tool_id == "opengrep" else []), *source_identity),
    }


def _internal_readiness(tool_id: str) -> ToolReadiness:
    ready = ReadinessFacet(state="ready", reason=None, component_ids=[])
    not_required = ReadinessFacet(state="not_required", reason=None, component_ids=[])
    return ToolReadiness(
        tool_id=tool_id,
        binary=ready,
        data=not_required,
        rules=not_required,
        execution=ready,
        ready=True,
    )


def _invalid_external_readiness(tool_id: str) -> ToolReadiness:
    invalid = ReadinessFacet(
        state="invalid",
        reason="scanner locks or cache state failed strict validation",
        component_ids=[],
    )
    return ToolReadiness(
        tool_id=tool_id,
        binary=invalid,
        data=invalid,
        rules=invalid,
        execution=invalid,
        ready=False,
    )


def scanner_runtime_context(
    *,
    tool_lock_path: Path,
    rules_lock_path: Path,
    cache_root: Path,
    checkpoint: Callable[[], object] | None = None,
    resolver: Callable[..., ResolvedGeneration] | None = None,
    requested_tools: set[str] | None = None,
    verification_wait: Callable[[], object] | None = None,
) -> ScannerRuntimeContext:
    """Load one immutable runtime snapshot and derive all tool readiness.

    Lock, pointer, generation, binary, and rule validation failures are kept as
    explicit non-ready state.  Callers never retry part of the decision against
    a potentially different active pointer.
    """

    # Binary identity is part of the authorization decision, so retain the
    # complete observation rather than sampling only ``status`` here and then
    # asking callers to inspect the executable a second time.  This keeps
    # /tools and scan execution internally consistent even if a development
    # image is modified while a request is in flight.
    runtime_by_id: dict[str, dict[str, Any]] = {}
    checkpoint_error: BaseException | None = None

    def guarded_checkpoint() -> None:
        nonlocal checkpoint_error
        if checkpoint is None:
            return
        try:
            checkpoint()
        except BaseException as exc:
            checkpoint_error = exc
            raise

    try:
        loaded_tools = load_tool_lock(tool_lock_path)
        loaded_rules = load_rules_lock(rules_lock_path)
        validate_runtime_lock_contract(loaded_tools.value)
        resolved = (resolver or resolve_active_generation_cached)(
            cache_root,
            tool_lock_sha256=loaded_tools.sha256,
            rules_lock_sha256=loaded_rules.sha256,
            checkpoint=guarded_checkpoint if checkpoint is not None else None,
        )
        # A restarted scanner has to verify its read-only cache again. Only an
        # executing scan waits, under its existing cancellation/deadline; status
        # readers stay nonblocking. No binary or component is admitted until the
        # same active reference has reached a terminal verification state.
        needs_cache = verification_wait is not None and any(
            tool.id in (requested_tools or set())
            and any(requirement.required for requirement in tool.requirements)
            for tool in loaded_tools.value.tools
        )
        reference = resolved.pointer.active if needs_cache and resolved.pointer else None
        while needs_cache and resolved.state == "verifying":
            if checkpoint is None or reference is None:
                raise CacheValidationError("cache verification wait requires bounded ownership")
            guarded_checkpoint()
            verification_wait()
            guarded_checkpoint()
            resolved = (resolver or resolve_active_generation_cached)(
                cache_root,
                tool_lock_sha256=loaded_tools.sha256,
                rules_lock_sha256=loaded_rules.sha256,
                checkpoint=guarded_checkpoint,
            )
            if resolved.pointer is None or resolved.pointer.active != reference:
                raise CacheValidationError("active cache changed during scan verification")
        if resolved.generation is not None:
            loaded_tools, loaded_rules = generation_locks(resolved.generation,
                loaded_tools, loaded_rules, checkpoint=guarded_checkpoint if checkpoint is not None else None)
        # Observe each binary exactly once, after the generation selects its
        # immutable lock. Stock tool call signatures remain unchanged.
        runtime_by_id = {
            tool_id: (tool_runtime_state(tool_id, locked_tool=loaded_tools.value.tool(tool_id))
                      if tool_id == "bearer" and (
                          loaded_tools.value.tool(tool_id).binary.source_build is not None
                          or (isinstance(_verified_tool_manifest().get(tool_id), dict)
                              and "source_build" in _verified_tool_manifest()[tool_id])
                      ) else tool_runtime_state(tool_id))
            for tool_id in sorted(external_tool_ids())
        }
        binary_states = {
            tool_id: str(runtime.get("status") or "missing")
            for tool_id, runtime in runtime_by_id.items()
        }
        readiness = evaluate_tool_readiness(
            loaded_tools,
            loaded_rules,
            resolved,
            binary_states,
        )
        if resolved.state == "fallback":
            degraded: list[ToolReadiness] = []
            for item in readiness:
                data_facet = ReadinessFacet(
                    state="invalid",
                    reason="active cache generation is invalid; previous-good is not execution-ready",
                    component_ids=item.data.component_ids,
                )
                rules_facet = ReadinessFacet(
                    state="invalid",
                    reason="active cache generation is invalid; previous-good is not execution-ready",
                    component_ids=item.rules.component_ids,
                )
                degraded.append(
                    item.model_copy(
                        update={"data": data_facet, "rules": rules_facet, "ready": False}
                    )
                )
            readiness = degraded
        return ScannerRuntimeContext(
            tools=loaded_tools,
            rules=loaded_rules,
            resolved=resolved,
            runtime_by_id=runtime_by_id,
            readiness_by_id={item.tool_id: item for item in readiness},
        )
    except (CacheValidationError, LockValidationError, OSError, ValueError):
        if checkpoint_error is not None:
            raise checkpoint_error
        if not runtime_by_id:
            runtime_by_id = {
                tool_id: tool_runtime_state(tool_id) for tool_id in sorted(external_tool_ids())
            }
        return ScannerRuntimeContext(
            tools=None,
            rules=None,
            resolved=None,
            runtime_by_id=runtime_by_id,
            readiness_by_id={
                tool_id: _invalid_external_readiness(tool_id)
                for tool_id in sorted(external_tool_ids())
            },
        )


def scanner_runtime_readiness(
    *,
    tool_lock_path: Path,
    rules_lock_path: Path,
    cache_root: Path,
) -> tuple[dict[str, ToolReadiness], str | None]:
    context = scanner_runtime_context(
        tool_lock_path=tool_lock_path,
        rules_lock_path=rules_lock_path,
        cache_root=cache_root,
    )
    return dict(context.readiness_by_id), context.generation_id


def scanner_tools_snapshot_with_runtime(
    *,
    tool_lock_path: Path | None = None,
    rules_lock_path: Path | None = None,
    cache_root: Path | None = None,
    resolver: Callable[..., ResolvedGeneration] | None = None,
) -> ScannerToolsSnapshot:
    readiness_by_id: dict[str, ToolReadiness] = {}
    runtime_by_id: Mapping[str, Mapping[str, Any]] | None = None
    active_generation: str | None = None
    verification: CacheVerification | None = None
    if tool_lock_path is not None and rules_lock_path is not None and cache_root is not None:
        context = scanner_runtime_context(
            tool_lock_path=tool_lock_path,
            rules_lock_path=rules_lock_path,
            cache_root=cache_root,
            resolver=resolver,
        )
        readiness_by_id = dict(context.readiness_by_id)
        runtime_by_id = context.runtime_by_id
        active_generation = context.generation_id
        verification = context.resolved.verification if context.resolved is not None else None
    result: list[dict[str, Any]] = []
    for item in SCANNER_TOOLS:
        runtime = (
            tool_runtime_state(item["id"])
            if item.get("source") == "internal" or runtime_by_id is None
            else dict(
                runtime_by_id.get(
                    item["id"],
                    {
                        "id": item["id"],
                        "available": False,
                        "status": "unverified",
                        "installed_version": None,
                    },
                )
            )
        )
        readiness = (
            _internal_readiness(item["id"])
            if item.get("source") == "internal"
            else readiness_by_id.get(item["id"], _invalid_external_readiness(item["id"]))
        )
        result.append(
            {
                **item,
                **runtime,
                "readiness": {
                    "binary": readiness.binary.model_dump(mode="json"),
                    "data": readiness.data.model_dump(mode="json"),
                    "rules": readiness.rules.model_dump(mode="json"),
                    "execution": readiness.execution.model_dump(mode="json"),
                },
                "runtime_ready": readiness.ready,
            }
        )
    return ScannerToolsSnapshot(tools=result, active_generation=active_generation, cache_verification=verification)
