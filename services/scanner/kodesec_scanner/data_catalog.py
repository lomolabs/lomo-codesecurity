"""Signed data admission, independent of immutable scanner executable pins.

Catalogs are retained by their effective lock pair. Active/previous generations
therefore never acquire the identities of a newer selected catalog.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
import hashlib
import os
from pathlib import Path
import re
import stat
import threading
import time
from typing import Callable, Literal
from urllib.parse import urlsplit
import urllib.request

from pydantic import Field, ValidationError, model_validator

from .cache_manifest import (
    CacheValidationError, LoadedDocument, RulesLockFile, ToolLockFile,
    GenerationManifest, ValidatedGeneration, _StrictModel, _atomic_write_json, _decode_json_object, _parse_utc,
    _read_bounded_regular_file, _secure_directory, canonical_json_bytes,
    validate_lock_alignment, load_active_pointer,
)
from .release_signature import CosignTrust, SignatureVerificationError, verify_blob

MAX_CATALOG_BYTES = 4 * 1024 * 1024
MAX_CATALOG_BUNDLE_BYTES = 2 * 1024 * 1024
MAX_CATALOGS = 4
TRUST_FILENAME = "scanner-data-trust.json"


class DataCatalogError(CacheValidationError):
    def __init__(self, code: str):
        if code not in {"trust", "signature", "schema", "compatibility", "expired", "rollback", "selection", "storage", "transport"}:
            raise ValueError("unrecognized scanner data catalog failure")
        self.code = code
        super().__init__(f"scanner data catalog admission failed: {code}")


class DataCatalogTrust(_StrictModel):
    schema_version: Literal[1]
    catalog_url: str = Field(max_length=2048)
    bundle_url: str = Field(max_length=2048)
    cosign_path: str = Field(max_length=1024)
    cosign_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trusted_root_path: str = Field(max_length=1024)
    trusted_root_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    certificate_identity: str = Field(max_length=2048)
    oidc_issuer: str = Field(max_length=2048)

    @model_validator(mode="after")
    def validate_fixed_transport(self) -> "DataCatalogTrust":
        for value in (self.catalog_url, self.bundle_url):
            parsed = urlsplit(value)
            if (parsed.scheme != "https" or parsed.netloc != "raw.githubusercontent.com"
                    or parsed.query or parsed.fragment or "%" in parsed.path
                    or re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+", parsed.path) is None
                    or any(part in {"", ".", ".."} for part in parsed.path.split("/")[1:])):
                raise ValueError("catalog transport must be one exact reviewed GitHub raw URL")
        if self.bundle_url != self.catalog_url + ".sigstore.json":
            raise ValueError("catalog signature bundle must be its exact configured companion")
        if not Path(self.cosign_path).is_absolute() or not Path(self.trusted_root_path).is_absolute():
            raise ValueError("catalog trust paths must be absolute")
        return self

    def signature_trust(self) -> CosignTrust:
        return CosignTrust(Path(self.cosign_path), self.cosign_sha256,
            Path(self.trusted_root_path), self.trusted_root_sha256,
            self.certificate_identity, self.oidc_issuer)


def binary_compatibility_sha256(tools: ToolLockFile, rules: RulesLockFile) -> str:
    """Separate data outputs from executable/adapter/fixture compatibility.

    A catalog cannot introduce scanner commands, fixtures, schemas, file roots,
    freshness policy, volatile-file exceptions, or a changed embedded rule set.
    """
    tool_contracts = []
    for tool in tools.tools:
        requirements = []
        for requirement in tool.requirements:
            contract = None if requirement.data_contract is None else requirement.data_contract.model_dump(mode="json")
            if contract is not None:
                for name in ("built_at", "publisher_updated_at", "publisher_refresh_due_at"):
                    contract.pop(name, None)
            requirements.append({
                "id": requirement.id, "kind": requirement.kind, "required": requirement.required,
                "cache_subpath": requirement.cache_subpath, "source_kind": requirement.source.kind,
                "discovery_ref": requirement.source.discovery_ref, "data_contract": contract,
                "max_age_seconds": requirement.max_age_seconds,
                "installed_algorithm": requirement.installed_content.hash_algorithm if requirement.installed_content else None,
                "volatile_paths": requirement.installed_content.volatile_paths if requirement.installed_content else [],
                "fixtures": [{key: value for key, value in canary.model_dump(mode="json").items()
                              if key.startswith("fixture") or key == "id"} for canary in requirement.canaries],
            })
        tool_contracts.append({"id": tool.id, "version": tool.version,
            "binary": tool.binary.model_dump(mode="json"), "adapter": tool.adapter.model_dump(mode="json"),
            "requirements": requirements})
    rule_contracts = []
    for rule in rules.rule_sets:
        if rule.distribution_mode == "embedded":
            rule_contracts.append(rule.model_dump(mode="json"))
        else:
            rule_contracts.append({"id": rule.id, "tool_id": rule.tool_id,
                "engine_version": rule.engine_version, "distribution_mode": rule.distribution_mode,
                "source_repository": rule.source_repository,
                "fixtures": [{key: value for key, value in canary.model_dump(mode="json").items()
                              if key.startswith("fixture") or key == "id"} for canary in rule.canaries]})
    return hashlib.sha256(canonical_json_bytes({"contract": "kodesec-scanner-data-compatibility/v1",
        "tools": tool_contracts, "rules": rule_contracts})).hexdigest()


class DataCatalog(_StrictModel):
    schema_version: Literal[1]
    sequence: int = Field(ge=1, le=2**53 - 1)
    issued_at: str
    expires_at: str
    binary_compatibility_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tools: ToolLockFile
    rules: RulesLockFile

    @model_validator(mode="after")
    def validate_catalog(self) -> "DataCatalog":
        issued = _parse_utc(self.issued_at, "catalog issued_at")
        expires = _parse_utc(self.expires_at, "catalog expires_at")
        if not issued < expires <= issued + timedelta(days=7):
            raise ValueError("catalog validity must be positive and at most seven days")
        validate_lock_alignment(self.tools, self.rules)
        if binary_compatibility_sha256(self.tools, self.rules) != self.binary_compatibility_sha256:
            raise ValueError("catalog binary compatibility identity differs")
        return self


@dataclass(frozen=True)
class VerifiedDataCatalog:
    catalog: DataCatalog
    digest: str
    tools: LoadedDocument[ToolLockFile]
    rules: LoadedDocument[RulesLockFile]


_PROOFS: OrderedDict[tuple[object, ...], VerifiedDataCatalog] = OrderedDict()
_PROOF_LOCK = threading.Lock()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


class DataCatalogStore:
    def __init__(self, cache_root: Path, tools: LoadedDocument[ToolLockFile],
                 rules: LoadedDocument[RulesLockFile], *, trust_path: Path | None = None):
        self.cache_root, self.tools, self.rules = cache_root, tools, rules
        self.trust_path = trust_path or tools.path.parent / TRUST_FILENAME

    def _trust(self) -> tuple[DataCatalogTrust, bytes]:
        try:
            raw = _read_bounded_regular_file(self.trust_path, 16 * 1024, "scanner data trust")
            trust = DataCatalogTrust.model_validate(_decode_json_object(raw, "scanner data trust"))
            for path in (self.trust_path, Path(trust.cosign_path), Path(trust.trusted_root_path)):
                real = path.resolve(strict=True)
                if real.is_relative_to(self.cache_root.resolve()):
                    raise DataCatalogError("trust")
            return trust, raw
        except (OSError, ValueError, CacheValidationError) as exc:
            raise DataCatalogError("trust") from exc

    def _verify(self, artifact: Path, bundle: Path, *, checkpoint: Callable[[], object] | None = None) -> VerifiedDataCatalog:
        trust, trust_raw = self._trust()
        try:
            raw = _read_bounded_regular_file(artifact, MAX_CATALOG_BYTES, "scanner data catalog")
            bundle_raw = _read_bounded_regular_file(bundle, MAX_CATALOG_BUNDLE_BYTES, "scanner data signature")
            trust_files = tuple((str(path), path.stat().st_ino, path.stat().st_size,
                path.stat().st_mtime_ns, path.stat().st_ctime_ns)
                for path in (Path(trust.cosign_path), Path(trust.trusted_root_path)))
        except (OSError, CacheValidationError) as exc:
            raise DataCatalogError("storage") from exc
        compatibility = binary_compatibility_sha256(self.tools.value, self.rules.value)
        key = (hashlib.sha256(raw).hexdigest(), hashlib.sha256(bundle_raw).hexdigest(),
               hashlib.sha256(trust_raw).hexdigest(), trust_files, compatibility)
        if checkpoint is not None:
            checkpoint()
        with _PROOF_LOCK:
            cached = _PROOFS.get(key)
        if cached is not None:
            return cached
        try:
            proof = verify_blob(artifact, bundle, trust.signature_trust(), checkpoint=checkpoint)
        except SignatureVerificationError as exc:
            raise DataCatalogError("signature") from exc
        if proof.artifact != raw or proof.bundle_sha256 != key[1]:
            raise DataCatalogError("storage")
        try:
            catalog = DataCatalog.model_validate(_decode_json_object(proof.artifact, "scanner data catalog"))
        except (ValueError, ValidationError) as exc:
            raise DataCatalogError("schema") from exc
        if catalog.binary_compatibility_sha256 != compatibility:
            raise DataCatalogError("compatibility")
        tools_raw = canonical_json_bytes(catalog.tools.model_dump(mode="json"))
        rules_raw = canonical_json_bytes(catalog.rules.model_dump(mode="json"))
        verified = VerifiedDataCatalog(catalog, proof.sha256,
            LoadedDocument(catalog.tools, hashlib.sha256(tools_raw).hexdigest(), artifact),
            LoadedDocument(catalog.rules, hashlib.sha256(rules_raw).hexdigest(), artifact))
        with _PROOF_LOCK:
            _PROOFS[key] = verified
            _PROOFS.move_to_end(key)
            while len(_PROOFS) > 2:
                _PROOFS.popitem(last=False)
        return verified

    def _selection(self) -> dict[str, object]:
        try:
            raw = _read_bounded_regular_file(self.cache_root / "catalogs" / "selected.json", 1024, "selected data catalog")
            selected = _decode_json_object(raw, "selected data catalog")
            if (not isinstance(selected, dict) or set(selected) != {"digest", "tools_sha256", "rules_sha256", "sequence"}
                or any(not isinstance(selected[name], str) or re.fullmatch(r"[0-9a-f]{64}", selected[name]) is None
                       for name in ("digest", "tools_sha256", "rules_sha256"))
                or type(selected["sequence"]) is not int or not 1 <= selected["sequence"] <= 2**53 - 1):
                raise DataCatalogError("selection")
            return selected
        except (OSError, ValueError, CacheValidationError) as exc:
            raise DataCatalogError("selection") from exc

    def for_locks(self, tools_sha256: str, rules_sha256: str,
                  *, checkpoint: Callable[[], object] | None = None) -> VerifiedDataCatalog:
        if any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in (tools_sha256, rules_sha256)):
            raise DataCatalogError("selection")
        directory = self.cache_root / "catalogs" / f"{tools_sha256}-{rules_sha256}"
        verified = self._verify(directory / "catalog.json", directory / "catalog.sigstore.json", checkpoint=checkpoint)
        if (verified.tools.sha256, verified.rules.sha256) != (tools_sha256, rules_sha256):
            raise DataCatalogError("selection")
        return replace(verified,
            tools=replace(verified.tools, path=directory / "catalog.json"),
            rules=replace(verified.rules, path=directory / "catalog.json"))

    def selected(self, expected_digest: str, *, now: datetime | None = None,
                 checkpoint: Callable[[], object] | None = None) -> VerifiedDataCatalog:
        selected = self._selection()
        if selected["digest"] != expected_digest:
            raise DataCatalogError("selection")
        verified = self.for_locks(str(selected["tools_sha256"]), str(selected["rules_sha256"]), checkpoint=checkpoint)
        if verified.digest != expected_digest or verified.catalog.sequence != selected["sequence"]:
            raise DataCatalogError("selection")
        self._fresh(verified, now)
        return verified

    @staticmethod
    def _fresh(verified: VerifiedDataCatalog, now: datetime | None) -> None:
        moment = now or datetime.now(UTC)
        if not _parse_utc(verified.catalog.issued_at, "issued_at") <= moment < _parse_utc(verified.catalog.expires_at, "expires_at"):
            raise DataCatalogError("expired")

    def _prune(self, root: Path) -> None:
        protected: set[str] = set()
        if (root / "selected.json").exists() or (root / "selected.json").is_symlink():
            selected = self._selection()
            protected.add(f"{selected['tools_sha256']}-{selected['rules_sha256']}")
        pointer_path = self.cache_root / "active.json"
        if pointer_path.exists() or pointer_path.is_symlink():
            pointer = load_active_pointer(self.cache_root)
            for reference in (pointer.active, pointer.previous_good):
                if reference is None:
                    continue
                raw = _read_bounded_regular_file(self.cache_root / "generations" / reference.generation_id / "manifest.json",
                    4 * 1024 * 1024, "referenced scanner generation")
                if hashlib.sha256(raw).hexdigest() != reference.manifest_sha256:
                    raise DataCatalogError("storage")
                try:
                    manifest = GenerationManifest.model_validate_json(raw)
                except ValueError as exc:
                    raise DataCatalogError("storage") from exc
                protected.add(f"{manifest.tool_lock_sha256}-{manifest.rules_lock_sha256}")
        entries = list(root.iterdir())
        if len(entries) > MAX_CATALOGS + 2:
            raise DataCatalogError("storage")
        for entry in entries:
            temporary = re.fullmatch(r"check-[a-z0-9_]{8}", entry.name) is not None
            if (not temporary and re.fullmatch(r"[0-9a-f]{64}-[0-9a-f]{64}", entry.name) is None) or entry.name in protected:
                continue
            _secure_directory(entry, "retained catalog")
            metadata = entry.lstat()
            if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
                raise DataCatalogError("storage")
            children = list(entry.iterdir())
            names = {child.name for child in children}
            allowed = {"catalog.json", "catalog.sigstore.json"}
            if (not names <= allowed) or (not temporary and names != allowed):
                raise DataCatalogError("storage")
            for child, limit in ((entry / "catalog.json", MAX_CATALOG_BYTES), (entry / "catalog.sigstore.json", MAX_CATALOG_BUNDLE_BYTES)):
                if child.name not in names:
                    continue
                child_metadata = child.lstat()
                if child_metadata.st_uid != os.getuid() or child_metadata.st_nlink != 1:
                    raise DataCatalogError("storage")
                _read_bounded_regular_file(child, limit, "retained catalog input")
            for child in children:
                child.unlink()
            entry.rmdir()

    def check(self, *, checkpoint: Callable[[], object], now: datetime | None = None) -> VerifiedDataCatalog:
        """Fetch only the configured channel; failure never changes selection/cache."""
        trust, _raw = self._trust()
        import tempfile
        root = _secure_directory(self.cache_root / "catalogs", "catalog store", create=True)
        self._prune(root)
        with tempfile.TemporaryDirectory(prefix="check-", dir=root) as temporary:
            directory = Path(temporary)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
            for url, name, limit in ((trust.catalog_url, "catalog.json", MAX_CATALOG_BYTES),
                    (trust.bundle_url, "catalog.sigstore.json", MAX_CATALOG_BUNDLE_BYTES)):
                checkpoint()
                try:
                    response = opener.open(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=15)
                except OSError as exc:
                    raise DataCatalogError("transport") from exc
                with response:
                    if response.geturl() != url or response.status != 200:
                        raise DataCatalogError("transport")
                    content = bytearray()
                    deadline = time.monotonic() + 30
                    while True:
                        checkpoint()
                        if time.monotonic() >= deadline:
                            raise DataCatalogError("transport")
                        try:
                            chunk = response.read1(min(64 * 1024, limit + 1 - len(content)))
                        except OSError as exc:
                            raise DataCatalogError("transport") from exc
                        content.extend(chunk)
                        if len(content) > limit:
                            raise DataCatalogError("transport")
                        if not chunk:
                            break
                if not content:
                    raise DataCatalogError("transport")
                (directory / name).write_bytes(content)
                (directory / name).chmod(0o600)
                checkpoint()
            verified = self._verify(directory / "catalog.json", directory / "catalog.sigstore.json", checkpoint=checkpoint)
            self._fresh(verified, now)
            selection_path = root / "selected.json"
            if selection_path.exists() or selection_path.is_symlink():
                prior = self._selection()
                if verified.catalog.sequence < prior["sequence"] or (verified.catalog.sequence == prior["sequence"] and verified.digest != prior["digest"]):
                    raise DataCatalogError("rollback")
            target = root / f"{verified.tools.sha256}-{verified.rules.sha256}"
            if target.exists() or target.is_symlink():
                prior = self.for_locks(verified.tools.sha256, verified.rules.sha256, checkpoint=checkpoint)
                if prior.digest != verified.digest:
                    # One effective pair has one immutable signed authority.
                    # Metadata-only re-signing cannot refresh unchanged data.
                    raise DataCatalogError("rollback")
            else:
                # Refuse unbounded retained metadata; never delete a generation's
                # authority as a side effect of checking a channel.
                if sum(1 for item in root.iterdir() if re.fullmatch(r"[0-9a-f]{64}-[0-9a-f]{64}", item.name)) >= MAX_CATALOGS:
                    raise DataCatalogError("storage")
                for name in ("catalog.json", "catalog.sigstore.json"):
                    (directory / name).chmod(0o400)
                    with (directory / name).open("rb") as stream:
                        os.fsync(stream.fileno())
                descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.rename(directory, target)
            checkpoint()
            _atomic_write_json(root, "selected.json", {"digest": verified.digest,
                "tools_sha256": verified.tools.sha256, "rules_sha256": verified.rules.sha256,
                "sequence": verified.catalog.sequence}, 1024)
            return replace(verified,
                tools=replace(verified.tools, path=target / "catalog.json"),
                rules=replace(verified.rules, path=target / "catalog.json"))


def generation_locks(generation: ValidatedGeneration, tools: LoadedDocument[ToolLockFile],
                     rules: LoadedDocument[RulesLockFile], *,
                     checkpoint: Callable[[], object] | None = None) -> tuple[LoadedDocument[ToolLockFile], LoadedDocument[RulesLockFile]]:
    """Resolve the generation's own authority, never the selected/latest catalog.

    Catalog expiry limits *new admission*. Active data keeps its own existing
    intrinsic freshness/canary/content checks, without requiring channel access.
    """
    manifest = generation.manifest
    if (manifest.tool_lock_sha256, manifest.rules_lock_sha256) == (tools.sha256, rules.sha256):
        return tools, rules
    store = DataCatalogStore(generation.path.parent.parent, tools, rules)
    verified = store.for_locks(manifest.tool_lock_sha256, manifest.rules_lock_sha256, checkpoint=checkpoint)
    return verified.tools, verified.rules
