from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import base64
import hashlib
import hmac
import math
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import threading
import time
from typing import Any, AsyncIterator, Mapping
import unicodedata
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request
import httpx

from kodesec_api.advisor.providers import (
    MODEL_DIGEST,
    disclosure_destination,
    exact_host_set,
    normalize_profile,
    provider_test_failure,
)
from kodesec_api.advisor.disclosure import normalize_confirmation
from kodesec_api.advisor.grants import (
    verify_cancellation_grant,
    verify_execution_grant,
    LOCAL_CANCELLATION_SCHEMA,
    verify_local_operation_grant,
    verify_local_cancellation_grant,
    verify_local_observation_grant,
)


REQUEST_MAX_BYTES = 96 * 1024
TAGS_MAX_BYTES = 64 * 1024
GENERATE_MAX_BYTES = 32 * 1024
AUTH_MAX_BYTES = 16 * 1024
SSH_START_SECONDS = 8.0
SSH_STOP_SECONDS = 2.0
GENERATE_SECONDS = 90.0
SAFE_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}=?\Z")
AUTHORIZED_KEYS_POLICY = 'restrict,port-forwarding,permitopen="127.0.0.1:11434"'
AUTH_DIR = Path(os.environ.get("KODESEC_ADVISOR_AUTH_DIR", "/run/kodesec-advisor-auth"))
LOCAL_URL = os.environ.get("KODESEC_ADVISOR_LOCAL_URL", "http://host.docker.internal:11434")
DIRECT_HOSTS = exact_host_set(
    os.environ.get("KODESEC_ADVISOR_DIRECT_HOSTS", "").split(",")
)
GRANT_SECRET = os.environ.get("KODESEC_ADVISOR_GRANT_SECRET", "")
PROFILE_KEYS = frozenset(
    {
        "id",
        "name",
        "transport",
        "priority",
        "enabled",
        "base_url",
        "model",
        "model_digest",
        "ssh_host",
        "ssh_port",
        "ssh_user",
        "status",
        "reason",
        "last_activity_at",
        "content_disclosure_approved",
        "config_revision",
        "config_digest",
        "reason_code",
        "remediation",
    }
)
_GENERATION_SLOTS = threading.BoundedSemaphore(value=1)
_USED_GRANTS: dict[str, int] = {}
_USED_GRANTS_LOCK = threading.Lock()


class _ConnectorOperation:
    __slots__ = (
        "operation_id",
        "grant_signature",
        "expires_at",
        "binding",
        "cancel_requested",
        "completed",
        "status",
        "cleanup",
        "owned_generation_active",
    )

    def __init__(
        self,
        *,
        operation_id: str,
        grant_signature: str,
        expires_at: int,
        binding: dict[str, Any],
        cancel_requested: asyncio.Event,
        completed: asyncio.Event,
    ) -> None:
        self.operation_id = operation_id
        self.grant_signature = grant_signature
        self.expires_at = expires_at
        self.binding = binding
        self.cancel_requested = cancel_requested
        self.completed = completed
        self.status = "admitted"
        self.cleanup = "pending"
        self.owned_generation_active = False


_OPERATIONS: dict[str, _ConnectorOperation] = {}
_OPERATIONS_LOCK = threading.Lock()
_REGISTRY_INSTANCE = os.urandom(16).hex()
_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["true_positive", "false_positive", "needs_review"],
        },
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "reasoning": {"type": "string", "maxLength": 4000},
        "fix": {"type": "string", "maxLength": 4000},
    },
    "required": ["verdict", "confidence", "reasoning", "fix"],
    "additionalProperties": False,
}
_GENERATE_RESPONSE_KEYS = frozenset(
    {
        "model",
        "created_at",
        "response",
        "thinking",
        "done",
        "done_reason",
        "context",
        "total_duration",
        "load_duration",
        "prompt_eval_count",
        "prompt_eval_cached_count",
        "prompt_eval_duration",
        "eval_count",
        "eval_duration",
    }
)
_ADVISOR_RESULT_KEYS = frozenset({"verdict", "confidence", "reasoning", "fix"})
_ADVISOR_VERDICTS = frozenset({"true_positive", "false_positive", "needs_review"})


def _test_failure(code: str, *, status_code: int) -> HTTPException:
    message, _retryable = provider_test_failure(code)
    return HTTPException(
        status_code,
        detail={"code": code, "message": message},
    )


def _generation_slot() -> Iterator[None]:
    if not _GENERATION_SLOTS.acquire(blocking=False):
        raise HTTPException(429, "Advisor connector generation capacity is busy")
    try:
        yield
    finally:
        _GENERATION_SLOTS.release()


def _strict_object(raw: bytes, *, keys: frozenset[str]) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("request contains a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(422, "request must be one strict UTF-8 JSON object") from exc
    if not isinstance(value, dict) or set(value) != keys:
        raise HTTPException(422, "request fields do not match the connector contract")
    return value


async def _bounded_request(request: Request, *, keys: frozenset[str]) -> dict[str, Any]:
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            size = int(declared)
        except ValueError as exc:
            raise HTTPException(413, "invalid request length") from exc
        if size < 0 or size > REQUEST_MAX_BYTES:
            raise HTTPException(413, "connector request exceeds the bounded size")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > REQUEST_MAX_BYTES:
            raise HTTPException(413, "connector request exceeds the bounded size")
    return _strict_object(bytes(body), keys=keys)


async def _bounded_json_response(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    maximum: int,
    total_seconds: float,
    json_body: Mapping[str, Any] | None = None,
    provider_transport: str | None = None,
    request_trace: Any = None,
) -> dict[str, Any]:
    try:
        async with asyncio.timeout(total_seconds):
            extensions = {"trace": request_trace} if request_trace is not None else None
            async with client.stream(method, url, json=json_body, extensions=extensions) as response:
                if response.is_redirect:
                    raise ValueError("redirects are forbidden")
                response.raise_for_status()
                declared = response.headers.get("content-length")
                if declared is not None and int(declared) > maximum:
                    raise _test_failure(
                        "advisor_provider_tags_invalid" if provider_transport is not None
                        else "advisor_generation_response_too_large",
                        status_code=502,
                    )
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > maximum:
                        raise _test_failure(
                            "advisor_provider_tags_invalid" if provider_transport is not None
                            else "advisor_generation_response_too_large",
                            status_code=502,
                        )
    except (TimeoutError, httpx.TimeoutException) as exc:
        raise _test_failure("advisor_provider_timeout", status_code=504) from exc
    except httpx.HTTPStatusError as exc:
        raise _test_failure("advisor_provider_http_status", status_code=502) from exc
    except (httpx.NetworkError, OSError) as exc:
        if provider_transport is not None:
            code = (
                "advisor_provider_local_unavailable"
                if provider_transport == "local"
                else "advisor_provider_unreachable"
            )
            raise _test_failure(code, status_code=503) from exc
        raise _test_failure("advisor_provider_unreachable", status_code=502) from exc
    except ValueError as exc:
        if provider_transport is not None:
            raise _test_failure("advisor_provider_tags_invalid", status_code=502) from exc
        raise _test_failure("advisor_generation_response_invalid", status_code=502) from exc
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate response key")
            result[key] = value
        return result

    def nonfinite(_value: str) -> None:
        raise ValueError("non-finite response number")

    try:
        result = json.loads(
            bytes(body), object_pairs_hook=pairs, parse_constant=nonfinite
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        if provider_transport is not None:
            raise _test_failure("advisor_provider_tags_invalid", status_code=502) from exc
        raise _test_failure("advisor_generation_json_invalid", status_code=502) from exc
    if not isinstance(result, dict):
        if provider_transport is not None:
            raise _test_failure("advisor_provider_tags_invalid", status_code=502)
        raise _test_failure("advisor_generation_response_invalid", status_code=502)
    return result


def _safe_file(path: Path, *, maximum: int, private: bool = True) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise _test_failure(
            "advisor_provider_ssh_authorization_failed", status_code=409
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.getuid()
            or metadata.st_size > maximum
            or (private and stat.S_IMODE(metadata.st_mode) & 0o077)
        ):
            raise _test_failure(
                "advisor_provider_ssh_authorization_failed", status_code=409
            )
        result = bytearray()
        while len(result) <= maximum:
            chunk = os.read(descriptor, min(4096, maximum + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        if len(result) > maximum:
            raise _test_failure(
                "advisor_provider_ssh_authorization_failed", status_code=409
            )
        return bytes(result)
    finally:
        os.close(descriptor)


def _ssh_authorization(profile: Mapping[str, Any]) -> tuple[Path, Path]:
    provider_id = str(profile["id"])
    directory = AUTH_DIR / provider_id
    try:
        canonical_root = AUTH_DIR.resolve(strict=True)
        canonical = directory.resolve(strict=True)
        canonical.relative_to(canonical_root)
    except (OSError, ValueError) as exc:
        raise _test_failure(
            "advisor_provider_ssh_authorization_failed", status_code=409
        ) from exc
    raw = _safe_file(canonical / "authorization.json", maximum=AUTH_MAX_BYTES)
    try:
        metadata = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _test_failure(
            "advisor_provider_ssh_authorization_failed", status_code=409
        ) from exc
    expected = {
        "schema": "lomo-advisor-ssh-authorization/v1",
        "provider_id": provider_id,
        "host": profile["ssh_host"],
        "port": profile["ssh_port"],
        "user": profile["ssh_user"],
        "restricted_account_attested": True,
        "authorized_keys_policy": AUTHORIZED_KEYS_POLICY,
    }
    if not isinstance(metadata, dict) or any(metadata.get(key) != value for key, value in expected.items()):
        raise _test_failure(
            "advisor_provider_ssh_authorization_failed", status_code=409
        )
    fingerprint = metadata.get("host_key_fingerprint")
    if not isinstance(fingerprint, str) or SAFE_FINGERPRINT.fullmatch(fingerprint) is None:
        raise _test_failure(
            "advisor_provider_ssh_authorization_failed", status_code=409
        )
    identity = canonical / "id_ed25519"
    known_hosts = canonical / "known_hosts"
    _safe_file(identity, maximum=32 * 1024)
    known_hosts_payload = _safe_file(known_hosts, maximum=64 * 1024)
    try:
        entries = [
            line
            for line in known_hosts_payload.decode("utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        fields = entries[0].split() if len(entries) == 1 else []
        accepted_hosts = {
            str(profile["ssh_host"]),
            f"[{profile['ssh_host']}]:22",
        }
        if (
            len(fields) != 3
            or fields[0] not in accepted_hosts
            or fields[1] != "ssh-ed25519"
        ):
            raise ValueError
        key_bytes = base64.b64decode(fields[2], validate=True)
    except (UnicodeDecodeError, ValueError, IndexError) as exc:
        raise _test_failure(
            "advisor_provider_ssh_authorization_failed", status_code=409
        ) from exc
    observed = "SHA256:" + base64.b64encode(
        hashlib.sha256(key_bytes).digest()
    ).decode("ascii").rstrip("=")
    if observed != fingerprint.rstrip("="):
        raise _test_failure(
            "advisor_provider_ssh_authorization_failed", status_code=409
        )
    return identity, known_hosts


def _unused_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


@asynccontextmanager
async def _ssh_tunnel(profile: Mapping[str, Any]) -> AsyncIterator[str]:
    identity, known_hosts = _ssh_authorization(profile)
    local_port = _unused_loopback_port()
    argv = [
        "/usr/bin/ssh",
        "-F",
        "/dev/null",
        "-N",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "ForwardAgent=no",
        "-o",
        "RequestTTY=no",
        "-o",
        "ClearAllForwardings=no",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=1",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "HashKnownHosts=no",
        "-o",
        "CheckHostIP=yes",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "ProxyCommand=none",
        "-o",
        "ProxyJump=none",
        "-o",
        "RemoteCommand=none",
        "-o",
        f"HostName={profile['ssh_host']}",
        "-o",
        f"HostKeyAlias={profile['ssh_host']}",
        "-o",
        "CanonicalizeHostname=no",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "ControlPersist=no",
        "-o",
        "KnownHostsCommand=none",
        "-o",
        "UpdateHostKeys=no",
        "-o",
        "VerifyHostKeyDNS=no",
        "-i",
        str(identity),
        "-p",
        str(profile["ssh_port"]),
        "-L",
        f"127.0.0.1:{local_port}:127.0.0.1:11434",
        f"{profile['ssh_user']}@{profile['ssh_host']}",
    ]
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
        env={"HOME": "/tmp", "LANG": "C", "PATH": "/usr/bin:/bin", "SSH_AUTH_SOCK": ""},
    )
    base_url = f"http://127.0.0.1:{local_port}"
    deadline = time.monotonic() + SSH_START_SECONDS
    try:
        while time.monotonic() < deadline:
            if process.returncode is not None:
                raise _test_failure(
                    "advisor_provider_ssh_tunnel_failed", status_code=502
                )
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", local_port), timeout=0.2
                )
                del reader
                writer.close()
                await writer.wait_closed()
                break
            except (OSError, TimeoutError):
                await asyncio.sleep(0.1)
        else:
            raise _test_failure(
                "advisor_provider_ssh_tunnel_failed", status_code=504
            )
        yield base_url
    finally:
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(process.wait(), timeout=SSH_STOP_SECONDS)
            except TimeoutError:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.wait_for(process.wait(), timeout=SSH_STOP_SECONDS)
                except TimeoutError:
                    pass


def _dedicated_local_url() -> str:
    value = LOCAL_URL.rstrip("/")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or (parsed.hostname or "").lower()
        not in {"127.0.0.1", "localhost", "host.docker.internal"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port != 11434
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise _test_failure("advisor_provider_route_misconfigured", status_code=500)
    return value


@asynccontextmanager
async def _provider_url(profile: Mapping[str, Any]) -> AsyncIterator[str]:
    transport = profile["transport"]
    if transport == "local":
        yield _dedicated_local_url()
        return
    if transport == "direct":
        host = (urlsplit(str(profile["base_url"])).hostname or "").lower()
        if host not in DIRECT_HOSTS:
            raise _test_failure(
                "advisor_provider_direct_authorization_required", status_code=409
            )
        yield str(profile["base_url"])
        return
    async with _ssh_tunnel(profile) as tunnel:
        yield tunnel


def _models_from_tags(payload: Mapping[str, Any]) -> list[dict[str, str]]:
    raw_models = payload.get("models")
    if not isinstance(raw_models, list) or len(raw_models) > 200:
        raise _test_failure("advisor_provider_tags_invalid", status_code=502)
    models: list[dict[str, str]] = []
    for item in raw_models:
        if not isinstance(item, dict):
            raise _test_failure("advisor_provider_tags_invalid", status_code=502)
        name = item.get("name")
        digest = item.get("digest")
        if (
            isinstance(name, str)
            and 0 < len(name) <= 120
            and isinstance(digest, str)
            and MODEL_DIGEST.fullmatch(digest.lower()) is not None
        ):
            models.append({"name": name, "digest": digest.lower()})
        else:
            raise _test_failure("advisor_provider_tags_invalid", status_code=502)
    return models


def _local_catalog_from_tags(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Project Ollama's dedicated local catalog without accepting a target URL.

    Ollama marks cloud-only entries with remote-model metadata. Their small
    local catalog records are not model weights, so keep them visible without
    recommending or admitting them as a private local provider.
    """

    raw_models = payload.get("models")
    if not isinstance(raw_models, list) or len(raw_models) > 200:
        raise _test_failure("advisor_provider_tags_invalid", status_code=502)
    models: list[dict[str, Any]] = []
    names: set[str] = set()
    for item in raw_models:
        if not isinstance(item, dict):
            raise _test_failure("advisor_provider_tags_invalid", status_code=502)
        name = item.get("name")
        digest = item.get("digest")
        size = item.get("size")
        remote_model = item.get("remote_model")
        remote_host = item.get("remote_host")
        if (
            not isinstance(name, str)
            or not 0 < len(name) <= 120
            or any(unicodedata.category(character) in {"Cc", "Cf"} for character in name)
            or name in names
            or not isinstance(digest, str)
            or MODEL_DIGEST.fullmatch(digest.lower()) is None
            or isinstance(size, bool)
            or not isinstance(size, int)
            # The catalog crosses a JSON/TypeScript boundary. Keep numeric
            # evidence exactly representable by every supported client.
            or not 0 <= size <= 9_007_199_254_740_991
            or (
                remote_model is not None
                and (
                    not isinstance(remote_model, str)
                    or not 0 < len(remote_model) <= 120
                    or any(
                        unicodedata.category(character) in {"Cc", "Cf"}
                        for character in remote_model
                    )
                )
            )
            or (
                remote_host is not None
                and (
                    not isinstance(remote_host, str)
                    or not 0 < len(remote_host) <= 500
                    or any(
                        unicodedata.category(character) in {"Cc", "Cf"}
                        for character in remote_host
                    )
                )
            )
        ):
            raise _test_failure("advisor_provider_tags_invalid", status_code=502)
        cloud_stub = remote_model is not None or remote_host is not None
        if not cloud_stub and size == 0:
            raise _test_failure("advisor_provider_tags_invalid", status_code=502)
        names.add(name)
        models.append(
            {
                "name": name,
                "digest": digest.lower(),
                "size_bytes": size,
                "storage": "cloud_stub" if cloud_stub else "local_weights",
            }
        )
    models.sort(key=lambda item: (item["storage"] != "local_weights", item["name"]))
    local_names = {
        str(item["name"]) for item in models if item["storage"] == "local_weights"
    }
    recommended = (
        "qwen3:8b"
        if "qwen3:8b" in local_names
        else next(iter(sorted(local_names)), None)
    )
    return {
        "schema": "lomo-advisor-local-catalog/v1",
        "source": "dedicated_local_connector",
        "models": models,
        "recommended_model": recommended,
    }


async def _local_catalog() -> dict[str, Any]:
    timeout = httpx.Timeout(8.0, connect=3.0, read=8.0, write=3.0, pool=3.0)
    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=False, trust_env=False
    ) as client:
        tags = await _bounded_json_response(
            client,
            "GET",
            f"{_dedicated_local_url()}/api/tags",
            maximum=TAGS_MAX_BYTES,
            total_seconds=8.0,
            provider_transport="local",
        )
    return _local_catalog_from_tags(tags)


async def _test(profile: Mapping[str, Any]) -> dict[str, Any]:
    timeout = httpx.Timeout(8.0, connect=3.0, read=8.0, write=3.0, pool=3.0)
    async with _provider_url(profile) as base_url:
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=False, trust_env=False
        ) as client:
            tags = await _bounded_json_response(
                client,
                "GET",
                f"{base_url}/api/tags",
                maximum=TAGS_MAX_BYTES,
                total_seconds=8.0,
                provider_transport=str(profile["transport"]),
            )
    local = profile["transport"] == "local"
    models = (
        _local_catalog_from_tags(tags)["models"]
        if local
        else _models_from_tags(tags)
    )
    expected = {
        "name": str(profile["model"]),
        "digest": str(profile["model_digest"]),
    }
    matching_model = [item for item in models if item["name"] == expected["name"]]
    if not matching_model:
        raise _test_failure("advisor_provider_model_missing", status_code=409)
    if not any(item["digest"] == expected["digest"] for item in matching_model):
        raise _test_failure("advisor_provider_digest_mismatch", status_code=409)
    if local and matching_model[0]["storage"] != "local_weights":
        raise _test_failure("advisor_provider_local_weights_required", status_code=409)
    return {
        "schema": "lomo-advisor-provider-receipt/v1",
        "provider_id": profile["id"],
        "kind": profile["transport"],
        "route": profile["transport"],
        "model": profile["model"],
        "model_digest": profile["model_digest"],
        "status": "ready",
        "tested_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "revision": 1,
    }


def _validate_generate_request(value: object, profile: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "model", "prompt", "format", "stream", "think", "options"
    }:
        raise HTTPException(422, "Advisor generation request does not match the bounded contract")
    if value.get("model") != profile["model"] or value.get("stream") is not False:
        raise HTTPException(422, "Advisor generation must use the exact model with stream=false")
    prompt = value.get("prompt")
    if not isinstance(prompt, str) or not prompt or len(prompt.encode("utf-8")) > 64 * 1024:
        raise HTTPException(422, "Advisor prompt is empty or exceeds the bounded size")
    if value.get("format") != _OUTPUT_SCHEMA or len(
        json.dumps(value["format"], separators=(",", ":")).encode("utf-8")
    ) > 16 * 1024:
        raise HTTPException(422, "Advisor output schema does not match the exact bounded contract")
    options = value.get("options")
    if not isinstance(options, dict) or set(options) != {
        "temperature", "top_p", "num_predict", "num_ctx"
    }:
        raise HTTPException(422, "Advisor options do not match the bounded contract")
    if not isinstance(value.get("think"), bool):
        raise HTTPException(422, "Advisor think option must be boolean")
    temperature = options.get("temperature")
    top_p = options.get("top_p")
    num_predict = options.get("num_predict")
    num_ctx = options.get("num_ctx")
    if (
        isinstance(temperature, bool)
        or not isinstance(temperature, (int, float))
        or not math.isfinite(float(temperature))
        or not 0 <= float(temperature) <= 1
        or isinstance(top_p, bool)
        or not isinstance(top_p, (int, float))
        or not math.isfinite(float(top_p))
        or not 0 < float(top_p) <= 1
        or isinstance(num_predict, bool)
        or not isinstance(num_predict, int)
        or not 1 <= num_predict <= 2048
        or isinstance(num_ctx, bool)
        or not isinstance(num_ctx, int)
        or not 1024 <= num_ctx <= 32768
    ):
        raise HTTPException(422, "Advisor generation options exceed the exact bounded contract")
    return dict(value)


def _validate_generation_confirmation(
    profile: Mapping[str, Any],
    request_payload: Mapping[str, Any],
    value: object,
) -> dict[str, Any] | None:
    """Bind remote prompt bytes to one API-admitted disclosure confirmation."""

    if profile["transport"] == "local":
        if value is not None:
            raise HTTPException(422, "local Advisor generation does not accept remote confirmation")
        return None
    if not isinstance(value, dict):
        raise HTTPException(
            409,
            "Remote Advisor generation requires one exact disclosure confirmation",
        )
    try:
        confirmation = normalize_confirmation(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(409, "Remote Advisor disclosure confirmation is invalid") from exc
    expected = {
        "provider_id": profile["id"],
        "provider_config_revision": profile["config_revision"],
        "provider_config_digest": profile["config_digest"],
        "transport": profile["transport"],
        "destination": disclosure_destination(profile),
        "model": profile["model"],
        "model_digest": profile["model_digest"],
    }
    prompt = request_payload.get("prompt")
    prompt_digest = (
        hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        if isinstance(prompt, str)
        else ""
    )
    if any(confirmation.get(key) != expected_value for key, expected_value in expected.items()) or not hmac.compare_digest(
        str(confirmation.get("prompt_sha256") or ""), prompt_digest
    ):
        raise HTTPException(
            409,
            "Remote Advisor disclosure confirmation does not match the exact provider and prompt",
        )
    return confirmation


def _consume_execution_grant(
    profile: Mapping[str, Any],
    request_payload: Mapping[str, Any],
    confirmation: Mapping[str, Any] | None,
    value: object,
    *,
    consume: bool = True,
) -> dict[str, Any] | None:
    """Consume one signed worker capability before provider work."""

    local = profile["transport"] == "local"
    if not isinstance(value, dict) or (not local and confirmation is None):
        raise HTTPException(409, "Advisor execution requires a signed single-use grant")
    prompt = request_payload.get("prompt")
    if not isinstance(prompt, str):
        raise HTTPException(422, "Advisor generation prompt is invalid")
    try:
        grant = (
            verify_local_operation_grant(GRANT_SECRET, value, profile, prompt)
            if local else verify_execution_grant(
                GRANT_SECRET, value, profile, confirmation, prompt,
            )
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(409, "Advisor execution grant is invalid") from exc
    if consume:
        now = int(time.time())
        nonce = str(grant["nonce"])
        with _USED_GRANTS_LOCK:
            expired = [
                existing_nonce
                for existing_nonce, expires_at in _USED_GRANTS.items()
                if expires_at <= now
            ]
            for existing_nonce in expired:
                del _USED_GRANTS[existing_nonce]
            if nonce in _USED_GRANTS:
                raise HTTPException(409, "Remote Advisor execution grant was already used")
            _USED_GRANTS[nonce] = int(grant["expires_at"])
    return grant


def _operation_binding(grant: Mapping[str, Any]) -> dict[str, Any]:
    if grant["transport"] == "local":
        return {
            "purpose": "local",
            **{key: grant[key] for key in (
                "provider_id", "provider_config_revision", "provider_config_digest",
                "transport", "model", "model_digest", "prompt_sha256",
            )},
        }
    return {key: grant[key] for key in (
        "provider_id", "provider_config_revision", "provider_config_digest",
        "transport", "model_digest", "confirmation_digest",
    )}


def _admit_operation(grant: Mapping[str, Any]) -> _ConnectorOperation:
    operation_id = str(grant["nonce"])
    with _OPERATIONS_LOCK:
        expired = [
            existing_id
            for existing_id, operation in _OPERATIONS.items()
            if operation.expires_at <= int(time.time()) and operation.completed.is_set()
        ]
        for existing_id in expired:
            del _OPERATIONS[existing_id]
        if operation_id in _OPERATIONS:
            raise HTTPException(409, "Remote Advisor operation is already admitted")
        operation = _ConnectorOperation(
            operation_id=operation_id,
            grant_signature=str(grant["signature"]),
            expires_at=int(grant["expires_at"]),
            binding=_operation_binding(grant),
            cancel_requested=asyncio.Event(),
            completed=asyncio.Event(),
        )
        _OPERATIONS[operation_id] = operation
        return operation


def _start_operation(grant: Mapping[str, Any]) -> _ConnectorOperation:
    operation_id = str(grant["nonce"])
    with _OPERATIONS_LOCK:
        operation = _OPERATIONS.get(operation_id)
        if (
            operation is None
            or operation.grant_signature != grant.get("signature")
            or operation.status != "admitted"
        ):
            raise HTTPException(409, "Remote Advisor operation was not exactly admitted")
        operation.status = "running"
        return operation


def _finish_operation(operation: _ConnectorOperation, *, status: str) -> None:
    with _OPERATIONS_LOCK:
        operation.status = status
        operation.cleanup = "confirmed"
        operation.completed.set()


async def _cancel_operation(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise HTTPException(409, "Advisor cancellation requires a signed grant")
    try:
        grant = (
            verify_local_cancellation_grant(GRANT_SECRET, value)
            if value.get("schema") == LOCAL_CANCELLATION_SCHEMA
            else verify_cancellation_grant(GRANT_SECRET, value)
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(409, "Advisor cancellation grant is invalid") from exc
    operation_id = str(grant["operation_id"])
    expected = _operation_binding(grant)
    with _OPERATIONS_LOCK:
        operation = _OPERATIONS.get(operation_id)
        if operation is None and grant["transport"] == "local":
            # Retain cancellation in the same expiring registry before ACK.
            # Admission and this tombstone share the lock, so a delayed original
            # request cannot start after cancellation reports no active work.
            operation = _ConnectorOperation(
                operation_id=operation_id, grant_signature=str(grant["signature"]),
                expires_at=int(grant["expires_at"]), binding=expected,
                cancel_requested=asyncio.Event(), completed=asyncio.Event(),
            )
            operation.status = "cancelled"
            operation.cleanup = "confirmed"
            operation.completed.set()
            _OPERATIONS[operation_id] = operation
    if operation is None:
        # The only connector process owns every tunnel. An absent remote
        # operation never started here, or restart destroyed its namespace.
        return {
            "operation_id": operation_id,
            "status": "not_active",
            "cleanup": "confirmed",
        }
    with _OPERATIONS_LOCK:
        if operation.binding != expected:
            raise HTTPException(
                409, "Advisor cancellation does not match the admitted operation"
            )
        operation.cancel_requested.set()
        if operation.status == "admitted":
            # No provider request or tunnel exists yet, so cancellation is
            # already complete. Mark it terminal here rather than waiting for
            # a generation coroutine that will never be started.
            operation.status = "cancelled"
            operation.cleanup = "confirmed"
            operation.completed.set()
    try:
        async with asyncio.timeout(SSH_START_SECONDS + (SSH_STOP_SECONDS * 2) + 5):
            await operation.completed.wait()
    except TimeoutError as exc:
        raise HTTPException(503, "Advisor connector cleanup is still pending") from exc
    return {
        "operation_id": operation_id,
        "status": operation.status,
        "cleanup": operation.cleanup,
    }


async def _wait_for_disconnect(request: Request) -> None:
    while True:
        message = await request.receive()
        if message["type"] == "http.disconnect":
            return


def _observe_local_operation(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise HTTPException(409, "Local Advisor observation capability is invalid")
    try:
        grant = verify_local_observation_grant(GRANT_SECRET, value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(409, "Local Advisor observation capability is invalid") from exc
    with _OPERATIONS_LOCK:
        operation = _OPERATIONS.get(grant["operation_id"])
        if (operation is None or operation.expires_at <= int(time.time())
                or operation.binding != _operation_binding(grant)):
            # Absence (including connector restart) is never a cleanup ACK.
            raise HTTPException(409, "Local Advisor operation observation is unavailable")
        return {"operation_id": operation.operation_id, "registry_instance": _REGISTRY_INSTANCE,
                "status": operation.status, "owned_generation_active": operation.owned_generation_active,
                "cleanup": operation.cleanup}


def _local_generation_trace(operation: _ConnectorOperation):
    async def trace(event: str, _info: Mapping[str, Any]) -> None:
        # httpcore 1.0.9's HTTP/1.1 event proves only this request body's send.
        # No trace payload is retained; unknown events cannot prove activity.
        if event == "http11.send_request_body.complete":
            with _OPERATIONS_LOCK:
                operation.owned_generation_active = True
    return trace


@asynccontextmanager
async def _generation_client(timeout: httpx.Timeout, operation: _ConnectorOperation | None):
    client = httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False)
    await client.__aenter__()
    try:
        yield client
    finally:
        # A failed close cannot clear activity or establish positive cleanup.
        await client.__aexit__(None, None, None)
        if operation is not None:
            with _OPERATIONS_LOCK:
                operation.owned_generation_active = False


async def _generate_with_disconnect_cleanup(
    request: Request,
    profile: Mapping[str, Any],
    payload: Mapping[str, Any],
    cancel_requested: asyncio.Event | None = None,
    operation: _ConnectorOperation | None = None,
) -> dict[str, Any]:
    async def provider_work() -> dict[str, Any]:
        # Resolve and pin exactly one provider before any prompt bytes are sent.
        await _test(profile)
        timeout = httpx.Timeout(
            GENERATE_SECONDS,
            connect=5.0,
            read=GENERATE_SECONDS,
            write=10.0,
            pool=5.0,
        )
        async with _provider_url(profile) as base_url:
            async with _generation_client(timeout, operation) as client:
                response = await _bounded_json_response(
                    client,
                    "POST",
                    f"{base_url}/api/generate",
                    maximum=GENERATE_MAX_BYTES,
                    total_seconds=GENERATE_SECONDS,
                    json_body=payload,
                    request_trace=(_local_generation_trace(operation)
                                   if operation is not None and profile["transport"] == "local" else None),
                )
        text = _validate_model_response(response, profile)
        # Re-read the exact model identity after generation. Any drift discards
        # the output and never triggers a fallback, because bytes were sent.
        await _test(profile)
        return {"response": text, "done": True}

    generation = asyncio.create_task(provider_work())
    disconnect = asyncio.create_task(_wait_for_disconnect(request))
    cancellation = (
        asyncio.create_task(cancel_requested.wait())
        if cancel_requested is not None
        else None
    )
    try:
        waiters = {generation, disconnect}
        if cancellation is not None:
            waiters.add(cancellation)
        done, _pending = await asyncio.wait(
            waiters, return_when=asyncio.FIRST_COMPLETED
        )
        if generation in done:
            return await generation
        generation.cancel()
        try:
            await generation
        except asyncio.CancelledError:
            pass
        raise HTTPException(
            499,
            (
                "Advisor operation was cancelled; connector work and any SSH tunnel were stopped"
                if cancellation is not None and cancellation in done
                else "Advisor caller disconnected; connector work and any SSH tunnel were stopped"
            ),
        )
    finally:
        tasks = [generation, disconnect]
        if cancellation is not None:
            tasks.append(cancellation)
        for task in tasks:
            if not task.done():
                task.cancel()
        for task in tasks:
            try:
                await task
            except (asyncio.CancelledError, HTTPException):
                pass


def _validate_model_response(response: Mapping[str, Any], profile: Mapping[str, Any]) -> str:
    if not set(response).issubset(_GENERATE_RESPONSE_KEYS):
        raise _test_failure("advisor_generation_response_invalid", status_code=502)
    if "model" in response and response["model"] != profile["model"]:
        raise _test_failure("advisor_generation_model_mismatch", status_code=502)
    if response.get("done") is not True:
        raise _test_failure("advisor_generation_incomplete", status_code=502)
    text = response.get("response")
    if not isinstance(text, str) or not text or len(text.encode("utf-8")) > 16 * 1024:
        raise _test_failure("advisor_generation_text_invalid", status_code=502)
    for key in ("created_at", "done_reason"):
        item = response.get(key)
        if item is not None and (
            not isinstance(item, str)
            or len(item) > 100
            or any(ord(character) < 32 for character in item)
        ):
            raise _test_failure("advisor_generation_response_invalid", status_code=502)
    thinking = response.get("thinking")
    if thinking is not None and (
        not isinstance(thinking, str)
        or len(thinking.encode("utf-8")) > 16 * 1024
    ):
        raise _test_failure("advisor_generation_response_invalid", status_code=502)
    context = response.get("context")
    if context is not None and (
        not isinstance(context, list)
        or len(context) > 32768
        or any(
            isinstance(item, bool) or not isinstance(item, int) or item < 0
            for item in context
        )
    ):
        raise _test_failure("advisor_generation_response_invalid", status_code=502)
    for key in (
        "total_duration",
        "load_duration",
        "prompt_eval_count",
        "prompt_eval_cached_count",
        "prompt_eval_duration",
        "eval_count",
        "eval_duration",
    ):
        item = response.get(key)
        if item is not None and (
            isinstance(item, bool)
            or not isinstance(item, int)
            or not 0 <= item <= 2**63 - 1
        ):
            raise _test_failure("advisor_generation_response_invalid", status_code=502)

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate Advisor result key")
            result[key] = value
        return result

    try:
        projected = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite Advisor result")
            ),
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise _test_failure("advisor_generation_output_json_invalid", status_code=502) from exc
    if not isinstance(projected, dict) or set(projected) != _ADVISOR_RESULT_KEYS:
        raise _test_failure("advisor_generation_output_schema_invalid", status_code=502)
    confidence = projected.get("confidence")
    if (
        projected.get("verdict") not in _ADVISOR_VERDICTS
        or isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not math.isfinite(float(confidence))
        or not 0 <= float(confidence) <= 1
        or not isinstance(projected.get("reasoning"), str)
        or len(projected["reasoning"]) > 4000
        or not isinstance(projected.get("fix"), str)
        or len(projected["fix"]) > 4000
    ):
        raise _test_failure("advisor_generation_output_schema_invalid", status_code=502)
    return text


app = FastAPI(title="Lomo CodeSecurity Advisor Connector", docs_url=None, redoc_url=None)


@app.get("/healthz")
def healthz() -> dict[str, bool]:
    return {"ok": True}


@app.post("/v1/test")
async def test_provider(request: Request) -> dict[str, Any]:
    document = await _bounded_request(request, keys=frozenset({"provider"}))
    if not isinstance(document["provider"], dict) or set(document["provider"]) != PROFILE_KEYS:
        raise HTTPException(422, "Advisor provider fields do not match the connector contract")
    try:
        profile = normalize_profile(document["provider"])
    except (TypeError, ValueError) as exc:
        raise HTTPException(422, "Advisor provider profile is invalid") from exc
    # A same-device readiness check only reads Ollama's model catalog. Let it
    # remain truthful while the one bounded generation slot is occupied; it
    # neither sends finding content nor competes for model generation. Remote
    # tests retain the connector slot because their managed transport may own
    # a single forward or remote operation boundary.
    if profile["transport"] == "local":
        return {"receipt": await _test(profile)}
    slot = _generation_slot()
    next(slot)
    try:
        return {"receipt": await _test(profile)}
    finally:
        slot.close()


@app.post("/v1/local-models")
async def local_models(request: Request) -> dict[str, Any]:
    # The empty contract is deliberate: callers cannot supply a URL, host, or
    # discovery range. The connector checks only its product-managed local URL.
    await _bounded_request(request, keys=frozenset())
    return await _local_catalog()


@app.post("/v1/operations")
async def admit_operation(request: Request) -> dict[str, str]:
    document = await _bounded_request(
        request, keys=frozenset({"provider", "request", "confirmation", "grant"})
    )
    if not isinstance(document["provider"], dict) or set(document["provider"]) != PROFILE_KEYS:
        raise HTTPException(422, "Advisor provider fields do not match the connector contract")
    try:
        profile = normalize_profile(document["provider"])
    except (TypeError, ValueError) as exc:
        raise HTTPException(422, "Advisor provider profile is invalid") from exc
    payload = _validate_generate_request(document["request"], profile)
    confirmation = _validate_generation_confirmation(
        profile, payload, document["confirmation"]
    )
    grant = _consume_execution_grant(
        profile, payload, confirmation, document["grant"]
    )
    assert grant is not None
    operation = _admit_operation(grant)
    return {"operation_id": operation.operation_id, "status": operation.status}


@app.post("/v1/observe")
async def observe_local_operation(request: Request) -> dict[str, Any]:
    document = await _bounded_request(request, keys=frozenset({"observation_grant"}))
    return _observe_local_operation(document["observation_grant"])


@app.post("/v1/cancel")
async def cancel_operation(request: Request) -> dict[str, str]:
    document = await _bounded_request(
        request, keys=frozenset({"cancellation_grant"})
    )
    return await _cancel_operation(document["cancellation_grant"])


@app.post("/v1/generate", dependencies=[Depends(_generation_slot)])
async def generate(request: Request) -> dict[str, Any]:
    document = await _bounded_request(
        request, keys=frozenset({"provider", "request", "confirmation", "grant"})
    )
    if not isinstance(document["provider"], dict) or set(document["provider"]) != PROFILE_KEYS:
        raise HTTPException(422, "Advisor provider fields do not match the connector contract")
    try:
        profile = normalize_profile(document["provider"])
    except (TypeError, ValueError) as exc:
        raise HTTPException(422, "Advisor provider profile is invalid") from exc
    payload = _validate_generate_request(document["request"], profile)
    confirmation = _validate_generation_confirmation(
        profile, payload, document["confirmation"]
    )
    grant = _consume_execution_grant(
        profile,
        payload,
        confirmation,
        document["grant"],
        consume=False,
    )
    operation = _start_operation(grant)
    try:
        result = await _generate_with_disconnect_cleanup(
            request,
            profile,
            payload,
            operation.cancel_requested,
            operation,
        )
    except HTTPException as exc:
        _finish_operation(
            operation,
            status="cancelled" if exc.status_code == 499 else "failed",
        )
        raise
    except BaseException:
        if profile["transport"] == "local":
            # Unexpected client/task cleanup failures are not positive proof of
            # transport closure. Cancellation must remain unconfirmed.
            with _OPERATIONS_LOCK:
                operation.status = "failed"
        else:
            _finish_operation(operation, status="failed")
        raise
    _finish_operation(operation, status="completed")
    return result
