from __future__ import annotations

from pathlib import Path, PurePosixPath
from urllib.parse import unquote

from fastapi import FastAPI
from starlette.exceptions import HTTPException
from starlette.responses import Response
from starlette.staticfiles import StaticFiles


_RESERVED_PREFIXES = {"v1", "healthz", "metrics", "docs", "redoc", "openapi.json"}


def _unsafe_request_path(path: str, scope: dict) -> bool:
    """Reject traversal before Starlette's mount routing can normalize it."""

    raw_path = scope.get("raw_path", b"")
    try:
        raw = bytes(raw_path).decode("ascii", errors="strict") if raw_path else path
    except (TypeError, UnicodeDecodeError):
        return True

    candidates = {path, raw}
    decoded = raw
    # Decode twice so a proxy or client performing one decode cannot turn a
    # previously harmless-looking segment into traversal after this check.
    try:
        for _ in range(2):
            decoded = unquote(decoded, errors="strict")
            candidates.add(decoded)
    except (UnicodeDecodeError, ValueError):
        return True
    return any(
        "\x00" in candidate
        or "\\" in candidate
        or ".." in candidate.split("/")
        for candidate in candidates
    )


class SinglePageApplication(StaticFiles):
    """Serve immutable build assets and safe client-side route fallbacks."""

    async def get_response(self, path: str, scope: dict) -> Response:
        if _unsafe_request_path(path, scope):
            return Response(status_code=404)
        normalized = PurePosixPath("/" + path.lstrip("/"))
        first = normalized.parts[1] if len(normalized.parts) > 1 else ""
        if first in _RESERVED_PREFIXES:
            return Response(status_code=404)

        try:
            response = await super().get_response(path, scope)
        except HTTPException as exc:
            if exc.status_code != 404:
                raise
            response = Response(status_code=404)
        if response.status_code == 404 and first != "assets" and "." not in normalized.name:
            response = await super().get_response("index.html", scope)

        if response.status_code < 400:
            if normalized.name == "index.html" or "." not in normalized.name:
                response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            elif first == "assets":
                response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            response.headers["X-Content-Type-Options"] = "nosniff"
        return response


def mount_static_application(app: FastAPI, directory: str | Path | None) -> None:
    if not directory:
        return
    static_root = Path(directory).resolve()
    index = static_root / "index.html"
    if not static_root.is_dir() or not index.is_file():
        raise RuntimeError(f"production web build is missing at {static_root}")
    app.mount("/", SinglePageApplication(directory=static_root, html=True), name="web")
