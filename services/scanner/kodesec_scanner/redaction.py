from __future__ import annotations

import re
from collections.abc import Iterator
from array import array
from typing import Any

from .models import Finding


REDACTED = "[REDACTED]"
_MAX_JSON_DEPTH = 64

_SENSITIVE_NAME = (
    r"(?:access[_-]?token|api[_-]?key|auth(?:orization|[_-]?token)|bearer[_-]?token|"
    r"client[_-]?secret|consumer[_-]?secret|credentials?|password|passwd|passphrase|"
    r"private[_-]?key|pwd|refresh[_-]?token|secret|session(?:[_-]?(?:id|key|token))?|"
    r"signature|token|x[_-]?amz[_-]?signature)"
)
_SENSITIVE_KEY = re.compile(
    rf"(?:{_SENSITIVE_NAME}|raw|value)",
    re.IGNORECASE,
)
_ASSIGNMENT_START = re.compile(
    r"(?P<prefix>(?P<key_quote>['\"]?)(?P<key>[A-Za-z][\w.-]*)(?P=key_quote)\s*(?::(?!//)|=)\s*)"
)
_ASSIGNMENT_TOKEN = re.compile(r"[A-Za-z][\w.-]*")
_CAMEL_ACRONYM_BOUNDARY = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")
_CAMEL_WORD_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")
_SENSITIVE_KEY_PARTS = frozenset(
    {
        "authorization",
        "credential",
        "credentials",
        "passwd",
        "passphrase",
        "password",
        "pwd",
        "secret",
        "signature",
        "token",
    }
)
_SENSITIVE_KEY_SEQUENCES = (
    ("access", "token"),
    ("api", "key"),
    ("auth", "token"),
    ("bearer", "token"),
    ("client", "secret"),
    ("consumer", "secret"),
    ("private", "key"),
    ("refresh", "token"),
    ("session", "id"),
    ("session", "key"),
    ("session", "token"),
    ("x", "amz", "signature"),
)
_SENSITIVE_COMPACT_SUFFIXES = (
    "accesstoken",
    "apikey",
    "authorization",
    "authtoken",
    "bearertoken",
    "clientsecret",
    "consumersecret",
    "credential",
    "credentials",
    "passphrase",
    "passwd",
    "password",
    "privatekey",
    "pwd",
    "refreshtoken",
    "secret",
    "sessionid",
    "sessionkey",
    "sessiontoken",
    "signature",
    "token",
    "xamzsignature",
)
_URL_SCHEME = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*")
_URL_USERINFO_SUFFIX = re.compile(r"[^/?#@\s]+@")
_URL_QUERY_CREDENTIAL = re.compile(
    rf"(?P<prefix>[?&]{_SENSITIVE_NAME}=)(?P<value>[^&#\s]*)",
    re.IGNORECASE,
)
_BEARER_CREDENTIAL = re.compile(
    rf"(?P<prefix>\bBearer\s+)(?P<value>(?!{re.escape(REDACTED)})[^\s,;]+)",
    re.IGNORECASE,
)
_KNOWN_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"(?:gh[pousr]_|github_pat_|glpat-|xox[baprs]-|sk_(?:live|test)_|rk_(?:live|test)_|"
    r"sk-(?:proj-)?|npm_|pypi-|ya29\.|AIza)[A-Za-z0-9._-]{6,}"
    r"|AKIA[A-Z0-9_]{12,}"
    r"|eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"
    r")(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_LONG_TOKEN = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z0-9+/=_-]{32,}(?![A-Za-z0-9_])")
_PEM_BEGIN = re.compile(r"-----BEGIN (?=[A-Z0-9 ]*(?:PRIVATE KEY|SECRET))[A-Z0-9 ]*+-----", re.IGNORECASE)
_PEM_END = re.compile(r"-----END (?=[A-Z0-9 ]*(?:PRIVATE KEY|SECRET))[A-Z0-9 ]*+-----", re.IGNORECASE)


def _url_userinfo_matches(content: str) -> Iterator[tuple[int, int, str]]:
    # Visit disjoint scheme candidates instead of retrying every dotted suffix.
    cursor = 0
    while scheme := _URL_SCHEME.search(content, cursor):
        cursor = scheme.end()
        if content[cursor:cursor + 3] != "://":
            continue
        userinfo = _URL_USERINFO_SUFFIX.match(content, cursor + 3)
        if userinfo is not None:
            yield scheme.start(), userinfo.end(), scheme.group() + "://"
            cursor = userinfo.end()


def _redact_url_userinfo(content: str) -> str:
    output: list[str] = []
    cursor = 0
    for start, end, scheme in _url_userinfo_matches(content):
        output.extend((content[cursor:start], scheme, REDACTED, "@"))
        cursor = end
    output.append(content[cursor:])
    return "".join(output)


def _assignment_value_end(content: str, start: int) -> int:
    index = start
    while index < len(content):
        if content[index] in ",&;#":
            separator = content[index]
            candidate = index + 1
            while candidate < len(content) and content[candidate].isspace():
                candidate += 1
            if _ASSIGNMENT_START.match(content, candidate):
                return index
            if separator == "#" and (
                (index > start and content[index - 1].isspace())
                or (index + 1 < len(content) and content[index + 1].isspace())
            ):
                return index
            if separator == ";" and candidate > index + 1:
                return index
            if separator == "&" and content[index:index + 2] == "&&":
                return index
        if content[index].isspace():
            whitespace_start = index
            candidate = index
            while candidate < len(content) and content[candidate].isspace():
                candidate += 1
            if _ASSIGNMENT_START.match(content, candidate):
                return whitespace_start
            index = candidate
            continue
        index += 1
    return len(content)


def _assignment_key_parts(key: str) -> tuple[str, ...]:
    separated = _CAMEL_ACRONYM_BOUNDARY.sub("_", key)
    separated = _CAMEL_WORD_BOUNDARY.sub(r"\1_\2", separated)
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", separated).strip("_").casefold()
    return tuple(part for part in normalized.split("_") if part)


def _is_sensitive_assignment_key(key: str) -> bool:
    parts = _assignment_key_parts(key)
    if not parts:
        return False
    if any(part in _SENSITIVE_KEY_PARTS for part in parts):
        return True
    if any(
        parts[index:index + len(sequence)] == sequence
        for sequence in _SENSITIVE_KEY_SEQUENCES
        for index in range(len(parts) - len(sequence) + 1)
    ):
        return True
    # Some environment formats omit separators entirely (for example,
    # ``DBPASSWORD``). Restrict that fallback to suffixes so ordinary words
    # such as ``tokenizer`` and ``passwordless`` retain useful evidence.
    compact = "".join(parts)
    return compact.endswith(_SENSITIVE_COMPACT_SUFFIXES)


def _next_sensitive_assignment(content: str, start: int) -> re.Match[str] | None:
    # Visit disjoint identifiers instead of retrying every suffix of a long word.
    for token in _ASSIGNMENT_TOKEN.finditer(content, start):
        begin = token.start()
        quoted = begin > start and content[begin - 1] in {"'", '"'}
        match = _ASSIGNMENT_START.match(content, begin - 1) if quoted else None
        match = match or _ASSIGNMENT_START.match(content, begin)
        if match and _is_sensitive_assignment_key(match.group("key")):
            return match
    return None


def _redact_assignments(content: str) -> str:
    output: list[str] = []
    cursor = 0
    while match := _next_sensitive_assignment(content, cursor):
        output.append(content[cursor:match.start()])
        output.append(match.group("prefix"))
        value_start = match.end()
        placeholder_end = value_start + len(REDACTED)
        if content.startswith(REDACTED, value_start) and (
            placeholder_end == len(content) or content[placeholder_end] in ",&;#"
        ):
            output.append(REDACTED)
            value_end = placeholder_end
        elif value_start < len(content) and content[value_start] in {'"', "'"}:
            quote = content[value_start]
            value_end = value_start + 1
            escaped = False
            while value_end < len(content):
                character = content[value_end]
                if character == quote and not escaped:
                    value_end += 1
                    break
                escaped = character == "\\" and not escaped
                if character != "\\":
                    escaped = False
                value_end += 1
            output.append(f"{quote}{REDACTED}{quote}" if content[value_end - 1:value_end] == quote else f"{quote}{REDACTED}")
        else:
            value_end = _assignment_value_end(content, value_start)
            value = content[value_start:value_end]
            output.append(f'{REDACTED}{value[len(value.rstrip()):]}')
        cursor = value_end
    output.append(content[cursor:])
    return "".join(output)


def _redact_credential_shapes(content: str) -> str:
    content = _redact_url_userinfo(content)
    content = _URL_QUERY_CREDENTIAL.sub(lambda match: f'{match.group("prefix")}{REDACTED}', content)
    content = _redact_assignments(content)
    content = _BEARER_CREDENTIAL.sub(lambda match: f'{match.group("prefix")}{REDACTED}', content)
    return _KNOWN_TOKEN.sub(REDACTED, content)


def _redact_line(content: str) -> str:
    return _LONG_TOKEN.sub(REDACTED, _redact_credential_shapes(content))


def private_key_body_boundaries(value: str) -> array[int]:
    """Index disjoint PEM bodies once, without retaining another source copy."""

    boundaries = array("I")
    cursor = 0
    while begin := _PEM_BEGIN.search(value, cursor):
        end = _PEM_END.search(value, begin.end())
        boundaries.extend((begin.end(), end.start() if end else len(value)))
        if end is None:
            break
        cursor = end.end()
    return boundaries


def _redact_pem_line(content: str, inside_pem: bool) -> tuple[str, bool]:
    """Consume disjoint key blocks without treating later bodies as safe suffixes."""

    output: list[str] = []
    cursor = 0
    if inside_pem and not content:
        return REDACTED, True
    while cursor < len(content):
        if inside_pem:
            end = _PEM_END.search(content, cursor)
            if end is None:
                output.append(REDACTED)
                break
            body = content[cursor:end.start()]
            output.extend((REDACTED if body.strip() else body, content[end.start():end.end()]))
            cursor = end.end()
            inside_pem = False
            continue
        begin = _PEM_BEGIN.search(content, cursor)
        if begin is None:
            output.append(_redact_line(content[cursor:]))
            break
        output.extend((_redact_line(content[cursor:begin.start()]), content[begin.start():begin.end()]))
        end = _PEM_END.search(content, begin.end())
        if end is None:
            output.append(REDACTED if content[begin.end():] else "")
            inside_pem = True
            break
        output.extend((REDACTED, content[end.start():end.end()]))
        cursor = end.end()
    return "".join(output), inside_pem


def redact_text(value: str | None, *, inside_pem: bool = False) -> str | None:
    """Remove common credential material while preserving useful line context."""

    if value is None:
        return None
    output: list[str] = []
    for line in value.splitlines(keepends=True):
        newline_match = re.search(r"(?:\r\n|\r|\n)$", line)
        newline = newline_match.group(0) if newline_match else ""
        content = line[: -len(newline)] if newline else line
        content, inside_pem = _redact_pem_line(content, inside_pem)
        output.append(f"{content}{newline}")
    return "".join(output)


def has_source_path_credentials(path: str) -> bool:
    """Screen a typed source path without treating separators as token bytes."""

    return (
        _PEM_BEGIN.search(path) is not None
        or _redact_credential_shapes(path) != path
        or any(part == REDACTED or redact_text(part) != part for part in path.split("/"))
    )


def redact_json(value: Any, key: str = "", *, _depth: int = 0) -> Any:
    if key and _SENSITIVE_KEY.search(key):
        return REDACTED
    if _depth >= _MAX_JSON_DEPTH and isinstance(value, (dict, list)):
        return REDACTED
    if isinstance(value, dict):
        return {
            str(item_key): redact_json(item, str(item_key), _depth=_depth + 1)
            for item_key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_json(item, _depth=_depth + 1) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_finding(finding: Finding) -> Finding:
    return finding.model_copy(
        update={
            "message": redact_text(finding.message) or "",
            "code_snippet": redact_text(finding.code_snippet),
            "metadata": redact_json(finding.metadata),
        }
    )
