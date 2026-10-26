"""Small, conservative Docker USER policy checks; no image or account inspection."""

from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
import re
from typing import Literal


UserState = Literal["declared", "root", "unresolved"]
_USER = re.compile(r"(?:[A-Za-z_][A-Za-z0-9_.-]*|[0-9]+)(?::(?:[A-Za-z_][A-Za-z0-9_.-]*|[0-9]+))?")
_FRONTEND = re.compile(r"docker/dockerfile:1(?:\.[0-9]+)*(?:-labs)?(?:@sha256:[0-9a-f]{64})?")
_STAGE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*")


class _UnsupportedSyntax(ValueError):
    pass


def is_docker_source_name(path: Path) -> bool:
    name = path.name.lower()
    return name == "containerfile" or name.startswith("dockerfile") or name.endswith(".dockerfile")


def _instructions(lines: Sequence[str], checkpoint: Callable[[], None]) -> Iterator[tuple[str, str]]:
    escape = "\\"
    directives = True
    seen_directives = set()
    parts = []
    for line in lines:
        checkpoint()
        content = line.strip()
        if content.startswith("#"):
            match = re.fullmatch(r"#\s*(syntax|escape|check)\s*=\s*(.*?)\s*", content, re.IGNORECASE)
            if directives and match:
                key, value = match.group(1).lower(), match.group(2)
                if key in seen_directives:
                    raise _UnsupportedSyntax("duplicate directive")
                seen_directives.add(key)
                if key == "escape":
                    if value not in {"\\", "`"}:
                        raise _UnsupportedSyntax("unsupported escape")
                    escape = value
                elif key == "syntax" and not _FRONTEND.fullmatch(value):
                    raise _UnsupportedSyntax("custom frontend")
            else:
                directives = False
            continue
        directives = False
        if not content:
            continue
        if "<<" in content:
            raise _UnsupportedSyntax("heredoc context unavailable")
        if content.endswith(escape):
            parts.append(content[:-1])
            continue
        parts.append(content)
        instruction = "".join(parts).split(None, 1)
        parts.clear()
        yield instruction[0].upper(), instruction[1] if len(instruction) == 2 else ""
    if parts:
        raise _UnsupportedSyntax("unfinished continuation")


def docker_user_state(lines: Sequence[str], checkpoint: Callable[[], None]) -> UserState:
    """Classify a final-stage declaration, retaining unknown inherited users."""

    state: UserState = "unresolved"
    stages: dict[str, UserState] = {}
    alias = None
    stage_count = 0
    try:
        for operation, value in _instructions(lines, checkpoint):
            if operation == "FROM":
                if stage_count:
                    stages[str(stage_count - 1)] = state
                    if alias:
                        stages[alias] = state
                tokens = value.split(None, 4)
                if tokens and tokens[0].startswith("--platform="):
                    tokens = tokens[1:]
                if len(tokens) not in {1, 3} or len(tokens) == 3 and (
                    tokens[1].upper() != "AS" or not _STAGE.fullmatch(tokens[2])):
                    return "unresolved"
                state = stages.get(tokens[0].lower(), "unresolved")
                alias = tokens[2].lower() if len(tokens) == 3 else None
                stage_count += 1
            elif operation == "USER":
                if not stage_count or not _USER.fullmatch(value):
                    state = "unresolved"
                    continue
                user = value.split(":", 1)[0]
                state = "root" if user == "root" or set(user) == {"0"} else "declared"
    except _UnsupportedSyntax:
        return "unresolved"
    checkpoint()
    return state if stage_count else "unresolved"
