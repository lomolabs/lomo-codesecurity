from __future__ import annotations

from collections.abc import Sequence


def _without_final_line_ending(value: str) -> str:
    if value.endswith("\r\n"):
        return value[:-2]
    if value.endswith(("\n", "\r")):
        return value[:-1]
    return value


def _final_line_ending_length(value: str) -> int:
    if value.endswith("\r\n"):
        return 2
    if value.endswith(("\n", "\r")):
        return 1
    return 0


def bounded_line_snippet(
    lines: Sequence[str],
    offender_index: int,
    *,
    context_lines: int,
    max_chars: int,
) -> tuple[str, int]:
    """Return bounded whole-line context and its exact one-based first line."""

    if not 0 <= offender_index < len(lines):
        raise IndexError("offender line is outside the source")
    if context_lines < 0:
        raise ValueError("context_lines must not be negative")
    if max_chars < 1:
        raise ValueError("max_chars must be positive")

    start = max(offender_index - context_lines, 0)
    end = min(offender_index + context_lines, len(lines) - 1)
    selected_chars = sum(len(lines[index]) for index in range(start, end + 1))

    def visible_chars() -> int:
        return selected_chars - _final_line_ending_length(lines[end])

    while visible_chars() > max_chars and (start < offender_index or end > offender_index):
        before = offender_index - start
        after = end - offender_index
        if before > after:
            selected_chars -= len(lines[start])
            start += 1
        elif after > before:
            selected_chars -= len(lines[end])
            end -= 1
        elif len(lines[start]) >= len(lines[end]):
            selected_chars -= len(lines[start])
            start += 1
        else:
            selected_chars -= len(lines[end])
            end -= 1

    # A single source line can itself exceed the persistence boundary. With no
    # column range available, retain its leading content and indentation.
    if visible_chars() > max_chars:
        snippet = _without_final_line_ending(lines[offender_index])[:max_chars]
    else:
        snippet = _without_final_line_ending("".join(lines[start : end + 1]))
    return snippet, start + 1
