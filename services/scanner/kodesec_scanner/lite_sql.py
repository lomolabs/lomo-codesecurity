"""Bounded SQL construction signals, deliberately without sink or taint analysis."""

from collections.abc import Callable, Iterator
import re


_WORDS = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
_PAIRS = {"SELECT": "FROM", "INSERT": "INTO", "UPDATE": "SET", "DELETE": "FROM"}
_CONVERSIONS = frozenset("diouxXeEfFgGcrsa")


def _literals(line: str, python: bool, check: Callable[[], None]) -> Iterator[tuple[str, str, int, int, int]]:
    index, next_check = 0, 0
    quotes = {"'", '"'} if python else {"'", '"', "`"}
    while index < len(line):
        if index >= next_check:
            check()
            next_check = index + 4096
        if line[index] == "#" and python or not python and line.startswith("//", index):
            return
        quote = line[index]
        if quote not in quotes:
            index += 1
            continue
        if python and line.startswith(quote * 3, index):
            return  # Multiline/triple-quoted recognition belongs to native engines.
        before = index
        while before and index - before < 3 and (line[before - 1].isalnum() or line[before - 1] == "_"):
            before -= 1
        prefix = line[before:index].lower() if python else ""
        start = index + 1
        index = start
        while index < len(line):
            if index >= next_check:
                check()
                next_check = index + 4096
            if line[index] == "\\":
                index += 2
            elif line[index] == quote:
                yield quote, prefix, start, index, index + 1
                index += 1
                break
            else:
                index += 1
        else:
            return


def _has_field(line: str, start: int, end: int, template: bool, check: Callable[[], None], *, allow_empty: bool = False) -> bool:
    index, next_check = start, start
    while index < end:
        if index >= next_check:
            check()
            next_check = index + 4096
        if template and line[index] == "\\":
            index += 2
            continue
        opening = line.startswith("${", index) if template else line[index] == "{"
        if not opening:
            index += 1
            continue
        if not template and line.startswith("{{", index):
            index += 2
            continue
        index += 2 if template else 1
        field_start = index
        content, nested = False, False
        while index < end and line[index] != "}":
            if index >= next_check:
                check()
                next_check = index + 4096
            nested |= line[index] == "{"
            content |= not line[index].isspace()
            index += 1
        if index < end and not nested and (content or allow_empty and index == field_start):
            return True
        index += 1
    return False


def _has_percent_field(line: str, start: int, end: int, check: Callable[[], None]) -> bool:
    index, next_check = start, start
    while index < end:
        if index >= next_check:
            check()
            next_check = index + 4096
        if line[index] != "%":
            index += 1
            continue
        index += 1
        if index < end and line[index] == "%":
            index += 1
            continue
        if index < end and line[index] == "(":
            index += 1
            while index < end and line[index] != ")":
                if index >= next_check:
                    check()
                    next_check = index + 4096
                index += 1
            index += 1
        while index < end and line[index] in "#0 +-0123456789.":
            if index >= next_check:
                check()
                next_check = index + 4096
            index += 1
        if index < end and line[index] in _CONVERSIONS:
            return True
    return False


def _skip_space(line: str, index: int, check: Callable[[], None]) -> int:
    next_check = index
    while index < len(line) and line[index].isspace():
        if index >= next_check:
            check()
            next_check = index + 4096
        index += 1
    return index


def _sql_shape(line: str, start: int, end: int, check: Callable[[], None]) -> bool:
    wanted = set()
    for match in _WORDS.finditer(line, start, end):
        check()
        # SQL control words are short; avoid copying a permitted megabyte word.
        if match.end() - match.start() > 6:
            continue
        word = match.group().upper()
        if word in wanted:
            return True
        if word in _PAIRS:
            wanted.add(_PAIRS[word])
    return False


def looks_like_constructed_sql(line: str, python: bool, check: Callable[[], None]) -> bool:
    check()
    for quote, prefix, start, end, after in _literals(line, python, check):
        constructed = False
        if not python and quote == "`":
            constructed = _has_field(line, start, end, True, check)
        elif python:
            if prefix in {"f", "fr", "rf"}:
                constructed = _has_field(line, start, end, False, check)
            else:
                operator = _skip_space(line, after, check)
                if line.startswith(".format", operator):
                    call = _skip_space(line, operator + 7, check)
                    constructed = call < len(line) and line[call] == "(" and _has_field(line, start, end, False, check, allow_empty=True)
                elif operator < len(line) and line[operator] == "%":
                    operand = _skip_space(line, operator + 1, check)
                    constructed = operand < len(line) and line[operand] not in ";,)]}#" and _has_percent_field(line, start, end, check)
        if constructed and _sql_shape(line, start, end, check):
            return True
    check()
    return False
