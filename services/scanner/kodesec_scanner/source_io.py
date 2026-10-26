from __future__ import annotations

import os
import posixpath
import re
import stat
from array import array
from bisect import bisect_left, bisect_right
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import overload

from .redaction import private_key_body_boundaries, redact_text


_FORBIDDEN_PATH_FORMATTING = frozenset(
    "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
)


def _utf16_endpoint(line: str) -> int:
    return len(line.encode("utf-16-le")) // 2 + 1


class SourceEvidenceError(RuntimeError):
    """A stable, evidence-free reason why exact source evidence was rejected."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class SourceDocument:
    """One compact source view shared by range and snippet projection."""

    text: str
    line_starts: array[int]
    utf16_endpoints: array[int]

    @classmethod
    def from_text(cls, text: str) -> "SourceDocument":
        line_starts = array("I", [0])
        utf16_endpoints = array("I")
        start = 0
        for ending in re.finditer(r"\r\n|\r|\n", text):
            line = text[start : ending.start()]
            utf16_endpoints.append(_utf16_endpoint(line))
            start = ending.end()
            line_starts.append(start)
        utf16_endpoints.append(_utf16_endpoint(text[start:]))
        return cls(text, line_starts, utf16_endpoints)

    @property
    def line_count(self) -> int:
        return len(self.line_starts)

    def _bounds(self, index: int) -> tuple[int, int, int]:
        if index < 0:
            index += self.line_count
        if not 0 <= index < self.line_count:
            raise IndexError("source line index is out of range")
        start = self.line_starts[index]
        full_end = (
            self.line_starts[index + 1]
            if index + 1 < self.line_count
            else len(self.text)
        )
        content_end = full_end
        if self.text[max(start, full_end - 2) : full_end] == "\r\n":
            content_end -= 2
        elif full_end > start and self.text[full_end - 1] in "\r\n":
            content_end -= 1
        return start, content_end, full_end

    def line(self, index: int, *, keepend: bool = False) -> str:
        start, content_end, full_end = self._bounds(index)
        return self.text[start : full_end if keepend else content_end]

    def line_view(self, *, keepends: bool = False) -> "SourceLineView":
        return SourceLineView(self, keepends)

    @cached_property
    def private_key_boundaries(self) -> array[int]:
        return private_key_body_boundaries(self.text)

    def redact_snippet(self, snippet: str, first_line: int) -> str:
        """Carry original PEM context into bounded, line-aligned evidence."""

        if not 1 <= first_line <= self.line_count:
            raise SourceEvidenceError("source_location_out_of_range")
        offset = self.line_starts[first_line - 1]
        inside = bisect_right(self.private_key_boundaries, offset) % 2 == 1
        return redact_text(snippet, inside_pem=inside) or ""

    def context_exceeds_chars(self, offender_line: int, context_lines: int, maximum: int) -> bool:
        """Keep the original context-bound notice even when redaction shrinks it."""

        index = offender_line - 1
        if not 0 <= index < self.line_count:
            raise SourceEvidenceError("source_location_out_of_range")
        first = max(index - context_lines, 0)
        last = min(index + context_lines, self.line_count - 1)
        return self._bounds(last)[1] - self.line_starts[first] > maximum


class SourceLineView(Sequence[str]):
    """Lazy line slices over one compact source document."""

    def __init__(self, source: SourceDocument, keepends: bool) -> None:
        self._source = source
        self._keepends = keepends

    def __len__(self) -> int:
        return self._source.line_count

    @overload
    def __getitem__(self, index: int) -> str: ...

    @overload
    def __getitem__(self, index: slice) -> list[str]: ...

    def __getitem__(self, index: int | slice) -> str | list[str]:
        if isinstance(index, slice):
            return [self[item] for item in range(*index.indices(len(self)))]
        return self._source.line(index, keepend=self._keepends)


def _relative_parts(relative_path: str) -> tuple[str, ...]:
    if (
        not relative_path
        or relative_path.startswith("/")
        or "\\" in relative_path
        or posixpath.normpath(relative_path) != relative_path
        or any(
            ord(character) < 32
            or ord(character) == 127
            or character in _FORBIDDEN_PATH_FORMATTING
            for character in relative_path
        )
    ):
        raise SourceEvidenceError("unsafe_source_path")
    parts = tuple(relative_path.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        raise SourceEvidenceError("unsafe_source_path")
    try:
        if len(relative_path.encode("utf-8")) > 4096:
            raise SourceEvidenceError("unsafe_source_path")
    except UnicodeEncodeError as exc:
        raise SourceEvidenceError("unsafe_source_path") from exc
    return parts


def read_regular_file_at(
    root_descriptor: int,
    relative_path: str,
    maximum_bytes: int,
    *, checkpoint: Callable[[], None] | None = None,
) -> bytes:
    """Read one stable regular file below an already-authorized directory fd."""

    if maximum_bytes < 1:
        raise ValueError("maximum_bytes must be positive")
    check = checkpoint or (lambda: None)
    check()
    parts = _relative_parts(relative_path)
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = -1
    source_descriptor = -1
    try:
        descriptor = os.dup(root_descriptor)
        for part in parts[:-1]:
            check()
            child = os.open(part, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        check()
        source_descriptor = os.open(
            parts[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=descriptor,
        )
        before = os.fstat(source_descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SourceEvidenceError("unsupported_source_type")
        if before.st_size > maximum_bytes:
            raise SourceEvidenceError("source_file_oversized")

        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            check()
            chunk = os.read(source_descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(source_descriptor)
        check()
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity or len(content) != before.st_size:
            raise SourceEvidenceError("source_file_changed")
        if len(content) > maximum_bytes:
            raise SourceEvidenceError("source_file_oversized")
        return content
    except SourceEvidenceError:
        raise
    except OSError as exc:
        raise SourceEvidenceError("unsafe_or_unreadable_source_path") from exc
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)
        if descriptor >= 0:
            os.close(descriptor)


def _open_source_root(root: Path) -> int:
    flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
    )
    descriptor = -1
    try:
        descriptor = os.open(root, flags)
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise SourceEvidenceError("unsafe_source_root")
        return descriptor
    except SourceEvidenceError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise SourceEvidenceError("unsafe_source_root") from exc


class SourceTextReader:
    """Read exact UTF-8 source while retaining only the current compact document."""

    def __init__(self, root: Path, maximum_bytes: int, *, checkpoint: Callable[[], None] | None = None,
                 root_descriptor: int | None = None) -> None:
        self._root = root
        self._maximum_bytes = maximum_bytes
        self._checkpoint = checkpoint or (lambda: None)
        self._root_descriptor = root_descriptor
        self._descriptor = -1
        self._cached_path: str | None = None
        self._cached_document: SourceDocument | None = None

    def __enter__(self) -> "SourceTextReader":
        self._checkpoint()
        if self._root_descriptor is None:
            self._descriptor = _open_source_root(self._root)
        else:
            # The caller retains the authorized anchor; this reader owns a copy.
            if not stat.S_ISDIR(os.fstat(self._root_descriptor).st_mode):
                raise SourceEvidenceError("unsafe_source_root")
            self._descriptor = os.dup(self._root_descriptor)
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._descriptor >= 0:
            os.close(self._descriptor)
            self._descriptor = -1
        self._cached_path = None
        self._cached_document = None

    def read_document(self, relative_path: str) -> SourceDocument:
        self._checkpoint()
        if self._descriptor < 0:
            raise RuntimeError("source reader is not open")
        if relative_path == self._cached_path and self._cached_document is not None:
            return self._cached_document
        content = self.read_bytes(relative_path)
        try:
            text = content.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise SourceEvidenceError("invalid_utf8_source") from exc
        if "\x00" in text:
            raise SourceEvidenceError("nul_in_source")
        self._checkpoint()
        document = SourceDocument.from_text(text)
        self._checkpoint()
        self._cached_path = relative_path
        self._cached_document = document
        return document

    def read_bytes(self, relative_path: str) -> bytes:
        self._checkpoint()
        if self._descriptor < 0:
            raise RuntimeError("source reader is not open")
        return read_regular_file_at(
            self._descriptor,
            relative_path,
            self._maximum_bytes,
            checkpoint=self._checkpoint,
        )

    def projected_path_lookup(
        self,
        requested: set[str],
        project: Callable[[str], str],
        maximum_entries: int,
        checkpoint: Callable[[], None],
    ) -> dict[str, str | None]:
        """Match producer paths uniquely below the same pinned evidence root.

        A projection may erase path separators. Prefix pruning consequently
        uses string prefixes rather than directory-component prefixes; this
        still visits possible colliding names while skipping unrelated trees.
        None records an ambiguous projection and must never select one file.
        """
        if self._descriptor < 0 or maximum_entries < 1:
            raise RuntimeError("source reader is not open or lookup bound is invalid")
        lookup: dict[str, str | None] = {}
        ordered_requested = sorted(requested)
        entries = 0
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW

        def identity(metadata: os.stat_result) -> tuple[int, ...]:
            return (metadata.st_dev, metadata.st_ino, metadata.st_mode,
                    metadata.st_mtime_ns, metadata.st_ctime_ns)

        def walk(descriptor: int, parts: tuple[str, ...]) -> None:
            nonlocal entries
            checkpoint()
            before = os.fstat(descriptor)
            for name in sorted(os.listdir(descriptor)):
                checkpoint()
                entries += 1
                if entries > maximum_entries:
                    raise SourceEvidenceError("producer_path_lookup_limit")
                relative = "/".join((*parts, name))
                _relative_parts(relative)
                key = project(relative)
                metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    if key in requested:
                        lookup[key] = None
                    position = bisect_left(ordered_requested, key)
                    if (position == len(ordered_requested)
                            or not ordered_requested[position].startswith(key)):
                        continue
                    child = os.open(name, flags, dir_fd=descriptor)
                    try:
                        if identity(os.fstat(child)) != identity(metadata):
                            raise SourceEvidenceError("producer_path_lookup_changed")
                        walk(child, (*parts, name))
                    finally:
                        os.close(child)
                elif stat.S_ISREG(metadata.st_mode) and key in requested:
                    lookup[key] = None if key in lookup else relative
                elif key in requested:
                    lookup[key] = None
            if identity(os.fstat(descriptor)) != identity(before):
                raise SourceEvidenceError("producer_path_lookup_changed")

        try:
            if requested:
                walk(self._descriptor, ())
        except SourceEvidenceError:
            raise
        except (OSError, UnicodeError) as exc:
            raise SourceEvidenceError("producer_path_lookup_unavailable") from exc
        return lookup


def complete_source_location(
    source: SourceDocument,
    start_line: int | None,
    start_column: int | None,
    end_line: int | None,
    end_column: int | None,
    column_kind: str | None,
) -> tuple[int | None, int | None, int | None, int | None]:
    """Complete a source location to exact 1-based UTF-16, end-exclusive columns.

    An omitted producer declaration is accepted only when both SARIF column
    interpretations produce the same normalized range; it is never defaulted.
    """

    if column_kind is None:
        completions: list[
            tuple[int | None, int | None, int | None, int | None]
        ] = []
        failures: list[str] = []
        for candidate_kind in ("unicodeCodePoints", "utf16CodeUnits"):
            try:
                completions.append(
                    complete_source_location(
                        source,
                        start_line,
                        start_column,
                        end_line,
                        end_column,
                        candidate_kind,
                    )
                )
            except SourceEvidenceError as exc:
                failures.append(exc.reason)
        if len(completions) == 2 and completions[0] == completions[1]:
            return completions[0]
        if not completions and len(set(failures)) == 1:
            raise SourceEvidenceError(failures[0])
        raise SourceEvidenceError("ambiguous_missing_column_kind")

    if start_line is None:
        if any(value is not None for value in (start_column, end_line, end_column)):
            raise SourceEvidenceError("invalid_source_location")
        return None, None, None, None
    resolved_end_line = end_line if end_line is not None else start_line
    if start_line < 1 or resolved_end_line < start_line:
        raise SourceEvidenceError("invalid_source_location")
    if (
        start_line > source.line_count
        or resolved_end_line > source.line_count
    ):
        raise SourceEvidenceError("source_location_out_of_range")

    start_endpoint = source.utf16_endpoints[start_line - 1]
    end_endpoint = source.utf16_endpoints[resolved_end_line - 1]
    if column_kind not in {"unicodeCodePoints", "utf16CodeUnits"}:
        raise SourceEvidenceError("invalid_column_kind")

    def normalize_column(line_number: int, column: int) -> int:
        if column < 1:
            raise SourceEvidenceError("invalid_source_location")
        if column_kind == "utf16CodeUnits":
            if column > source.utf16_endpoints[line_number - 1]:
                raise SourceEvidenceError("invalid_source_location")
            return column
        line = source.line(line_number - 1)
        if column > len(line) + 1:
            raise SourceEvidenceError("invalid_source_location")
        return len(line[: column - 1].encode("utf-16-le")) // 2 + 1

    resolved_start_column = (
        normalize_column(start_line, start_column)
        if start_column is not None
        else 1
    )
    resolved_end_column = (
        normalize_column(resolved_end_line, end_column)
        if end_column is not None
        else end_endpoint
    )
    if (
        resolved_start_column < 1
        or resolved_start_column > start_endpoint
        or resolved_end_column < 1
        or resolved_end_column > end_endpoint
        or (
            start_line == resolved_end_line
            and resolved_end_column < resolved_start_column
        )
    ):
        raise SourceEvidenceError("invalid_source_location")
    return (
        start_line,
        resolved_start_column,
        resolved_end_line,
        resolved_end_column,
    )
