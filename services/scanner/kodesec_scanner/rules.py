from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

from .models import Finding, canonical_json_bytes
from .snippets import bounded_line_snippet
from .source_io import SourceDocument, complete_source_location
from .lite_iac import docker_user_state, is_docker_source_name
from .lite_sql import looks_like_constructed_sql


SECRET_PATTERNS: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    ("secret.aws_access_key", "critical", "AWS access key pattern", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("secret.github_token", "critical", "GitHub token pattern", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("secret.slack_token", "critical", "Slack token pattern", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("secret.private_key", "critical", "Private key material", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "secret.generic_assignment",
        "high",
        "Sensitive-looking assignment",
        re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"][^'\"]{12,}['\"]"),
    ),
)

_SUBPROCESS_CALL = re.compile(r"subprocess\.[a-zA-Z_]+\(")
_SHELL_TRUE = re.compile(r"shell\s*=\s*True")

SAST_PATTERNS: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    ("sast.python_shell_true", "high", "Python subprocess shell=True", _SUBPROCESS_CALL),
    ("sast.javascript_eval", "high", "JavaScript eval-like execution", re.compile(r"\b(eval|Function)\s*\(")),
    ("sast.insecure_random", "low", "Non-cryptographic random used near security token", re.compile(r"(?i)(token|secret|password).{0,80}(random\.random|Math\.random)")),
)

IAC_PATTERNS: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    ("iac.k8s_privileged", "critical", "Kubernetes privileged container", re.compile(r"privileged:\s*true", re.IGNORECASE)),
    ("iac.k8s_host_path", "high", "Kubernetes hostPath volume", re.compile(r"hostPath:", re.IGNORECASE)),
    ("iac.k8s_root_allowed", "medium", "Kubernetes runAsNonRoot disabled", re.compile(r"runAsNonRoot:\s*false", re.IGNORECASE)),
    ("iac.terraform_public_ingress", "high", "Public ingress CIDR", re.compile(r'0\.0\.0\.0/0|::/0')),
)

TEXT_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".rs",
    ".java",
    ".rb",
    ".php",
    ".cs",
    ".sh",
    ".bash",
    ".zsh",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".tf",
    ".Dockerfile",
    ".env",
    ".ini",
    ".cfg",
    ".md",
}

ENTROPY_SUPPRESSED_FILES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
    "cargo.lock",
    "go.sum",
    "poetry.lock",
}
SNIPPET_CONTEXT_LINES = 40
SNIPPET_MAX_CHARS = 20000
LITE_SCANNERS = frozenset({"secrets-lite", "sast-lite", "iac-lite"})
ENTROPY_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{32,}")


def _fingerprint(rule_id: str, rel_path: str, line_number: int | None, text: str) -> str:
    payload = f"{rule_id}:{rel_path}:{line_number or 0}:{text.strip()[:160]}"
    return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()


def _snippet(lines: Sequence[str], index: int) -> tuple[str, int]:
    return bounded_line_snippet(
        lines,
        index,
        context_lines=SNIPPET_CONTEXT_LINES,
        max_chars=SNIPPET_MAX_CHARS,
    )


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    counts = Counter(value)
    return -math.fsum(
        (counts[character] / length) * math.log2(counts[character] / length)
        for character in sorted(counts)
    )


def _high_entropy_tokens(line: str, checkpoint: Callable[[], None]) -> Iterable[tuple[int, str, float]]:
    for match in ENTROPY_TOKEN.finditer(line):
        checkpoint()
        token = match.group()
        entropy = _entropy(token)
        checkpoint()
        if entropy >= 4.4:
            yield match.start(), token, entropy


def _entropy_fingerprint(rel_path: str, line_number: int, offset: int, token: str) -> str:
    token_digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    identity = ["secret.high_entropy/v2", rel_path, line_number, offset, token_digest]
    return hashlib.sha256(canonical_json_bytes(identity)).hexdigest()


def _is_iac_path(path: str) -> bool:
    source = Path(path)
    return source.suffix.lower() in {".yaml", ".yml", ".tf"} or is_docker_source_name(source)


def _has_python_shell_true(line: str, checkpoint: Callable[[], None]) -> bool:
    """Keep the existing first-closing-parenthesis heuristic with disjoint work."""

    cursor = 0
    while cursor < len(line):
        checkpoint()
        call = _SUBPROCESS_CALL.search(line, cursor)
        checkpoint()
        if call is None:
            return False
        closing = line.find(")", call.end())
        end = len(line) if closing < 0 else closing
        checkpoint()
        matched = _SHELL_TRUE.search(line, call.end(), end) is not None
        checkpoint()
        if matched:
            return True
        # Nested starts share this same suffix; retrying each one was quadratic.
        cursor = end + 1
    return False


def scan_text_file(
    root: Path, path: Path, text: str, *,
    enabled_tools: set[str] | None = None,
    checkpoint: Callable[[], None] | None = None,
) -> list[Finding]:
    check = checkpoint or (lambda: None)
    check()
    enabled = LITE_SCANNERS if enabled_tools is None else LITE_SCANNERS.intersection(enabled_tools)
    if not enabled:
        return []
    rel_path = path.relative_to(root).as_posix()
    source = SourceDocument.from_text(text)
    lines = source.line_view(keepends=True)
    check()
    findings: list[Finding] = []
    scan_secrets = "secrets-lite" in enabled
    suffix = path.suffix.lower()
    python_source = suffix == ".py"
    javascript_source = suffix in {".js", ".jsx", ".ts", ".tsx"}
    scan_sast = "sast-lite" in enabled and (python_source or javascript_source)
    sast_patterns = tuple(row for row in SAST_PATTERNS
                          if (row[0] != "sast.python_shell_true" or python_source)
                          and (row[0] != "sast.javascript_eval" or javascript_source)) if scan_sast else ()
    scan_iac = "iac-lite" in enabled and _is_iac_path(rel_path)
    scan_entropy = scan_secrets and path.name.lower() not in ENTROPY_SUPPRESSED_FILES

    def add(rule_id: str, severity: str, message: str, idx: int, line: str, scanner: str,
            extra: dict | None = None, *, fingerprint: str | None = None) -> None:
        check()
        snippet, snippet_start_line = _snippet(lines, idx)
        snippet = source.redact_snippet(snippet, snippet_start_line)
        check()
        start_line, start_column, end_line, end_column = complete_source_location(
            source,
            idx + 1,
            None,
            idx + 1,
            None,
            "utf16CodeUnits",
        )
        findings.append(
            Finding(
                scanner=scanner,
                rule_id=rule_id,
                severity=severity,  # type: ignore[arg-type]
                file_path=rel_path,
                start_line=start_line,
                start_column=start_column,
                end_line=end_line,
                end_column=end_column,
                message=message,
                code_snippet=snippet,
                fingerprint=fingerprint or _fingerprint(rule_id, rel_path, idx + 1, line),
                metadata={**(extra or {}), "snippet_start_line": snippet_start_line,
                    **({"snippet_truncated": True} if source.context_exceeds_chars(
                        idx + 1, SNIPPET_CONTEXT_LINES, SNIPPET_MAX_CHARS) else {})},
            )
        )

    for idx, line in enumerate(lines):
        check()
        if scan_secrets:
            for rule_id, severity, message, pattern in SECRET_PATTERNS:
                check()
                if pattern.search(line):
                    add(rule_id, severity, message, idx, line, "secrets-lite")

        if scan_entropy:
            nearby = line.lower()
            suppressed = '"integrity"' in nearby or "sha256-" in nearby or "sha512-" in nearby
            if not suppressed and any(marker in nearby for marker in ("token", "secret", "key", "password", "credential")):
                for offset, token, entropy in _high_entropy_tokens(line, check):
                    add(
                        "secret.high_entropy",
                        "medium",
                        "High-entropy token near sensitive keyword",
                        idx,
                        token,
                        "secrets-lite",
                        {"entropy": round(entropy, 2)},
                        fingerprint=_entropy_fingerprint(rel_path, idx + 1, offset, token),
                    )

        if scan_sast and not line.lstrip().startswith("#" if python_source else "//"):
            for rule_id, severity, message, pattern in sast_patterns:
                check()
                matched = (_has_python_shell_true(line, check)
                           if rule_id == "sast.python_shell_true" else pattern.search(line))
                if matched:
                    add(rule_id, severity, message, idx, line, "sast-lite")
            check()
            if looks_like_constructed_sql(line, python_source, check):
                add("sast.sql_string_format", "medium", "SQL query appears string-formatted", idx, line, "sast-lite")

        if scan_iac:
            for rule_id, severity, message, pattern in IAC_PATTERNS:
                check()
                if pattern.search(line):
                    add(rule_id, severity, message, idx, line, "iac-lite")

    check()
    if "iac-lite" in enabled and is_docker_source_name(path):
        state = docker_user_state(lines, check)
        if state != "declared":
            findings.append(
                Finding(
                    scanner="iac-lite",
                    rule_id="iac.docker_no_user",
                    severity="medium",
                    file_path=rel_path,
                    start_line=None,
                    start_column=None,
                    end_line=None,
                    end_column=None,
                    message=("Dockerfile final stage explicitly declares root USER" if state == "root"
                             else "Dockerfile final stage has no established non-root USER declaration"),
                    code_snippet=None,
                    fingerprint=_fingerprint("iac.docker_no_user", rel_path, None, text[:200]),
                    metadata={"container_hardening": True},
                )
            )

    return findings
