from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from kodesec_api.redaction import (
    REDACTED,
    has_source_path_credentials,
    redact_finding_payload,
    redact_json,
    redact_text,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPOSITORY_ROOT / "services" / "scanner"))

from kodesec_scanner.redaction import (  # noqa: E402
    REDACTED as SCANNER_REDACTED,
    redact_finding as scanner_redact_finding,
    redact_json as scanner_redact_json,
    redact_text as scanner_redact_text,
)
from kodesec_scanner.models import Finding as ScannerFinding  # noqa: E402


FIXTURE_MATERIAL = "fixture-only-material"
SHORT_OPAQUE_FIXTURE = "q7"


@pytest.mark.parametrize(("path", "credential_like"), [
    ("tests/scanner-runtime/fixtures/dependencies/positive/requirements.txt", False),
    ("bearer/requirements.txt", False),
    ("Bearer /foo", True),
    ("prefix/Bearer /foo/file.txt", True),
    ("password=/foo", True),
    ("src/-----BEGIN PRIVATE KEY-----/fixture/file.txt", True),
    ("src/[REDACTED]/requirements.txt", True),
    ("src/" + "a" * 32 + "/requirements.txt", True),
])
def test_typed_source_path_screen_preserves_strong_credential_checks(
    path: str, credential_like: bool,
) -> None:
    assert has_source_path_credentials(path) is credential_like


def test_source_path_exception_does_not_change_generic_redaction() -> None:
    path = "tests/scanner-runtime/fixtures/dependencies/positive/requirements.txt"

    assert not has_source_path_credentials(path)
    assert REDACTED in redact_text(path)
    assert REDACTED in scanner_redact_text(path)


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (f"Authorization: Bearer {SHORT_OPAQUE_FIXTURE}", f"Authorization: {REDACTED}"),
        (f"authorization = Basic {SHORT_OPAQUE_FIXTURE}", f"authorization = {REDACTED}"),
        (f"request uses Bearer {SHORT_OPAQUE_FIXTURE}, then continues", f"request uses Bearer {REDACTED}, then continues"),
        ('password = "fixture phrase only"; mode=safe', f'password = "{REDACTED}"; mode=safe'),
        ("client_secret='fixture phrase only' # generated", f"client_secret='{REDACTED}' # generated"),
        ("api-key=fixture phrase only, mode=safe", f"api-key={REDACTED}, mode=safe"),
        ('"refresh_token": "fixture phrase only", "safe": true', f'"refresh_token": "{REDACTED}", "safe": true'),
    ],
)
def test_authorization_and_assignment_redaction(source: str, expected: str) -> None:
    assert redact_text(source) == expected


@pytest.mark.parametrize(
    "key",
    [
        "DB_PASSWORD",
        "MY_API_KEY",
        "dbPassword",
        "secretValue",
        "service.client-secret",
        "sessionTokenDigest",
        "xAmzSignatureV4",
        "DBPASSWORD",
    ],
)
def test_composite_credential_assignment_keys_are_redacted_with_scanner_parity(key: str) -> None:
    source = f'{key}="short fixture value"; mode=safe'
    expected = f'{key}="{REDACTED}"; mode=safe'

    assert redact_text(source) == expected
    assert scanner_redact_text(source) == expected


@pytest.mark.parametrize(("source", "expected"), [
    ("123password=fixture", f"123password={REDACTED}"),
    ("épassword=fixture", f"épassword={REDACTED}"),
    ("'password=fixture", f"'password={REDACTED}"),
    ('"password=fixture', f'"password={REDACTED}'),
    ("'password'='fixture'", f"'password'='{REDACTED}'"),
    ("password://example.invalid", "password://example.invalid"),
    ("safe=plain; 'password'='fixture'", f"safe=plain; 'password'='{REDACTED}'"),
])
def test_disjoint_assignment_search_preserves_masking_edges(source: str, expected: str) -> None:
    assert redact_text(source) == scanner_redact_text(source) == expected


def test_long_identifiers_cannot_stall_redaction_or_lite_evidence() -> None:
    # A child bound catches catastrophic suffix retries without hanging pytest.
    program = """
import sys
from pathlib import Path
root = Path(sys.argv[1])
sys.path[:0] = [str(root / 'apps/api'), str(root / 'services/scanner')]
from kodesec_api.redaction import redact_text as api
from kodesec_scanner.redaction import redact_text as scanner, _assignment_key_parts
from kodesec_scanner.rules import scan_text_file
for redact in (api, scanner):
    assert redact('A' * 20000) == '[REDACTED]'
assert _assignment_key_parts('A' * 20000) == ('a' * 20000,)
source = 'eval(input); // ' + 'A' * 19980
findings = scan_text_file(root, root / 'fixture.js', source, enabled_tools={'sast-lite'})
assert [item.rule_id for item in findings] == ['sast.javascript_eval']
assert '[REDACTED]' in findings[0].code_snippet
"""
    subprocess.run([sys.executable, "-B", "-c", program, str(REPOSITORY_ROOT)],
                   check=True, capture_output=True, timeout=4)


@pytest.mark.parametrize(
    "key",
    [
        "monkey",
        "passwordlessMode",
        "publicKey",
        "secretariat",
        "tokenizer",
    ],
)
def test_credential_substrings_inside_non_sensitive_words_are_not_redacted(key: str) -> None:
    source = f'{key}="short fixture value"'

    assert redact_text(source) == source
    assert scanner_redact_text(source) == source


def test_composite_credential_in_surrounding_finding_context_cannot_persist() -> None:
    source = (
        "safe_before = 1\n"
        'DB_PASSWORD="short fixture value"\n'
        "offender_call()\n"
        "safe_after = 2\n"
    )
    payload = {
        "scanner": "fixture-detector",
        "rule_id": "generated-finding",
        "severity": "high",
        "file_path": "generated/example.py",
        "start_line": 3,
        "end_line": 3,
        "message": "Generated finding",
        "code_snippet": source,
        "fingerprint": "a" * 64,
        "metadata": {},
    }

    api_result = redact_finding_payload(payload)
    scanner_result = scanner_redact_finding(ScannerFinding(**payload)).model_dump()

    assert "short fixture value" not in api_result["code_snippet"]
    assert api_result["code_snippet"] == scanner_result["code_snippet"]
    assert f'DB_PASSWORD="{REDACTED}"' in api_result["code_snippet"]


@pytest.mark.parametrize("separator", ["#", ",", ";", "&"])
def test_unquoted_credential_punctuation_does_not_leak_a_suffix(separator: str) -> None:
    source = f"password=fixture{separator}material"
    assert redact_text(source) == f"password={REDACTED}"


@pytest.mark.parametrize(
    "scheme",
    ["https", "postgresql", "ssh"],
)
def test_url_userinfo_and_sensitive_query_values_are_redacted(scheme: str) -> None:
    source = (
        f"{scheme}://fixture-user:fixture-pass@example.invalid/resource"
        f"?access_token={SHORT_OPAQUE_FIXTURE}&mode=safe&api_key={FIXTURE_MATERIAL}#details"
    )

    assert redact_text(source) == (
        f"{scheme}://{REDACTED}@example.invalid/resource"
        f"?access_token={REDACTED}&mode=safe&api_key={REDACTED}#details"
    )


@pytest.mark.parametrize(
    "token_parts",
    [
        ("gh", "p_", "NOT_REAL_VALUE"),
        ("github", "_pat_", "NOT_REAL_VALUE"),
        ("gl", "pat-", "NOT_REAL_VALUE"),
        ("xo", "xb-", "NOT_REAL_VALUE"),
        ("sk", "_live_", "NOT_REAL_VALUE"),
        ("sk", "-", "NOT_REAL_VALUE"),
        ("np", "m_", "NOT_REAL_VALUE"),
        ("py", "pi-", "NOT_REAL_VALUE"),
        ("ya", "29.", "NOT_REAL_VALUE"),
        ("AK", "IA_", "NOT_REAL_VALUE"),
        ("eyJ", "fixture.", "not_real.", "fixture"),
    ],
)
def test_common_token_shapes_are_redacted_without_usable_fixtures(token_parts: tuple[str, ...]) -> None:
    fixture_token = "".join(token_parts)
    assert redact_text(f"detector saw {fixture_token} in generated input") == (
        f"detector saw {REDACTED} in generated input"
    )


def test_long_opaque_material_is_redacted_without_a_provider_prefix() -> None:
    fixture_token = "fixture_only_" * 3
    assert redact_text(f"detector saw {fixture_token} in generated input") == (
        f"detector saw {REDACTED} in generated input"
    )


def test_private_key_block_preserves_boundaries_and_line_structure() -> None:
    source = (
        "before = 1\r\n"
        "-----BEGIN TEST PRIVATE KEY-----\r\n"
        "fixture body line one\r\n"
        "fixture body line two\r\n"
        "-----END TEST PRIVATE KEY-----\r\n"
        "after = 2\r\n"
    )

    redacted = redact_text(source)

    assert redacted is not None
    assert "fixture body" not in redacted
    assert "BEGIN TEST PRIVATE KEY" in redacted
    assert "END TEST PRIVATE KEY" in redacted
    assert redacted.count("\r\n") == source.count("\r\n")
    assert "before = 1" in redacted
    assert "after = 2" in redacted


def test_inline_private_key_block_is_redacted() -> None:
    source = (
        f"token={FIXTURE_MATERIAL}; -----BEGIN TEST PRIVATE KEY-----"
        f"fixture body-----END TEST PRIVATE KEY----- password={FIXTURE_MATERIAL}"
    )
    assert redact_text(source) == (
        f"token={REDACTED}; -----BEGIN TEST PRIVATE KEY-----{REDACTED}"
        f"-----END TEST PRIVATE KEY----- password={REDACTED}"
    )


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
@pytest.mark.parametrize("unclosed", [False, True])
def test_each_inline_private_key_body_is_masked_with_scanner_parity(newline: str, unclosed: bool) -> None:
    begin, end = "-----BEGIN TEST PRIVATE KEY-----", "-----END TEST PRIVATE KEY-----"
    source = f"before{begin}QUJD{end}; {begin}REVG" + ("" if unclosed else end + "safe")
    expected = f"before{begin}{REDACTED}{end}; {begin}{REDACTED}" + ("" if unclosed else end + "safe")
    source += newline + ("R0hJ" if unclosed else "ordinary context")
    expected += newline + (REDACTED if unclosed else "ordinary context")
    assert redact_text(source) == expected
    assert scanner_redact_text(source) == expected
    assert redact_text(expected) == expected
    assert scanner_redact_text(expected) == expected


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_private_key_end_then_begin_on_the_same_body_line(newline: str) -> None:
    begin, end = "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"
    source = begin + newline + f"QUJD{end}; {begin}REVG{end}; safe" + newline
    expected = begin + newline + f"{REDACTED}{end}; {begin}{REDACTED}{end}; safe" + newline
    assert redact_text(source) == scanner_redact_text(source) == expected
    assert redact_text(expected) == scanner_redact_text(expected) == expected


def test_nested_begin_marker_cannot_make_an_existing_key_body_public() -> None:
    begin, end = "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"
    source = begin + "\nQUJD" + begin + "REVG" + end + "; safe"
    expected = begin + "\n" + REDACTED + end + "; safe"
    assert redact_text(source) == scanner_redact_text(source) == expected
    assert redact_text(expected) == scanner_redact_text(expected) == expected


def test_finding_and_nested_metadata_are_safe_to_serialize() -> None:
    payload = {
        "scanner": "fixture-detector",
        "rule_id": "generated-credential",
        "message": f"Authorization: Bearer {SHORT_OPAQUE_FIXTURE}",
        "code_snippet": f'password = "{FIXTURE_MATERIAL}"',
        "metadata": {
            "Raw": FIXTURE_MATERIAL,
            "nested": [
                {"authorization": f"Bearer {SHORT_OPAQUE_FIXTURE}"},
                {"safe": f"https://example.invalid/?token={SHORT_OPAQUE_FIXTURE}&mode=safe"},
                [f"client_secret={FIXTURE_MATERIAL}", {"line": 12}],
            ],
            "safe": "detector context",
        },
    }

    redacted = redact_finding_payload(payload)
    serialized = json.dumps(redacted, sort_keys=True)

    assert FIXTURE_MATERIAL not in serialized
    assert SHORT_OPAQUE_FIXTURE not in serialized
    assert redacted["metadata"]["Raw"] == REDACTED
    assert redacted["metadata"]["nested"][0]["authorization"] == REDACTED
    assert redacted["metadata"]["nested"][1]["safe"].endswith(f"?token={REDACTED}&mode=safe")
    assert redacted["metadata"]["nested"][2][1]["line"] == 12
    assert redacted["metadata"]["safe"] == "detector context"


def test_api_and_scanner_finding_wrappers_apply_the_same_redaction() -> None:
    payload = {
        "scanner": "fixture-detector",
        "rule_id": "generated-credential",
        "severity": "high",
        "file_path": "generated/example.py",
        "start_line": 4,
        "end_line": 4,
        "message": f"Authorization: Bearer {SHORT_OPAQUE_FIXTURE}",
        "code_snippet": f"api_key={FIXTURE_MATERIAL}",
        "fingerprint": "a" * 64,
        "metadata": {"nested": [{"client_secret": FIXTURE_MATERIAL}]},
    }

    api_result = redact_finding_payload(payload)
    scanner_result = scanner_redact_finding(ScannerFinding(**payload)).model_dump()

    assert scanner_result["message"] == api_result["message"]
    assert scanner_result["code_snippet"] == api_result["code_snippet"]
    assert scanner_result["metadata"] == api_result["metadata"]


def test_redact_json_does_not_change_non_sensitive_scalar_types() -> None:
    assert redact_json({"verified": True, "line": 12, "score": 4.5, "empty": None}) == {
        "verified": True,
        "line": 12,
        "score": 4.5,
        "empty": None,
    }


def test_nested_metadata_depth_is_bounded_and_matches_scanner() -> None:
    value: Any = "generated leaf"
    for _ in range(80):
        value = [value]

    api_result = redact_json(value)

    assert REDACTED in json.dumps(api_result)
    assert "generated leaf" not in json.dumps(api_result)
    assert scanner_redact_json(value) == api_result


@pytest.mark.parametrize(
    "source",
    [
        None,
        "safe detector context",
        f"Authorization: Bearer {SHORT_OPAQUE_FIXTURE}",
        f"password={FIXTURE_MATERIAL}; mode=safe",
        f"https://fixture:material@example.invalid/?token={SHORT_OPAQUE_FIXTURE}&mode=safe",
        "-----BEGIN TEST PRIVATE KEY-----\nfixture body\n-----END TEST PRIVATE KEY-----\n",
    ],
)
def test_text_redaction_is_idempotent_and_matches_scanner(source: str | None) -> None:
    api_result = redact_text(source)

    assert redact_text(api_result) == api_result
    assert scanner_redact_text(source) == api_result
    assert scanner_redact_text(scanner_redact_text(source)) == api_result


@pytest.mark.parametrize(
    "value",
    [
        {"safe": "context", "password": FIXTURE_MATERIAL},
        {"items": [{"safe": f"Bearer {SHORT_OPAQUE_FIXTURE}"}, {"token": SHORT_OPAQUE_FIXTURE}]},
        [f"api_key={FIXTURE_MATERIAL}", {"verified": True, "line": 12}],
    ],
)
def test_json_redaction_is_idempotent_and_matches_scanner(value: Any) -> None:
    api_result = redact_json(value)

    assert REDACTED == SCANNER_REDACTED
    assert redact_json(api_result) == api_result
    assert scanner_redact_json(value) == api_result
    assert scanner_redact_json(scanner_redact_json(value)) == api_result


@pytest.mark.parametrize(("source", "expected"), [
    ("9.a://user:fixture@example.invalid/path", "9.a://[REDACTED]@example.invalid/path"),
    ("_a://user:fixture@example.invalid", "_a://user:fixture@example.invalid"),
    ("éa://user:fixture@example.invalid", "éa://user:fixture@example.invalid"),
    ("a+b.c-d://user:fixture@host", "a+b.c-d://[REDACTED]@host"),
    ("https://u@@host", "https://[REDACTED]@@host"),
    ("a://one@host b://two@host", "a://[REDACTED]@host b://[REDACTED]@host"),
    ("a.b.c without a URI", "a.b.c without a URI"),
])
def test_url_scheme_boundaries_preserve_redaction_and_scanner_parity(source: str, expected: str) -> None:
    assert redact_text(source) == expected
    assert scanner_redact_text(source) == expected


def test_malformed_pem_labels_and_dotted_schemes_have_bounded_work() -> None:
    program = r'''
import sys
from pathlib import Path
root = Path(sys.argv[1])
sys.path[:0] = [str(root / "apps/api"), str(root / "services/scanner")]
from kodesec_api import redaction as api
from kodesec_scanner import redaction as scanner
label = "PRIVATE KEY " * 32768
malformed_begin = "-----BEGIN " + label
malformed_end = "-----BEGIN PRIVATE KEY-----\n-----END " + label
dotted = "a." * 65536
missing_userinfo_end = "https://" + "!" * 262144
for module in (api, scanner):
    assert module.redact_text(malformed_begin) == malformed_begin
    assert module.redact_text(malformed_end) == "-----BEGIN PRIVATE KEY-----\n[REDACTED]"
    assert module.redact_text(dotted) == dotted
    assert module.redact_text(missing_userinfo_end) == missing_userinfo_end
    assert module.redact_text(dotted + " a://fixture@host").endswith(" a://[REDACTED]@host")
assert not api.contains_explicit_credential(dotted)
assert not api.contains_explicit_credential(missing_userinfo_end)
assert api.contains_explicit_credential(dotted + " a://fixture@host")
'''
    subprocess.run([sys.executable, "-B", "-c", program, str(REPOSITORY_ROOT)],
                   check=True, capture_output=True, timeout=5)
