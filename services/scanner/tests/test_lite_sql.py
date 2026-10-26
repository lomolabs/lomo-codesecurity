from pathlib import Path
import time

import pytest

from kodesec_scanner.external import ExecutionControl, RunCancelled
from kodesec_scanner.lite_sql import looks_like_constructed_sql
from kodesec_scanner.rules import scan_text_file, _fingerprint


@pytest.mark.parametrize("name,text,expected", [
    ("source.py", 'q = f"SELECT id FROM accounts WHERE id={id}"', True),
    ("source.py", 'q = rf"SELECT id FROM accounts WHERE id={id}"', True),
    ("source.py", r'q = rf"SELECT id FROM accounts WHERE id=\{id}"', True),
    ("source.py", r'q = fr"SELECT id FROM accounts WHERE id=\{id}"', True),
    ("source.py", r'q = f"SELECT id FROM accounts WHERE id=\{id}"', True),
    ("source.py", r'q = "SELECT id FROM accounts WHERE id=\{id}".format(id=id)', True),
    ("source.py", r'q = rf"SELECT id FROM accounts WHERE id=\{{literal}}"', False),
    ("source.py", r'q = "SELECT id FROM accounts WHERE id=\{{literal}}".format(id=id)', False),
    ("source.py", 'q = "SELECT id FROM accounts WHERE id=%s" % id', True),
    ("source.py", 'q = "SELECT id FROM accounts WHERE id=%(id)s" % values', True),
    ("source.py", 'q = "SELECT id FROM accounts WHERE id=%04d" % id', True),
    ("source.py", 'q = "SELECT id FROM accounts WHERE id={id}".format(id=id)', True),
    ("source.py", 'q = "SELECT id FROM accounts WHERE id={}".format(id)', True),
    ("source.py", 'q = f"INSERT INTO accounts VALUES ({id})"', True),
    ("source.py", 'q = f"UPDATE accounts SET name={name}"', True),
    ("source.py", 'q = f"DELETE FROM accounts WHERE id={id}"', True),
    ("source.js", 'const q = `SELECT id FROM accounts WHERE id=${id}`;', True),
    ("source.ts", 'const q = `SELECT id FROM accounts WHERE id=${id}`;', True),
    ("source.py", 'db.execute("SELECT id FROM accounts WHERE id=%s", (id,))', False),
    ("source.py", 'db.execute("SELECT id FROM accounts WHERE id=:id", {"id": id})', False),
    ("source.py", 'q = "SELECT \'{literal}\' FROM accounts"', False),
    ("source.py", 'q = f"SELECT \'{{literal}}\' FROM accounts"', False),
    ("source.py", 'q = "SELECT \'{{literal}}\' FROM accounts".format(id)', False),
    ("source.py", 'q = "SELECT id FROM accounts"; other = "{}".format(id)', False),
    ("source.py", 'q = "SELECT id FROM accounts"; other = f"{id}"', False),
    ("source.py", 'q = "SELECT %% FROM accounts" % id', False),
    ("source.py", 'q = "SELECT id FROM accounts WHERE id=%s" % # no operand', False),
    ("source.py", 'q = "SELECT id FROM accounts WHERE id={id}".formatting(id)', False),
    ("source.py", 'q = f"SELECT id FROM accounts WHERE id={}"', False),
    ("source.js", 'db.query("SELECT id FROM accounts WHERE id=$1", [id]);', False),
    ("source.js", r'const q = `SELECT id FROM accounts WHERE id=\${id}`;', False),
    ("source.js", '// const q = `SELECT id FROM accounts WHERE id=${id}`;', False),
    ("source.py", '# q = f"SELECT id FROM accounts WHERE id={id}"', False),
    ("source.py", 'safe(); # q = f"SELECT id FROM accounts WHERE id={id}"', False),
    ("source.js", 'safe(); // const q = `SELECT id FROM accounts WHERE id=${id}`;', False),
])
def test_sql_construction_is_bound_to_its_literal_and_language(
    tmp_path: Path, name: str, text: str, expected: bool,
) -> None:
    findings = scan_text_file(tmp_path, tmp_path / name, text + "\n", enabled_tools={"sast-lite"})
    sql = [finding for finding in findings if finding.rule_id == "sast.sql_string_format"]
    assert len(sql) == int(expected)
    for finding in sql:
        assert finding.severity == "medium"
        assert finding.fingerprint == _fingerprint("sast.sql_string_format", name, 1, text + "\n")
        assert finding.start_line == finding.end_line == 1


@pytest.mark.parametrize("body", ["SELECT " * 140000, "x" * 1000000, "'x' " * 240000])
def test_permitted_long_sql_inputs_have_bounded_work_and_cancellation(body: str) -> None:
    text = 'f"' + body + '{value}"'
    assert len(text.encode()) <= 1048576
    started = time.monotonic()
    assert looks_like_constructed_sql(text, True, lambda: None) is False
    assert time.monotonic() - started < 3
    control = ExecutionControl.with_timeout(10)
    calls = 0

    def cancel_during_scan():
        nonlocal calls
        calls += 1
        if calls == 6:
            control.cancel_event.set()
        control.checkpoint()

    with pytest.raises(RunCancelled):
        looks_like_constructed_sql(text, True, cancel_during_scan)
