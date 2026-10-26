"""Verify the license texts shipped with the locked scanner binaries."""

import argparse
import hashlib
import json
from pathlib import Path


NOTICES = {
    "trivy.NOTICE": (
        "trivy",
        "https://raw.githubusercontent.com/aquasecurity/trivy/40c73e5d6166dcc0346a1ab4e94499d1572854e4/LICENSE",
        "aed9bc6dab87c6f6567d20bf0f5c0433a8ccd3ad7873322cf79b9244eb720a1f",
    ),
    "opengrep.COPYRIGHT": (
        "opengrep",
        "https://raw.githubusercontent.com/opengrep/opengrep/3bd8e95fea8992e15ea2451286dd1cb145e57add/LICENSE",
        "0f90eaca8e598c6c67a6cda7beb4470518fb2dababc996b3898344d380769aca",
    ),
}


def verify(lock_path: Path, directory: Path) -> None:
    tools = json.loads(lock_path.read_text())["tools"]
    expected = {"README.md"}
    for tool in tools:
        name = tool["id"]
        if not isinstance(name, str) or not name.isascii() or not name.isalnum():
            raise ValueError("invalid scanner license name")
        filename = f"{name}.txt"
        if filename in expected:
            raise ValueError("duplicate scanner license name")
        expected.add(filename)
        license = tool["binary"]["license"]
        path = directory / filename
        if license["state"] != "verified" or path.is_symlink() or not path.is_file():
            raise ValueError(f"missing verified license text: {name}")
        if not 0 < path.stat().st_size <= 128 * 1024:
            raise ValueError(f"license text size out of bounds: {name}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != license["source_sha256"]:
            raise ValueError(f"license text differs from scanner lock: {name}")
    for filename, (name, source_ref, digest) in NOTICES.items():
        matches = [tool for tool in tools if tool["id"] == name]
        if len(matches) != 1 or matches[0]["binary"]["license"]["source_ref"] != source_ref:
            raise ValueError(f"scanner notice requires review for the selected source: {name}")
        path = directory / filename
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 128 * 1024:
            raise ValueError(f"missing verified scanner notice: {name}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f"scanner notice differs from reviewed source: {name}")
        expected.add(filename)
    if {path.name for path in directory.iterdir()} != expected:
        raise ValueError("scanner license directory differs from locked tool set")
    readme = directory / "README.md"
    if readme.is_symlink() or not readme.is_file():
        raise ValueError("scanner license index must be a regular file")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lock", type=Path)
    parser.add_argument("licenses", type=Path)
    args = parser.parse_args()
    verify(args.lock, args.licenses)
