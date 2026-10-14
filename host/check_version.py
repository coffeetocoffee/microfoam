#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check that every place the release version is written agrees.

The release procedure touches seven files by hand: CMakeLists.txt,
pyproject.toml, conanfile.py, host/microfoam.py, the MCF_VERSION_* macros in
include/microfoam.h, the spec table in README.md, and the reconciliation note
in docs/architecture.md. That is seven chances to bump five and forget two, and
the failure is silent in the worst way -- the build succeeds, the tests pass,
and `pip install microfoam` reports a version the firmware header contradicts.
Nothing downstream compares the two, so the drift survives until a user does.

This script is the missing comparison. It exits non-zero and names the offending
file when the sites disagree, and it is registered as the `version_check` CTest
so every build runs it. With --tag-check it additionally compares the tree
version against an exact git tag on HEAD, which catches the "bumped three sites
but never tagged" half of the same mistake.

Usage:
    check_version.py [--root DIR] [--tag-check]
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# Each site is (label, relative path, regex with one capturing group). The regex
# is anchored tightly enough that an unrelated number cannot satisfy it, so a
# rewrite that renames or reorders the site fails loudly here instead of
# silently passing on a stale group.
SITES = [
    ("CMakeLists.txt", "CMakeLists.txt", r"^\s*VERSION\s+(\d+\.\d+\.\d+)\s*$"),
    ("pyproject.toml", "pyproject.toml", r'^version\s*=\s*"(\d+\.\d+\.\d+)"\s*$'),
    ("conanfile.py", "conanfile.py", r'^\s*version\s*=\s*"(\d+\.\d+\.\d+)"\s*$'),
    ("host/microfoam.py", "host/microfoam.py", r'^TOOL_VERSION\s*=\s*"(\d+\.\d+\.\d+)"\s*$'),
    ("include/microfoam.h", "include/microfoam.h", r"^#define\s+MCF_VERSION_MAJOR\s+(\d+)u\s*$"),
    ("include/microfoam.h (minor)", "include/microfoam.h", r"^#define\s+MCF_VERSION_MINOR\s+(\d+)u\s*$"),
    ("include/microfoam.h (patch)", "include/microfoam.h", r"^#define\s+MCF_VERSION_PATCH\s+(\d+)u\s*$"),
    ("README.md", "README.md", r"`(\d+\.\d+\.\d+)`"),
    ("docs/architecture.md", "docs/architecture.md", r"reconciled with the `(\d+\.\d+\.\d+)` tree"),
]


def read_site(root: Path, label: str, rel: str, pattern: str) -> str | None:
    """Return the version this site declares, or None if it declares nothing."""
    path = root / rel
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return f"<unreadable: {exc}>"
    rx = re.compile(pattern, re.MULTILINE)
    found = [m.group(1) for m in rx.finditer(text)]
    if not found:
        return None
    distinct = sorted(set(found))
    if len(distinct) > 1:
        # One file disagreeing with itself is just as fatal as two files
        # disagreeing; report it here rather than picking one silently.
        return "<conflicting: " + ", ".join(distinct) + ">"
    return distinct[0]


def git_tags_pointing_at_head(root: Path) -> list[str]:
    """Exact version tags on HEAD. Non-exact tags (v1.9.8-rc1) are ignored."""
    try:
        out = subprocess.run(
            ["git", "describe", "--tags", "--exact-match", "HEAD"],
            cwd=root, capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if out.returncode != 0:
        return []
    return [out.stdout.strip()]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=".", help="repository root (default: cwd)")
    ap.add_argument("--tag-check", action="store_true",
                    help="also require an exact git tag on HEAD to match the tree version")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()

    found: dict[str, str] = {}
    missing: list[str] = []
    for label, rel, pattern in SITES:
        value = read_site(root, label, rel, pattern)
        if value is None:
            missing.append(label)
        else:
            found[label] = value

    if missing:
        print("version sites no longer declare a version:", file=sys.stderr)
        for label in missing:
            print(f"  {label}: no match", file=sys.stderr)
        print("If a site was intentionally removed, drop it from SITES in "
              f"{Path(__file__).name} so this failure cannot be silenced by "
              "editing a file and forgotten here.", file=sys.stderr)
        return 1

    # The three header macros are one logical site; fold them before comparing
    # so "1", "9", "8" do not read as three separate versions.
    versions = dict(found)
    header = "{}.{}.{}".format(found["include/microfoam.h"],
                               found["include/microfoam.h (minor)"],
                               found["include/microfoam.h (patch)"])
    for key in ("include/microfoam.h", "include/microfoam.h (minor)",
                "include/microfoam.h (patch)"):
        versions[key] = header

    distinct = sorted(set(versions.values()))
    if len(distinct) > 1:
        print("version drift between release sites:", file=sys.stderr)
        for label in sorted(versions, key=lambda k: (versions[k], k)):
            mark = "  " if versions[label] == distinct[0] else "->"
            print(f"{mark} {label}: {versions[label]}", file=sys.stderr)
        print(f"\nAll sites must read the same version; found {len(distinct)}: "
              f"{', '.join(distinct)}", file=sys.stderr)
        return 1

    version = distinct[0]
    print(f"version sites agree: {version}")

    if args.tag_check:
        tags = git_tags_pointing_at_head(root)
        if tags:
            expected = "v" + version
            mismatched = [t for t in tags if t != expected]
            if mismatched:
                print(f"HEAD is tagged {', '.join(tags)} but the tree says "
                      f"{version} (expected a tag of {expected}).",
                      file=sys.stderr)
                return 1
            print(f"HEAD tag {expected} matches the tree version")
        else:
            print("HEAD carries no exact version tag (unreleased tree); "
                  "tree version check only")

    return 0


if __name__ == "__main__":
    sys.exit(main())