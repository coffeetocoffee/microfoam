#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Microfoam - check that documented test counts match what the suites report.

The README's status table states how many checks each suite runs. Those numbers
are prose, and nothing in the build has ever checked them against reality, so
they drift: the LZ4-ratio commit added three checks to host_selftest and left the
README saying "101" while the suite reported 104. A stated number the suite does
not hold is the same defect class the project already fixed twice in the code
(the mcf_ctx_size() false claim, the LZ4 ratio wrong in sign), and the same fix
applies: make the number a thing that is checked, not a thing that is remembered.

This script runs each suite it can find in a build tree, reads the count the
suite reports for itself, and compares it against the README. A suite that is
not built in this configuration, or that skipped work because an optional
dependency is absent, is reported as skipped rather than failed - the counts in
the README assume every optional dependency is present.

Usage:
    python host/check_counts.py --build build

Exit status is 0 when every suite that ran agrees with the README, and 1 on any
mismatch.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
README = os.path.join(REPO, "README.md")
SELFTEST = os.path.join(REPO, "host", "selftest.py")

# suite name -> (kind, count pattern). `kind` decides how the suite is invoked:
#   "binary"  - a compiled test executable in the build tree
#   "vectors" - like binary, but needs the generated lzma_vectors.bin argument
#   "selftest"- the Python host self-test, run from the source tree
SUITES = {
    "microfoam_tests":       ("binary",  r"(\d+) checks"),
    "custom_codec_test":     ("binary",  r"(\d+) checks"),
    "hal_concurrency_test":  ("binary",  r"(\d+) checks"),
    "v2_format_test":        ("binary",  r"(\d+) checks"),
    "sodium_rfc_test":       ("binary",  r"(\d+) checks"),
    "lzma_policy_test":      ("binary",  r"(\d+) checks"),
    "lzma_conformance_test": ("vectors", r"(\d+) passed"),
    "host_selftest":         ("selftest", r"(\d+) checks"),
}


def documented_counts() -> dict[str, int]:
    """Counts the README states, e.g. "| `host_selftest` | 114 checks: ...".

    Only rows that name a count are collected; descriptive rows in the other
    tables do not match and are ignored.
    """
    out: dict[str, int] = {}
    with open(README, "r", encoding="utf-8") as f:
        for line in f:
            m = re.match(r"\s*\|\s*`([a-z0-9_]+)`\s*\|\s*(\d+)\s+checks\b", line)
            if m:
                out[m.group(1)] = int(m.group(2))
    return out


def find_binary(build: str, name: str) -> str | None:
    """Locate a compiled suite in the build tree.

    Single-config generators (Ninja, Makefiles) put binaries at the root of the
    build directory. Multi-config ones (Visual Studio, Xcode) put them in a
    per-configuration subdirectory, so a search of the root alone would find
    nothing and every suite would be reported as "not built" - a guard that
    skips on Windows is exactly the vacuous-green failure this script exists to
    prevent. Both layouts are searched.
    """
    names = (name, name + ".exe")
    roots = [build] + [os.path.join(build, cfg) for cfg in
                       ("Release", "Debug", "RelWithDebInfo", "MinSizeRel")]
    for root in roots:
        for n in names:
            path = os.path.join(root, n)
            if os.path.isfile(path):
                return path
    return None


def run(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
    return proc.stdout + proc.stderr


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--build", required=True,
                    help="build directory holding the compiled test binaries")
    args = ap.parse_args()

    build = os.path.abspath(args.build)
    if not os.path.isdir(build):
        print(f"error: build directory not found: {build}", file=sys.stderr)
        return 2

    documented = documented_counts()
    if not documented:
        print("error: no documented check counts found in the README",
              file=sys.stderr)
        return 2

    mismatches = 0
    checked = 0
    skipped = 0

    for suite in sorted(documented):
        want = documented[suite]
        kind, pattern = SUITES.get(suite, (None, None))
        if kind is None:
            print(f"  ?  {suite}: documented but no runner is known")
            skipped += 1
            continue

        if kind == "selftest":
            cmd = [sys.executable, SELFTEST]
        else:
            binary = find_binary(build, suite)
            if binary is None:
                print(f"  -  {suite}: not built in this configuration")
                skipped += 1
                continue
            cmd = [binary]
            if kind == "vectors":
                vectors = os.path.join(build, "lzma_vectors.bin")
                if not os.path.isfile(vectors):
                    print(f"  -  {suite}: vectors not generated in this build")
                    skipped += 1
                    continue
                cmd.append(vectors)

        output = run(cmd)

        # A suite that skipped work because an optional dependency is absent
        # reports a lower count. The README's numbers assume the full set, so
        # that is a skip here, not a mismatch.
        if "SKIP" in output:
            print(f"  -  {suite}: skipped (optional dependency absent)")
            skipped += 1
            continue

        m = re.search(pattern, output)
        if m is None:
            print(f"  !  {suite}: could not read a count from its output")
            mismatches += 1
            continue

        got = int(m.group(1))
        checked += 1
        if got == want:
            print(f"  ok {suite}: {got} checks (matches the README)")
        else:
            print(f"  XX {suite}: README says {want}, the suite reports {got}")
            mismatches += 1

    print(f"\n{checked} suite(s) checked, {skipped} skipped, "
          f"{mismatches} mismatch(es)")
    return 0 if mismatches == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
