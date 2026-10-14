#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Microfoam - check that documented test counts match what the suites report.

docs/verification.md states how many checks each suite runs. Those numbers are
prose, and nothing in the build has ever checked them against reality, so they
drift: the LZ4-ratio commit added three checks to host_selftest and left the
docs saying "101" while the suite reported 104. A stated number the suite does
not hold is the same defect class the project already fixed twice in the code
(the mcf_ctx_size() false claim, the LZ4 ratio wrong in sign), and the same fix
applies: make the number a thing that is checked, not a thing that is remembered.

This script runs each suite it can find in a build tree, reads the count the
suite reports for itself, and compares it against the document.

A suite that is not built in this configuration, or that skipped work because
an optional dependency is absent, cannot have its documented count checked - the
documented counts assume every optional dependency is present. Those are
reported separately from a mismatch, and by default they do not fail the run:
the default build tree legitimately omits four of the nine suites, and a local
developer should not have to build every optional configuration to check the
five that exist.

The two are deliberately NOT collapsed into one "skipped" bucket, and skip
detection is deliberately strict, because collapsing them is a vacuous green:

  - "not built" means no binary was found. That is a property of the build
    tree, and it is what the default configuration looks like.
  - "skipped" means the binary ran and printed a skip marker. That is a
    property of the suite, and it is what the ed25519 suite looks like when
    libsodium is absent - it reports 29 checks instead of 354, which would be
    a mismatch if the skip were not recognised.
  - A skip marker is a line whose first token is "SKIP:" (leading whitespace
    allowed). Matching a bare "SKIP" substring anywhere in the output would
    also match a failure message that merely contains the word, so a suite
    could report a genuine mismatch and be counted as skipped. The suites that
    skip work print the marker in that form; tests/ed25519_test.c and
    host/selftest.py are the two that do.

In CI, --require-all turns both categories into failures. It is meant to run in
a job that builds every suite with every optional dependency present, where a
missing binary or an unexpected skip is a defect in that job - the way a
sodium job silently losing -DMCF_ENABLE_SODIUM would otherwise pass while
leaving 17 documented checks unverified everywhere.

Usage:
    python host/check_counts.py --build build
    python host/check_counts.py --build build-sodium --require-all

Exit status is 0 when every suite that ran agrees with the document, and 1 on
any mismatch. With --require-all, a suite that is not built or that reported a
skip is also a failure. A suite named in the document with no runner known here
is always a failure: its count is verified nowhere.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DOC = os.path.join(REPO, "docs", "verification.md")
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
    "ed25519_test":          ("binary",  r"(\d+) checks"),
    "lzma_policy_test":      ("binary",  r"(\d+) checks"),
    "lzma_conformance_test": ("vectors", r"(\d+) passed"),
    "host_selftest":         ("selftest", r"(\d+) checks"),
}

# The skip marker: "SKIP:" as the first token on a line, leading whitespace
# allowed. See the module docstring for why this is not a bare substring match.
SKIP_MARKER = re.compile(r"^\s*SKIP:", re.MULTILINE)


def documented_counts(doc: str) -> dict[str, int]:
    """Counts the document states, e.g. "| `host_selftest` | 119 checks: ...".

    Only rows that name a count are collected; descriptive rows in the other
    tables do not match and are ignored.
    """
    out: dict[str, int] = {}
    with open(doc, "r", encoding="utf-8") as f:
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
    ap.add_argument("--doc", default=DEFAULT_DOC,
                    help="document stating the check counts "
                         "(default: docs/verification.md)")
    ap.add_argument("--require-all", action="store_true",
                    help="fail when a documented suite is not built or reports "
                         "a skip; for a CI job that builds every suite with "
                         "every optional dependency present")
    args = ap.parse_args()

    build = os.path.abspath(args.build)
    if not os.path.isdir(build):
        print(f"error: build directory not found: {build}", file=sys.stderr)
        return 2

    doc = os.path.abspath(args.doc)
    if not os.path.isfile(doc):
        print(f"error: document not found: {doc}", file=sys.stderr)
        return 2

    documented = documented_counts(doc)
    if not documented:
        print(f"error: no documented check counts found in {doc}",
              file=sys.stderr)
        return 2

    mismatches = 0
    checked = 0
    skipped = 0
    not_built = 0
    unknown = 0

    for suite in sorted(documented):
        want = documented[suite]
        kind, pattern = SUITES.get(suite, (None, None))
        if kind is None:
            # A suite the document names and this script cannot run. Its
            # documented count is verified nowhere, which is a defect in this
            # script or the document, not a configuration to tolerate.
            print(f"  !! {suite}: documented but no runner is known here")
            unknown += 1
            continue

        if kind == "selftest":
            cmd = [sys.executable, SELFTEST]
        else:
            binary = find_binary(build, suite)
            if binary is None:
                print(f"  -  {suite}: not built in this configuration")
                not_built += 1
                continue
            cmd = [binary]
            if kind == "vectors":
                vectors = os.path.join(build, "lzma_vectors.bin")
                if not os.path.isfile(vectors):
                    print(f"  -  {suite}: not built in this configuration "
                          f"(vectors not generated)")
                    not_built += 1
                    continue
                cmd.append(vectors)

        output = run(cmd)

        # A suite that skipped work because an optional dependency is absent
        # reports a lower count. The documented numbers assume the full set, so
        # that is a skip here, not a mismatch.
        if SKIP_MARKER.search(output):
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
            print(f"  ok {suite}: {got} checks (matches the docs)")
        else:
            print(f"  XX {suite}: docs say {want}, the suite reports {got}")
            mismatches += 1

    print(f"\n{checked} suite(s) checked, {skipped} skipped, "
          f"{not_built} not built, {unknown} with no runner, "
          f"{mismatches} mismatch(es)")

    if args.require_all and (skipped or not_built):
        print(f"--require-all: {skipped} suite(s) skipped and {not_built} not "
              f"built; this job must build every documented suite",
              file=sys.stderr)
    elif not_built or skipped:
        # Not a failure, but not silence either: a green run that checked five
        # of nine suites should say so where the maintainer is looking.
        print("note: the suites above were not verified in this tree; the "
              "counts they hold are checked only where they are built "
              "(see docs/verification.md, and --require-all for CI)")

    if mismatches or unknown:
        return 1
    if args.require_all and (skipped or not_built):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
