#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Microfoam - run the code-size gate, or skip it honestly.

The README claims a Cortex-M0 .text figure and 0 B of static RAM. Those numbers
are gated by cmake/size_gate.cmake, which CI runs per core - but that gate was
reachable only from the CI workflow and a shell snippet in docs/quickstart.md,
so the documented local recipe (`cmake -S . -B build && ctest`) silently
omitted the footprint claim entirely. A maintainer changing engine code could
watch the whole suite pass and still land a size regression.

This script is the ctest entry point for that gate. It runs the same
cmake/size_gate.cmake CI runs, once per core named in the baseline file, so the
core list cannot drift from the ceilings. It needs arm-none-eabi-gcc, which
most machines do not have; rather than being absent from ctest in that case -
indistinguishable from the gate having passed - it exits with SKIP_RETURN_CODE
so ctest reports it as skipped, by name.

Exit status:
    0    every core passed the gate
    1    a core failed, or the gate itself could not run
    127  the bare-metal ARM toolchain is not present (ctest reports a skip)

Usage:
    python host/size_gate.py
    python host/size_gate.py --cc /path/to/arm-none-eabi-gcc
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_BASELINE = os.path.join(REPO, "cmake", "size_baseline.txt")
GATE = os.path.join(REPO, "cmake", "size_gate.cmake")

# Must match SKIP_RETURN_CODE on the size_gate ctest in CMakeLists.txt.
SKIP_RETURN_CODE = 127


def baseline_cores(path: str) -> list[str]:
    """Core names in the baseline file, e.g. "cortex-m0 12700".

    Read from the file rather than hard-coded here so the gate cannot run for a
    core the ceilings do not cover, or miss one they do.
    """
    cores: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            m = re.match(r"\s*([A-Za-z0-9_-]+)\s+(\d+)\s*$", line)
            if m:
                cores.append(m.group(1))
    return cores


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--src", default=REPO,
                    help="repository root holding src/ and include/")
    ap.add_argument("--baseline", default=DEFAULT_BASELINE,
                    help="file naming the cores and their .text ceilings")
    ap.add_argument("--cc", default=None,
                    help="arm-none-eabi-gcc to use; default: search PATH")
    ap.add_argument("--work", default=None,
                    help="scratch directory for the object files "
                         "(default: a temporary directory)")
    args = ap.parse_args()

    cc = args.cc or shutil.which("arm-none-eabi-gcc")
    # size_gate.cmake invokes arm-none-eabi-size unqualified, so it must be
    # reachable too. Check both here rather than letting the gate fail at that
    # step, which would look like a size regression instead of a missing tool.
    size_tool = shutil.which("arm-none-eabi-size")

    if not cc or not size_tool:
        missing = "arm-none-eabi-gcc" if not cc else "arm-none-eabi-size"
        print(f"SKIP: {missing} is not on PATH")
        print("      the size gate needs the bare-metal ARM toolchain")
        print("      (Debian/Ubuntu: apt-get install gcc-arm-none-eabi)")
        print("      CI runs this gate per core; see docs/verification.md")
        return SKIP_RETURN_CODE

    cores = baseline_cores(os.path.abspath(args.baseline))
    if not cores:
        print(f"error: no cores found in {args.baseline}", file=sys.stderr)
        return 1

    work_root = args.work
    tmp = None
    if work_root is None:
        tmp = tempfile.TemporaryDirectory(prefix="microfoam-size-")
        work_root = tmp.name

    failures = 0
    try:
        for core in cores:
            cmd = [
                "cmake",
                f"-DCORE={core}",
                f"-DCC={cc}",
                f"-DSRC={os.path.abspath(args.src)}",
                f"-DBASELINE={os.path.abspath(args.baseline)}",
                f"-DWORK={os.path.join(work_root, core)}",
                "-P", GATE,
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            out = (proc.stdout + proc.stderr).strip()
            for line in out.splitlines():
                if line.startswith("-- ") and "text" in line:
                    print(f"  {line[3:].strip()}")
            if proc.returncode != 0:
                failures += 1
                print(f"  XX {core}: size gate failed")
                print(out)
            else:
                print(f"  ok {core}: within the committed ceiling, 0 B static RAM")
    finally:
        if tmp is not None:
            tmp.cleanup()

    if failures:
        print(f"\n{failures} core(s) failed the size gate", file=sys.stderr)
        return 1

    print(f"\n{len(cores)} core(s) passed the size gate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
