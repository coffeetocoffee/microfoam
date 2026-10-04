#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Microfoam - check that the README's quick-start configuration actually works.

The README shows a device snippet (`cfg.block_size`, `cfg.ram_budget`) and a host
command that builds a patch. Those two are a *pair*, and the pairing is a hard
format constraint: the device decodes each LZ4 block into a buffer of
`cfg.block_size` bytes, so a patch whose framing is larger than that window is
rejected as corrupt. Nothing checked the pair, and it drifted -- the documented
device window was 512 while the documented host command framed at the tool's
default 1024, and the documented budget was below the cost of the documented
window. Following the quick start verbatim failed twice over, and the host
command also signed the patch while the documented HAL configured no verifier,
which fails closed.

This script reads the quick-start values out of the README, builds a real patch
with the host tool at the documented framing, and applies it with the C library
at the documented window and budget. The documented configuration must apply
byte-exact. Two deliberately-broken variants must then fail at the exact gates
this format's contract names, so the check cannot pass vacuously.

Usage:
    python host/check_quickstart.py --cross-test <path to cross_test binary>
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
README = os.path.join(REPO, "README.md")
TOOL = os.path.join(REPO, "host", "microfoam.py")
FIXTURES = os.path.join(REPO, "tests", "fixtures")

# Site codes from src/mcf_internal.h, named for the message the guard prints.
SITE_WORKSPACE = 14   # MCF_SITE_WORKSPACE: the budget pre-check refused
SITE_CODEC_DECODE = 17  # MCF_SITE_CODEC_DECODE: a block overran the window


def code_block(text: str, after: str) -> str:
    """The first fenced code block following the heading `after`."""
    start = text.find(after)
    if start < 0:
        raise SystemExit(f"README: heading not found: {after!r}")
    fence = text.find("```", start)
    if fence < 0:
        raise SystemExit(f"README: no code block after {after!r}")
    end = text.find("```", fence + 3)
    if end < 0:
        raise SystemExit(f"README: unterminated code block after {after!r}")
    return text[fence + 3:end]


def parse_readme() -> dict:
    with open(README, "r", encoding="utf-8") as f:
        text = f.read()

    device = code_block(text, "### 1. On the device")
    host = code_block(text, "### 2. On the build host")

    def need(pattern: str, src: str, what: str, default=None):
        m = re.search(pattern, src)
        if m is None:
            if default is not None:
                return default
            raise SystemExit(f"README: could not find {what}")
        return m.group(1)

    block_size = int(need(r"cfg\.block_size\s*=\s*(\d+)", device,
                          "cfg.block_size in the device snippet"))
    ram_budget = int(need(r"cfg\.ram_budget\s*=\s*(\d+)", device,
                          "cfg.ram_budget in the device snippet"))
    block_log2 = int(need(r"--block-log2\s+(\d+)", host,
                          "--block-log2 in the host command",
                          default=str(10)))  # the tool's default when unset

    return {
        "block_size": block_size,
        "ram_budget": ram_budget,
        "block_log2": block_log2,
        "signed": "--key" in host,
        "device": device,
        "host": host,
    }


def run(cmd: list[str]) -> tuple[int, str]:
    proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cross-test", required=True,
                    help="path to the built cross_test binary")
    args = ap.parse_args()

    if not os.path.isfile(args.cross_test):
        print(f"error: cross_test not found: {args.cross_test}", file=sys.stderr)
        return 2

    cfg = parse_readme()
    framing = 1 << cfg["block_log2"]
    failures = 0

    print("README quick start:")
    print(f"  device cfg.block_size = {cfg['block_size']}")
    print(f"  device cfg.ram_budget = {cfg['ram_budget']}")
    print(f"  host framing          = {framing} (--block-log2 {cfg['block_log2']})")

    # 1. The documented pair must satisfy the format's own rule. This is the
    #    cheap, direct statement of the constraint: the device window must be at
    #    least as large as the framing the producer used.
    if cfg["block_size"] < framing:
        print(f"  XX the device window ({cfg['block_size']}) is smaller than the "
              f"host framing ({framing}); the documented patch cannot apply")
        failures += 1
    else:
        print(f"  ok device window {cfg['block_size']} >= host framing {framing}")

    # 2. The quick start must be the minimum that works: an unsigned patch
    #    against the generic HAL sketch. A signed example would need a verifier
    #    the device snippet does not show, and a signed patch is rejected unless
    #    one is supplied -- so signing belongs in its own section, not in the
    #    first example a reader copies.
    if cfg["signed"]:
        print("  XX the quick-start host command signs the patch (--key); a "
              "signed patch fails closed unless the device supplies a verifier, "
              "so the quick start must be unsigned")
        failures += 1
    else:
        print("  ok the quick start is unsigned, matching the generic HAL sketch")

    # 3. Build the documented patch and apply it at the documented settings.
    with tempfile.TemporaryDirectory() as tmp:
        patch = os.path.join(tmp, "patch.bin")
        cmd = [sys.executable, TOOL, "make",
               "--old", os.path.join(FIXTURES, "old.bin"),
               "--new", os.path.join(FIXTURES, "new.bin"),
               "--out", patch,
               "--product", "0x1234", "--version", "0x00020000",
               "--old-version", "0x00010000",
               "--block-log2", str(cfg["block_log2"])]
        if cfg["signed"]:
            key = os.path.join(tmp, "key.priv")
            rc, out = run([sys.executable, TOOL, "keygen",
                           "--private", key,
                           "--public", os.path.join(tmp, "key.pub")])
            if rc != 0:
                print(f"  XX keygen failed:\n{out}")
                return 1
            cmd += ["--key", key]

        rc, out = run(cmd)
        if rc != 0:
            print(f"  XX the documented host command failed:\n{out}")
            return 1

        old = os.path.join(FIXTURES, "old.bin")
        new = os.path.join(FIXTURES, "new.bin")

        def apply_with(block_size: int, budget: int) -> tuple[int, str]:
            return run([args.cross_test, old, new, patch,
                        str(block_size), str(budget)])

        # 3a. The documented configuration must work.
        rc, out = apply_with(cfg["block_size"], cfg["ram_budget"])
        if rc == 0 and "PASS" in out:
            print(f"  ok the documented configuration applies byte-exact "
                  f"(block_size={cfg['block_size']}, "
                  f"ram_budget={cfg['ram_budget']})")
        else:
            print("  XX the documented configuration did not apply:")
            for line in out.strip().splitlines():
                print(f"       {line}")
            failures += 1

        # 3b. Non-vacuity, window too small: the patch must be refused at the
        #     decode stage, which is the failure the LZ4 window rule names
        #     (docs/format-v2.md, "LZ4 stream").
        if cfg["block_size"] > 8:
            rc, out = apply_with(cfg["block_size"] // 2, cfg["ram_budget"])
            if rc != 0 and f"site {SITE_CODEC_DECODE}" in out:
                print(f"  ok a window below the framing is refused at "
                      f"site {SITE_CODEC_DECODE} (decode)")
            else:
                print("  XX halving the window did not fail at the decode "
                      "stage; the guard is not testing what it claims")
                failures += 1

        # 3c. Non-vacuity, budget too small: refused before any allocation.
        rc, out = apply_with(cfg["block_size"], framing)
        if rc != 0 and f"site {SITE_WORKSPACE}" in out:
            print(f"  ok a budget below the cost is refused at "
                  f"site {SITE_WORKSPACE} (workspace), before allocating")
        else:
            print("  XX a too-small budget did not fail at the workspace "
                  "stage; the guard is not testing what it claims")
            failures += 1

    print(f"\n{0 if failures else 1} quick-start configuration(s) verified, "
          f"{failures} problem(s)")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
