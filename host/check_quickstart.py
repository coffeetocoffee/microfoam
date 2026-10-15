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

It also compiles the device snippet verbatim, because a snippet whose values are
right can still be code that does not build - and this one was: it called
mcf_session_run() without mcf_session_open(), on a session that had never been
opened. Reading two integers out of the block could not see that.

Usage:
    python host/check_quickstart.py --cross-test <path to cross_test binary>
                                    [--cc <compiler>]
"""

from __future__ import annotations

import argparse
import glob
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
    """The first fenced code block following the heading `after`.

    The info string after the opening fence (`c`, `sh`) is stripped, so the
    block is exactly the code a reader would copy. Leaving it in made the
    snippet start with a stray `c`, which is not a compile error a reader would
    ever see and is not what the README shows.
    """
    start = text.find(after)
    if start < 0:
        raise SystemExit(f"README: heading not found: {after!r}")
    fence = text.find("```", start)
    if fence < 0:
        raise SystemExit(f"README: no code block after {after!r}")
    end = text.find("```", fence + 3)
    if end < 0:
        raise SystemExit(f"README: unterminated code block after {after!r}")
    body = text[fence + 3:end]
    # Drop the info string: everything up to the first newline.
    nl = body.find("\n")
    if nl >= 0:
        body = body[nl + 1:]
    return body


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


# Everything the device snippet uses but does not define: the HAL, the two
# symbols the snippet reads, and the logging macro. Kept minimal and deliberately
# declared rather than #included so that a snippet which stops declaring its own
# dependencies is still compiled as written.
SNIPPET_PREAMBLE = """\
#include "microfoam.h"
#include <stdint.h>

#define FW_SIZE 0x20000u
#define log_error(fmt, ...) ((void)0)

/* Counted so the epilogue can tell an opened session from an unopened one. */
static unsigned g_hal_calls;

static int32_t stub_erase(void *c, uint32_t a, uint32_t l) { (void)c;(void)a;(void)l; g_hal_calls++; return MCF_OK; }
static int32_t stub_write(void *c, uint32_t a, const uint8_t *p, uint32_t l) { (void)c;(void)a;(void)p;(void)l; g_hal_calls++; return MCF_OK; }
static int32_t stub_read(void *c, uint32_t a, uint8_t *p, uint32_t l) { (void)c;(void)a;(void)p; g_hal_calls++; return (int32_t)l; }
static uint32_t stub_block(void *c) { (void)c; g_hal_calls++; return 1024u; }
static uint32_t stub_pid(void *c) { (void)c; g_hal_calls++; return 0x1234u; }
static uint32_t stub_fw(void *c) { (void)c; g_hal_calls++; return 0x00010000u; }

static const mcf_hal_t g_hal = {
    stub_erase, stub_write, stub_read, stub_block,
    NULL, NULL, NULL, stub_pid, stub_fw, NULL, NULL, NULL
};
"""

# Drives the snippet the way an integrator would, then reports whether the
# snippet's session ever reached the HAL.
#
# That is the observable difference between a snippet that opens its session and
# one that does not, and it is the reason this check is not a compile check. The
# snippet omitted mcf_session_open() entirely; a missing call is legal C, so it
# compiled cleanly while being wrong. But an unopened session is rejected by
# mcf_session_run()'s state guard before the HAL is consulted at all, whereas an
# opened session reaches mcf_session_begin() and asks the HAL for its erase
# granularity before it does anything else. So a HAL call count of zero means
# the snippet never opened its session, whatever it printed.
SNIPPET_EPILOGUE = """\

#include <stdio.h>
int main(void)
{
    static const uint8_t patch[64] = {0};
    apply_update(patch, (uint32_t)sizeof(patch));
    printf("SNIPPET_HAL_CALLS %u\\n", (unsigned)g_hal_calls);
    return 0;
}
"""


def check_snippet_compiles(device: str, cc: str, lib: str,
                          sanitize: str = "") -> int:
    """Compile the README device snippet verbatim, link it, and run it.

    The snippet is the first code a new integrator copies, and nothing compiled
    it: the guard above reads two numbers out of it by regex, and the values can
    be right while the code around them does not build.

    Compiling is necessary but not sufficient, which is worth stating because it
    is the trap this check nearly fell into. The snippet omitted
    mcf_session_open() entirely, and a missing call is legal C, so it compiled
    cleanly while being wrong. The run is what catches that, via the HAL call
    count the epilogue reports.
    """
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "snippet.c")
        with open(src, "w", encoding="utf-8") as f:
            f.write(SNIPPET_PREAMBLE)
            f.write(device)
            f.write(SNIPPET_EPILOGUE)
        exe = os.path.join(tmp, "snippet.exe" if os.name == "nt" else "snippet")
        # MSVC and gcc/clang disagree on nearly every flag, and the tree may be
        # built by either (CMAKE_C_COMPILER is passed in), so the flags are
        # chosen by compiler family rather than assumed. Matching on "cl" would
        # catch "clang" too, which is how the clang CI job came to hand clang a
        # set of /W4 flags. /W4 /WX is the MSVC equivalent of
        # -Wall -Wextra -Werror.
        base = os.path.basename(cc).replace("\\", "/").rsplit("/", 1)[-1].lower()
        base = base[:-4] if base.endswith(".exe") else base
        is_msvc = base in ("cl", "cl2", "_cl", "cl386")
        if is_msvc:
            cmd = [cc, "/nologo", "/W4", "/WX", "/std:c11",
                   "/I", os.path.join(REPO, "include"),
                   src, lib, "/Fe:" + exe]
        else:
            # A library built with MCF_SANITIZE carries sanitizer runtime
            # references, so the snippet linking it needs the same runtime on the
            # command line. Without this the link fails with no diagnostic,
            # because clang reports a missing runtime as an empty error.
            cmd = [cc, "-std=c99", "-Wall", "-Wextra", "-Werror",
                   "-I", os.path.join(REPO, "include")]
            if sanitize:
                cmd.append(f"-fsanitize={sanitize}")
            cmd += [src, lib, "-o", exe]
        rc, out = run(cmd)
        if rc != 0:
            # Report as unchecked, not as a failure, when the compiler cannot be
            # used from here at all. Two cases, both environmental: a library
            # built by a different toolchain than the one named (the link fails
            # on object format, which says nothing about the README), and a
            # compiler that needs environment the caller has not set up (MSVC
            # without INCLUDE cannot find stddef.h). Both are reported as
            # unchecked in the same spirit as the size gate skipping by name,
            # because a false red here trains people to ignore the check.
            unchecked = (
                "corrupt .drectve" in out
                or "file format not recognized" in out
                or "Cannot open include file: 'stddef.h'" in out
            )
            if unchecked:
                print("  -- the device snippet was not compiled: the named C "
                      "compiler is not usable against this build tree "
                      "(toolchain mismatch or unset environment)")
                return 0
            print("  XX the device snippet does not compile or link:")
            for line in out.strip().splitlines()[:12]:
                print(f"       {line}")
            return 1

        proc = subprocess.run([exe], cwd=REPO, capture_output=True, text=True)
        text = proc.stdout + proc.stderr
        calls = re.search(r"SNIPPET_HAL_CALLS\s+(\d+)", text)
        if calls is not None and int(calls.group(1)) > 0:
            print("  ok the device snippet compiles and drives the library")
            return 0
        print("  XX the device snippet compiled but never reached the HAL.")
        print("     It must open its session before run(): an unopened session")
        print("     is refused by run()'s state guard before the HAL is")
        print("     consulted, so zero HAL calls means open() is missing.")
        for line in text.strip().splitlines()[:12]:
            print(f"       {line}")
        return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cross-test", required=True,
                    help="path to the built cross_test binary")
    ap.add_argument("--cc", default=None,
                    help="C compiler used to compile the device snippet "
                         "(default: $CC, else cc)")
    ap.add_argument("--lib", default=None,
                    help="path to the built microfoam library, linked into the "
                         "device snippet so it can be run, not only compiled")
    ap.add_argument("--sanitize", default="",
                    help="sanitizer set the library was built with, e.g. "
                         "'address,undefined'; the snippet needs the same "
                         "runtime to link against it")
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

    # 2b. The snippet must compile, link and drive the library. Values can be
    #     right while the code around them does not build, and this one called
    #     run() without open() - which compiles, so the run is the real check.
    if args.lib is None:
        print("  -- the device snippet was not compiled (no --lib given); "
              "CI passes one, a local run may not")
    else:
        cc = args.cc or os.environ.get("CC") or "cc"
        failures += check_snippet_compiles(cfg["device"], cc, args.lib,
                                           args.sanitize)

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
