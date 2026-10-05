# Microfoam

**Tiny bubbles. Tiny footprint. Full-strength upgrade.**

A firmware delta-update library for resource-constrained microcontrollers. Ship only the
difference between two firmware versions, and reconstruct the full image on the device — in a
few kilobytes of RAM, with no heap and no RTOS.

[![CI](https://github.com/coffeetocoffee/microfoam/actions/workflows/ci.yml/badge.svg)](https://github.com/coffeetocoffee/microfoam/actions/workflows/ci.yml)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)
![Language: C99](https://img.shields.io/badge/language-C99-blue.svg)
[![RAM: 868 B, no heap](https://img.shields.io/badge/RAM-868%20B%20%C2%B7%20no%20heap-success.svg)](#verified-footprint)

| | |
|---|---|
| **Footprint** | **868 B RAM** (LZ4, 256 B block), no heap · **12,358 B ROM** on Cortex-M0 |
| **Patch size** | typically **1–15%** of the image |
| **Formats** | **MFP1** (compact) and **MFP2** (signed + encrypted, per-record) |
| **Build** | C99, MIT · `<stdint.h>`, `<stddef.h>`, `<string.h>` only · no heap, no RTOS |
| **Verified targets** | arm-none-eabi-gcc (shipping size gate): Cortex-M0, M3, M4, M7; upstream clang `--target=arm-none-eabi` (portability proxy): the same four cores, full strict warning set. Licensed armclang and IAR builds remain unverified. |
| **Status** | `1.9.5` |

> [!NOTE]
> **Best for** small embedded devices and constrained links — BLE, LoRa, infrared, a
> 9600-baud serial line — where sending a whole image is too slow or too expensive.
> **Not** a transport, an encryption-only product, or a bootloader replacement. Microfoam
> reconstructs and verifies an image on the device; getting the patch there, and deciding when
> to activate it, is yours.

**Contents**

[Why](#why) ·
[Quick start](#quick-start) ·
[Choose your profile](#choose-your-profile) ·
[Design commitments](#design-commitments) ·
[The HAL contract](#the-hal-contract) ·
[Signature verification](#signature-verification) ·
[Codecs](#codecs) ·
[Proof, not promises](#proof-not-promises) ·
[Building and testing](#building-and-testing) ·
[Explore the repo](#explore-the-repo) ·
[Licence](#licence)

---

## Why

- **Send the difference, not the image.** A patch is typically 1–15% of the image. For a
  realistic maintenance change to a 35 KB firmware — a few functions rewritten, a version
  string bumped — the whole update is **719 bytes, 2.0%** of the image.
- **Runs where the alternatives cannot.** Comparable libraries need 10–20 KB of heap for a
  decompressor whose probability tables alone have a ~15.6 KB floor. Microfoam makes the codec
  pluggable and ships a small one by default, which moves the primary target from *"Cortex-M3
  with a 20 KB heap"* down to **a Cortex-M0 with 4 KB** — and the whole library fits an 8 KB
  part.
- **Two profiles, one engine.** MFP1 is a compact patch, unsigned or signed. MFP2 adds Ed25519ph
  authentication and XChaCha20-Poly1305 encryption, record by record, streaming so the whole
  decrypted payload is never resident. Both hand the reconstructed delta to the same engine.

<details>
<summary><b>Why "microfoam"?</b></summary>

Microfoam is the thin layer of bubbles on a latte — roughly one percent of the volume and all
of the texture. That is the design target: the smallest possible resident cost, carrying the
whole capability. It is also the right expectation to set for anyone told this replaces a
library that wanted 10–20 KB of heap. The footprint is the point.

</details>

---

## Quick start

### 1. On the device

Implement the HAL — everything platform-specific lives there — then run a session. The two
values to get right are `block_size` and `ram_budget`; both must agree with the patch.

```c
#include "microfoam.h"

static mcf_config_t cfg;
MCF_SESSION_DECLARE(session);

cfg.hal         = &g_hal;                        /* your callbacks; see the HAL contract */
cfg.patch       = patch;
cfg.patch_size  = patch_size;
cfg.old         = (const uint8_t *)0x08000000u;  /* running image */
cfg.old_size    = FW_SIZE;
cfg.dst_addr    = 0x08020000u;                   /* staging slot    */
cfg.codec       = MCF_CODEC_AUTO;
cfg.block_size  = 1024u;   /* must be >= the patch's framing block size */
cfg.ram_budget  = 4096u;   /* >= 2*block_size + the codec's own state   */

if (mcf_session_run(session) != MCF_OK) {
    /* Every failure is a distinct code. mcf_session_strerror() names it. */
    log_error("microfoam: %s", mcf_session_strerror(mcf_session_status(session)));
}
mcf_session_close(session);
```

A complete, commented HAL for a generic Cortex-M part — flash callbacks, workspace, and how to
choose `block_size`, `ram_budget` and the codec — is in
**[docs/quickstart.md](docs/quickstart.md)**.

### 2. On the build host

```sh
python host/microfoam.py make \
    --old old.bin --new new.bin --out patch.bin \
    --product 0x1234 --version 0x00020000 --old-version 0x00010000 \
    --block-log2 10

python host/microfoam.py inspect patch.bin
python host/microfoam.py apply   --old old.bin --patch patch.bin --out out.bin
```

`--block-log2 10` frames each LZ4 block to 1024 bytes, matching the device snippet's
`cfg.block_size`. The two are a pair: a patch framed larger than the device's window is
rejected as corrupt, so the values must agree. The host tool also caps its framing at the
image, so an image smaller than the framing still yields an applicable patch. See
[the LZ4 stream](docs/format-v2.md#lz4-stream) for the rule.

`make` is deterministic: identical inputs produce a byte-identical patch. No timestamps, no
randomness. (The encrypted `make --v2` profile is the exception — it draws a fresh random
nonce prefix per patch, because reusing one with the same key would repeat every AEAD nonce.)

**Choose your path**

| Profile | Host command | Device needs |
|---|---|---|
| **Unsigned MFP1** (the default) | `make …` | nothing extra — the generic HAL above |
| **Signed MFP1** | `make … --key mfkey.priv` | a verifier: `-DMCF_ENABLE_ED25519=ON` and `cfg.verify` |
| **Signed + encrypted MFP2** | `make … --v2 --key mfkey.priv` | `-DMCF_ENABLE_ED25519=ON` and an XChaCha20-Poly1305 provider |

<details>
<summary><b>Signing a patch</b></summary>

Generate a key and pass it to `make`:

```sh
python host/microfoam.py keygen --private mfkey.priv --public mfkey.pub
python host/microfoam.py make --old old.bin --new new.bin --out patch.bin \
    --product 0x1234 --version 0x00020000 --old-version 0x00010000 \
    --key mfkey.priv
python host/microfoam.py verify patch.bin --pub mfkey.pub
```

A signed patch is **rejected unless the device supplies a verifier** — that is the fail-closed
property, not an oversight. The generic HAL sketch above configures none, so it applies
unsigned patches only. To accept signed patches, set `verify` (or `cfg.verify`) to a vetted
Ed25519 provider; see [Signature verification](#signature-verification).

</details>

### 3. Or install the host tool

```sh
pip install .            # provides the `microfoam` command
microfoam --version
microfoam make --old old.bin --new new.bin --out patch.bin \
    --product 0x1234 --version 0x00020000 --old-version 0x00010000
```

Signing is an extra: `pip install .[mfp1]` for MFP1 Ed25519 (`cryptography`) and
`pip install .[mfp2]` for MFP2 signed/encrypted patches (`pynacl`). LZ4 and raw patches need
nothing beyond the standard library. A minimal **Conan 2** recipe (`conanfile.py`) covers the
core library, with both optional paths off; consumers enable them explicitly.

---

## Choose your profile

| Decision | Options | Where to look |
|---|---|---|
| **Format** | MFP1 (compact) · MFP2 (signed + encrypted, per-record) | [format-v2-design.md](docs/format-v2-design.md) · [mfp2-streaming-decryption-design.md](docs/mfp2-streaming-decryption-design.md) |
| **Codec** | LZ4 (default) · raw · LZMA (opt-in) | [Codecs](#codecs) · [format-v2.md](docs/format-v2.md) |
| **Verifier** | built-in Ed25519 (no external crypto) · libsodium adapter | [Signature verification](#signature-verification) |
| **Memory** | heapless (static workspace) · allocator-backed | [quickstart.md](docs/quickstart.md) · [architecture §10](docs/architecture.md#10-memory-model-and-budget) |
| **Resume** | off (default) · opt-in journal | [architecture §15](docs/architecture.md#15-power-fail-resilience-and-recovery) |

---

## Design commitments

The properties the library is built around — each exists because its absence causes silent
field failures in comparable libraries. Full rationale in
[docs/architecture.md](docs/architecture.md).

- **Every failure is reported, specifically.** There are 18 status codes; zero means success
  and means only success. A failed flash program is `MCF_E_FLASH`, never a full-length,
  silently corrupt image. ([§9.2](docs/architecture.md#92-error-model-p1))
- **The memory contract is explicit and enforced.** `mcf_ctx_size()` returns the exact dynamic
  workspace a configuration will allocate, and the suite asserts that number against the
  allocator's real request; a patch over `ram_budget` is refused *before anything is
  allocated*. ([§10](docs/architecture.md#10-memory-model-and-budget))
- **The caller owns all state.** No mutable globals; a session is a caller-provided
  `mcf_session_t`, so the library is reentrant and works from a static buffer on a system with
  no heap. ([§9.3](docs/architecture.md#93-context-ownership-p3))
- **Long operations are steppable.** `mcf_session_step()` does at most one block of work and
  returns, so a watchdog can be serviced between steps; aborting is a clean `MCF_E_ABORTED`.
  ([§9.6](docs/architecture.md#96-step-wise-state-machine-p7))
- **The flash contract is enforced, not assumed.** The library never issues an unaligned or
  block-crossing erase or program, and reads every programmed region back and compares it.
  ([§12](docs/architecture.md#12-flash-write-contract))
- **Updates can be authenticated, and the choice is explicit.** Product binding and
  anti-rollback are always enforced; signature verification fails closed — a patch that claims
  to be signed is rejected if no verifier is available, never accepted unverified. An
  *unsigned* patch carries no signature to check and is applied by default, so a product that
  must reject them configures a verifier. ([§14](docs/architecture.md#14-security-model))

---

## The HAL contract

Six callbacks are required on every path — `flash_erase`, `flash_write`, `flash_read`,
`flash_block_size`, `get_product_id`, `get_fw_version` — plus `alloc`/`free` unless you supply
a static workspace. Everything else is optional. This is the entire platform dependency.

| Callback | Required | Contract |
|---|---|---|
| `flash_erase(ctx, addr, len)` | yes | `len` is always a whole multiple of `flash_block_size()`, and `addr` is aligned to it. Return `MCF_OK` on success or a negative status on failure. |
| `flash_write(ctx, addr, p, len)` | yes | Never crosses an erase-block boundary. May be called repeatedly for one logical block. Return `MCF_OK` on success or a negative status on failure; positive byte counts are not valid. |
| `flash_read(ctx, addr, p, len)` | yes | Used for read-back verification after programming and for the whole-image CRC read at finish, which always reads the destination back from flash rather than trusting the buffer just written. Required on every path, including a write-only region. Return exactly `len` on success or a negative status on failure. The old-image `old_read` callback follows the same exact-count rule. |
| `flash_block_size(ctx)` | yes | Erase granularity in bytes. Must be a power of two. |
| `alloc` / `free` | unless static | Returning `NULL` is reported as `MCF_E_NOMEM`. |
| `get_product_id`, `get_fw_version` | yes | Device-provisioned identity and running version. |
| `flash_is_readonly` | no | Non-zero skips the per-write read-back compare. It does **not** remove the need for `flash_read`: the whole-image CRC at finish still reads the destination back. |
| `verify` | no | Signature verifier. `NULL` means no verifier available → signed patches rejected. |
| `log` | no | Diagnostics. |

**No heap?** Set `workspace` and `workspace_size` on each session's `mcf_config_t`; each
simultaneously active session must receive a distinct buffer.

A complete, commented HAL implementation is in [docs/quickstart.md](docs/quickstart.md); the
full contract and its rationale are in
[architecture §12](docs/architecture.md#12-flash-write-contract).

---

## Signature verification

Two providers ship, and neither is in a default build. Both are opt-in and supported.

| | Built-in | libsodium adapter |
|---|---|---|
| Enable with | `-DMCF_ENABLE_ED25519=ON` | `-DMCF_ENABLE_SODIUM=ON` |
| External dependency | **none** | libsodium |
| Heap | **none** | the context's allocator, for one temporary message buffer |
| Signed-message handling | **streamed** | concatenated into one buffer |
| Callbacks | `mcf_ed25519_verify`, `mcf_ed25519ph_verify3` | `mcf_sodium_verify`, `mcf_sodium_ed25519ph_verify3` |

```c
#include "microfoam_ed25519.h"

static mcf_ed25519_ctx_t g_verify = { g_public_key };   /* 32 bytes, immutable */

cfg.verify     = mcf_ed25519_verify;      /* MFP1: plain Ed25519    */
cfg.verify_ctx = &g_verify;
/* MFP2 takes the same context through mcf_v2_config_t.verify, with
 * mcf_ed25519ph_verify3 as the function. */
```

- The built-in verifier implements plain **Ed25519** (RFC 8032 §5.1) for MFP1 and
  **Ed25519ph** for MFP2, and streams the signed message, so verifying a patch needs **no
  allocator and no buffer proportional to the patch**. It costs **≈ 6.3 KB of flash** on
  Cortex-M4 with `--gc-sections` (`.text` 4,342 B + `.rodata` 1,928 B, 0 B static RAM).
- **The field and group arithmetic is vendored, not written here.** It is
  [TweetNaCl](third_party/tweetnacl/README.md) — public domain, ~700 lines, no `__int128` —
  which is the reviewed part; `src/mcf_sha512.c` and `src/mcf_ed25519.c` are ours. An earlier
  from-scratch verifier was written for this project and **rejected** after twelve defects, one
  permissive; it remains in [`contrib/ed25519-wip/`](contrib/ed25519-wip/README.md) as a record
  and **must not be linked into production.**
- **The `S < L` canonicality check is enforced, and it is load-bearing.** TweetNaCl's own
  `crypto_sign_open` does not enforce it and libsodium does, so a signature carrying `S + L`
  satisfies the group equation and is accepted by one while the other rejects it. Both halves
  were checked by execution, and deleting the check makes the test fail.
- **Domain separation is real** — an Ed25519ph signature is refused by the plain-Ed25519 path
  and vice versa, asserted in both directions.
- **The evidence is differential, not just round-trip.** With libsodium also built,
  `ed25519_test` asserts both implementations return the **same verdict for every case**,
  including signatures libsodium generated over messages neither implementation chose.

Design and provenance: [architecture §14.3](docs/architecture.md#143-signature-algorithm-selection) ·
[third_party/tweetnacl/README.md](third_party/tweetnacl/README.md).

---

## Codecs

| Codec | Decoder state | Payload vs LZMA | Default |
|---|---|---|---|
| **LZ4** | ~16 B | ~1.7× at the default 1 KB block | **yes** |
| LZMA | probability table + dictionary | baseline | no (`-DMCF_ENABLE_LZMA=ON`) |
| Raw | 16 B | delta verbatim | no (`--codec raw`) |

**LZ4 is the default because it buys RAM, not bytes.** It decodes in ~16 B of state rather than
an LZMA probability table, but on the same delta it emits a **larger** payload — on the suite's
35 KB fixture, **1.67×** LZMA's at the default 1 KB block (1,934 B vs 1,160 B). `host_selftest`
measures and pins this figure, so it cannot drift. **Raw** is the delta stream passed through
untouched — no framing, no properties, no per-block headers — for when a codec's headers cost
more than they save. **LZMA** is opt-in because its probability table is an unconditional RAM
floor this architecture exists to remove; when enabled it is fully supported and CI-tested, and
its 9-byte properties block carries the exact decompressed length, which is what makes
truncation detectable.

> [!IMPORTANT]
> **The LZ4 decode window is a hard format constraint.** The device decodes each block into a
> single fixed buffer (`cfg.block_size` clamped to `new_size`), so a producer must frame within
> the image and the device window must be at least the framing. The host tool does both
> automatically. See [the LZ4 stream](docs/format-v2.md#lz4-stream).

Codec parameter policy, workspace formulas and the encode/verify path are in
[docs/format-v2.md](docs/format-v2.md); the LZMA decoder's history is in
[docs/lzma-history.md](docs/lzma-history.md); custom codecs and the codec vtable are in
[architecture §7.3](docs/architecture.md#73-l1--pluggable-codec).

---

## Proof, not promises

The build is warning-clean under `-Wall -Wextra -Wconversion -Wsign-conversion -Werror`, and
the standard configurations pass in both Debug and Release. What the suites actually check:

| Suite | Checks | What it proves |
|---|---|---|
| `microfoam_tests` | 110 checks | round trip, the `mcf_ctx_size()` cost query, resume, the BSDIFF43 seek ordering, small-image framing, and fault injection at every stage |
| `custom_codec_test` | 46 checks | caller-owned codec descriptors, per-session table isolation, and failure propagation at init, decode, and finish |
| `hal_concurrency_test` | 27 checks | two sessions driven interleaved through the whole decode |
| `v2_format_test` | 45 checks | MFP2 header/TLV/record-framing rules, plus a deterministic mutation/property loop |
| `host_selftest` | 119 checks | host round-trips, the measured LZ4-vs-LZMA ratio, format-layout agreement, signing, the MFP2 KAT, and host-side tamper cases |
| `sodium_rfc_test` | 17 checks | published Ed25519 / Ed25519ph / XChaCha20-Poly1305 vectors and adapter tamper cases *(with `MCF_ENABLE_SODIUM=ON`)* |
| `ed25519_test` | 354 checks | the built-in verifier: SHA-512 digests, RFC 8032 §7.1/§7.3 vectors, a negative matrix, the `S + L` case, domain separation, and a **differential** against libsodium *(with `MCF_ENABLE_ED25519=ON`)* |
| `lzma_conformance_test` | 335 checks | 67 liblzma vectors at five block sizes each *(with `MCF_ENABLE_LZMA=ON`)* |
| `lzma_policy_test` | 15 checks | dictionary and `lc+lp` policy rejections with their exact status and stage *(with `MCF_ENABLE_LZMA=ON`)* |

Also in the ctest matrix: `v2_fuzz_smoke` (the parser property oracle, portable), `cross_test` /
`cross_test_raw` / `cross_test_lzma` (host-tool patches applied by the C library, byte-exact),
`mfp2_host_to_session` (a PyNaCl signed+encrypted patch rejecting 14 tamper variants with zero
flash mutations, each pinned to its exact status), `documented_counts` (this table against what
the suites report), and `quickstart_config` (the quick-start pair is runnable, not just
plausible).

> [!IMPORTANT]
> **The cross test is the one that matters most.** A library verified only against its own
> encoder proves nothing about the format. Two independently written implementations agreeing
> on a real 35 KB firmware pair is evidence.

**The MFP2 parser** is the one surface that consumes attacker-controlled bytes, so it is held to
a property contract rather than a list of cases. **Fault injection** covers erase failure,
program failure, *program succeeding but storing the wrong bytes*, truncated payloads, flipped
bits, wrong product, downgrade attempts, base version mismatch, over-budget workspace, unknown
codec, future format version, wrong new-image CRC, abort, and signed-without-verifier — each
asserting a *specific* status code, and none may return `MCF_OK`. The zero-flash-mutation claim
is itself falsifiable. Details in [architecture §18](docs/architecture.md#18-test-strategy-and-ci).

### Verified footprint

Measured with `arm-none-eabi-gcc` at `-Os`, every source compiled with the full strict warning
set and zero warnings. CI gates `.text` against committed ceilings
(`cmake/size_gate.cmake`) and fails if any static RAM appears at all.

| Target | Code (`.text`) | Static RAM |
|---|---|---|
| Cortex-M0 | **12,358 B** | 0 B |
| Cortex-M3 | 11,420 B | 0 B |
| Cortex-M4 | 11,426 B | 0 B |
| Cortex-M7 | 11,422 B | 0 B |

A CI job also compiles the same core and opt-in source set with upstream clang
`--target=arm-none-eabi` on all four cores under the same strict warning set. This is a free,
redistributable **armclang frontend/diagnostic proxy**, not proof of Arm's licensed backend,
driver or runtime; licensed armclang and IAR builds remain unverified. The baseline ceilings sit
a few percent above these figures because the CI runner's toolchain minor version differs.

RAM, measured on Cortex-M0: **340 B** session + **528 B** workspace at a 256 B block =
**868 B total**, no heap — the workspace figures are what `mcf_ctx_size()` returns, and the
self-test asserts that query against the allocator's actual request. Full profile tables,
including the LZMA case, are in
[architecture §10.4](docs/architecture.md#104-measured-profiles).

---

## Building and testing

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --output-on-failure -C Release
```

The signing tests need a host Ed25519 module (`pip install cryptography`). The signing seed
itself is generated into the build tree at configure time, so no key needs to be checked out or
created by hand; `cross_test` fails rather than skips if the module is missing.

Two opt-in build modes exist for verification rather than for shipping:

```sh
# Whole host suite under ASan and UBSan, unrecoverable (a finding aborts the run).
# Needs a toolchain with the runtimes: Linux/macOS Clang or GCC. The configure step
# fails with an explicit message where they are missing, rather than at link time.
cmake -S . -B build-san -DMCF_SANITIZE=ON -DCMAKE_C_COMPILER=clang
cmake --build build-san && ctest --test-dir build-san --output-on-failure

# Coverage-guided fuzzing of the MFP2 parser (Clang, libFuzzer).
cmake -S . -B build-fuzz -DMCF_BUILD_FUZZER=ON -DCMAKE_C_COMPILER=clang
```

`MCF_BUILD_FUZZER=ON` builds `v2_parse_fuzzer`, a libFuzzer target for `mcf_v2_parse` compiled
with ASan/UBSan (Clang only; run it directly with a corpus directory rather than through
ctest). It asserts the same oracle as `v2_fuzz_smoke`, with coverage feedback on top; the CI
`fuzz` job seeds it from real host-produced patches and runs it for a bounded time.

**Device code size is gated in CI.** `cmake/size_gate.cmake` compiles every non-opt-in source
per core and fails if `.text` exceeds the committed ceiling, or if any static RAM appears at
all. Run it locally the same way CI does:

```sh
cmake -DCORE=cortex-m0 -DCC="$(which arm-none-eabi-gcc)" -DSRC="$PWD" \
      -DBASELINE="$PWD/cmake/size_baseline.txt" -DWORK="$PWD/build-size" \
      -P cmake/size_gate.cmake
```

**Build options**

| Option | Default | Effect |
|---|---|---|
| `MCF_ENABLE_LZMA` | `OFF` | Build the LZMA codec (vendored LZMA SDK) |
| `MCF_ENABLE_SODIUM` | `OFF` | Build libsodium adapters and MFP2 host-to-session integration tests |
| `MCF_ENABLE_ED25519` | `OFF` | Build the built-in Ed25519/Ed25519ph verifier (vendored TweetNaCl; no external crypto or heap) |
| `MCF_BUILD_TESTS` | `ON` | Build the host test suite |
| `MCF_BUILD_FUZZER` | `OFF` | Build the coverage-guided `v2_parse_fuzzer` with ASan/UBSan (requires Clang) |
| `MCF_WERROR` | `ON` | Warnings are errors |
| `MCF_STRICT` | `ON` | Add `-Wconversion -Wsign-conversion` |

Or drop the sources into an existing project — no generated code, and only the sources the
build selects are compiled:

```cmake
add_subdirectory(microfoam)
target_link_libraries(my_app PRIVATE microfoam::microfoam)
```

---

## Explore the repo

| Path | What is there |
|---|---|
| `include/` | Public API: `microfoam.h` (v1), `microfoam_v2.h` (MFP2), `microfoam_sodium.h`, `microfoam_ed25519.h` |
| `src/` | The library: container, delta engine, session, codecs, and the MFP2 execution path |
| `host/` | Patch generator/inspector/verifier, self-test, and the two README guards |
| `tests/` | Fault-injection suite, codec conformance, cross tests, and the MFP2 fuzz target |
| `third_party/` | Vendored LZMA SDK decoder and TweetNaCl (both public domain) |
| `cmake/` | The size gate and the cross-test driver |
| `docs/` | [architecture.md](docs/architecture.md), [format-v2.md](docs/format-v2.md), the MFP2 design notes, and the bring-up and LZMA histories |

---

## Licence

MIT. See [LICENSE](LICENSE) for the full text and the required third-party notices
(bsdiff/bspatch, BSD 2-Clause).

Copyright (c) 2026 Microfoam contributors.
