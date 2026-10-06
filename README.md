# Microfoam

**Tiny bubbles. Tiny footprint. Full-strength upgrade.**

You never need to send a whole firmware image to update a device. You need to send the
**difference** — and rebuild the image on the far end, in **868 bytes of RAM**, with no heap
and no RTOS.

[![CI](https://github.com/coffeetocoffee/microfoam/actions/workflows/ci.yml/badge.svg)](https://github.com/coffeetocoffee/microfoam/actions/workflows/ci.yml)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)
![Language: C99](https://img.shields.io/badge/language-C99-blue.svg)
[![RAM: 868 B, no heap](https://img.shields.io/badge/RAM-868%20B%20%C2%B7%20no%20heap-success.svg)](#verified-footprint)

| | |
|---|---|
| **RAM** | **868 B**, no heap, no scheduler |
| **ROM** | **12,358 B** on Cortex-M0 |
| **Patch** | typically **1–15%** of the image |
| **Build** | C99 · MIT · `<stdint.h>`, `<stddef.h>`, `<string.h>` and nothing else |
| **Formats** | **MFP1** (compact) · **MFP2** (signed + encrypted, per record) |
| **Status** | `1.9.5` |

> [!NOTE]
> **Sweet spot:** small embedded devices and slow links — BLE, LoRa, infrared, a 9600-baud
> serial line. That line carries a 35 KB image in about 37 seconds; the same update as a patch
> arrives in under one.
> **Not** a transport, an encryption product, or a bootloader. Microfoam reconstructs and
> verifies an image. Getting the patch there, and deciding when to activate it, is yours.

**Start here:** [why](#why) · [quick start](#quick-start) · [profiles](#choose-your-profile) ·
[the HAL](#the-hal-contract) · [signing](#signature-verification) · [codecs](#codecs) ·
[proof](#proof-not-promises) · [build](#building-and-testing) · [the repo](#explore-the-repo)

---

## Why

- **Send the difference.** A patch is usually 1–15% of the firmware. The suite's own 35 KB
  fixture turns into a **2,052-byte** patch — **5.8%**.
- **It fits where the alternatives won't.** Comparable libraries want 10–20 KB of heap for a
  decompressor whose probability tables alone have a ~15.6 KB floor. Microfoam makes the codec
  pluggable and ships a small one by default, which moves the target from *"Cortex-M3 with a
  20 KB heap"* down to **a Cortex-M0 with 4 KB** — the whole library fits an 8 KB part.
- **Two formats, one engine.** **MFP1** is a compact patch, unsigned or signed. **MFP2** adds
  Ed25519ph authentication and XChaCha20-Poly1305 encryption record by record, streaming, so the
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

Fill in the HAL — everything platform-specific lives there — then run a session. The two values
to get right are `block_size` and `ram_budget`, and both have to agree with the patch.

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
pick the codec — is in **[docs/quickstart.md](docs/quickstart.md)**.

### 2. On the build host

```sh
python host/microfoam.py make \
    --old old.bin --new new.bin --out patch.bin \
    --product 0x1234 --version 0x00020000 --old-version 0x00010000 \
    --block-log2 10

python host/microfoam.py inspect patch.bin
python host/microfoam.py apply   --old old.bin --patch patch.bin --out out.bin
```

`--block-log2 10` frames each LZ4 block to 1024 bytes, which is what `cfg.block_size` is
waiting for. **The two are a pair**: a patch framed larger than the device's window is rejected
as corrupt, so they must agree. The tool also caps its framing at the image, so a small image
still yields an applicable patch.

`make` is deterministic — same inputs, byte-identical patch, no timestamps, no randomness. (The
encrypted `make --v2` profile is the exception: it draws a fresh random nonce prefix per patch,
because reusing one under the same key would repeat every AEAD nonce.)

### 3. Or install the tool

```sh
pip install .            # provides the `microfoam` command
microfoam --version
microfoam make --old old.bin --new new.bin --out patch.bin \
    --product 0x1234 --version 0x00020000 --old-version 0x00010000
```

Signing is an extra: `pip install .[mfp1]` for MFP1 Ed25519 (`cryptography`) and
`pip install .[mfp2]` for MFP2 signed/encrypted patches (`pynacl`). LZ4 and raw patches need
nothing beyond the standard library.

---

## Choose your profile

| | Host command | Device needs |
|---|---|---|
| **Unsigned MFP1** (default) | `make …` | nothing extra |
| **Signed MFP1** | `make … --key mfkey.priv` | a verifier: `-DMCF_ENABLE_ED25519=ON` and `cfg.verify` |
| **Signed + encrypted MFP2** | `make … --v2 --key mfkey.priv` | `-DMCF_ENABLE_ED25519=ON` and an XChaCha20-Poly1305 provider |

Other dials, when you need them: **codec** is LZ4 (default), raw or opt-in LZMA; **memory** is
heapless (a static workspace) or allocator-backed; **resume** is off by default, with an opt-in
journal. [quickstart.md](docs/quickstart.md) covers the choices, and
[architecture](docs/architecture.md) covers why they exist. A minimal **Conan 2** recipe
(`conanfile.py`) covers the core library with both optional paths off.

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
property, not an oversight. The HAL sketch above configures none, so it applies unsigned
patches only. To accept signed patches, set `verify` (or `cfg.verify`) to a vetted Ed25519
provider; see [Signature verification](#signature-verification).

</details>

---

## Design commitments

Six properties the library is built around. Each exists because its absence causes silent field
failures somewhere else; the full rationale is in [architecture.md](docs/architecture.md).

- **Every failure is reported, specifically.** 18 status codes; zero means success and means
  only success. A failed flash program is `MCF_E_FLASH`, never a full-length, silently corrupt
  image. ([§9.2](docs/architecture.md#92-error-model-p1))
- **The memory contract is explicit and enforced.** `mcf_ctx_size()` returns the exact
  workspace a configuration will allocate, and the suite asserts that number against the
  allocator's real request. A patch over `ram_budget` is refused *before anything is
  allocated*. ([§10](docs/architecture.md#10-memory-model-and-budget))
- **The caller owns all state.** No mutable globals, so the library is reentrant and runs from
  a static buffer on a system with no heap. ([§9.3](docs/architecture.md#93-context-ownership-p3))
- **Long operations are steppable.** `mcf_session_step()` does at most one block of work and
  returns, so a watchdog gets serviced between steps; aborting is a clean `MCF_E_ABORTED`.
  ([§9.6](docs/architecture.md#96-step-wise-state-machine-p7))
- **The flash contract is enforced, not assumed.** No unaligned or block-crossing erase or
  program is ever issued, and every programmed region is read back and compared.
  ([§12](docs/architecture.md#12-flash-write-contract))
- **Authentication is opt-in and explicit.** Product binding and anti-rollback are always on;
  signature verification fails closed — a patch claiming to be signed is rejected when no
  verifier is available, never quietly accepted. ([§14](docs/architecture.md#14-security-model))

---

## The HAL contract

Everything platform-specific lives in the HAL. Six callbacks are required on every path —
`flash_erase`, `flash_write`, `flash_read`, `flash_block_size`, `get_product_id`,
`get_fw_version` — plus `alloc`/`free` unless you supply a static workspace. `verify`, `log` and
`flash_is_readonly` are optional. That is the entire platform dependency.

The rules are short but not negotiable: erase addresses and lengths are whole erase blocks, a
write never crosses a block, a read returns exactly what was asked for, and a failed program is
`MCF_E_FLASH` rather than a plausible-looking image.

**No heap?** Set `workspace` and `workspace_size` on the config, and give every simultaneously
active session its own buffer.

**[docs/quickstart.md](docs/quickstart.md)** has the callback contract as a table and a
complete, commented HAL for a generic Cortex-M part; the rationale is in
[architecture §12](docs/architecture.md#12-flash-write-contract).

---

## Signature verification

Two providers ship, and neither is in a default build.

- **The built-in one pulls in nothing.** No external crypto, no heap, no buffer proportional to
  the patch — the signed message is streamed. It costs **≈ 6.3 KB of flash** on Cortex-M4 with
  `--gc-sections` and **0 B of static RAM**. The alternative is a libsodium adapter, which
  needs libsodium and one temporary message buffer.
- **The arithmetic is vendored, not written here.**
  [TweetNaCl](third_party/tweetnacl/README.md) — public domain, ~700 lines, no `__int128` — is
  the reviewed part; `src/mcf_sha512.c` and `src/mcf_ed25519.c` are ours. A from-scratch
  verifier was also written and **rejected** after twelve defects, one permissive; it stays in
  [`contrib/ed25519-wip/`](contrib/ed25519-wip/README.md) as a record and **must not be linked
  into production.**
- **The checks that bite are checked by execution.** The `S < L` canonicality rule is enforced
  even though TweetNaCl omits it, so the two implementations cannot disagree on it; domain
  separation is asserted in both directions; and with libsodium also built, `ed25519_test`
  demands **the same verdict for every case** — including signatures libsodium generated over
  messages neither implementation chose.

Design and provenance: [architecture §14.3](docs/architecture.md#143-signature-algorithm-selection) ·
[third_party/tweetnacl/README.md](third_party/tweetnacl/README.md).

<details>
<summary><b>Wiring up a verifier</b></summary>

| | Built-in | libsodium adapter |
|---|---|---|
| Enable with | `-DMCF_ENABLE_ED25519=ON` | `-DMCF_ENABLE_SODIUM=ON` |
| External dependency | **none** | libsodium |
| Heap | **none** | one temporary message buffer |
| Signed-message handling | **streamed** | concatenated |
| Callbacks | `mcf_ed25519_verify`, `mcf_ed25519ph_verify3` | `mcf_sodium_verify`, `mcf_sodium_ed25519ph_verify3` |

```c
#include "microfoam_ed25519.h"

static mcf_ed25519_ctx_t g_verify = { g_public_key };   /* 32 bytes, immutable */

cfg.verify     = mcf_ed25519_verify;      /* MFP1: plain Ed25519    */
cfg.verify_ctx = &g_verify;
/* MFP2 takes the same context through mcf_v2_config_t.verify, with
 * mcf_ed25519ph_verify3 as the function. */
```

</details>

---

## Codecs

| Codec | Decoder state | Payload vs LZMA | Default |
|---|---|---|---|
| **LZ4** | ~16 B | ~1.7× at the default 1 KB block | **yes** |
| LZMA | probability table + dictionary | baseline | no (`-DMCF_ENABLE_LZMA=ON`) |
| Raw | 16 B | delta verbatim | no (`--codec raw`) |

**LZ4 is the default because it buys RAM, not bytes.** ~16 B of decoder state instead of an LZMA
probability table — but on the same delta it emits a *larger* payload: **1.67× LZMA's** on the
suite's 35 KB fixture at the default 1 KB block (1,934 B vs 1,160 B). `host_selftest` measures
and pins that figure, so it cannot quietly drift.

**Raw** is the delta stream untouched — no framing, no properties, no per-block headers — for
when headers cost more than they save. **LZMA** is opt-in because its probability table is an
unconditional RAM floor this architecture exists to remove; enabled, it is fully supported and
CI-tested, and its 9-byte properties block carries the exact decompressed length, which is what
makes truncation detectable.

> [!IMPORTANT]
> **The LZ4 decode window is a hard format constraint.** Each block decodes into one fixed
> buffer (`cfg.block_size`, clamped to `new_size`), so the producer must frame within the image
> and the device window must be at least the framing. The host tool does both automatically.
> See [the LZ4 stream](docs/format-v2.md#lz4-stream).

Parameter policy, workspace formulas and the encode/verify path are in
[format-v2.md](docs/format-v2.md); the LZMA decoder's history is in
[lzma-history.md](docs/lzma-history.md); custom codecs and the vtable are in
[architecture §7.3](docs/architecture.md#73-l1-%E2%80%94-pluggable-codec).

---

## Proof, not promises

Warning-clean under `-Wall -Wextra -Wconversion -Wsign-conversion -Werror`, with the standard
configurations passing in Debug and Release, and a CI size gate that fails the build if `.text`
grows past its committed ceiling or any static RAM appears at all.

The evidence, in **[docs/verification.md](docs/verification.md)**:

- **Nine suites, every count machine-checked.** `host/check_counts.py` runs each suite, reads
  the count it reports for itself, and fails if the documented number disagrees — so a stated
  figure cannot quietly go stale.
- **Fault injection at every stage.** Erase failure, program failure, *program succeeding but
  storing the wrong bytes*, truncation, flipped bits, wrong product, downgrade attempts,
  over-budget workspace, unknown codec, wrong CRC, abort, signed-without-verifier — each
  asserting a specific status, none allowed to return `MCF_OK`.
- **A parser held to a property contract,** not a list of cases, because it is the one surface
  that eats attacker-controlled bytes.
- **A cross test**, which is the one that matters most: a library verified only against its own
  encoder proves nothing about the format, so host-made patches are applied by the C library and
  must come out byte-exact.

### Verified footprint

Measured with `arm-none-eabi-gcc` at `-Os`, every source compiled under the full strict warning
set with zero warnings.

| Target | Code (`.text`) | Static RAM |
|---|---|---|
| Cortex-M0 | **12,358 B** | 0 B |
| Cortex-M3 | 11,420 B | 0 B |
| Cortex-M4 | 11,426 B | 0 B |
| Cortex-M7 | 11,422 B | 0 B |

RAM, on Cortex-M0: **340 B** session + **528 B** workspace at a 256 B block = **868 B total**,
no heap. Those are the figures `mcf_ctx_size()` returns, and the self-test asserts that query
against the allocator's actual request.

The same sources also compile clean with upstream clang `--target=arm-none-eabi` on all four
cores — a free armclang frontend and diagnostic proxy, not a licensed-toolchain result. Full
profile tables, the fault catalogue and the portability caveats are in
[docs/verification.md](docs/verification.md) and
[architecture §10.4](docs/architecture.md#104-measured-profiles).

---

## Building and testing

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --output-on-failure -C Release
```

The signing tests need a host Ed25519 module (`pip install cryptography`); the signing seed is
generated into the build tree at configure time, so no key needs checking out by hand, and
`cross_test` fails rather than skips if the module is missing.

Or drop the sources into an existing project — no generated code, and only the sources the
build selects are compiled:

```cmake
add_subdirectory(microfoam)
target_link_libraries(my_app PRIVATE microfoam::microfoam)
```

<details>
<summary><b>Build switches, and the verification builds</b></summary>

| Option | Default | Effect |
|---|---|---|
| `MCF_ENABLE_LZMA` | `OFF` | Build the LZMA codec (vendored LZMA SDK) |
| `MCF_ENABLE_SODIUM` | `OFF` | Build libsodium adapters and the MFP2 host-to-session tests |
| `MCF_ENABLE_ED25519` | `OFF` | Build the built-in Ed25519/Ed25519ph verifier (vendored TweetNaCl; no external crypto, no heap) |
| `MCF_BUILD_TESTS` | `ON` | Build the host test suite |
| `MCF_BUILD_FUZZER` | `OFF` | Build `v2_parse_fuzzer` with ASan/UBSan (needs Clang) |
| `MCF_WERROR` | `ON` | Warnings are errors |
| `MCF_STRICT` | `ON` | Add `-Wconversion -Wsign-conversion` |

Two more modes exist for checking the library rather than shipping it:

```sh
# Whole host suite under ASan and UBSan, unrecoverable - a finding aborts the run.
# Needs a toolchain with the runtimes: Linux/macOS Clang or GCC. The configure step
# fails with an explicit message where they are missing, rather than at link time.
cmake -S . -B build-san -DMCF_SANITIZE=ON -DCMAKE_C_COMPILER=clang
cmake --build build-san && ctest --test-dir build-san --output-on-failure

# Coverage-guided fuzzing of the MFP2 parser (Clang, libFuzzer). Run it directly
# with a corpus directory rather than through ctest; the CI fuzz job seeds it from
# real host-produced patches and runs it for a bounded time, and the scheduled
# "Long fuzz" workflow runs it for ten minutes against a corpus cached across runs.
cmake -S . -B build-fuzz -DMCF_BUILD_FUZZER=ON -DCMAKE_C_COMPILER=clang
```

The size gate, run exactly the way CI runs it:

```sh
cmake -DCORE=cortex-m0 -DCC="$(which arm-none-eabi-gcc)" -DSRC="$PWD" \
      -DBASELINE="$PWD/cmake/size_baseline.txt" -DWORK="$PWD/build-size" \
      -P cmake/size_gate.cmake
```

</details>

---

## Explore the repo

| Path | What is there |
|---|---|
| `include/` | Public API: `microfoam.h`, `microfoam_v2.h`, `microfoam_sodium.h`, `microfoam_ed25519.h` |
| `src/` | Container, delta engine, session, codecs, the MFP2 execution path |
| `host/` | Patch generator/inspector/verifier, self-test, and the two README guards |
| `tests/` | Fault injection, codec conformance, cross tests, the MFP2 fuzz target |
| `third_party/` | Vendored LZMA SDK decoder and TweetNaCl (both public domain) |
| `cmake/` | The size gate and the cross-test driver |
| `docs/` | [quickstart.md](docs/quickstart.md) (full HAL + contract), [verification.md](docs/verification.md) (suites, faults, size), [architecture.md](docs/architecture.md), [format-v2.md](docs/format-v2.md), the MFP2 design notes, and the bring-up and LZMA histories |

---

## Licence

MIT. See [LICENSE](LICENSE) for the full text and the required third-party notices
(bsdiff/bspatch, BSD 2-Clause).

Copyright (c) 2026 Microfoam contributors.