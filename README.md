# Microfoam

### Tiny bubbles. Tiny footprint. Full-strength upgrade.

[![CI](https://github.com/coffeetocoffee/microfoam/actions/workflows/ci.yml/badge.svg)](https://github.com/coffeetocoffee/microfoam/actions/workflows/ci.yml)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)
![Language: C99](https://img.shields.io/badge/language-C99-blue.svg)
[![RAM: 868 B, no heap](https://img.shields.io/badge/RAM-868%20B%20%C2%B7%20no%20heap-success.svg)](#verified-footprint)

You never need to send a whole firmware image to update a device. You send the **difference**,
and the device rebuilds the image in **868 bytes of RAM** — no heap, no RTOS, no scheduler.

```text
   35 KB old image   +   2 KB patch   ──▶   35 KB new image, rebuilt in 868 B of RAM
        running              5.8%              verified in staging flash, then activated
```

| RAM | ROM (Cortex-M0) | Patch size | Build | Formats | Version |
|---|---|---|---|---|---|
| **868 B**, no heap | **12,358 B** | **1–15%** of the image | C99 · MIT · 3 libc headers | MFP1 · MFP2 | `1.9.5` |

> [!NOTE]
> **Sweet spot:** small embedded devices and slow links — BLE, LoRa, infrared, a 9600-baud
> serial line. That line carries a 35 KB image in about 37 seconds; the same update as a patch
> arrives in under one.
> **Not** a transport, an encryption product, or a bootloader. Microfoam reconstructs and
> verifies an image. Getting the patch there, and deciding when to activate it, is yours.

**Jump in:** [quick start](#quick-start) · [profiles](#choose-your-profile) ·
[footprint](#verified-footprint) · [proof](#proof-not-promises) · [docs/](docs/quickstart.md)

---

## Why it fits

- **Send the difference.** A patch is usually 1–15% of the firmware. The suite's own 35 KB
  fixture turns into a **2,052-byte** patch — **5.8%**.
- **It fits where the alternatives won't.** Comparable libraries want 10–20 KB of heap for a
  decompressor whose probability tables alone floor it at ~15.6 KB. Microfoam makes the codec
  pluggable and ships a small one by default, which moves the target from *"Cortex-M3 with a
  20 KB heap"* down to **a Cortex-M0 with 4 KB** — the whole library fits an 8 KB part.
- **Two formats, one engine.** **MFP1** is a compact patch, unsigned or signed. **MFP2** adds
  Ed25519ph authentication and XChaCha20-Poly1305 encryption record by record, streaming, so the
  decrypted payload is never resident. Both hand the delta to the same engine.

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

`--block-log2 10` frames each LZ4 block to 1024 bytes, which is what `cfg.block_size` is waiting
for. **The two are a pair** — a patch framed larger than the device window is rejected as
corrupt. `make` is deterministic: same inputs, byte-identical patch, no timestamps, no randomness.

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

Other dials when you need them: **codec** is LZ4 (default), raw or opt-in LZMA; **memory** is
heapless (a static workspace) or allocator-backed; **resume** is off by default, with an opt-in
journal. A minimal **Conan 2** recipe (`conanfile.py`) covers the core library with both optional
paths off.

<details>
<summary><b>Signing a patch</b></summary>

```sh
python host/microfoam.py keygen --private mfkey.priv --public mfkey.pub
python host/microfoam.py make --old old.bin --new new.bin --out patch.bin \
    --product 0x1234 --version 0x00020000 --old-version 0x00010000 \
    --key mfkey.priv
python host/microfoam.py verify patch.bin --pub mfkey.pub
```

A signed patch is **rejected unless the device supplies a verifier** — that is the fail-closed
property, not an oversight. The HAL sketch above configures none, so it applies unsigned patches
only. See [Signature verification](#signature-verification).

</details>

---

## Six promises the library keeps

Each exists because its absence causes silent field failures somewhere else. The rationale for
every one is in [architecture.md](docs/architecture.md).

| | Promise | Where |
|---|---|---|
| **Errors** | 18 status codes; zero means success and means *only* success. A failed flash program is `MCF_E_FLASH`, never a full-length, silently corrupt image. | [§9.2](docs/architecture.md#92-error-model-p1) |
| **Memory** | `mcf_ctx_size()` returns the exact workspace a configuration will allocate, and the suite asserts it against the allocator's real request. Over `ram_budget` is refused *before anything is allocated*. | [§10](docs/architecture.md#10-memory-model-and-budget) |
| **Ownership** | The caller owns all state. No mutable globals, so the library is reentrant and runs from a static buffer with no heap. | [§9.3](docs/architecture.md#93-context-ownership-p3) |
| **Steppability** | `mcf_session_step()` does at most one block of work and returns, so a watchdog gets serviced between steps; aborting is a clean `MCF_E_ABORTED`. | [§9.6](docs/architecture.md#96-step-wise-state-machine-p7) |
| **Flash** | No unaligned or block-crossing erase or program is ever issued, and every programmed region is read back and compared. | [§12](docs/architecture.md#12-flash-write-contract) |
| **Auth** | Product binding and anti-rollback are always on; signature verification fails closed. | [§14](docs/architecture.md#14-security-model) |

### The HAL contract

Everything platform-specific lives in the HAL: **six required callbacks** — `flash_erase`,
`flash_write`, `flash_read`, `flash_block_size`, `get_product_id`, `get_fw_version` — plus
`alloc`/`free` unless you supply a static workspace. `verify`, `log` and `flash_is_readonly` are
optional. That is the entire platform dependency. The rules are short but not negotiable: erase
addresses and lengths are whole erase blocks, a write never crosses a block, a read returns
exactly what was asked for, and a failed program is `MCF_E_FLASH` rather than a
plausible-looking image. Callback table and a complete HAL: [quickstart.md](docs/quickstart.md).

### Signature verification

Two providers ship; neither is in a default build. The **built-in** one
(`-DMCF_ENABLE_ED25519=ON`) pulls in no external crypto, needs no heap, and streams the signed
message — **≈ 6.3 KB of flash** on Cortex-M4, **0 B of static RAM**. The alternative is a
libsodium adapter (`-DMCF_ENABLE_SODIUM=ON`). The arithmetic is
[vendored, not written here](third_party/tweetnacl/README.md); a from-scratch verifier was
written, **rejected** after twelve defects, and stays in
[`contrib/ed25519-wip/`](contrib/ed25519-wip/README.md) as a record. With libsodium also built,
the suite demands **the same verdict for every case** — on signatures libsodium generated over
messages neither implementation chose.
[architecture §14.3](docs/architecture.md#143-signature-algorithm-selection).

### Codecs

| Codec | Decoder state | Payload vs LZMA | Default |
|---|---|---|---|
| **LZ4** | ~16 B | ~1.7× at the default 1 KB block | **yes** |
| LZMA | probability table + dictionary | baseline | no (`-DMCF_ENABLE_LZMA=ON`) |
| Raw | 16 B | delta verbatim | no (`--codec raw`) |

**LZ4 is the default because it buys RAM, not bytes.** ~16 B of decoder state instead of an LZMA
probability table — but on the same delta it emits a *larger* payload: **1.67× LZMA's** on the
suite's 35 KB fixture at the default 1 KB block (1,934 B vs 1,160 B). `host_selftest` measures
and pins that figure, so it cannot quietly drift. **Raw** is the delta stream untouched, for when
headers cost more than they save. LZMA is opt-in because its probability table is an
unconditional RAM floor this architecture exists to remove; its 9-byte properties block carries
the exact decompressed length, which is what makes truncation detectable. Policy and workspace
formulas: [format-v2.md](docs/format-v2.md).

> [!IMPORTANT]
> **The LZ4 decode window is a hard format constraint.** Each block decodes into one fixed
> buffer (`cfg.block_size`, clamped to `new_size`), so the producer must frame within the image
> and the device window must be at least the framing. The host tool does both automatically.
> See [the LZ4 stream](docs/format-v2.md#lz4-stream).

---

## Proof, not promises

Warning-clean under `-Wall -Wextra -Wconversion -Wsign-conversion -Werror`, the standard
configurations passing in Debug and Release, and a CI size gate that fails the build if `.text`
grows past its committed ceiling or any static RAM appears at all.

- **Nine suites, every count machine-checked.** `host/check_counts.py` runs each suite, reads the
  count it reports for itself, and fails if the documented number disagrees.
- **Fault injection at every stage** — erase failure, program failure, *program succeeding but
  storing the wrong bytes*, truncation, flipped bits, wrong product, downgrade attempts,
  over-budget workspace, unknown codec, wrong CRC, abort, signed-without-verifier — each
  asserting a specific status, none allowed to return `MCF_OK`.
- **Both parsers held to a property contract,** not a list of cases, because they are the
  surfaces that eat attacker-controlled bytes.
- **A cross test**, the one that matters most: host-made patches applied by the C library,
  byte-exact. A library verified only against its own encoder proves nothing about the format.

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
no heap — the figures `mcf_ctx_size()` returns, asserted by the self-test against the
allocator's actual request. The same sources also compile clean with upstream clang
`--target=arm-none-eabi` on all four cores: a free armclang frontend and diagnostic proxy,
**not** a licensed-toolchain result. Full profile tables, the fault catalogue and the portability
caveats are in [docs/verification.md](docs/verification.md).

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

Or drop the sources into an existing project — no generated code, only what the build selects:

```cmake
add_subdirectory(microfoam)
target_link_libraries(my_app PRIVATE microfoam::microfoam)
```

<details>
<summary><b>Why "microfoam"?</b></summary>

The thin layer of bubbles on a latte — roughly one percent of the volume and all of the texture.
That is the design target: the smallest possible resident cost, carrying the whole capability.
It is also the right expectation to set for anyone told this replaces a library that wanted
10–20 KB of heap. The footprint is the point. See
[architecture §On the name](docs/architecture.md).

</details>

<details>
<summary><b>More docs</b></summary>

| Page | What is there |
|---|---|
| [quickstart.md](docs/quickstart.md) | The complete HAL, the callback contract, choosing `block_size` / `ram_budget` / codec / memory, build switches, sanitizer and fuzz builds |
| [verification.md](docs/verification.md) | Every suite, the fault catalogue, the measured size tables, portability |
| [architecture.md](docs/architecture.md) | The design, and the rationale behind every commitment above |
| [format-v2.md](docs/format-v2.md) | The on-flash container: layout, validation order, LZ4 window, codec properties |

`include/` is the public API (`microfoam.h`, `microfoam_v2.h`, `microfoam_sodium.h`,
`microfoam_ed25519.h`); `src/` is the container, delta engine, session and codecs; `host/` is the
patch generator, inspector and the two documentation guards; `tests/` holds fault injection,
codec conformance, cross tests and the two parser fuzz targets; `third_party/` vendors the public
domain LZMA SDK and TweetNaCl.

</details>

---

## Licence

MIT. See [LICENSE](LICENSE) for the full text and the required third-party notices
(bsdiff/bspatch, BSD 2-Clause).

Copyright (c) 2026 Microfoam contributors.
