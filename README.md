# Microfoam

**Tiny bubbles. Tiny footprint. Full-strength upgrade.**

A firmware delta update library for resource-constrained microcontrollers. Transmit only
the difference between firmware versions; reconstruct the full image on the device in a few
kilobytes of RAM.

```c
#include "microfoam.h"
```

| | |
|---|---|
| **RAM (LZ4, 256 B block)** | **744 B** total, no heap | 216 B session + 528 B workspace |
| **RAM (LZ4, 512 B block)** | ~1.3 KB total | 216 B session + 1,040 B workspace |
| **ROM (Cortex-M0)** | **5,810 B** | measured, `-Os`, all tables `const` |
| **Dependencies** | `<stdint.h>`, `<string.h>`. No heap required. No RTOS. | |
| **Language** | C99, MISRA-friendly, `-Wall -Wextra -Wconversion` clean | |
| **Targets verified** | arm-none-eabi-gcc: M0, M0+, M3, M4, M7, M33 | |
| **Licence** | MIT | |
| **Status** | 1.2.0 — see [Status](#status) | |

---

## Why

A device in the field holds firmware version *N*. The manufacturer ships *N+1*. Sending the
whole image over BLE, LoRa, infrared or a 9600-baud serial link is slow and power-hungry.
Sending only the difference is typically 1–15% of the image size.

For a realistic maintenance change to a 35 KB firmware — a few functions rewritten, a version
string bumped:

```
image              35357 bytes
patch                719 bytes   2.0%
```

Most libraries in this space need 10–20 KB of heap, because their default decompressor has an
unconditional ~15.6 KB floor for probability tables before a single processing buffer exists.
Microfoam makes the codec pluggable and ships a small one by default, which is what moves the
primary target from "Cortex-M3 with a 20 KB heap" down to a Cortex-M0 with 4 KB.

---

## Quick start

### On the device

```c
#include "microfoam.h"

/* 1. Implement the HAL. Everything platform-specific lives here. */
static int32_t my_erase(void *ctx, uint32_t addr, uint32_t len)
{
    (void)ctx;
    if (HAL_FLASH_Erase(addr, addr + len) != HAL_OK) return MCF_E_FLASH;
    return MCF_OK;
}

static int32_t my_write(void *ctx, uint32_t addr, const uint8_t *p, uint32_t len)
{
    (void)ctx;
    if (HAL_FLASH_Program(addr, (uint32_t)p, len) != HAL_OK) return MCF_E_FLASH;
    return MCF_OK;
}

static int32_t my_read(void *ctx, uint32_t addr, uint8_t *p, uint32_t len)
{
    (void)ctx;
    memcpy(p, (const void *)addr, len);
    return (int32_t)len;
}

static uint32_t my_block_size(void *ctx) { (void)ctx; return 2048u; }
static uint32_t my_product_id(void *ctx) { (void)ctx; return 0x1234u; }
static uint32_t my_fw_version(void *ctx) { (void)ctx; return FW_VERSION; }

static void *my_alloc(void *ctx, uint32_t n) { (void)ctx; return pvPortMalloc(n); }
static void  my_free(void *ctx, void *p)     { (void)ctx; vPortFree(p); }

static const mcf_hal_t g_hal = {
    .flash_erase       = my_erase,
    .flash_write       = my_write,
    .flash_read        = my_read,
    .flash_block_size  = my_block_size,
    .alloc             = my_alloc,
    .free              = my_free,
    .get_product_id    = my_product_id,
    .get_fw_version    = my_fw_version,
};

/* 2. Apply a patch. */
void apply_update(const uint8_t *patch, uint32_t patch_size)
{
    static mcf_config_t cfg;
    MCF_SESSION_DECLARE(session);

    cfg.hal         = &g_hal;
    cfg.patch       = patch;
    cfg.patch_size  = patch_size;
    cfg.old         = (const uint8_t *)0x08000000u;  /* running image */
    cfg.old_size    = FW_SIZE;
    cfg.dst_addr    = 0x08020000u;                  /* staging slot    */
    cfg.codec       = MCF_CODEC_AUTO;
    cfg.block_size  = 512u;
    cfg.ram_budget  = 2048u;                        /* hard ceiling    */

    if (mcf_session_run(session) != MCF_OK) {
        /* Every failure is a distinct code. mcf_session_strerror() names it. */
        log_error("microfoam: %s", mcf_session_strerror(mcf_session_status(session)));
    }
    mcf_session_close(session);
}
```

### On the build host

```sh
python host/microfoam.py keygen --private mfkey.priv --public mfkey.pub

python host/microfoam.py make \
    --old old.bin --new new.bin --out patch.bin \
    --product 0x1234 --version 0x00020000 --old-version 0x00010000 \
    --key mfkey.priv

python host/microfoam.py inspect patch.bin
python host/microfoam.py verify  patch.bin --pub mfkey.pub
python host/microfoam.py apply   --old old.bin --patch patch.bin --out out.bin
```

`make` is deterministic: identical inputs produce a byte-identical patch. No timestamps, no
randomness.

---

## Design commitments

These are the properties the library is built around. Each one exists because its absence
causes silent field failures in comparable libraries.

**Every failure is reported, specifically.** There are 18 status codes. Zero means success
and means only success. There is no value that means both "succeeded" and "failed", and no
code path that reports success after an error. If a flash program fails, you get
`MCF_E_FLASH` — not a full-length, silently corrupt image.

**The memory contract is explicit and enforced.** `mcf_ctx_size()` tells you the exact cost.
The patch declares its own decoder requirement in `workspace_req`, and the device returns
`MCF_E_DICT_TOO_LARGE` *before allocating anything* if it does not fit `ram_budget`. It never
attempts an allocation it cannot satisfy, and never dereferences a null codec.

**The caller owns all state.** There is no mutable global session state. All state lives in a
caller-provided `mcf_session_t`, so the library is reentrant and usable from a static buffer
on a system with no heap.

**Long operations are steppable.** `mcf_session_step()` performs at most one block of work and
returns. Service a watchdog, sleep, or report progress between steps. Aborting through the
progress callback is a clean `MCF_E_ABORTED`, not a forced reset.

**The flash contract is enforced, not assumed.** The library never issues an unaligned or
block-crossing erase or program, and it performs read-back verification after every write.
Your callback does not have to know the erase geometry.

**Updates are authenticated.** Product binding, anti-rollback, and signature verification are
built in, not bolted on. Verification fails closed: a patch that claims to be signed is
rejected if no verifier is available, never accepted unverified.

---

## Packaging

A minimal Conan 2 recipe is provided in `conanfile.py` for the stabilized core library.
It builds with LZMA and optional libsodium disabled; the recipe is packaging support, and
both optional paths are enabled explicitly by consumers (`MCF_ENABLE_LZMA`,
`MCF_ENABLE_SODIUM`).

## The HAL contract

Five required callbacks and one optional. This is the entire platform dependency.

| Callback | Required | Contract |
|---|---|---|
| `flash_erase(ctx, addr, len)` | yes | `len` is always a whole multiple of `flash_block_size()`, and `addr` is aligned to it. Return `MCF_OK` on success or a negative status on failure. |
| `flash_write(ctx, addr, p, len)` | yes | Never crosses an erase-block boundary. May be called repeatedly for one logical block. Return `MCF_OK` on success or a negative status on failure; positive byte counts are not valid. |
| `flash_read(ctx, addr, p, len)` | for read-back verify | Needed unless `flash_is_readonly` reports the region unreadable. Return exactly `len` on success or a negative status on failure. The old-image `old_read` callback follows the same exact-count rule. |
| `flash_block_size(ctx)` | yes | Erase granularity in bytes. Must be a power of two. |
| `alloc` / `free` | unless static | Returning `NULL` is reported as `MCF_E_NOMEM`. |
| `get_product_id`, `get_fw_version` | yes | Device-provisioned identity and running version. |
| `flash_is_readonly` | no | Non-zero skips read-back verify. |
| `verify` | no | Signature verifier. `NULL` means no verifier available → signed patches rejected. |
| `log` | no | Diagnostics. |

For a system with no heap, set `workspace` and `workspace_size` on each session's
`mcf_config_t`; each simultaneously active session must receive a distinct buffer.
The former global `mcf_hal_set_static_workspace()` entry point is deprecated and
returns `MCF_E_UNSUPPORTED`. `mcf_hal_register()` is also compatibility-only and
stores nothing; every session must set `cfg.hal`.

For vetted device-side Ed25519 verification, configure `-DMCF_ENABLE_SODIUM=ON`, keep a
32-byte public key in immutable storage, and install `mcf_sodium_verify` as the HAL's
`verify` callback. The adapter uses the context's allocator for its temporary concatenated
message; default builds include no cryptography and reject signed patches unless a verifier
callback is configured.

---

## Codecs

Custom codec descriptors are caller-owned and session-scoped: set `cfg.codecs` and
`cfg.codec_count` before opening a session. `mcf_codec_register()` validates a descriptor
but does not retain global state. Built-in LZ4 remains available automatically; custom IDs
must be in the `MCF_CODEC_CUSTOM_MIN` range and are never accepted without a matching
per-session descriptor.

| Codec | Decoder state | RAM | Ratio vs LZMA | Default |
|---|---|---|---|---|
| **LZ4** | ~16 B | + block buffers | −5% to −15% on binary diffs | **yes** |
| LZMA | probability table + dictionary | see below | baseline | no (`-DMCF_ENABLE_LZMA=ON`) |

LZMA is opt-in because its probability table is an unconditional RAM floor that this
architecture exists to remove — but when enabled it is a fully supported, CI-tested codec.
The decoder is the vendored **LZMA SDK** (`third_party/lzma-sdk`, public domain, Igor
Pavlov), the same implementation shipped in 7-Zip, U-Boot, and EDK2. A patch declaring LZMA
on a build without it is rejected as `MCF_E_UNSUPPORTED` rather than handed to a stub.

LZMA workspace, as reported by `mcf_lzma_workspace()` and declared in the patch header:

```
2 * (1984 + (768 << (lc + lp)))    probability table   (16,256 B at lc=3, lp=0)
+ dicBufSize                      dictionary, SDK-rounded (default 16,384 B)
+ 256 B                           decoder state
```

At the host tool's defaults (`lc=3`, `lp=0`, `pb=2`, 16 KB dictionary) that is **32,896
bytes** of workspace — a Cortex-M4/M7-class figure, not a Cortex-M0 one. The host tool
computes the same number and writes it to `workspace_req`, so the device refuses an
over-budget LZMA patch during header validation, before allocating anything. Use
`--dict-size 4096` to trade ratio for RAM (≈20 KB total).

Register your own codec through `mcf_codec_ops_t`; the descriptor is caller-owned and resolved per
session. `workspace_size` must not allocate, `init`/`decode`/`finish` return `MCF_OK` or a
negative status, and `decode` must report bounded output counts and make progress unless the
stream has ended. `destroy` is called after successful initialization on every later failure path.
`mcf_codec_register()` validates a descriptor but does not retain global state.

---

## Verified footprint

Measured with `arm-none-eabi-gcc 16.1.0` at `-Os`, every source compiled with
`-Wall -Wextra -Werror -Wconversion -Wsign-conversion -Wshadow -Wcast-qual -Wstrict-prototypes
-Wmissing-prototypes`. All six configurations compile with zero warnings.

| Target | Code (text) | Initialised data |
|---|---|---|
| Cortex-M0 / M0+ | **5,810 B** | 0 B |
| Cortex-M3 / M33 | 5,530 B | 0 B |
| Cortex-M4 | 5,532 B | 0 B |
| Cortex-M7 | 5,538 B | 0 B |

All tables are `const`, so nothing lands in RAM. The variation is the architectures'
different multiply routines; the library's own code is essentially identical across cores.

### RAM, measured on Cortex-M0 (32-bit)

| Item | Bytes | Notes |
|---|---|---|
| `mcf_session_t` | **216** | Caller-owned; can be `static`, so not heap |
| `mcf_journal_t` | **20** | Resume record; lives in NVM, not RAM |
| Workspace, `block_size = 256` | **528** | 2 × 256 processing + 16 LZ4 state |
| Workspace, `block_size = 512` | 1,040 | |
| Workspace, `block_size = 1024` | 2,064 | |
| `mcf_config_t` | 56 | Prefer a `static const` in flash |
| `mcf_hal_t` | 48 | Prefer a `static const` in flash |
| `mcf_header_t` | 120 | Equals the wire header exactly — no padding |

**Constrained profile: 216 + 528 = 744 bytes of RAM**, plus a small stack for the integrity
chunks. No heap needed, on a part with 8 KB.

The LZMA codec, when enabled, adds its probability table (16 KB at the default
`lc=3`) plus a dictionary (16 KB default, `--dict-size` to change) — see the
[Codecs](#codecs) section for the exact formula. That is why it is opt-in and why
LZ4 is the default.

## Building

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
```

| Test | What it checks |
|---|---|
| `microfoam_tests` | Round trip and fault injection against a mock device |
| `custom_codec_test` | Caller-owned codec validation, isolation, budget enforcement, and failure propagation |
| `host_selftest` | The Python tool against an independent reference implementation |
| `cross_test` | A Python-produced patch applied by the C library |
| `lzma_conformance_test` | 67 liblzma vectors × 5 block sizes against the LZMA decoder (with `MCF_ENABLE_LZMA=ON`) |
| `cross_test_lzma` | A Python-produced **LZMA** patch applied by the C library (with `MCF_ENABLE_LZMA=ON`) |

| Option | Default | Effect |
|---|---|---|
| `MCF_ENABLE_LZMA` | `OFF` | Build the LZMA codec (vendored LZMA SDK) |
| `MCF_BUILD_TESTS` | `ON` | Build the host test suite |
| `MCF_WERROR` | `ON` | Warnings are errors |
| `MCF_STRICT` | `ON` | Add `-Wconversion -Wsign-conversion` |

Or drop the sources into an existing project — there are seven `.c` files, one header, and no
generated code:

```cmake
add_subdirectory(microfoam)
target_link_libraries(my_app PRIVATE microfoam::microfoam)
```

---

## Repository layout

```
include/microfoam.h        the public API — the entire contract
src/mcf_container.c        header parse and validation (the only place it's interpreted)
src/mcf_engine.c           BSDIFF43 delta loop, resumable, 32-bit clean
src/mcf_session.c          state machine, workspace, flash write path
src/mcf_codec_lz4.c        LZ4 block decoder
src/mcf_lzma.c             LZMA codec adapter (opt-in)
src/mcf_codec.c            codec registry
src/mcf_hal.c              HAL registration, workspace allocation
src/mcf_util.c             CRC-32, version, diagnostics
third_party/lzma-sdk/      vendored LZMA SDK decoder (public domain)
host/microfoam.py          patch generator, inspector, verifier, reference decoder
host/selftest.py           host tool self-test
host/lzma_vectors.py       generates the LZMA conformance vectors via liblzma
tests/test_microfoam.c     fault-injection and round-trip tests
tests/lzma_conformance_test.c  LZMA conformance harness (67 vectors x 5 block sizes)
tests/cross_test.c         host-tool patch applied by the C library
tests/fixtures/            deterministic firmware pair and a test key
contrib/ed25519-wip/       rejected verifier, defect log, and conformance harness
docs/architecture.md       the design this implements, and why
docs/format-v2.md          the shipped v1 on-flash patch format
docs/format-v2-design.md   proposed v2 format/API for AEAD and codec checkpoints
docs/lzma-history.md       the retired from-scratch LZMA decoder's defect log
include/microfoam_v2.h     experimental MFP2 structural inspection API (no session execution yet)
```

---

## Status

Honest accounting of what exists and what does not.

**Working and tested**

The build is warning-clean under `-Wall -Wextra -Wconversion -Wsign-conversion -Werror`,
and all three test suites pass in both Debug and Release:

| Suite | What it proves |
|---|---|
| `microfoam_tests` | 71 checks: round trip, **resume journal**, and fault injection at every stage |
| `host_selftest` | 64 checks: 500 randomised delta round-trips, LZ4 and LZMA round-trips, format layout agreement, signing |
| `cross_test` | The Python host tool's patch, applied by the C library, byte-exact |
| `lzma_conformance_test` | 335 checks: 67 liblzma vectors at five block sizes each (opt-in build) |

The cross test is the one that matters most: a library verified only against its own
encoder proves nothing about the format. Two independently written implementations agreeing
on a real 35 KB firmware pair is evidence.

Fault injection covers erase failure, program failure, **program succeeding but storing the
wrong bytes**, truncated payloads, flipped bits, wrong product, downgrade attempts, base
version mismatch, over-budget workspace, unknown codec, future format version, wrong
new-image CRC, abort, and signed-without-verifier. Each asserts a *specific* status code, and
none may return `MCF_OK`.

The resume journal is covered too: interrupt-and-continue, cleared-on-success, and four
rejection paths — torn record, foreign patch, corrupted flash prefix, and absent journal —
each of which must fall back to a cold start that still succeeds.

### Resume

```c
cfg.journal_addr     = 0x0F000000u;  /* your NVM; 0 disables resume */
cfg.journal_interval = 32;           /* blocks between checkpoints, 0 = 32 */
...
mcf_session_open(s, &cfg);
if (mcf_resume_probe(s, &cfg) != MCF_OK) { /* no usable resume point */ }
mcf_session_begin(s);
```

Set `journal_addr` and the session records a resume point at every control-triple boundary.
After a reset, `mcf_resume_probe()` validates the record and the reconstructed prefix, and
`begin()` continues from there. A damaged, stale, or mismatched record is not an error — it
returns `MCF_E_NOT_FOUND` and the update starts clean.

**What resume saves and what it does not.** The prefix is re-derived from the start of the
delta stream and discarded, so the work saved is *flash programming*, not CPU. That is the
right trade: flash writes are the expensive part, and seeking the decompressor to an arbitrary
byte offset is not expressible in the current codec interface — a decompressed-stream
position and a compressed-stream position are different coordinate systems, and only the
codec knows where its block boundaries are. A future codec `rewind` entry point would make
resume cheaper still; see the note in `docs/architecture.md` §15.

If a checkpoint prefix read or journal write fails, the update continues best-effort but
sets `MCF_SESSION_FLAG_RESUME_DEGRADED`; no further resume point is promised. The caller
should record that diagnostic if resumability is a product requirement.

The journal proves the prefix on flash still matches what the patch says. It is **not** an
authenticity control: it lives in NVM the device itself writes, and the threat it addresses
is corruption and interruption, not forgery.


**Not yet done**

- **Device-side Ed25519.** A from-scratch verifier was written and **rejected**: after fixing
  twelve real defects, every primitive tested correct in isolation yet end-to-end
  verification still failed — and partway through, a transposed comparison made *forged*
  signatures verify. A verifier that is subtly wrong in the permissive direction silently
  defeats the one control this library exists to provide. Work, defect log, and the
  conformance harness are in [`contrib/ed25519-wip/`](contrib/ed25519-wip/README.md).
  The arithmetic remains quarantined and is never part of `MCF_SOURCES`. Signed patches
  are rejected with `MCF_E_SIGNATURE` unless the application supplies a vetted provider
  through `mcf_verify_fn`. An optional libsodium adapter is available with
  `-DMCF_ENABLE_SODIUM=ON`; its RFC 8032 test uses published TEST 1 values. Do not link
  `contrib/ed25519-wip/mcf_ed25519.c` into production.
- **armclang and IAR.** The code is written with portability to both in mind (C99, no GNU
  extensions, no VLAs, no designated-initialiser dependence in the public header,
  `extern "C"` guards), but neither toolchain is currently verified in CI or locally.
  The verified embedded compiler path is ARM GCC; armclang/IAR support remains an
  unverified portability target pending licensed toolchain builds.

## LZMA

The LZMA decoder is the vendored **LZMA SDK** — the reviewed implementation, not a
from-scratch one. An earlier from-scratch decoder was written, fixed through fifteen
real defects, and retired at 133/335 conformance; the defect log is preserved in
[`docs/lzma-history.md`](docs/lzma-history.md) as a record of why the SDK is the
recommendation for a range coder.

- **Wire format.** The 9-byte properties block: encoded `lc/lp/pb`, dictionary size, exact
  decompressed length. The exact length is what makes truncation detectable.
- **Encode (host).** `python host/microfoam.py make ... --codec lzma [--dict-size N]`.
  Compression is Python's stdlib `lzma` module (liblzma), the format's reference
  implementation.
- **Verify (device).** `tests/lzma_conformance_test.c` decodes 67 liblzma-generated vectors
  (the full legal `lc/lp/pb` range, ring-wrap dictionaries, both literal forms, repeated
  distances, the position-slot and align trees) at five block sizes each: **335/335**.
  `cross_test_lzma` additionally proves a host-produced LZMA patch applies byte-exact
  through the C session.
- **Fail closed.** A build without `-DMCF_ENABLE_LZMA=ON` rejects an LZMA patch with
  `MCF_E_UNSUPPORTED` during header validation, before any allocation.

## Codec vtable

`decode` takes capacity and produced as **separate** parameters, and `init` returns its
handle through an out-parameter. Both were changed after the LZMA harness found that the
original in/out length pointer let a caller zero-initialise the capacity and get a codec that
correctly produced nothing — which presents as a corrupt stream, not as misuse.

```c
int32_t (*decode)(mcf_codec_t *c,
                  uint8_t *out, uint32_t cap, uint32_t *produced,
                  const uint8_t *in, uint32_t in_avail, uint32_t *consumed);
```

A stateless codec (LZ4) is handed the sliding window: current position and bytes remaining.
A stateful codec — LZMA's range coder — cannot use that convention and defines its own:
it captures the stream base and total length on the first call and keeps its own cursor;
`consumed` reports the per-call delta. Both conventions are documented in their headers
(`mcf_codec_lz4.h`, `mcf_lzma.h`).

## Known issues


### The LZ4 block size is a hard format constraint

A single LZ4 block may not expand past `block_size`, taken from the header's
`block_size_log2`. The device decodes into a buffer of exactly that size and rejects
anything larger as `MCF_E_CORRUPT`.

This is not a hint. The host tool must chunk its framing to the same field the device reads,
and the C test fixture must do the same. Getting it wrong produces a patch that is
byte-perfect when decoded by a reference implementation and rejected by the device — which
is exactly how this was found. The format is documented in `docs/format-v2.md` and the
self-test asserts no block exceeds the window.

### Defects found during bring-up

Recorded because they are the kind that survive to the field:

| Found by | Defect |
|---|---|
| Host round-trip | An Ed25519 signature is **64** bytes, not 32. The 32-byte figure is the *public key*. A 32-byte field shifted the payload and corrupted every field after it. |
| Randomised testing | A suffix-search `bsdiff` that assumed 16 verified bytes when it had proven 8. |
| Randomised testing | The BSDIFF43 seek positions the base for the **next** triple, not its own. |
| Compilation | `MCF_SESSION_DECLARE` cast the storage object rather than its address. |
| Compilation | The codec decoded the 4-byte length prefix as block data. |
| Compilation | The codec reported the *remaining* count where the caller expected *consumed*, so the source cursor jumped to the end marker. |
| Test suite | The host tool and the device disagreed on the LZ4 block size. |
| Test suite | The payload CRC was only verified for signed patches, leaving unsigned ones unchecked. |

The last two are the argument for the fault-injection suite: neither was visible from
reading the code, and both would have shipped.


---

## Licence

MIT. See [LICENSE](LICENSE) for the full text and the required third-party notices
(bsdiff/bspatch, BSD 2-Clause).

Copyright (c) 2026 Microfoam contributors.
