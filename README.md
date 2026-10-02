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
| **Status** | 1.8.4 — see [Status](#status) | |

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
randomness. (The encrypted `make --v2` profile is the exception — it draws a fresh random
nonce prefix per patch, because reusing one with the same key would repeat every AEAD nonce.)

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
stores nothing; every session must set `cfg.hal`. Both are marked
`MCF_DEPRECATED` in the header, so a migrating caller gets a compiler diagnostic
rather than silence; define `MCF_NO_DEPRECATED` to suppress it. Neither is on any
session path — `mcf_session_open()` repeats the same HAL checks — and both are
removal candidates for the next major version.

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

Two consequences of per-session resolution are worth stating explicitly:

- The session's own table is consulted **before** the built-ins, so a descriptor whose id
  equals a built-in id replaces that built-in for that session. Use this to install a
  device-specific decoder for an existing wire id.
- The v1 container carries a leading parameter block only for the parameterised
  built-in ids (LZ4 and LZMA), so a custom codec is always handed `props_len == 0`.
  A custom format cannot depend on out-of-band parameters; the codec must ignore
  the `props` argument.

| Codec | Decoder state | RAM | Ratio vs LZMA | Default |
|---|---|---|---|---|
| **LZ4** | ~16 B | + block buffers | −5% to −15% on binary diffs | **yes** |
| LZMA | probability table + dictionary | see below | baseline | no (`-DMCF_ENABLE_LZMA=ON`) |
| Raw | 16 B | none | delta verbatim | no (`--codec raw`) |

**Raw** is the delta stream passed through untouched — no framing, no properties, no
per-block headers. Use it when the delta is small enough that a codec's headers cost more
than they save, or when the producer knows the delta is incompressible. It weakens nothing:
the payload CRC, the engine's control-triple bounds checks and the whole-image CRC all still
apply.

LZMA is opt-in because its probability table is an unconditional RAM floor that this
architecture exists to remove — but when enabled it is a fully supported, CI-tested codec.
The decoder is the vendored **LZMA SDK** (`third_party/lzma-sdk`, public domain, Igor
Pavlov), the same implementation shipped in 7-Zip, U-Boot, and EDK2. A patch declaring LZMA
on a build without it is rejected as `MCF_E_UNSUPPORTED` rather than handed to a stub.

This adds no external link dependency: the SDK sources are compiled into the library, so
nothing outside the standard C library is required at link time. **liblzma is host-side
only** — it is the reference encoder behind `host/lzma_vectors.py` that generates the
conformance vectors, which is what makes those vectors an external check rather than a
self-confirming one. `docs/lzma-history.md` is the retirement record of the hand-written
decoder this replaced, not a proposal for future work.

### LZMA parameter policy

A patch's properties block declares `lc/lp/pb` and a dictionary size, and those set the
decoder's resident cost. Two optional `mcf_config_t` fields let a product bound that by
policy, checked during header validation **before anything is allocated**:

| Field | `0` means | Rejection |
|---|---|---|
| `lzma_max_dict` | no limit | `MCF_E_DICT_TOO_LARGE` at the workspace stage |
| `lzma_max_lc_plus_lp` | no limit | `MCF_E_FORMAT` at the LZMA-properties stage |

Setting both on a deployed product turns "the decoder needed more RAM than we have" from an
unreportable field failure into a named rejection with its own diagnostic stage. The decoded
parameters are readable afterwards through `mcf_session_lzma_info()`.

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
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --output-on-failure -C Release
```

The signing tests need a host Ed25519 module (`pip install cryptography`). The signing
seed itself is generated into the build tree at configure time, so no key needs to be
checked out or created by hand; `cross_test` fails rather than skips if the module is
missing.

| Test | What it checks |
|---|---|
| `microfoam_tests` | Round trip and fault injection against a mock device |
| `custom_codec_test` | Caller-owned codec descriptors: validation of every required member and the reserved id gap, per-session table isolation, built-in shadowing, budget enforcement, properties-less payload contract, and failure propagation |
| `host_selftest` | The Python tool against an independent reference implementation |
| `cross_test` | A Python-produced patch applied by the C library, plus a **signed** patch the device must refuse because no verifier is configured (needs a host signing module; the seed is generated into the build tree) |
| `cross_test_raw` | A Python-produced **raw** patch applied by the C library |
| `lzma_policy_test` | Dictionary / `lc+lp` policy rejections and diagnostics (with `MCF_ENABLE_LZMA=ON`) |
| `lzma_conformance_test` | 67 liblzma vectors × 5 block sizes against the LZMA decoder (with `MCF_ENABLE_LZMA=ON`) |
| `cross_test_lzma` | A Python-produced **LZMA** patch applied by the C library (with `MCF_ENABLE_LZMA=ON`) |
| `sodium_rfc_test` | libsodium adapter against published vectors: RFC 8032 §7.1 Ed25519 and §7.3 Ed25519ph (including the three-span streaming verify and its domain separation from plain Ed25519), the draft-irtf-cfrg-xchacha-03 §A.1 XChaCha20-Poly1305 AEAD vector, and adapter tamper cases (with `MCF_ENABLE_SODIUM=ON`) |
| `v2_format_test` | MFP2 structural parser: header/TLV/record-framing rules, plus a deterministic mutation loop (~4,200 truncations, byte mutations, and random blobs) |
| `v2_fuzz_smoke` | The parser property oracle shared with the fuzz target, run over a built-in seed, every truncation of it, and any corpus files given on the command line: a defined status, an untouched input buffer, and an independently re-derived framing and record iteration on success. Portable, so the assertions have a gate on every platform |
| `hal_concurrency_test` | Two independent sessions on separate HALs, with no shared state |
| `mfp2_host_to_session` | PyNaCl-produced signed+encrypted MFP2 patch: the C session applies it byte-exact in a workspace far smaller than the payload, and rejects 14 tamper variants with zero flash mutations, each pinned to its exact status. Six of them are re-signed with a recomputed payload CRC, so a valid signature and payload CRC leave the AAD record index, the nonce derivation, the AEAD tag, the ciphertext, or the key provider as the only thing that can reject them. The successful apply asserts the flash-mutation counter moved, so "zero flash mutations" is falsifiable rather than a counter that can never increment (sodium + PyNaCl required). |

`MCF_BUILD_FUZZER=ON` additionally builds `v2_parse_fuzzer`, a coverage-guided libFuzzer
target for `mcf_v2_parse` compiled with ASan/UBSan (Clang only; run it directly with a corpus
directory rather than through ctest). It asserts the same oracle as `v2_fuzz_smoke`, with
coverage feedback on top; the CI `fuzz` job seeds it from real host-produced patches and runs
it for a bounded time.

| Option | Default | Effect |
|---|---|---|
| `MCF_ENABLE_LZMA` | `OFF` | Build the LZMA codec (vendored LZMA SDK) |
| `MCF_ENABLE_SODIUM` | `OFF` | Build libsodium adapters and MFP2 host-to-session integration tests |
| `MCF_BUILD_TESTS` | `ON` | Build the host test suite |
| `MCF_BUILD_FUZZER` | `OFF` | Build the coverage-guided `v2_parse_fuzzer` with ASan/UBSan (requires Clang) |
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
include/microfoam.h        the public v1 API — the entire production contract
src/mcf_container.c        MFP1 header parse and validation (the only session format)
src/mcf_engine.c           BSDIFF43 delta loop, resumable, 32-bit clean
src/mcf_session.c          state machine, workspace, flash write path
src/mcf_codec_lz4.c        LZ4 block decoder
src/mcf_codec_raw.c        raw (uncompressed) codec
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
tests/v2_format_test.c     MFP2 structural parser cases and mutation/property loop
tests/v2_parse_fixture.h   parser property oracle shared by the suite and fuzz target
tests/fuzz_v2_parse.c      MFP2 parser fuzz target (libFuzzer entry and portable smoke driver)
tests/fixtures/            deterministic firmware pair and a test key
contrib/ed25519-wip/       rejected verifier, defect log, and conformance harness
docs/architecture.md       the design this implements, and why
docs/format-v2.md          the shipped MFP1 on-flash patch format
docs/format-v2-design.md   MFP2 design: AEAD container, signed message, resume
docs/lzma-history.md       the retired from-scratch LZMA decoder's defect log
include/microfoam_v2.h     MFP2 execution API: session, journal, structural parser
```

---

## Status

Honest accounting of what exists and what does not.

**Working and tested**

The production/session path supports MFP1 and MFP2. MFP2 execution is a caller-owned session
(`mcf_v2_session_*`, libsodium-backed through the application's Ed25519ph and
XChaCha20-Poly1305 providers): it verifies the signature before key lookup, authenticates
every record before decode, decrypts records one at a time into a small sliding window (the
whole decrypted payload is never resident), and hands the reconstructed delta stream to the
unchanged MFP1 engine. Resume is opt-in via `journal_addr` and record-aligned. The
optional sodium/PyNaCl CI test applies a host-produced encrypted patch end to end, byte-exact,
and rejects 14 tamper variants with zero flash mutations, each pinned to its exact status.
Six of those variants are re-signed with a recomputed payload CRC, so signature and payload
CRC both verify and only the AAD record index, the nonce derivation, the AEAD tag, the
ciphertext, or the key provider can reject them; a further check asserts the variants parse
and verify on the host before it rejects them, which is what stops a case from passing for
the wrong reason. The zero-mutation claim is itself falsifiable: the successful apply asserts
the counter moved, so a counter that could never increment fails the suite instead of
quietly making every tamper assertion vacuous.

The build is warning-clean under `-Wall -Wextra -Wconversion -Wsign-conversion -Werror`,
and the standard test configurations pass in both Debug and Release; the sodium configuration additionally requires libsodium and PyNaCl:

| Suite | What it proves |
|---|---|
| `microfoam_tests` | 79 checks: round trip, **resume journal**, and fault injection at every stage |
| `host_selftest` | 101 checks: 500 randomised delta round-trips, LZ4/raw/LZMA round-trips, LZMA props + policy fields, format layout agreement, signing, MFP2 KAT, the fixed-nonce-prefix guard, and host-side tamper cases each pinned to the layer that rejects them |
| `cross_test` | The Python host tool's patch, applied by the C library, byte-exact |
| `v2_format_test` | 45 checks: MFP2 header/TLV/record-framing rules, plus a ~4,200-case deterministic mutation/property loop |
| `v2_fuzz_smoke` | The shared parser property oracle over a built-in seed and its truncations (portable; no sanitizer runtime needed) |
| `sodium_rfc_test` | 17 checks: published Ed25519, Ed25519ph and XChaCha20-Poly1305 vectors, plus adapter tamper cases (opt-in build) |
| `lzma_conformance_test` | 335 checks: 67 liblzma vectors at five block sizes each (opt-in build) |
| `lzma_policy_test` | 15 checks: dictionary and `lc+lp` policy rejections with their exact status and stage |

The cross test is the one that matters most: a library verified only against its own
encoder proves nothing about the format. Two independently written implementations agreeing
on a real 35 KB firmware pair is evidence.

The MFP2 parser is the one surface that consumes attacker-controlled bytes, so it is held to
a property contract rather than a list of cases: for *every* input, `mcf_v2_parse` must return
a defined status, must not modify its input buffer, and on success must produce a view that an
independent re-derivation of the frozen framing reproduces, with iteration yielding exactly the
declared records. `v2_format_test` samples that space deterministically; `v2_fuzz_smoke`
asserts the same oracle on every platform; and with `MCF_BUILD_FUZZER=ON` a Clang/libFuzzer
target searches it with coverage feedback under ASan/UBSan. The oracle is proven non-vacuous -
it rejects a view with an inflated record count, a shifted header length, or a mutated framing
byte - so a passing run is evidence rather than a tautology.

Fault injection covers erase failure, program failure, **program succeeding but storing the
wrong bytes**, truncated payloads, flipped bits, wrong product, downgrade attempts, base
version mismatch, over-budget workspace, unknown codec, future format version, wrong
new-image CRC, abort, and signed-without-verifier. Each asserts a *specific* status code, and
none may return `MCF_OK`.

The resume journal is covered in `microfoam_tests`: interrupt-and-continue, cleared-on-success,
four invalid-record fallback cases, and the default-disabled behavior. Resume remains opt-in at
runtime: both journal configuration fields are zero by default; a zero `journal_addr` means no
checkpointing, and `mcf_resume_probe()` returns `MCF_E_NOT_FOUND`.

### Resume

```c
cfg.journal_addr     = 0x0F000000u;  /* your NVM; leave zero to disable resume */
cfg.journal_interval = 32;           /* blocks between checkpoints, 0 = 32 */
...
mcf_session_open(s, &cfg);
if (mcf_resume_probe(s, &cfg) != MCF_OK) { /* no usable resume point */ }
mcf_session_begin(s);
```

Resume is disabled by default. Only when `journal_addr` points to a caller-provided NVM
region does the session record checkpoints at control-triple boundaries. After a reset,
`mcf_resume_probe()` validates the record and reconstructed prefix, and `begin()` continues
from there. With no valid checkpoint it returns `MCF_E_NOT_FOUND` and the update starts clean.

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

**MFP2 resume is record-aligned.** `mcf_v2_config_t` carries the same
`journal_addr` / `journal_interval` pair, and the same opt-in rule applies:
zero disables it entirely. Because every MFP2 record is an independently
authenticated unit, the checkpoint is taken on erase-block boundaries and the
resume re-feeds the codec from the record that contains the recorded position
only — the prefix records are neither re-decrypted nor re-programmed. Repeated
work is bounded by one record (at most `2^record_log2` bytes of plaintext);
everything below the checkpoint's erase block is left exactly as the
interrupted run left it. `mcf_v2_resume_probe()` returns `MCF_E_NOT_FOUND` for
a missing, damaged, or foreign record, and `MCF_V2_SESSION_FLAG_RESUME_DEGRADED`
reports a lost checkpoint guarantee. A completed update clears the journal.


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
  `-DMCF_ENABLE_SODIUM=ON`; `sodium_rfc_test` checks published vectors for both constructions
  the MFP2 profile depends on — RFC 8032 §7.3 Ed25519ph (the streaming three-span verify and
  its domain separation from plain Ed25519) and the draft-irtf-cfrg-xchacha-03 §A.1
  XChaCha20-Poly1305 AEAD vector — plus adapter tamper rejection. Pinning these matters
  because a round-trip through the same library that produced the ciphertext proves only
  self-consistency; the published vectors are what prove the construction is the standard one.
  Separately, `mfp2_host_to_session` uses PyNaCl to produce a
  signed+encrypted patch and has the C session apply it end to end, byte-exact, with the full
  tamper matrix. Do not link
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
