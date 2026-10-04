# Microfoam

**Tiny bubbles. Tiny footprint. Full-strength upgrade.**

A firmware delta-update library for resource-constrained microcontrollers. Ship only the
difference between two firmware versions, and reconstruct the full image on the device — in a
few kilobytes of RAM, with no heap and no RTOS.

[![CI](https://github.com/coffeetocoffee/microfoam/actions/workflows/ci.yml/badge.svg)](https://github.com/coffeetocoffee/microfoam/actions/workflows/ci.yml)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)
![Language: C99](https://img.shields.io/badge/language-C99-blue.svg)
[![RAM: 868 B, no heap](https://img.shields.io/badge/RAM-868%20B%20%C2%B7%20no%20heap-success.svg)](#verified-footprint)

| At a glance | |
|---|---|
| **Delta size** | typically **1–15%** of the image |
| **RAM** | **868 B** total (LZ4, 256 B block) — 340 B session + 528 B workspace, no heap; ~1.4 KB at a 512 B block |
| **ROM** | **12,358 B** on Cortex-M0; all tables `const`, enforced by a CI size gate |
| **Dependencies** | `<stdint.h>`, `<stddef.h>`, `<string.h>`. No heap. No RTOS. |
| **Language** | C99, MISRA-friendly, `-Wall -Wextra -Wconversion` clean |
| **Verified targets** | arm-none-eabi-gcc: Cortex-M0, M3, M4, M7 — the four cores in the CI matrix. M0+ and M33 are untested portability targets. |
| **Licence** | MIT |
| **Status** | `1.9.5` — see [what works and what does not](#status) |

```c
#include "microfoam.h"   /* the v1 API; MFP2 adds microfoam_v2.h */
```

> [!NOTE]
> The header is declarations only — no macros that hide control flow, and no dependency
> beyond `<stdint.h>` and `<stddef.h>`.

**Contents**

[Why](#why) ·
[Quick start](#quick-start) ·
[Design commitments](#design-commitments) ·
[The HAL contract](#the-hal-contract) ·
[Signature verification](#signature-verification) ·
[Codecs](#codecs) ·
[Footprint](#verified-footprint) ·
[Building and testing](#building-and-testing) ·
[Status](#status) ·
[Licence](#licence)

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
primary target from *"Cortex-M3 with a 20 KB heap"* down to **a Cortex-M0 with 4 KB**.

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

Implement the HAL — everything platform-specific lives there — then run a session.

```c
#include "microfoam.h"

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
    cfg.block_size  = 1024u;   /* must be >= the patch's framing block size */
    cfg.ram_budget  = 4096u;   /* >= 2*block_size + the codec's own state   */

    if (mcf_session_run(session) != MCF_OK) {
        /* Every failure is a distinct code. mcf_session_strerror() names it. */
        log_error("microfoam: %s", mcf_session_strerror(mcf_session_status(session)));
    }
    mcf_session_close(session);
}
```

No heap? Give each session its own static buffer instead — see
[the HAL contract](#the-hal-contract).

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
Ed25519 provider; see [the HAL contract](#the-hal-contract).

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

<details>
<summary><b>Why a packaging CI job exists</b></summary>

Running `python host/microfoam.py ...` from a checkout keeps working and is what most CI jobs
use. A dedicated packaging job builds the sdist, installs it with both extras, and round-trips
MFP1 and MFP2 through the installed `microfoam` command — so the published distribution is
exercised rather than assumed.

</details>

---

## Design commitments

The properties the library is built around. Each exists because its absence causes silent
field failures in comparable libraries.

**Every failure is reported, specifically.** There are 18 status codes. Zero means success and
means only success. There is no value that means both "succeeded" and "failed", and no code
path that reports success after an error. If a flash program fails you get `MCF_E_FLASH` — not
a full-length, silently corrupt image.

**The memory contract is explicit and enforced.** `mcf_ctx_size()` returns the exact dynamic
workspace a given patch and configuration will allocate — computable before any flash is
touched, so it can size a static buffer or a pool at build time. The test suite asserts that
number against what the allocator is actually asked for during a run, so the published figure
cannot drift from the real one. The patch declares its own decoder requirement in
`workspace_req`, and the device returns `MCF_E_DICT_TOO_LARGE` *before allocating anything* if
it does not fit `ram_budget`. It never attempts an allocation it cannot satisfy, and never
dereferences a null codec.

**The caller owns all state.** There is no mutable global session state. All state lives in a
caller-provided `mcf_session_t`, so the library is reentrant and usable from a static buffer on
a system with no heap.

**Long operations are steppable.** `mcf_session_step()` performs at most one block of work and
returns. Service a watchdog, sleep, or report progress between steps. Aborting through the
progress callback is a clean `MCF_E_ABORTED`, not a forced reset.

**The flash contract is enforced, not assumed.** The library never issues an unaligned or
block-crossing erase or program, and it reads every programmed region back and compares it
(unless `flash_is_readonly` reports that region cannot be read). Your callback does not have
to know the erase geometry.

**Updates can be authenticated, and the choice is explicit.** Product binding and
anti-rollback are always enforced. Signature verification is built in and fails closed — a
patch that claims to be signed is rejected if no verifier is available, never accepted
unverified. Note that an *unsigned* patch carries no signature to check and is applied by
default, so a product that must reject them configures a verifier (see the HAL contract).

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

**Device-side Ed25519.** Two options, both fail-closed by default.

- **Built-in, no external library:** configure `-DMCF_ENABLE_ED25519=ON` and install
  `mcf_ed25519_verify` as the HAL's `verify` callback (and `mcf_ed25519ph_verify3` as the MFP2
  `verify`). Keep a 32-byte public key in immutable storage. The verifier streams the signed
  message, so it needs **no allocator and no buffer proportional to the patch**. See
  [Signature verification](#signature-verification).
- **libsodium:** configure `-DMCF_ENABLE_SODIUM=ON` and install `mcf_sodium_verify`. The adapter
  uses the context's allocator for its temporary concatenated message.

A default build includes no cryptography and rejects signed patches unless a verifier callback
is configured. That is deliberate: it fails closed, visibly.

<details>
<summary><b>Deprecated compatibility helpers</b></summary>

The former global `mcf_hal_set_static_workspace()` entry point is deprecated and returns
`MCF_E_UNSUPPORTED`. `mcf_hal_register()` is also compatibility-only and stores nothing; every
session must set `cfg.hal`. Both are marked `MCF_DEPRECATED` in the header, so a migrating
caller gets a compiler diagnostic rather than silence; define `MCF_NO_DEPRECATED` to suppress
it. Neither is on any session path — `mcf_session_open()` repeats the same HAL checks — and
both are removal candidates for the next major version.

</details>

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

The built-in verifier implements both constructions this library needs — plain **Ed25519**
(RFC 8032 §5.1) for MFP1 and **Ed25519ph** (§5.1 with the `dom2` prehash) for MFP2 — and
streams the signed message, so verifying a patch needs **no allocator and no buffer
proportional to the patch**. It costs **≈ 6.3 KB of flash** on Cortex-M4 with `--gc-sections`
(`.text` 4,342 B + `.rodata` 1,928 B, 0 B static RAM), measured by linking only the verifier
path - see [`third_party/tweetnacl/README.md`](third_party/tweetnacl/README.md#measured-footprint).
All of TweetNaCl's salsa20, poly1305, `crypto_box` and keypair code is discarded by
`--gc-sections`, so only the ed25519 verify path is retained.

```c
#include "microfoam_ed25519.h"

static mcf_ed25519_ctx_t g_verify = { g_public_key };   /* 32 bytes, immutable */

cfg.verify     = mcf_ed25519_verify;      /* MFP1: plain Ed25519    */
cfg.verify_ctx = &g_verify;
/* MFP2 takes the same context through mcf_v2_config_t.verify, with
 * mcf_ed25519ph_verify3 as the function. */
```

**The field and group arithmetic is vendored, not written here.** It is
[TweetNaCl](third_party/tweetnacl/README.md) — public domain, ~700 lines, no `__int128` — which
is the reviewed part. `src/mcf_sha512.c` and `src/mcf_ed25519.c` are ours and supply the hash,
the two constructions and the callback adapters. That split is the whole point: an earlier
from-scratch verifier was written for this project and **rejected**. After twelve fixed defects,
one of them permissive — a transposed point comparison that made *forged* signatures verify — it
could not be shown to reject forgeries reliably. Writing the arithmetic is exactly what failed,
so the arithmetic is what is now borrowed. That work and its defect log remain in
[`contrib/ed25519-wip/`](contrib/ed25519-wip/README.md) as a record; it is never compiled and
**must not be linked into production.**

Three things are worth stating precisely, because each is a place a verifier quietly goes wrong:

- **The `S < L` canonicality check is enforced, and it is load-bearing.** TweetNaCl's own
  `crypto_sign_open` does **not** enforce it and libsodium does, so a signature carrying `S + L`
  satisfies the group equation — `[S+L]B == [S]B` — and is accepted by one while the other
  rejects it. Both halves were checked by execution: TweetNaCl accepts the `S + L` form of the
  RFC 8032 §7.1 vector, libsodium rejects it, and `ed25519_test` asserts the built-in verifier
  refuses it too. Deleting the check makes that case fail, so the test is falsifiable rather than
  merely green.
- **Domain separation is real.** An Ed25519ph signature is refused by the plain-Ed25519 path and
  vice versa, asserted in both directions. This is why a `ph` verifier cannot be built by handing
  TweetNaCl's `crypto_sign_open` a prehashed message: the `dom2` prefix precedes `R` and `A` in
  the hash input, so it cannot be injected by choosing the message.
- **The verifier streams, so it cannot lean on a one-shot hash.** That is what makes
  `mcf_sha512.c` necessary, and it is checked against published digests at the block boundaries
  (112, 128, 129 bytes) and on the streamed million-byte case, not only on short inputs.

**The evidence is differential, not just round-trip.** `ed25519_test` checks the published
RFC 8032 §7.1 and §7.3 vectors and a negative matrix, and then — when libsodium is *also*
built — asserts that the two implementations return the **same verdict for every case**,
including signatures libsodium generated over messages neither implementation chose, with the
tampering mutation applied to both. Agreement with an independently written implementation on
inputs it generated is not something a self-consistent bug can fake; a round-trip through one's
own code can be.

---

## Codecs

| Codec | Decoder state | RAM | Payload vs LZMA | Default |
|---|---|---|---|---|
| **LZ4** | ~16 B | + block buffers | ~1.7× at the default 1 KB block (see below) | **yes** |
| LZMA | probability table + dictionary | see below | baseline | no (`-DMCF_ENABLE_LZMA=ON`) |
| Raw | 16 B | none | delta verbatim | no (`--codec raw`) |

**LZ4 is the default because it buys RAM, not bytes.** It decodes in ~16 B of state rather than
an LZMA probability table, but on the same delta it emits a **larger** payload — on the suite's
35 KB fixture, **1.67×** LZMA's at the default 1 KB block (1,934 B vs 1,160 B). The gap narrows
as the block grows (1.09× at 32 KB), but the LZ4 workspace is `2 × block_size`, so closing it
that way costs the very RAM LZ4 was chosen to save. `host_selftest` measures and pins this
figure, so it cannot drift from the implementation.

**Raw** is the delta stream passed through untouched — no framing, no properties, no per-block
headers. Use it when the delta is small enough that a codec's headers cost more than they save,
or when the producer knows the delta is incompressible. It weakens nothing: the payload CRC,
the engine's control-triple bounds checks and the whole-image CRC all still apply.

**LZMA** is opt-in because its probability table is an unconditional RAM floor that this
architecture exists to remove — but when enabled it is a fully supported, CI-tested codec. Its
**9-byte properties block** carries the encoded `lc/lp/pb`, the dictionary size, and the exact
decompressed length — that exact length is what makes truncation detectable. The decoder is the
vendored **LZMA SDK** (`third_party/lzma-sdk`, public domain, Igor Pavlov), the same
implementation shipped in 7-Zip, U-Boot, and EDK2. A patch declaring LZMA on a build without it
is rejected as `MCF_E_UNSUPPORTED` rather than handed to a stub. This adds no external link
dependency: the SDK sources are compiled into the library. **liblzma is host-side only** — it is
the reference encoder behind `host/lzma_vectors.py` that generates the conformance vectors,
which is what makes those vectors an external check rather than a self-confirming one. (An
earlier hand-written decoder was fixed through fifteen real defects and retired at 133/335
conformance; `docs/lzma-history.md` is its retirement record, not a proposal for future work.)

<details>
<summary><b>LZMA parameter policy, workspace, and the encode/verify path</b></summary>

- **Encode (host).** `python host/microfoam.py make ... --codec lzma [--dict-size N]`.
  Compression is Python's stdlib `lzma` module (liblzma), the format's reference
  implementation.
- **Verify (device).** `tests/lzma_conformance_test.c` decodes 67 liblzma-generated vectors
  (the full legal `lc/lp/pb` range, ring-wrap dictionaries, both literal forms, repeated
  distances, the position-slot and align trees) at five block sizes each: **335/335**.
  `cross_test_lzma` additionally proves a host-produced LZMA patch applies byte-exact through
  the C session.
- **Fail closed.** A build without `-DMCF_ENABLE_LZMA=ON` rejects an LZMA patch with
  `MCF_E_UNSUPPORTED` during header validation, before any allocation.

A patch's properties block declares `lc/lp/pb` and a dictionary size, and those set the
decoder's resident cost. Two optional `mcf_config_t` fields let a product bound that by policy,
checked during header validation **before anything is allocated**:

| Field | `0` means | Rejection |
|---|---|---|
| `lzma_max_dict` | no limit | `MCF_E_DICT_TOO_LARGE` at the workspace stage |
| `lzma_max_lc_plus_lp` | no limit | `MCF_E_FORMAT` at the LZMA-properties stage |

Setting both on a deployed product turns *"the decoder needed more RAM than we have"* from an
unreportable field failure into a named rejection with its own diagnostic stage. The decoded
parameters are readable afterwards through `mcf_session_lzma_info()`.

LZMA workspace, as reported by `mcf_lzma_workspace()` and declared in the patch header:

```
2 * (1984 + (768 << (lc + lp)))    probability table   (16,256 B at lc=3, lp=0)
+ dicBufSize                       dictionary, SDK-rounded (default 16,384 B)
+ 256 B                            decoder state
```

At the host tool's defaults (`lc=3`, `lp=0`, `pb=2`, 16 KB dictionary) that is **32,896 bytes**
of workspace — a Cortex-M4/M7-class figure, not a Cortex-M0 one. The host tool computes the
same number and writes it to `workspace_req`, so the device refuses an over-budget LZMA patch
during header validation, before allocating anything. Use `--dict-size 4096` to trade ratio for
RAM (≈20 KB total).

</details>

<details>
<summary><b>Custom codecs and the codec vtable</b></summary>

Custom codec descriptors are caller-owned and session-scoped: set `cfg.codecs` and
`cfg.codec_count` before opening a session. `mcf_codec_register()` validates a descriptor but
does not retain global state. Built-in LZ4 remains available automatically; custom IDs must be
in the `MCF_CODEC_CUSTOM_MIN` range and are never accepted without a matching per-session
descriptor. Two consequences are worth stating explicitly:

- The session's own table is consulted **before** the built-ins, so a descriptor whose id
  equals a built-in id replaces that built-in for that session. Use this to install a
  device-specific decoder for an existing wire id.
- The v1 container carries a leading parameter block only for the parameterised built-in ids
  (LZ4 and LZMA), so a custom codec is always handed `props_len == 0`. A custom format cannot
  depend on out-of-band parameters; the codec must ignore the `props` argument.

`decode` takes capacity and produced as **separate** parameters, and `init` returns its handle
through an out-parameter. Both were changed after the LZMA harness found that the original
in/out length pointer let a caller zero-initialise the capacity and get a codec that correctly
produced nothing — which presents as a corrupt stream, not as misuse.

```c
int32_t (*decode)(mcf_codec_t *c,
                  uint8_t *out, uint32_t cap, uint32_t *produced,
                  const uint8_t *in, uint32_t in_avail, uint32_t *consumed);
```

A stateless codec (LZ4) is handed the sliding window: current position and bytes remaining. A
stateful codec — LZMA's range coder — cannot use that convention and defines its own: it
captures the stream base and total length on the first call and keeps its own cursor; `consumed`
reports the per-call delta. Both conventions are documented in their headers
(`mcf_codec_lz4.h`, `mcf_lzma.h`).

Register your own codec through `mcf_codec_ops_t`; the descriptor is caller-owned and resolved
per session. `workspace_size` must not allocate, `init`/`decode`/`finish` return `MCF_OK` or a
negative status, and `decode` must report bounded output counts and make progress unless the
stream has ended. `destroy` is called after successful initialization on every later failure
path.

</details>

---

## Verified footprint

Measured with `arm-none-eabi-gcc` at `-Os`, every source compiled with `-Wall -Wextra -Werror
-Wconversion -Wsign-conversion -Wshadow -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes`.
All four configurations compile with zero warnings. These figures are checked in CI by
`cmake/size_gate.cmake`, which fails if `.text` grows past the ceiling in
`cmake/size_baseline.txt` or if any static RAM appears at all. The four cores below are the
ones the CI matrix builds; M0+ and M33 are untested portability targets and no figure is
claimed for them.

| Target | Code (`.text`) | Static RAM |
|---|---|---|
| Cortex-M0 | **12,358 B** | 0 B |
| Cortex-M3 | 11,420 B | 0 B |
| Cortex-M4 | 11,426 B | 0 B |
| Cortex-M7 | 11,422 B | 0 B |

The baseline ceilings sit a few percent above these figures, because the CI runner's
`gcc-arm-none-eabi` minor version differs from the one used here and moves code size by tens of
bytes (CI's Cortex-M0 figure runs about 100 B above the one here). A real regression is an
order of magnitude larger, so the allowance costs no sensitivity.

All tables are `const`, so nothing lands in RAM — a property the size gate enforces per target
rather than asserts in prose. The variation between cores is the architectures' different
multiply routines; the library's own code is essentially identical across them.

The MFP2 authenticated execution path (`mcf_v2_session.c`) is the largest single contributor at
roughly a third of the total, and it is compiled in unconditionally. A build that only needs
MFP1 can drop that one source from `MCF_SOURCES`.

### RAM, measured on Cortex-M0 (32-bit)

| Item | Bytes | Notes |
|---|---|---|
| `mcf_session_t` | **340** | Caller-owned; can be `static`, so not heap |
| `mcf_journal_t` | **20** | Resume record; lives in NVM, not RAM |
| Workspace, `block_size = 256` | **528** | 2 × 256 processing + 16 LZ4 state |
| Workspace, `block_size = 512` | 1,040 | |
| Workspace, `block_size = 1024` | 2,064 | |
| `mcf_config_t` | 100 | Prefer a `static const` in flash |
| `mcf_hal_t` | 48 | Prefer a `static const` in flash |
| `mcf_header_t` | 120 | Equals the wire header exactly — no padding |

The workspace figures are what `mcf_ctx_size()` returns for that configuration; the self-test
asserts the query against the allocator's actual request rather than trusting the table.

> [!TIP]
> **Constrained profile: 340 + 528 = 868 bytes of RAM**, plus a small stack for the integrity
> chunks. No heap needed, on a part with 8 KB.

The LZMA codec, when enabled, adds its probability table (16 KB at the default `lc=3`) plus a
dictionary (16 KB default, `--dict-size` to change) — see [Codecs](#codecs) for the exact
formula. That is why it is opt-in and why LZ4 is the default.

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
| `MCF_BUILD_TESTS` | `ON` | Build the host test suite |
| `MCF_BUILD_FUZZER` | `OFF` | Build the coverage-guided `v2_parse_fuzzer` with ASan/UBSan (requires Clang) |
| `MCF_WERROR` | `ON` | Warnings are errors |
| `MCF_STRICT` | `ON` | Add `-Wconversion -Wsign-conversion` |

Or drop the sources into an existing project — twelve `.c` files and three headers, and no
generated code. Only the ones the build selects are compiled: `mcf_lzma.c` and `mcf_sodium.c`
are opt-in, and `mcf_v2.c`/`mcf_v2_session.c` are the MFP2 execution path:

```cmake
add_subdirectory(microfoam)
target_link_libraries(my_app PRIVATE microfoam::microfoam)
```

<details>
<summary><b>Repository layout</b></summary>

```
include/microfoam.h        the public v1 API
include/microfoam_v2.h     MFP2 execution API: session, journal, structural parser
include/microfoam_sodium.h libsodium adapter for Ed25519ph verify and XChaCha20-Poly1305 (opt-in)
src/mcf_container.c        MFP1 header parse and validation (the only session format)
src/mcf_engine.c           BSDIFF43 delta loop, resumable, 32-bit clean
src/mcf_session.c          state machine, workspace, flash write path
src/mcf_codec_lz4.c        LZ4 block decoder
src/mcf_codec_raw.c        raw (uncompressed) codec
src/mcf_lzma.c             LZMA codec adapter (opt-in)
src/mcf_codec.c            codec registry
src/mcf_hal.c              HAL registration, workspace allocation
src/mcf_util.c             CRC-32, version, diagnostics
src/mcf_v2.c               MFP2 structural parser (shape only; never decrypts)
src/mcf_v2_session.c       MFP2 authenticated execution: streaming decrypt, resume
src/mcf_sodium.c           libsodium adapter (opt-in, MCF_ENABLE_SODIUM)
third_party/lzma-sdk/      vendored LZMA SDK decoder (public domain)
host/microfoam.py          patch generator, inspector, verifier, reference decoder
host/selftest.py           host tool self-test
host/check_counts.py       checks the README's stated check counts against the suites
host/check_quickstart.py   builds the README's quick-start patch and applies it as documented
host/lzma_vectors.py       generates the LZMA conformance vectors via liblzma
tests/test_microfoam.c     fault-injection and round-trip tests
tests/hal_concurrency_test.c  two sessions driven interleaved, proving reentrancy
tests/custom_codec_test.c  caller-owned codec descriptors and failure propagation
tests/patch_fixture.h      shared MFP1 patch builder used by the C suites
tests/lzma_conformance_test.c  LZMA conformance harness (67 vectors x 5 block sizes)
tests/lzma_policy_test.c   LZMA dictionary and lc+lp policy rejections
tests/cross_test.c         host-tool patch applied by the C library
tests/v2_format_test.c     MFP2 structural parser cases and mutation/property loop
tests/v2_parse_fixture.h   parser property oracle shared by the suite and fuzz target
tests/fuzz_v2_parse.c      MFP2 parser fuzz target (libFuzzer entry and portable smoke driver)
tests/mfp2_boundary_test.c MFP2 session boundary: tamper matrix and resume
tests/mfp2_fixtures.py     re-signed MFP2 tamper variants for the boundary test
tests/sodium_rfc_test.c    published Ed25519/Ed25519ph/XChaCha20-Poly1305 vectors
tests/ed25519_test.c       built-in verifier: vectors, negatives, differential vs libsodium
src/mcf_ed25519.c          built-in Ed25519/Ed25519ph verifier (opt-in)
src/mcf_sha512.c           streaming SHA-512 over TweetNaCl's compression function
third_party/tweetnacl/     vendored public-domain field/group arithmetic (unmodified)
tests/fixtures/            deterministic firmware pair and a test key
contrib/ed25519-wip/       rejected verifier, defect log, and conformance harness
docs/architecture.md       the design this implements, and why
docs/format-v2.md          the shipped MFP1 on-flash patch format
docs/format-v2-design.md   MFP2 design: AEAD container, signed message, resume
docs/mfp2-streaming-decryption-design.md  the streaming record window and its trade-offs
docs/lzma-history.md       why the from-scratch LZMA decoder was retired
docs/bring-up-defects.md   defects found during bring-up, and how each was caught
```

</details>

---

## Status

Honest accounting of what exists and what does not.

### Working and tested

The production/session path supports MFP1 and MFP2. MFP2 execution is a caller-owned session
(`mcf_v2_session_*`, with Ed25519ph and XChaCha20-Poly1305 supplied either by the built-in
verifier or by the application's own providers): it verifies the signature **before** key
lookup, authenticates every record **before** decode, decrypts records one at a time into a
small sliding window (the whole decrypted payload is never resident), and hands the
reconstructed delta stream to the unchanged MFP1 engine. Resume is opt-in via `journal_addr`
and record-aligned.

Signature verification is available in-tree, with no external crypto library, via
`-DMCF_ENABLE_ED25519=ON` — see [Signature verification](#signature-verification). It is opt-in
rather than default so that a product which already carries a crypto stack does not pay for a
second one.

The build is warning-clean under `-Wall -Wextra -Wconversion -Wsign-conversion -Werror`, and
the standard test configurations pass in both Debug and Release.

| Suite | Checks | What it proves |
|---|---|---|
| `microfoam_tests` | 110 checks | round trip, the `mcf_ctx_size()` cost query, **resume journal**, the BSDIFF43 seek ordering, small-image framing, and fault injection at every stage |
| `custom_codec_test` | 46 checks | caller-owned codec descriptors, per-session table isolation, and failure propagation at init, decode, and finish |
| `hal_concurrency_test` | 27 checks | two sessions driven interleaved through the whole decode, each proving its own image |
| `v2_format_test` | 45 checks | MFP2 header/TLV/record-framing rules, plus a ~4,200-case deterministic mutation/property loop |
| `host_selftest` | 119 checks | 500 randomised delta round-trips, LZ4/raw/LZMA round-trips, the measured LZ4-vs-LZMA payload ratio, LZMA props + policy fields, format layout agreement, signing, small-image framing decoded at the device's window, MFP2 KAT, the fixed-nonce-prefix guard, MFP2 host hygiene (no cached nonce prefix, device-matching TLV walk, computed `workspace_req`), and host-side tamper cases each pinned to the layer that rejects them |
| `sodium_rfc_test` | 17 checks | published vectors for both constructions MFP2 depends on — RFC 8032 §7.1 Ed25519 and §7.3 Ed25519ph (with the three-span streaming verify and its domain separation from plain Ed25519) and the draft-irtf-cfrg-xchacha-03 §A.1 XChaCha20-Poly1305 AEAD vector — plus adapter tamper cases *(with `MCF_ENABLE_SODIUM=ON`)* |
| `ed25519_test` | 354 checks | the built-in verifier: NIST SHA-512 digests including the streamed million-byte case and the 112/128/129-byte padding boundaries, RFC 8032 §7.1 and §7.3 vectors, a negative matrix, the `S + L` malleability case, domain separation between the two constructions, and — with libsodium also built — a **differential** asserting both verifiers return the *same verdict* on every case, including signatures libsodium generated over messages neither implementation chose *(with `MCF_ENABLE_ED25519=ON`; the differential section needs `MCF_ENABLE_SODIUM=ON` too and reports `SKIP` without it)* |
| `lzma_conformance_test` | 335 checks | 67 liblzma vectors at five block sizes each *(with `MCF_ENABLE_LZMA=ON`)* |
| `lzma_policy_test` | 15 checks | dictionary and `lc+lp` policy rejections with their exact status and stage *(with `MCF_ENABLE_LZMA=ON`)* |
| `v2_fuzz_smoke` | — | the shared parser property oracle over a built-in seed and its truncations (portable; no sanitizer runtime needed) |
| `cross_test` | — | the Python host tool's patch, applied by the C library, byte-exact, plus a **signed** patch the device must refuse because no verifier is configured |
| `cross_test_raw` | — | a Python-produced **raw** patch applied by the C library |
| `cross_test_lzma` | — | a Python-produced **LZMA** patch applied by the C library *(with `MCF_ENABLE_LZMA=ON`)* |
| `mfp2_host_to_session` | — | a PyNaCl-produced signed+encrypted MFP2 patch applied byte-exact, rejecting 14 tamper variants with zero flash mutations, each pinned to its exact status *(sodium + PyNaCl)* |
| `documented_counts` | — | the counts in this table, compared against what the suites in the build tree actually report |
| `quickstart_config` | — | the quick-start device configuration applied to a patch built by the quick-start host command, so the documented pairing is runnable and not just plausible |

> [!IMPORTANT]
> **The cross test is the one that matters most.** A library verified only against its own
> encoder proves nothing about the format. Two independently written implementations agreeing
> on a real 35 KB firmware pair is evidence.

**The MFP2 parser is the one surface that consumes attacker-controlled bytes**, so it is held
to a property contract rather than a list of cases: for *every* input, `mcf_v2_parse` must
return a defined status, must not modify its input buffer, and on success must produce a view
that an independent re-derivation of the frozen framing reproduces, with iteration yielding
exactly the declared records. `v2_format_test` samples that space deterministically;
`v2_fuzz_smoke` asserts the same oracle on every platform; and with `MCF_BUILD_FUZZER=ON` a
Clang/libFuzzer target searches it with coverage feedback under ASan/UBSan. The oracle is proven
non-vacuous — it rejects a view with an inflated record count, a shifted header length, or a
mutated framing byte — so a passing run is evidence rather than a tautology.

**The zero-mutation claim is falsifiable.** The successful MFP2 apply asserts the flash-mutation
counter moved, so a counter that could never increment fails the suite instead of quietly making
every tamper assertion vacuous.

**Fault injection** covers erase failure, program failure, *program succeeding but storing the
wrong bytes*, truncated payloads, flipped bits, wrong product, downgrade attempts, base version
mismatch, over-budget workspace, unknown codec, future format version, wrong new-image CRC,
abort, and signed-without-verifier. Each asserts a *specific* status code, and none may return
`MCF_OK`.

<details>
<summary><b>Resume: what it saves, and what it is not</b></summary>

```c
cfg.journal_addr     = 0x0F000000u;  /* your NVM; leave zero to disable resume */
cfg.journal_interval = 32;           /* blocks between checkpoints, 0 = 32 */
...
mcf_session_open(s, &cfg);
if (mcf_resume_probe(s, &cfg) != MCF_OK) { /* no usable resume point */ }
mcf_session_begin(s);
```

Resume is disabled by default. Only when `journal_addr` points to a caller-provided NVM region
does the session record checkpoints at control-triple boundaries. After a reset,
`mcf_resume_probe()` validates the record and reconstructed prefix, and `begin()` continues from
there. With no valid checkpoint it returns `MCF_E_NOT_FOUND` and the update starts clean.

The prefix is re-derived from the start of the delta stream and discarded, so the work saved is
*flash programming*, not CPU. That is the right trade: flash writes are the expensive part, and
seeking the decompressor to an arbitrary byte offset is not expressible in the current codec
interface — a decompressed-stream position and a compressed-stream position are different
coordinate systems, and only the codec knows where its block boundaries are. A future codec
`rewind` entry point would make resume cheaper still; see `docs/architecture.md` §15.

If a checkpoint prefix read or journal write fails, the update continues best-effort but sets
`MCF_SESSION_FLAG_RESUME_DEGRADED`; no further resume point is promised. The caller should
record that diagnostic if resumability is a product requirement.

The journal proves the prefix on flash still matches what the patch says. It is **not** an
authenticity control: it lives in NVM the device itself writes, and the threat it addresses is
corruption and interruption, not forgery.

Coverage lives in `microfoam_tests`: interrupt-and-continue, cleared-on-success, four
invalid-record fallback cases, and the default-disabled behavior.

**MFP2 resume is record-aligned.** `mcf_v2_config_t` carries the same `journal_addr` /
`journal_interval` pair, and the same opt-in rule applies: zero disables it entirely. Because
every MFP2 record is an independently authenticated unit, the checkpoint is taken on erase-block
boundaries and the resume re-feeds the codec from the record that contains the recorded position
only — the prefix records are neither re-decrypted nor re-programmed. Repeated work is bounded by
one record (at most `2^record_log2` bytes of plaintext); everything below the checkpoint's erase
block is left exactly as the interrupted run left it. `mcf_v2_resume_probe()` returns
`MCF_E_NOT_FOUND` for a missing, damaged, or foreign record, and
`MCF_V2_SESSION_FLAG_RESUME_DEGRADED` reports a lost checkpoint guarantee. A completed update
clears the journal.

</details>

### Not yet done

- **A verifier that is on by default.** Device-side Ed25519 now exists in-tree and is opt-in
  (see [Signature verification](#signature-verification)). A build with no verifier still
  refuses a signed patch with `MCF_E_SIGNATURE`, which is fail-closed and deliberately
  unchanged. Promoting the built-in verifier to the default is a one-line CMake change plus a
  deliberate raise of the size ceiling; it is not done because a product that already carries a
  crypto stack should not pay roughly 6 KB of flash for a second one.
- **armclang and IAR.** The code is written with portability to both in mind (C99, no GNU
  extensions, no VLAs, no designated-initialiser dependence in the public header, `extern "C"`
  guards), but neither toolchain is currently verified in CI or locally. The verified embedded
  compiler path is ARM GCC; armclang/IAR support remains an unverified portability target
  pending licensed toolchain builds.

---

## Licence

MIT. See [LICENSE](LICENSE) for the full text and the required third-party notices
(bsdiff/bspatch, BSD 2-Clause).

Copyright (c) 2026 Microfoam contributors.
