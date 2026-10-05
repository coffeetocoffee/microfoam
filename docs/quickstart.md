# Quick start: device integration

The [README](../README.md#quick-start) shows the minimal session setup. This page is the
complete worked example — a full HAL for a generic Cortex-M part — and how to choose
`block_size`, `ram_budget`, the codec and the memory strategy.

Everything platform-specific lives in the HAL. The library itself is portable C99 with no
scheduler, no timers, no locks and no RTOS headers, so the same code runs on a bare-metal
superloop or an RTOS. The callback contract is below; its rationale is in
[architecture §12](architecture.md#12-flash-write-contract).

## The callback contract

Six callbacks are required on every path, plus `alloc`/`free` unless you supply a static
workspace. Everything else is optional. That is the entire platform dependency.

| Callback | Required | The rule, in one line |
|---|---|---|
| `flash_erase(ctx, addr, len)` | yes | `addr` aligned to, `len` a whole multiple of, `flash_block_size()`. `MCF_OK` or a negative status. |
| `flash_write(ctx, addr, p, len)` | yes | Never crosses an erase-block boundary; may be called repeatedly for one logical block. `MCF_OK` or negative — a byte count is not a valid return. |
| `flash_read(ctx, addr, p, len)` | yes | Returns exactly `len`, or a negative status. Required on every path, write-only regions included: the finish CRC reads the destination back out of flash. The base-image `old_read` callback follows the same exact-count rule. |
| `flash_block_size(ctx)` | yes | Erase granularity in bytes, a power of two. |
| `get_product_id`, `get_fw_version` | yes | Your provisioned identity and running version. |
| `alloc` / `free` | unless static | `NULL` from `alloc` is reported as `MCF_E_NOMEM`. |
| `flash_is_readonly` | no | Non-zero skips the per-write compare. It does **not** remove `flash_read`: the finish CRC still reads back. |
| `verify` | no | Signature verifier. `NULL` means none available, so signed patches are rejected. |
| `log` | no | Diagnostics. |

Two return-value rules catch integrators out, so they are worth stating twice: a `flash_write`
that programs correctly and returns a byte count is a **failure**, not a success; and a
`flash_read` that returns short is a failure even when it read something useful.

## A complete HAL

```c
#include "microfoam.h"
#include <string.h>

/* --- Flash geometry: adjust to your part. ------------------------------- */

#define FW_SIZE        0x00020000u   /* 128 KB application slot          */
#define FLASH_BASE     0x08000000u   /* running image, memory-mapped      */
#define STAGING_BASE   0x08020000u   /* the slot the update is written to */
#define ERASE_BLOCK    2048u         /* the part's page/sector size       */

/* Erase `len` bytes at `addr`. The library always passes an address aligned
 * to, and a length that is a whole multiple of, flash_block_size(). */
static int32_t my_erase(void *ctx, uint32_t addr, uint32_t len)
{
    (void)ctx;
    if (HAL_FLASH_Unlock() != HAL_OK) return MCF_E_FLASH;
    if (HAL_FLASHEx_Erase(addr, len) != HAL_OK) {
        HAL_FLASH_Lock();
        return MCF_E_FLASH;
    }
    HAL_FLASH_Lock();
    return MCF_OK;
}

/* Program `len` bytes. The library never crosses an erase-block boundary,
 * so a page-program primitive is enough. Return MCF_OK, not a byte count. */
static int32_t my_write(void *ctx, uint32_t addr, const uint8_t *p, uint32_t len)
{
    (void)ctx;
    if (HAL_FLASH_Unlock() != HAL_OK) return MCF_E_FLASH;
    if (HAL_FLASH_Program(addr, (uint32_t)p, len) != HAL_OK) {
        HAL_FLASH_Lock();
        return MCF_E_FLASH;
    }
    HAL_FLASH_Lock();
    return MCF_OK;
}

/* Read `len` bytes back. Required on every path: the library compares each
 * programmed region and reads the whole destination back for the finish CRC.
 * Return exactly `len`, or a negative status. */
static int32_t my_read(void *ctx, uint32_t addr, uint8_t *p, uint32_t len)
{
    (void)ctx;
    memcpy(p, (const void *)addr, len);   /* memory-mapped flash */
    return (int32_t)len;
}

static uint32_t my_block_size(void *ctx) { (void)ctx; return ERASE_BLOCK; }
static uint32_t my_product_id(void *ctx) { (void)ctx; return 0x1234u; }
static uint32_t my_fw_version(void *ctx) { (void)ctx; return FW_VERSION; }

/* --- Workspace: either let the library allocate ... --------------------- */

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
    /* .verify, .log, .flash_is_readonly and .ctx are optional */
};

void apply_update(const uint8_t *patch, uint32_t patch_size)
{
    static mcf_config_t cfg;
    MCF_SESSION_DECLARE(session);

    cfg.hal         = &g_hal;
    cfg.patch       = patch;
    cfg.patch_size  = patch_size;
    cfg.old         = (const uint8_t *)FLASH_BASE;  /* running image */
    cfg.old_size    = FW_SIZE;
    cfg.dst_addr    = STAGING_BASE;                 /* staging slot  */
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

## Choosing `block_size` and `ram_budget`

Two values decide whether a documented patch applies, and they are a **pair** with the host
tool's framing.

- **`block_size`** is the decode window: the device decompresses each codec block into a
  buffer of exactly this many bytes, clamped down to `new_size`. It must be a power of two,
  and it must be **at least the framing the host used** (`1 << --block-log2`). A patch framed
  larger than the window is rejected as corrupt (`MCF_E_CORRUPT`, site 17). See
  [the LZ4 stream](format-v2.md#lz4-stream).
- **`ram_budget`** is the ceiling the library may allocate. It must cover the two block
  buffers plus the codec's own state. `mcf_ctx_size()` returns the exact figure for a
  configuration, so a build script can size a static buffer from it rather than guessing.

Workspace figures `mcf_ctx_size()` returns, by block size:

| Codec | `block_size` | Workspace |
|---|---|---|
| LZ4 | 256 | **528 B** |
| LZ4 | 512 | 1,040 B |
| LZ4 | 1024 | 2,064 B |
| LZMA (opt-in) | 1024 | ~32,896 B at the defaults |

The default in the snippet above (`block_size = 1024`, `ram_budget = 4096`) matches the host
tool's default `--block-log2 10` and leaves headroom for the LZ4 state.

## Heapless (static) workspace

On a part with no heap, give the session its own buffer instead of `alloc`/`free`:

```c
static uint8_t g_workspace[4096];
MCF_SESSION_DECLARE(session);

cfg.hal            = &g_hal;
cfg.workspace      = g_workspace;
cfg.workspace_size = sizeof(g_workspace);
```

Each simultaneously active session needs a distinct buffer. `mcf_ctx_size()` is not a constant
expression, so either size the buffer to the figure you computed on the build host, or give it
the ceiling you are willing to spend and let `mcf_session_begin()` refuse anything larger. This
is the **868 B** profile: 340 B session + 528 B workspace at a 256 B block, no heap.

## Choosing a codec

| Codec | When to use it |
|---|---|
| **LZ4** (default) | Almost always. ~16 B of decoder state; the smallest RAM of the three. |
| **raw** (`--codec raw`) | When the delta is small enough that codec headers cost more than they save, or is known incompressible. |
| **LZMA** (`-DMCF_ENABLE_LZMA=ON`) | When payload size matters more than RAM and you have a Cortex-M4/M7-class part. |

Set `cfg.codec = MCF_CODEC_AUTO` to let the library pick from what the patch offers, or force
one by id. A patch declaring a codec this build does not include is rejected as
`MCF_E_UNSUPPORTED`, never handed to a stub. Details and the parameter policy are in
[the README's Codecs section](../README.md#codecs) and [format-v2.md](format-v2.md).

## Accepting signed patches

A signed patch is **rejected unless the device supplies a verifier** — fail-closed by design.
The generic HAL above configures none, so it applies unsigned patches only. To accept them:

```c
#include "microfoam_ed25519.h"          /* built-in, no external crypto */
static mcf_ed25519_ctx_t g_verify = { g_public_key };   /* 32 bytes, immutable */

g_hal.verify     = mcf_ed25519_verify;   /* MFP1: plain Ed25519 */
g_hal.verify_ctx = &g_verify;
```

Build with `-DMCF_ENABLE_ED25519=ON`. The verifier streams the signed message, so it needs no
allocator and no buffer proportional to the patch. The libsodium adapter is the alternative
(`-DMCF_ENABLE_SODIUM=ON`, `mcf_sodium_verify`). See
[the README](../README.md#signature-verification) and
[architecture §14.3](architecture.md#143-signature-algorithm-selection).

## MFP2 (signed and encrypted)

MFP2 execution uses its own session (`mcf_v2_session_*`) with `mcf_v2_config_t`. It verifies the
signature before key lookup, authenticates every record before decoding it, and decrypts one
record at a time into a small sliding window, so the whole decrypted payload is never resident.
`mcf_v2_config_t` carries the same `block_size` / `ram_budget` pair, plus the record window and
the Ed25519ph verifier. The design is in
[format-v2-design.md](format-v2-design.md) and
[mfp2-streaming-decryption-design.md](mfp2-streaming-decryption-design.md).

## Where to go next

- [README](../README.md) — overview, footprint, codecs, and where the evidence lives.
- [verification.md](verification.md) — the suites, the fault-injection catalogue, and the
  measured size tables.
- [architecture.md](architecture.md) — the full design and the rationale for each commitment.
- [format-v2.md](format-v2.md) — the on-flash container format, validation order, LZ4 window.
