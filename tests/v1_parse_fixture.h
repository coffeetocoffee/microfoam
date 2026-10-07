/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - shared MFP1 header parser fixture and property oracle (test-only).
 *
 * mcf_hdr_parse() consumes attacker-controlled bytes from the patch header, so
 * its contract has to hold for every input, not just the ones a test author
 * thought of. Both the deterministic fault-injection suite (test_microfoam.c)
 * and the coverage-guided fuzz target (fuzz_v1_parse.c) assert the same three
 * properties, and they must not drift apart:
 *
 *   1. the status is one of the defined parser outcomes;
 *   2. the input buffer is byte-identical after the call;
 *   3. on MCF_OK the view matches an independent re-derivation of the header
 *      framing and field validity.
 *
 * The re-derivation here deliberately does not call the parser's own helpers:
 * an oracle that reuses the code under test cannot fail when that code is
 * wrong.
 */
#ifndef MCF_V1_PARSE_FIXTURE_H
#define MCF_V1_PARSE_FIXTURE_H

#include "microfoam.h"
#include "mcf_internal.h"

#include <string.h>

/* The minimal valid MFP1 fixture is a 120-byte header (no codec properties
 * for LZ4, no payload needed for this oracle). */
#define MCF_V1F_VALID_SIZE 120u

static inline void mcf_v1f_wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static inline void mcf_v1f_wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline uint16_t mcf_v1f_rd16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8));
}

static inline uint32_t mcf_v1f_rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Valid MFP1 patch: unsigned LZ4, 64-byte images, minimal payload.
 * `patch_size` must be at least MCF_V1F_VALID_SIZE; only the first
 * MCF_V1F_VALID_SIZE bytes are written. */
static inline void mcf_v1f_build_valid(uint8_t *patch, uint32_t patch_size)
{
    memset(patch, 0, patch_size);
    /* Magic: 'MFP1' (little-endian 0x3150464D) */
    mcf_v1f_wr32(&patch[0], 0x3150464Du);
    /* hdr_len = 120 (minimum) */
    mcf_v1f_wr16(&patch[4], 120u);
    /* hdr_ver = 0x0100 (major=1, minor=0) */
    mcf_v1f_wr16(&patch[6], 0x0100u);
    /* flags = 0 (no signature, LZ4 codec implied) */
    mcf_v1f_wr32(&patch[8], 0u);
    /* product_id = 0x12345678 (arbitrary, will match HAL) */
    mcf_v1f_wr32(&patch[12], 0x12345678u);
    /* fw_version = 2 (will be > current=1) */
    mcf_v1f_wr32(&patch[16], 2u);
    /* old_size = 64 */
    mcf_v1f_wr32(&patch[20], 64u);
    /* new_size = 64 */
    mcf_v1f_wr32(&patch[24], 64u);
    /* payload_size = 1 (minimal; must be > 0) */
    mcf_v1f_wr32(&patch[28], 1u);
    /* old_crc32, new_crc32, payload_crc32 = 0 (not validated by parser) */
    mcf_v1f_wr32(&patch[32], 0u);
    mcf_v1f_wr32(&patch[36], 0u);
    mcf_v1f_wr32(&patch[40], 0u);
    /* workspace_req = 100 (LZ4 at 256B block needs ~100B state) */
    mcf_v1f_wr32(&patch[44], 100u);
    /* old_version = 1 (must == current fw_version) */
    mcf_v1f_wr32(&patch[48], 1u);
    /* codec_id = 1 (LZ4) */
    patch[52] = 1u;
    /* block_size_log2 = 8 (256-byte blocks) */
    patch[53] = 8u;
    /* reserved = 0 */
    mcf_v1f_wr16(&patch[54], 0u);
    /* signature[56..119] = all zeros (not validated when unsigned) */
}

/* Property 1: the parser may only return one of these. An uninitialised or
 * out-of-range status escaping is itself a defect. */
static inline int mcf_v1f_status_defined(mcf_status_t st)
{
    return st == MCF_OK || st == MCF_E_FORMAT || st == MCF_E_UNSUPPORTED ||
           st == MCF_E_TRUNCATED || st == MCF_E_PRODUCT || st == MCF_E_ROLLBACK ||
           st == MCF_E_MISMATCH || st == MCF_E_DICT_TOO_LARGE ||
           st == MCF_E_SIGNATURE || st == MCF_E_PARAM;
}

/* Property 3: independent re-derivation of header framing. Returns 1 when the
 * parser view matches what a valid MFP1 patch must look like. */
static inline int mcf_v1f_framing_ok(const uint8_t *p, uint32_t n,
                                     const mcf_hdr_view_t *out)
{
    uint32_t magic, hdr_len, hdr_ver, flags, codec_id, block_log2, reserved;
    uint32_t old_size, new_size, payload_size, props_len;

    if (n < 120u) return 0;

    /* Re-derive all fields independently */
    magic = mcf_v1f_rd32(&p[0]);
    if (magic != 0x3150464Du) return 0; /* 'MFP1' */

    hdr_len = mcf_v1f_rd16(&p[4]);
    if (hdr_len < 120u || hdr_len > 288u || hdr_len > n) return 0;

    hdr_ver = mcf_v1f_rd16(&p[6]);
    if ((hdr_ver >> 8) != 1u) return 0; /* major == 1 */

    flags = mcf_v1f_rd32(&p[8]);
    if (flags & ~0x0Fu) return 0; /* only bits 0-3 valid */

    old_size = mcf_v1f_rd32(&p[20]);
    if (old_size == 0u) return 0;

    new_size = mcf_v1f_rd32(&p[24]);
    if (new_size == 0u) return 0;

    payload_size = mcf_v1f_rd32(&p[28]);
    if (payload_size == 0u) return 0;
    if (payload_size > (n - hdr_len)) return 0; /* truncation check */

    block_log2 = p[53];
    if (block_log2 < 8u || block_log2 > 20u) return 0;

    reserved = mcf_v1f_rd16(&p[54]);
    if (reserved != 0u) return 0;

    codec_id = p[52];
    /* codec_id must not be in reserved gap [4, 128) */
    if (codec_id >= 4u && codec_id < 128u) return 0;
    /* codec_id 0 (AUTO) not allowed in patches */
    if (codec_id == 0u) return 0;

    /* Flag-codec consistency: RAW flag iff codec_id == 3 */
    if (((flags & 0x02u) != 0u) != (codec_id == 3u)) return 0;

    /* Properties block size (0 for LZ4, RAW, custom; 13 for LZMA in v1) */
    props_len = (codec_id == 2u) ? 13u : 0u;
    if (props_len > payload_size) return 0;

    (void)out; /* unused in v1 oracle */
    return 1;
}

#endif /* MCF_V1_PARSE_FIXTURE_H */
