/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - shared MFP2 parser fixture and property oracle (test-only).
 *
 * mcf_v2_parse() is the one entry point that consumes attacker-controlled
 * bytes, so its contract has to hold for every input, not just the ones a test
 * author thought of. Both the deterministic structural suite
 * (v2_format_test.c) and the coverage-guided fuzz target (fuzz_v2_parse.c)
 * assert the same four properties, and they must not drift apart:
 *
 *   1. the status is one of the defined parser outcomes;
 *   2. the input buffer is byte-identical after the call;
 *   3. on MCF_OK the view matches an independent re-derivation of the frozen
 *      profile's header and record framing;
 *   4. on MCF_OK iteration reproduces exactly record_count records.
 *
 * The re-derivation here deliberately does not call the parser's own helpers:
 * an oracle that reuses the code under test cannot fail when that code is
 * wrong.
 */
#ifndef MCF_V2_PARSE_FIXTURE_H
#define MCF_V2_PARSE_FIXTURE_H

#include "microfoam_v2.h"

#include <string.h>

/* The valid fixture is a minimal signed+encrypted+LZ4 header with two tagged
 * records: MCF_V2_HEADER_MIN + 4+2+16 + 4+2+16 bytes. */
#define MCF_V2F_VALID_SIZE (MCF_V2_HEADER_MIN + 44u)

static inline void mcf_v2f_wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static inline void mcf_v2f_wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline uint32_t mcf_v2f_rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Valid frozen-profile patch: signed + encrypted + LZ4, two tagged records.
 * `patch_size` must be at least MCF_V2F_VALID_SIZE; only the first
 * MCF_V2F_VALID_SIZE bytes are written. */
static inline void mcf_v2f_build_valid(uint8_t *patch, uint32_t patch_size)
{
    memset(patch, 0, patch_size);
    mcf_v2f_wr32(&patch[MCF_V2_OFF_MAGIC], MCF_V2_MAGIC);
    mcf_v2f_wr16(&patch[MCF_V2_OFF_HEADER_LEN], MCF_V2_HEADER_MIN);
    mcf_v2f_wr16(&patch[MCF_V2_OFF_VERSION], MCF_V2_VERSION);
    mcf_v2f_wr32(&patch[MCF_V2_OFF_FLAGS], MCF_V2_EXEC_REQUIRED_FLAGS);
    mcf_v2f_wr32(&patch[MCF_V2_OFF_PRODUCT], 0x1234u);
    mcf_v2f_wr32(&patch[MCF_V2_OFF_OLD_SIZE], 64u);
    mcf_v2f_wr32(&patch[MCF_V2_OFF_NEW_SIZE], 64u);
    mcf_v2f_wr32(&patch[MCF_V2_OFF_PAYLOAD_SIZE], 44u);
    mcf_v2f_wr32(&patch[MCF_V2_OFF_OLD_VERSION], 1u);
    patch[MCF_V2_OFF_CODEC] = (uint8_t)MCF_CODEC_LZ4;
    patch[MCF_V2_OFF_RECORD_LOG2] = MCF_V2_RECORD_LOG2_MIN;
    mcf_v2f_wr32(&patch[MCF_V2_OFF_CODEC_PROFILE], 0u);
    patch[MCF_V2_OFF_KEY_ID] = 1u;
    mcf_v2f_wr32(&patch[MCF_V2_OFF_RECORD_COUNT], 2u);

    /* nonce_prefix[16..23] is reserved zero; memset initialized it. */
    mcf_v2f_wr32(&patch[MCF_V2_HEADER_MIN], 2u);
    patch[MCF_V2_HEADER_MIN + 4u] = 0xAAu;
    patch[MCF_V2_HEADER_MIN + 5u] = 0xBBu;
    memset(&patch[MCF_V2_HEADER_MIN + 6u], 0xA1u, MCF_V2_RECORD_TAG_SIZE);
    mcf_v2f_wr32(&patch[MCF_V2_HEADER_MIN + 4u + 2u + MCF_V2_RECORD_TAG_SIZE], 2u);
    patch[MCF_V2_HEADER_MIN + 4u + 2u + MCF_V2_RECORD_TAG_SIZE + 4u] = 0xCCu;
    patch[MCF_V2_HEADER_MIN + 4u + 2u + MCF_V2_RECORD_TAG_SIZE + 5u] = 0xDDu;
    memset(&patch[MCF_V2_HEADER_MIN + 4u + 2u + MCF_V2_RECORD_TAG_SIZE + 6u],
           0xB2u, MCF_V2_RECORD_TAG_SIZE);
}

/* Property 1: the parser may only return one of these. An uninitialised or
 * out-of-range status escaping is itself a defect. */
static inline int mcf_v2f_status_defined(mcf_status_t st)
{
    return st == MCF_OK || st == MCF_E_FORMAT || st == MCF_E_UNSUPPORTED ||
           st == MCF_E_TRUNCATED || st == MCF_E_PARAM;
}

/* Property 3: independent re-derivation of the header and record framing.
 * Returns 1 when the parser view matches what the frozen profile says the blob
 * must look like. `out` was zeroed by the parser, so every field read here was
 * set by it, not by previous state. */
static inline int mcf_v2f_framing_ok(const uint8_t *p, uint32_t n,
                                     const mcf_v2_view_t *out)
{
    uint32_t header_len = (uint32_t)out->header_len;
    uint32_t tlv_len = out->tlv_len;
    uint32_t pos;
    uint32_t i;
    uint32_t max_block = 0u;

    if (header_len < MCF_V2_HEADER_MIN || header_len > MCF_V2_HEADER_MAX ||
        (header_len & 3u) != 0u || (uint32_t)out->version != MCF_V2_VERSION) {
        return 0;
    }
    if (out->flags != MCF_V2_EXEC_REQUIRED_FLAGS) return 0;
    if (tlv_len != header_len - MCF_V2_HEADER_MIN) return 0;
    if (out->record_log2 < MCF_V2_RECORD_LOG2_MIN ||
        out->record_log2 > MCF_V2_RECORD_LOG2_MAX) return 0;
    if (out->record_count == 0u) return 0;
    if (header_len + out->payload_size != n) return 0;
    if (out->codec_id != (uint8_t)MCF_CODEC_LZ4 || out->codec_profile != 0u) return 0;
    /* The view must point into the caller's buffer, at the documented offsets:
     * TLVs start at the minimal header, records at the real header length. */
    if (out->tlvs != p + MCF_V2_HEADER_MIN) return 0;
    if (out->records != p + header_len) return 0;

    /* Walk the record area exactly as the normative contract describes and
     * check that the parser's record_max_block agrees. */
    pos = header_len;
    for (i = 0u; i < out->record_count; i++) {
        uint32_t len;
        if (n - pos < 4u) return 0;
        len = mcf_v2f_rd32(&p[pos]);
        pos += 4u;
        if (len == 0u || len > (1u << out->record_log2) || len > n - pos) return 0;
        if (len > max_block) max_block = len;
        pos += len;
        if (n - pos < MCF_V2_RECORD_TAG_SIZE) return 0;
        pos += MCF_V2_RECORD_TAG_SIZE;
    }
    if (pos != n) return 0;
    if (max_block != out->record_max_block) return 0;
    return 1;
}

/* Property 4: iteration must reproduce exactly record_count records, with
 * strictly increasing indices, and stop. `view` must have come from a
 * successful parse. */
static inline int mcf_v2f_iterate_ok(const uint8_t *p, uint32_t n,
                                     const mcf_v2_view_t *view)
{
    uint32_t cursor = 0u;
    uint32_t seen = 0u;
    uint32_t guard = view->record_count + 1u;
    mcf_v2_record_t r;

    while (guard-- > 0u && mcf_v2_next_record(view, p, n, &cursor, &r) == MCF_OK) {
        if (r.index != seen) return 0;
        seen++;
    }
    return seen == view->record_count;
}

#endif /* MCF_V2_PARSE_FIXTURE_H */
