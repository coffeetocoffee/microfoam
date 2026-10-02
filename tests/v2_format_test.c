/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - MFP2 structural parser tests.
 *
 * The parser is inspection-only: it validates the container shape and nothing
 * else. These tests cover the shape rules that matter - header fields, TLV
 * framing, and the record area framing exactly into record_count records -
 * plus framing, iterator tags, unknown critical TLVs, and structural tampering.
 *
 * This suite validates encrypted record shape only. Decryption, signature
 * verification, decoding, and applying are execution behavior and are not tested
 * here; see docs/format-v2-design.md.
 *
 * Beyond hand-picked cases, a bounded deterministic mutation/property loop
 * feeds random blobs, truncations, and byte mutations of the valid fixture to
 * the parser and asserts the invariants that must hold for any input: a
 * defined status, an untouched input buffer, and - on MCF_OK - a view that
 * matches an independent re-derivation of the header and record framing. */

#include "microfoam_v2.h"
#include "v2_parse_fixture.h"

#include <stdio.h>
#include <string.h>

static int g_checks;
static int g_failures;

#define CHECK(cond, name) do { \
    g_checks++; \
    if (!(cond)) { \
        printf("  FAIL  %s  (%s:%d)\n", (name), __FILE__, __LINE__); \
        g_failures++; \
    } \
} while (0)

/* ======================================================================== *
 * Deterministic mutation/property loop
 * ======================================================================== */

/* xorshift32: tiny, deterministic, no external dependency. */
static uint32_t rng_state = 0x12345678u;
static uint32_t rng_next(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

static uint32_t rng_below(uint32_t n) { return rng_next() % n; }

/* Wrapper so every loop call site goes through one point; `v` may be a
 * scratch view the caller re-uses across iterations (the parser zeroes it). */
static mcf_status_t parse_quiet(const uint8_t *p, uint32_t n, mcf_v2_view_t *v)
{
    return mcf_v2_parse(p, n, v);
}

int main(void)
{
    static uint8_t patch[1024];
    static uint8_t bad[1024];
    mcf_v2_view_t view;
    mcf_v2_record_t rec;
    uint32_t off;

    mcf_v2f_build_valid(patch, sizeof(patch));

    /* --- the happy path: parse and iterate --------------------------------- */
    CHECK(mcf_v2_parse(patch, MCF_V2_HEADER_MIN + 44u, &view) == MCF_OK, "valid patch parses");
    CHECK(view.flags == MCF_V2_EXEC_REQUIRED_FLAGS, "required signed encrypted LZ4 profile is reported");
    CHECK(view.codec_profile == 0u, "codec profile zero is reported");
    CHECK(view.record_log2 == MCF_V2_RECORD_LOG2_MIN, "record log2 minimum is accepted");
    CHECK(view.record_count == 2u, "record count is reported");
    CHECK(view.payload_size == 44u, "payload size is reported");
    CHECK(view.product_id == 0x1234u, "product id is reported");

    off = 0u;
    CHECK(mcf_v2_next_record(&view, patch, sizeof(patch), &off, &rec) == MCF_OK,
          "first record iterates");
    CHECK(rec.index == 0u && rec.data_len == 2u && rec.data[0] == 0xAAu,
          "first record contents are correct");
    CHECK(mcf_v2_next_record(&view, patch, sizeof(patch), &off, &rec) == MCF_OK,
          "second record iterates");
    CHECK(rec.index == 1u && rec.data[0] == 0xCCu, "second record contents are correct");
    CHECK(mcf_v2_next_record(&view, patch, sizeof(patch), &off, &rec) == MCF_E_NOT_FOUND,
          "iteration ends after the last record");

    /* --- encrypted framing and iterator tags ------------------------------- */
    {
        static uint8_t encrypted[1024];
        const uint32_t rec0 = MCF_V2_HEADER_MIN;
        const uint32_t rec1 = rec0 + 4u + 2u + MCF_V2_RECORD_TAG_SIZE;
        memcpy(encrypted, patch, sizeof(encrypted));
        mcf_v2f_wr32(&encrypted[MCF_V2_OFF_FLAGS], MCF_V2_EXEC_REQUIRED_FLAGS);
        mcf_v2f_wr32(&encrypted[MCF_V2_OFF_PAYLOAD_SIZE], 44u);
        /* The fixture already contains two records with detached tags. */
        CHECK(mcf_v2_parse(encrypted, MCF_V2_HEADER_MIN + 44u, &view) == MCF_OK,
              "encrypted per-record framing parses without decrypting");
        off = 0u;
        CHECK(mcf_v2_next_record(&view, encrypted, MCF_V2_HEADER_MIN + 44u, &off, &rec) == MCF_OK,
              "first encrypted record iterates");
        CHECK(rec.index == 0u && rec.data_len == 2u && rec.tag_len == MCF_V2_RECORD_TAG_SIZE &&
              rec.tag[0] == 0xA1u, "first iterator result separates ciphertext and tag");
        CHECK(mcf_v2_next_record(&view, encrypted, MCF_V2_HEADER_MIN + 44u, &off, &rec) == MCF_OK,
              "second encrypted record iterates");
        CHECK(rec.index == 1u && rec.tag_len == MCF_V2_RECORD_TAG_SIZE &&
              rec.tag[0] == 0xB2u, "second iterator result carries the next index and tag");
        CHECK(mcf_v2_next_record(&view, encrypted, MCF_V2_HEADER_MIN + 44u, &off, &rec) == MCF_E_NOT_FOUND,
              "encrypted iteration ends after the declared records");

        /* Structural tampering is rejected irrespective of tag contents. */
        mcf_v2f_wr32(&encrypted[rec0], 2u);
        mcf_v2f_wr32(&encrypted[rec1], 2u);
        mcf_v2f_wr32(&encrypted[MCF_V2_OFF_PAYLOAD_SIZE], 43u);
        CHECK(mcf_v2_parse(encrypted, MCF_V2_HEADER_MIN + 44u, &view) == MCF_E_FORMAT,
              "encrypted framing with a truncated tag is rejected");
        mcf_v2f_wr32(&encrypted[MCF_V2_OFF_PAYLOAD_SIZE], 45u);
        CHECK(mcf_v2_parse(encrypted, MCF_V2_HEADER_MIN + 45u, &view) == MCF_E_FORMAT,
              "encrypted framing with trailing payload byte is rejected");
        mcf_v2f_wr32(&encrypted[MCF_V2_OFF_PAYLOAD_SIZE], 44u);
        mcf_v2f_wr32(&encrypted[rec1], 200u);
        CHECK(mcf_v2_parse(encrypted, MCF_V2_HEADER_MIN + 44u, &view) == MCF_E_FORMAT,
              "encrypted record length overrunning its framing is rejected");
    }

    /* --- header rejections ------------------------------------------------- */
    memcpy(bad, patch, sizeof(bad));
    mcf_v2f_wr32(&bad[MCF_V2_OFF_MAGIC], 0xDEADBEEFu);
    CHECK(mcf_v2_parse(bad, MCF_V2_HEADER_MIN + 44u, &view) == MCF_E_FORMAT, "bad magic rejected");

    memcpy(bad, patch, sizeof(bad));
    bad[MCF_V2_OFF_FLAGS] = 0x80u;
    CHECK(mcf_v2_parse(bad, MCF_V2_HEADER_MIN + 44u, &view) == MCF_E_FORMAT, "unknown flag rejected");

    memcpy(bad, patch, sizeof(bad));
    mcf_v2f_wr32(&bad[MCF_V2_OFF_FLAGS], MCF_V2_FLAG_ENCRYPTED | MCF_V2_FLAG_CODEC_LZ4);
    CHECK(mcf_v2_parse(bad, MCF_V2_HEADER_MIN + 44u, &view) == MCF_E_UNSUPPORTED,
          "unsigned plaintext LZ4 profile is unsupported");

    memcpy(bad, patch, sizeof(bad));
    mcf_v2f_wr32(&bad[MCF_V2_OFF_FLAGS], MCF_V2_FLAG_SIGNED | MCF_V2_FLAG_CODEC_LZ4);
    CHECK(mcf_v2_parse(bad, MCF_V2_HEADER_MIN + 44u, &view) == MCF_E_UNSUPPORTED,
          "signed plaintext LZ4 profile is unsupported");

    memcpy(bad, patch, sizeof(bad));
    mcf_v2f_wr32(&bad[MCF_V2_OFF_FLAGS], MCF_V2_FLAG_ENCRYPTED | MCF_V2_FLAG_SIGNED);
    CHECK(mcf_v2_parse(bad, MCF_V2_HEADER_MIN + 44u, &view) == MCF_E_UNSUPPORTED,
          "signed encrypted profile without LZ4 is unsupported");

    memcpy(bad, patch, sizeof(bad));
    mcf_v2f_wr32(&bad[MCF_V2_OFF_RESERVED], 1u);
    CHECK(mcf_v2_parse(bad, MCF_V2_HEADER_MIN + 44u, &view) == MCF_E_FORMAT, "nonzero reserved rejected");

    memcpy(bad, patch, sizeof(bad));
    mcf_v2f_wr16(&bad[MCF_V2_OFF_VERSION], 0x0300u);
    CHECK(mcf_v2_parse(bad, MCF_V2_HEADER_MIN + 44u, &view) == MCF_E_UNSUPPORTED,
          "future major version rejected");

    memcpy(bad, patch, sizeof(bad));
    bad[MCF_V2_OFF_RECORD_LOG2] = MCF_V2_RECORD_LOG2_MIN - 1u;
    CHECK(mcf_v2_parse(bad, MCF_V2_HEADER_MIN + 44u, &view) == MCF_E_FORMAT,
          "record_log2 below range rejected");
    memcpy(bad, patch, sizeof(bad));
    bad[MCF_V2_OFF_RECORD_LOG2] = MCF_V2_RECORD_LOG2_MAX + 1u;
    CHECK(mcf_v2_parse(bad, MCF_V2_HEADER_MIN + 44u, &view) == MCF_E_FORMAT,
          "record_log2 above range rejected");

    memcpy(bad, patch, sizeof(bad));
    mcf_v2f_wr32(&bad[MCF_V2_OFF_CODEC_PROFILE], 1u);
    CHECK(mcf_v2_parse(bad, MCF_V2_HEADER_MIN + 44u, &view) == MCF_E_UNSUPPORTED,
          "unknown codec profile rejected");
    memcpy(bad, patch, sizeof(bad));
    memset(&bad[MCF_V2_OFF_KEY_ID], 0, MCF_V2_KEY_ID_SIZE);
    CHECK(mcf_v2_parse(bad, MCF_V2_HEADER_MIN + 44u, &view) == MCF_E_FORMAT,
          "all-zero key identifier rejected");
    memcpy(bad, patch, sizeof(bad));
    bad[MCF_V2_OFF_NONCE_PREFIX + MCF_V2_NONCE_PREFIX_SIZE] = 1u;
    CHECK(mcf_v2_parse(bad, MCF_V2_HEADER_MIN + 44u, &view) == MCF_E_FORMAT,
          "nonzero reserved nonce suffix rejected");

    /* --- record-area framing: the checks that make record_count meaningful - */

    /* Count claims three records but only two are framed. */
    memcpy(bad, patch, sizeof(bad));
    mcf_v2f_wr32(&bad[MCF_V2_OFF_RECORD_COUNT], 3u);
    CHECK(mcf_v2_parse(bad, MCF_V2_HEADER_MIN + 44u, &view) == MCF_E_FORMAT,
          "record count larger than the framing is rejected");

    /* Count claims one record but the area frames two: trailing bytes. */
    memcpy(bad, patch, sizeof(bad));
    mcf_v2f_wr32(&bad[MCF_V2_OFF_RECORD_COUNT], 1u);
    CHECK(mcf_v2_parse(bad, MCF_V2_HEADER_MIN + 44u, &view) == MCF_E_FORMAT,
          "trailing bytes past the declared record count are rejected");

    /* A record whose declared length runs past the payload area. */
    memcpy(bad, patch, sizeof(bad));
    mcf_v2f_wr32(&bad[MCF_V2_HEADER_MIN], 200u);
    CHECK(mcf_v2_parse(bad, MCF_V2_HEADER_MIN + 44u, &view) == MCF_E_FORMAT,
          "record length past the payload area is rejected");

    /* A record larger than 2^record_log2. */
    memcpy(bad, patch, sizeof(bad));
    mcf_v2f_wr32(&bad[MCF_V2_HEADER_MIN], 300u);
    mcf_v2f_wr32(&bad[MCF_V2_OFF_PAYLOAD_SIZE], 4u + 300u + MCF_V2_RECORD_TAG_SIZE + 4u + MCF_V2_RECORD_TAG_SIZE);
    CHECK(mcf_v2_parse(bad, MCF_V2_HEADER_MIN + 4u + 300u + 2u * MCF_V2_RECORD_TAG_SIZE + 4u, &view) == MCF_E_FORMAT,
          "record larger than the declared record size is rejected");

    /* Zero-length record. */
    memcpy(bad, patch, sizeof(bad));
    mcf_v2f_wr32(&bad[MCF_V2_HEADER_MIN], 0u);
    CHECK(mcf_v2_parse(bad, MCF_V2_HEADER_MIN + 44u, &view) == MCF_E_FORMAT,
          "zero-length record is rejected");

    /* Payload larger than the file. */
    memcpy(bad, patch, sizeof(bad));
    mcf_v2f_wr32(&bad[MCF_V2_OFF_PAYLOAD_SIZE], 4096u);
    CHECK(mcf_v2_parse(bad, MCF_V2_HEADER_MIN + 44u, &view) == MCF_E_TRUNCATED,
          "payload larger than the patch is rejected");

    /* --- TLV area ---------------------------------------------------------- */

    /* A well-formed noncritical TLV is accepted and shifts the record area. */
    {
        static uint8_t tlv_patch[1024];
        memset(tlv_patch, 0, sizeof(tlv_patch));
        memcpy(tlv_patch, patch, sizeof(tlv_patch));
        mcf_v2f_wr16(&tlv_patch[MCF_V2_OFF_HEADER_LEN], MCF_V2_HEADER_MIN + 12u);
        mcf_v2f_wr16(&tlv_patch[MCF_V2_OFF_TLV_LEN], 12u);
        mcf_v2f_wr16(&tlv_patch[MCF_V2_HEADER_MIN], 2u);      /* type 2, noncritical */
        mcf_v2f_wr16(&tlv_patch[MCF_V2_HEADER_MIN + 2u], 0u); /* flags */
        mcf_v2f_wr32(&tlv_patch[MCF_V2_HEADER_MIN + 4u], 4u); /* length */
        /* 8 + 4 = 12 bytes, already 4-aligned. */
        memcpy(&tlv_patch[MCF_V2_HEADER_MIN + 12u], &patch[MCF_V2_HEADER_MIN], 44u);
        mcf_v2f_wr32(&tlv_patch[MCF_V2_OFF_PAYLOAD_SIZE], 44u);
        CHECK(mcf_v2_parse(tlv_patch, MCF_V2_HEADER_MIN + 12u + 44u, &view) == MCF_OK,
              "a noncritical TLV is accepted");
        CHECK(view.header_len == MCF_V2_HEADER_MIN + 12u, "TLV shifts the record area");
    }

    /* An unknown critical TLV must be refused. */
    {
        static uint8_t tlv_patch[1024];
        memset(tlv_patch, 0, sizeof(tlv_patch));
        memcpy(tlv_patch, patch, sizeof(tlv_patch));
        mcf_v2f_wr16(&tlv_patch[MCF_V2_OFF_HEADER_LEN], MCF_V2_HEADER_MIN + 12u);
        mcf_v2f_wr16(&tlv_patch[MCF_V2_OFF_TLV_LEN], 12u);
        mcf_v2f_wr16(&tlv_patch[MCF_V2_HEADER_MIN], 2u);      /* type 2, unknown */
        mcf_v2f_wr16(&tlv_patch[MCF_V2_HEADER_MIN + 2u], 1u); /* critical */
        mcf_v2f_wr32(&tlv_patch[MCF_V2_HEADER_MIN + 4u], 4u);
        CHECK(mcf_v2_parse(tlv_patch, sizeof(tlv_patch), &view) == MCF_E_FORMAT,
              "unknown critical TLV is rejected");
    }

    /* A TLV whose length runs past the TLV area. */
    {
        static uint8_t tlv_patch[1024];
        memset(tlv_patch, 0, sizeof(tlv_patch));
        memcpy(tlv_patch, patch, sizeof(tlv_patch));
        mcf_v2f_wr16(&tlv_patch[MCF_V2_OFF_HEADER_LEN], MCF_V2_HEADER_MIN + 12u);
        mcf_v2f_wr16(&tlv_patch[MCF_V2_OFF_TLV_LEN], 12u);
        mcf_v2f_wr16(&tlv_patch[MCF_V2_HEADER_MIN], 2u);
        mcf_v2f_wr16(&tlv_patch[MCF_V2_HEADER_MIN + 2u], 0u);
        mcf_v2f_wr32(&tlv_patch[MCF_V2_HEADER_MIN + 4u], 64u); /* overruns */
        CHECK(mcf_v2_parse(tlv_patch, sizeof(tlv_patch), &view) == MCF_E_FORMAT,
              "TLV length overrunning the area is rejected");
    }

    /* --- deterministic mutation/property loop ------------------------------- */

    /* Invariants for EVERY input, asserted by the three phases below:
     *   1. the parser returns a defined mcf_status_t (all returns in this test
     *      go through the CHECK macro, so an out-of-range value cannot hide),
     *   2. the input buffer is byte-identical after the call,
     *   3. on MCF_OK, the view matches an independent re-derivation of the
     *      frozen-profile framing, and iteration over the view reproduces the
     *      declared record count exactly.
     * The parser writes no flash and takes no HAL, so "no side effects beyond
     * the view" is enforced here by construction. */
    {
        enum { BLOB_MAX = 512 };
        static uint8_t base[BLOB_MAX];
        static uint8_t work[BLOB_MAX];
        static uint8_t want[BLOB_MAX]; /* what `work` must be after the call */
        static mcf_v2_view_t v;
        const uint32_t valid_size = MCF_V2_HEADER_MIN + 44u;
        uint32_t iter;
        uint32_t ok_count = 0u;
        uint32_t reject_count = 0u;
        int props_hold = 1;

        memcpy(base, patch, valid_size);

        /* Phase A: truncations of the valid patch at every byte boundary. */
        for (iter = 0u; iter <= valid_size; iter++) {
            mcf_status_t st;
            memcpy(work, base, valid_size);
            memcpy(want, base, valid_size);
            st = parse_quiet(work, iter, &v);
            if (!mcf_v2f_status_defined(st)) {
                props_hold = 0;
                printf("  phase A iter %u: undefined status %d\n", (unsigned)iter, (int)st);
            }
            if (st == MCF_OK && !mcf_v2f_framing_ok(work, iter, &v)) {
                props_hold = 0;
                printf("  phase A iter %u: accepted view does not match framing\n", (unsigned)iter);
            }
            if (memcmp(work, want, valid_size) != 0) {
                props_hold = 0;
                printf("  phase A iter %u: input buffer modified\n", (unsigned)iter);
            }
            if (st == MCF_OK) ok_count++; else reject_count++;
        }

        /* Phase B: random single and multi-byte mutations of the valid patch. */
        for (iter = 0u; iter < 2000u; iter++) {
            mcf_status_t st;
            uint32_t flips = 1u + rng_below(4u);
            uint32_t f;
            memcpy(work, base, valid_size);
            for (f = 0u; f < flips; f++) {
                uint32_t at = rng_below(valid_size);
                work[at] = (uint8_t)rng_next();
            }
            memcpy(want, work, valid_size);
            st = parse_quiet(work, valid_size, &v);
            if (!mcf_v2f_status_defined(st)) {
                props_hold = 0;
                printf("  phase B iter %u: undefined status %d\n", (unsigned)iter, (int)st);
            }
            if (st == MCF_OK && !mcf_v2f_framing_ok(work, valid_size, &v)) {
                props_hold = 0;
                printf("  phase B iter %u: accepted view does not match framing\n", (unsigned)iter);
            }
            if (st == MCF_OK && !mcf_v2f_iterate_ok(work, valid_size, &v)) {
                props_hold = 0;
                printf("  phase B iter %u: iteration did not reproduce record_count\n",
                       (unsigned)iter);
            }
            if (memcmp(work, want, valid_size) != 0) {
                props_hold = 0;
                printf("  phase B iter %u: input buffer modified\n", (unsigned)iter);
            }
            if (st == MCF_OK) ok_count++; else reject_count++;
        }

        /* Phase C: fully random blobs at varied lengths. */
        for (iter = 0u; iter < 2000u; iter++) {
            mcf_status_t st;
            uint32_t n = rng_below((uint32_t)(BLOB_MAX + 1u));
            uint32_t b;
            for (b = 0u; b < n; b++) {
                work[b] = (uint8_t)rng_next();
                want[b] = work[b];
            }
            st = parse_quiet(work, n, &v);
            if (!mcf_v2f_status_defined(st)) {
                props_hold = 0;
                printf("  phase C iter %u: undefined status %d\n", (unsigned)iter, (int)st);
            }
            if (st == MCF_OK && !mcf_v2f_framing_ok(work, n, &v)) {
                props_hold = 0;
                printf("  phase C iter %u: accepted view does not match framing\n", (unsigned)iter);
            }
            if (memcmp(work, want, n) != 0) {
                props_hold = 0;
                printf("  phase C iter %u: input buffer modified\n", (unsigned)iter);
            }
            if (st == MCF_OK) ok_count++; else reject_count++;
        }

        CHECK(props_hold, "mutation/property loop invariants hold");
        CHECK(ok_count > 0u, "mutation loop produced at least one accepted parse");
        printf("  mutation loop: %u accepted, %u rejected\n",
               (unsigned)ok_count, (unsigned)reject_count);
    }

    printf("v2 structural parser: %d checks, %d failures\n", g_checks, g_failures);
    return (g_failures == 0) ? 0 : 1;
}
