/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - MFP2 structural parser tests.
 *
 * The parser is inspection-only: it validates the container shape and nothing
 * else. These tests cover the shape rules that matter - header fields, TLV
 * framing, and the record area framing exactly into record_count records -
 * plus the two fail-closed answers (encrypted, unknown critical TLV).
 *
 * A note on what is NOT tested here: anything that requires decrypting,
 * decoding or applying. Those are v2 execution, which is deliberately deferred;
 * see docs/format-v2-design.md.
 */

#include "microfoam_v2.h"

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

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* A valid unencrypted LZ4 patch: 192-byte header, no TLVs, two records
 * (2 bytes + 2 bytes) inside a 12-byte payload area. */
static void build_valid(uint8_t *patch, uint32_t patch_size)
{
    memset(patch, 0, patch_size);
    wr32(&patch[MCF_V2_OFF_MAGIC], MCF_V2_MAGIC);
    wr16(&patch[MCF_V2_OFF_HEADER_LEN], MCF_V2_HEADER_MIN);
    wr16(&patch[MCF_V2_OFF_VERSION], MCF_V2_VERSION);
    wr32(&patch[MCF_V2_OFF_FLAGS], MCF_V2_FLAG_CODEC_LZ4);
    wr32(&patch[MCF_V2_OFF_PRODUCT], 0x1234u);
    wr32(&patch[MCF_V2_OFF_OLD_SIZE], 64u);
    wr32(&patch[MCF_V2_OFF_NEW_SIZE], 64u);
    wr32(&patch[MCF_V2_OFF_PAYLOAD_SIZE], 12u);
    wr32(&patch[MCF_V2_OFF_OLD_VERSION], 1u);
    patch[MCF_V2_OFF_CODEC] = (uint8_t)MCF_CODEC_LZ4;
    patch[MCF_V2_OFF_RECORD_LOG2] = 8u;
    wr32(&patch[MCF_V2_OFF_RECORD_COUNT], 2u);

    wr32(&patch[MCF_V2_HEADER_MIN], 2u);
    patch[MCF_V2_HEADER_MIN + 4u] = 0xAAu;
    patch[MCF_V2_HEADER_MIN + 5u] = 0xBBu;
    wr32(&patch[MCF_V2_HEADER_MIN + 6u], 2u);
    patch[MCF_V2_HEADER_MIN + 10u] = 0xCCu;
    patch[MCF_V2_HEADER_MIN + 11u] = 0xDDu;
}

int main(void)
{
    static uint8_t patch[1024];
    static uint8_t bad[1024];
    mcf_v2_view_t view;
    mcf_v2_record_t rec;
    uint32_t off;

    build_valid(patch, sizeof(patch));

    /* --- the happy path: parse and iterate --------------------------------- */
    CHECK(mcf_v2_parse(patch, sizeof(patch), &view) == MCF_OK, "valid patch parses");
    CHECK(view.record_count == 2u, "record count is reported");
    CHECK(view.payload_size == 12u, "payload size is reported");
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

    /* --- header rejections ------------------------------------------------- */
    memcpy(bad, patch, sizeof(bad));
    wr32(&bad[MCF_V2_OFF_MAGIC], 0xDEADBEEFu);
    CHECK(mcf_v2_parse(bad, sizeof(bad), &view) == MCF_E_FORMAT, "bad magic rejected");

    memcpy(bad, patch, sizeof(bad));
    bad[MCF_V2_OFF_FLAGS] = 0x80u;
    CHECK(mcf_v2_parse(bad, sizeof(bad), &view) == MCF_E_FORMAT, "unknown flag rejected");

    memcpy(bad, patch, sizeof(bad));
    wr32(&bad[MCF_V2_OFF_FLAGS], MCF_V2_FLAG_ENCRYPTED | MCF_V2_FLAG_CODEC_LZ4);
    CHECK(mcf_v2_parse(bad, sizeof(bad), &view) == MCF_E_UNSUPPORTED,
          "encrypted patch fails closed");

    memcpy(bad, patch, sizeof(bad));
    wr32(&bad[MCF_V2_OFF_RESERVED], 1u);
    CHECK(mcf_v2_parse(bad, sizeof(bad), &view) == MCF_E_FORMAT, "nonzero reserved rejected");

    memcpy(bad, patch, sizeof(bad));
    wr16(&bad[MCF_V2_OFF_VERSION], 0x0300u);
    CHECK(mcf_v2_parse(bad, sizeof(bad), &view) == MCF_E_UNSUPPORTED,
          "future major version rejected");

    memcpy(bad, patch, sizeof(bad));
    bad[MCF_V2_OFF_RECORD_LOG2] = 7u;
    CHECK(mcf_v2_parse(bad, sizeof(bad), &view) == MCF_E_FORMAT,
          "record_log2 below range rejected");

    /* --- record-area framing: the checks that make record_count meaningful - */

    /* Count claims three records but only two are framed. */
    memcpy(bad, patch, sizeof(bad));
    wr32(&bad[MCF_V2_OFF_RECORD_COUNT], 3u);
    CHECK(mcf_v2_parse(bad, sizeof(bad), &view) == MCF_E_FORMAT,
          "record count larger than the framing is rejected");

    /* Count claims one record but the area frames two: trailing bytes. */
    memcpy(bad, patch, sizeof(bad));
    wr32(&bad[MCF_V2_OFF_RECORD_COUNT], 1u);
    CHECK(mcf_v2_parse(bad, sizeof(bad), &view) == MCF_E_FORMAT,
          "trailing bytes past the declared record count are rejected");

    /* A record whose declared length runs past the payload area. */
    memcpy(bad, patch, sizeof(bad));
    wr32(&bad[MCF_V2_HEADER_MIN], 200u);
    CHECK(mcf_v2_parse(bad, sizeof(bad), &view) == MCF_E_FORMAT,
          "record length past the payload area is rejected");

    /* A record larger than 2^record_log2. */
    memcpy(bad, patch, sizeof(bad));
    wr32(&bad[MCF_V2_HEADER_MIN], 300u);
    wr32(&bad[MCF_V2_OFF_PAYLOAD_SIZE], 4u + 300u);
    CHECK(mcf_v2_parse(bad, sizeof(bad), &view) == MCF_E_FORMAT,
          "record larger than the declared record size is rejected");

    /* Zero-length record. */
    memcpy(bad, patch, sizeof(bad));
    wr32(&bad[MCF_V2_HEADER_MIN], 0u);
    CHECK(mcf_v2_parse(bad, sizeof(bad), &view) == MCF_E_FORMAT,
          "zero-length record is rejected");

    /* Payload larger than the file. */
    memcpy(bad, patch, sizeof(bad));
    wr32(&bad[MCF_V2_OFF_PAYLOAD_SIZE], 4096u);
    CHECK(mcf_v2_parse(bad, sizeof(bad), &view) == MCF_E_TRUNCATED,
          "payload larger than the patch is rejected");

    /* --- TLV area ---------------------------------------------------------- */

    /* A well-formed noncritical TLV is accepted and shifts the record area. */
    {
        static uint8_t tlv_patch[1024];
        memset(tlv_patch, 0, sizeof(tlv_patch));
        memcpy(tlv_patch, patch, sizeof(tlv_patch));
        wr16(&tlv_patch[MCF_V2_OFF_HEADER_LEN], MCF_V2_HEADER_MIN + 12u);
        wr16(&tlv_patch[MCF_V2_OFF_TLV_LEN], 12u);
        wr16(&tlv_patch[MCF_V2_HEADER_MIN], 2u);      /* type 2, noncritical */
        wr16(&tlv_patch[MCF_V2_HEADER_MIN + 2u], 0u); /* flags */
        wr32(&tlv_patch[MCF_V2_HEADER_MIN + 4u], 4u); /* length */
        /* 8 + 4 = 12 bytes, already 4-aligned. */
        memcpy(&tlv_patch[MCF_V2_HEADER_MIN + 12u], &patch[MCF_V2_HEADER_MIN], 12u);
        CHECK(mcf_v2_parse(tlv_patch, sizeof(tlv_patch), &view) == MCF_OK,
              "a noncritical TLV is accepted");
        CHECK(view.header_len == MCF_V2_HEADER_MIN + 12u, "TLV shifts the record area");
    }

    /* An unknown critical TLV must be refused. */
    {
        static uint8_t tlv_patch[1024];
        memset(tlv_patch, 0, sizeof(tlv_patch));
        memcpy(tlv_patch, patch, sizeof(tlv_patch));
        wr16(&tlv_patch[MCF_V2_OFF_HEADER_LEN], MCF_V2_HEADER_MIN + 12u);
        wr16(&tlv_patch[MCF_V2_OFF_TLV_LEN], 12u);
        wr16(&tlv_patch[MCF_V2_HEADER_MIN], 2u);      /* type 2, unknown */
        wr16(&tlv_patch[MCF_V2_HEADER_MIN + 2u], 1u); /* critical */
        wr32(&tlv_patch[MCF_V2_HEADER_MIN + 4u], 4u);
        CHECK(mcf_v2_parse(tlv_patch, sizeof(tlv_patch), &view) == MCF_E_FORMAT,
              "unknown critical TLV is rejected");
    }

    /* A TLV whose length runs past the TLV area. */
    {
        static uint8_t tlv_patch[1024];
        memset(tlv_patch, 0, sizeof(tlv_patch));
        memcpy(tlv_patch, patch, sizeof(tlv_patch));
        wr16(&tlv_patch[MCF_V2_OFF_HEADER_LEN], MCF_V2_HEADER_MIN + 12u);
        wr16(&tlv_patch[MCF_V2_OFF_TLV_LEN], 12u);
        wr16(&tlv_patch[MCF_V2_HEADER_MIN], 2u);
        wr16(&tlv_patch[MCF_V2_HEADER_MIN + 2u], 0u);
        wr32(&tlv_patch[MCF_V2_HEADER_MIN + 4u], 64u); /* overruns */
        CHECK(mcf_v2_parse(tlv_patch, sizeof(tlv_patch), &view) == MCF_E_FORMAT,
              "TLV length overrunning the area is rejected");
    }

    printf("v2 structural parser: %d checks, %d failures\n", g_checks, g_failures);
    return (g_failures == 0) ? 0 : 1;
}
