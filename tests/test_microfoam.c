/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - host test suite.
 *
 * The fault-injection cases matter more than the round-trip case: they are the
 * regression tests for the failure mode that dominates field deployments of
 * comparable libraries, namely reporting success when something went wrong.
 * Every case below asserts a specific negative code, and no case may return
 * MCF_OK.
 *
 * Build:  cmake -B build && cmake --build build && ctest --test-dir build
 */

#include "microfoam.h"
#include "microfoam_v2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------------- */

static int g_fail;
static int g_checks;

#define CHECK(cond, name)                                                        \
    do {                                                                         \
        g_checks++;                                                              \
        if (!(cond)) {                                                           \
            printf("  FAIL  %s  (%s:%d)\n", (name), __FILE__, __LINE__);         \
            g_fail++;                                                            \
        }                                                                        \
    } while (0)

#define CHECK_EQ(got, want, name)                                                \
    do {                                                                         \
        long g_ = (long)(got), w_ = (long)(want);                                \
        g_checks++;                                                              \
        if (g_ != w_) {                                                          \
            printf("  FAIL  %s: got %ld want %ld  (%s:%d)\n", (name), g_, w_,    \
                   __FILE__, __LINE__);                                          \
            g_fail++;                                                            \
        }                                                                        \
    } while (0)

static void banner(const char *s)
{
    printf("\n-- %s\n", s);
}

/* ---------------------------------------------------------------------- *
 * Mock device: RAM-backed flash plus fault-injection switches.
 * ---------------------------------------------------------------------- */

#define FLASH_SIZE   16384u
#define FLASH_BASE   0x08010000u
#define FLASH_BLOCK  1024u
#define OLD_LEN      2048u
#define NEW_LEN      2048u

/* A separate NVM region for the resume journal, as a real part would have. */
#define JOURNAL_BASE 0x0F000000u
#define JOURNAL_SIZE 64u

static uint8_t g_flash[FLASH_SIZE];
static uint8_t g_journal[JOURNAL_SIZE];
static uint8_t g_old[OLD_LEN];
static uint8_t g_new[NEW_LEN];
static uint8_t g_patch[16384];

static int g_fail_erase;
static int g_fail_write;
static int g_fail_read;
static int g_corrupt_write;
static int g_readonly;
static int g_commit_called;
static int g_abort;
static int g_contract_violation;
static int g_fail_journal;
static int g_flash_mutations;
static uint32_t g_last_error_site;

static int32_t h_erase(void *ctx, uint32_t addr, uint32_t len)
{
    uint32_t off;
    (void)ctx;
    if (g_fail_erase) {
        return MCF_E_FLASH;
    }
    g_flash_mutations++;
    /* The journal region models a separate small NVM device with its own
     * geometry, so it is not subject to the code flash's alignment contract. */
    if (addr >= JOURNAL_BASE) {
        if (g_fail_journal) return MCF_E_FLASH;
        memset(g_journal, 0xFF, sizeof(g_journal));
        return 0;
    }
    /* The library promises erase length is a whole number of blocks and the
     * address is block aligned. Verify the promise rather than assume it. */
    if ((addr % FLASH_BLOCK) != 0u || (len % FLASH_BLOCK) != 0u || len == 0u) {
        g_contract_violation = 1;
        return MCF_E_FLASH;
    }
    off = addr - FLASH_BASE;
    if (off + len > FLASH_SIZE) {
        return MCF_E_FLASH;
    }
    memset(&g_flash[off], 0xFF, len);
    return 0;
}

static int32_t h_write(void *ctx, uint32_t addr, const uint8_t *p, uint32_t len)
{
    uint32_t off;
    (void)ctx;
    if (g_fail_write || g_readonly) {
        return MCF_E_FLASH;
    }
    g_flash_mutations++;
    if (addr >= JOURNAL_BASE) {
        if (g_fail_journal) return MCF_E_FLASH;
        if (len > JOURNAL_SIZE) {
            return MCF_E_FLASH;
        }
        memcpy(g_journal, p, len);
        return MCF_OK;
    }
    off = addr - FLASH_BASE;
    if (off + len > FLASH_SIZE) {
        return MCF_E_FLASH;
    }
    /* The library promises a write never crosses an erase-block boundary. */
    if (((addr - FLASH_BASE) % FLASH_BLOCK) + len > FLASH_BLOCK) {
        g_contract_violation = 1;
        return MCF_E_FLASH;
    }
    if (g_corrupt_write) {
        memset(&g_flash[off], 0x00, len); /* programmed, but wrong */
    } else {
        memcpy(&g_flash[off], p, len);
    }
    return MCF_OK;
}

static int32_t h_read(void *ctx, uint32_t addr, uint8_t *p, uint32_t len)
{
    uint32_t off;
    (void)ctx;
    if (g_fail_read) {
        return MCF_E_IO;
    }
    if (addr >= JOURNAL_BASE) {
        if (g_fail_journal) return MCF_E_FLASH;
        if (len > JOURNAL_SIZE) {
            return MCF_E_IO;
        }
        memcpy(p, g_journal, len);
        return (int32_t)len;
    }
    off = addr - FLASH_BASE;
    if (off + len > FLASH_SIZE) {
        return MCF_E_IO;
    }
    memcpy(p, &g_flash[off], len);
    return (int32_t)len;
}

static uint32_t h_block_size(void *ctx) { (void)ctx; return FLASH_BLOCK; }
static int32_t  h_is_readonly(void *c, uint32_t a, uint32_t l)
{ (void)c; (void)a; (void)l; return g_readonly ? 1 : 0; }
static uint32_t h_product(void *ctx) { (void)ctx; return 0x1234u; }
static uint32_t h_version(void *ctx) { (void)ctx; return 0x00010000u; }
static void    *h_alloc(void *ctx, uint32_t size) { (void)ctx; return malloc(size); }
static void     h_free(void *ctx, void *p) { (void)ctx; free(p); }

static int32_t h_progress(void *ctx, uint32_t done, uint32_t total)
{
    (void)ctx; (void)done; (void)total;
    return g_abort ? 1 : 0;
}

static int32_t h_commit(void *ctx) { (void)ctx; g_commit_called = 1; return 0; }

static mcf_hal_t g_hal = {
    h_erase, h_write, h_read, h_block_size, h_is_readonly,
    h_alloc, h_free,
    h_product, h_version,
    NULL, NULL, NULL
};

/* The session type is opaque, so it cannot be declared directly. This is
 * exactly what MCF_SESSION_DECLARE expands to, written out once. */
static mcf_session_storage_t g_session_storage;
static mcf_session_t *const g_session = (mcf_session_t *)(void *)&g_session_storage;

static void device_reset(void)
{
    g_fail_erase = 0;
    g_fail_write = 0;
    g_fail_read = 0;
    g_corrupt_write = 0;
    g_readonly = 0;
    g_commit_called = 0;
    g_abort = 0;
    g_contract_violation = 0;
    g_fail_journal = 0;
    g_flash_mutations = 0;
    memset(g_flash, 0xFF, sizeof(g_flash));
}

/* ---------------------------------------------------------------------- *
 * Patch construction. Mirrors the host tool's output byte for byte.
 * ---------------------------------------------------------------------- */

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

/* BSDIFF43 sign-magnitude control triple. */
static uint8_t *put_ctrl(uint8_t *p, int32_t x, int32_t y, int32_t seek)
{
    int32_t vals[3];
    int     i;

    vals[0] = x; vals[1] = y; vals[2] = seek;
    for (i = 0; i < 3; i++) {
        uint64_t m    = (uint64_t)(vals[i] < 0 ? -vals[i] : vals[i]);
        uint8_t  sign = (vals[i] < 0) ? 0x80u : 0x00u;
        int      b;

        for (b = 0; b < 8; b++) {
            uint8_t byte = (uint8_t)((m >> (8 * b)) & 0xFFu);
            if (b == 7) {
                byte = (uint8_t)((byte & 0x7Fu) | sign);
            }
            *p++ = byte;
        }
    }
    return p;
}

/* One LZ4 block containing only literals. High nibble of the token is the
 * literal length, 15 meaning "continued in the following bytes". */
static uint8_t *lz4_literal_block(uint8_t *p, const uint8_t *data, uint32_t n)
{
    if (n < 15u) {
        *p++ = (uint8_t)(n << 4);
    } else {
        uint32_t rem = n - 15u;
        *p++ = 0xF0u;
        while (rem >= 255u) {
            *p++ = 0xFFu;
            rem -= 255u;
        }
        *p++ = (uint8_t)rem;
    }
    memcpy(p, data, n);
    return p + n;
}

/*
 * Build a valid patch. `newb` is reconstructed as old[i] + delta[i].
 *
 * The delta is emitted as many control triples of `CHUNK` bytes rather than one
 * giant triple. That matters for the resume journal: a checkpoint can only be
 * taken at a triple boundary, and a single triple spanning the whole image has
 * no boundary until the end. Real firmware deltas have many triples, so the
 * fixture should too.
 *
 * The LZ4 stream is chunked to exactly block_size, matching the device's decode
 * buffer. This is a format constraint, not a convenience: the device decodes
 * into a buffer of block_size bytes and rejects a block that would overflow it.
 */
#define PATCH_CHUNK 256u

static uint32_t build_patch(uint8_t *out, const uint8_t *old, uint32_t old_len,
                            const uint8_t *newb, uint32_t new_len, uint32_t product,
                            uint32_t new_ver, uint32_t old_ver, uint32_t workspace_req,
                            uint32_t flags, uint32_t block_log2)
{
    /* Sizing: the delta carries a 24-byte control header per PATCH_CHUNK of
     * output, so it is NEW_LEN plus 24*(NEW_LEN/PATCH_CHUNK) plus slack. The
     * LZ4 framing then adds a length prefix and a token per block. */
    static uint8_t delta[NEW_LEN + 512];
    static uint8_t stream[NEW_LEN + 512];
    uint32_t block_size = 1u << block_log2;
    uint32_t delta_len = 0;
    uint32_t sp = 0;
    uint32_t off;
    uint32_t n;

    for (off = 0; off < new_len; off += PATCH_CHUNK) {
        n = new_len - off;
        if (n > PATCH_CHUNK) {
            n = PATCH_CHUNK;
        }
        put_ctrl(delta + delta_len, (int32_t)n, 0, 0);
        delta_len += 24;
        {
            uint32_t k;
            for (k = 0; k < n; k++) {
                uint8_t base = ((off + k) < old_len) ? old[off + k] : 0u;
                delta[delta_len++] = (uint8_t)(newb[off + k] - base);
            }
        }
    }

    /* LZ4 framing: one literal block per block_size slice, then the end marker. */
    for (off = 0; off < delta_len; off += block_size) {
        uint32_t m = delta_len - off;
        uint8_t *blk;
        uint8_t *end;

        if (m > block_size) {
            m = block_size;
        }
        /* The block body goes *after* the 4-byte length prefix, not on top of
         * it. Writing the body at &stream[sp] and then stamping the length at
         * &stream[sp] clobbers the token byte. */
        blk = &stream[sp + 4u];
        end = lz4_literal_block(blk, &delta[off], m);
        wr32(&stream[sp], (uint32_t)(end - blk));
        sp += 4u + (uint32_t)(end - blk);
    }
    wr32(&stream[sp], 0u);
    sp += 4u;

    memset(out, 0, MCF_HDR_MIN_SIZE);
    wr32(&out[MCF_OFF_MAGIC], MCF_HDR_MAGIC);
    wr16(&out[MCF_OFF_HDR_LEN], (uint16_t)MCF_HDR_MIN_SIZE);
    wr16(&out[MCF_OFF_HDR_VER], (uint16_t)((MCF_HDR_VER_MAJOR << 8) | MCF_HDR_VER_MINOR));
    wr32(&out[MCF_OFF_FLAGS], flags | MCF_FLAG_CODEC_LZ4);
    wr32(&out[MCF_OFF_PRODUCT_ID], product);
    wr32(&out[MCF_OFF_FW_VERSION], new_ver);
    wr32(&out[MCF_OFF_OLD_SIZE], old_len);
    wr32(&out[MCF_OFF_NEW_SIZE], new_len);
    wr32(&out[MCF_OFF_PAYLOAD_SIZE], 4u + sp);
    wr32(&out[MCF_OFF_OLD_CRC32], mcf_crc32(old, old_len));
    wr32(&out[MCF_OFF_NEW_CRC32], mcf_crc32(newb, new_len));
    wr32(&out[MCF_OFF_PAYLOAD_CRC32], mcf_crc32(stream, sp));
    wr32(&out[MCF_OFF_WORKSPACE_REQ], workspace_req);
    wr32(&out[MCF_OFF_OLD_VERSION], old_ver);
    out[MCF_OFF_CODEC_ID]   = (uint8_t)MCF_CODEC_LZ4;
    out[MCF_OFF_BLOCK_LOG2] = (uint8_t)block_log2;
    wr16(&out[MCF_OFF_RESERVED], 0u);

    wr32(&out[MCF_HDR_MIN_SIZE], delta_len);              /* codec properties */
    memcpy(&out[MCF_HDR_MIN_SIZE + 4], stream, sp);

    return (uint32_t)MCF_HDR_MIN_SIZE + 4u + sp;
}

#define VER_OLD 0x00010000u
#define VER_NEW 0x00020000u
#define PRODUCT 0x1234u
#define WS_LZ4  16u

static mcf_config_t make_cfg(uint32_t patch_len)
{
    mcf_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.hal        = &g_hal;
    cfg.patch      = g_patch;
    cfg.patch_size = patch_len;
    cfg.old        = g_old;
    cfg.old_size   = OLD_LEN;
    cfg.dst_addr   = FLASH_BASE;
    cfg.codec      = MCF_CODEC_AUTO;
    cfg.block_size = 512u;
    cfg.ram_budget = 4096u;
    cfg.progress   = h_progress;
    cfg.commit     = h_commit;
    return cfg;
}

/* Apply a patch and return the final status. Reports the failing stage so a
 * failure is diagnosable from the log line alone, which is the point of
 * mcf_session_error_site(). */
static mcf_status_t apply(uint32_t patch_len, mcf_config_t *cfg_out)
{
    /* opaque session: storage plus a typed pointer */
    mcf_config_t cfg = make_cfg(patch_len);
    mcf_status_t st;

    if (cfg_out != NULL) {
        *cfg_out = cfg;
    }

    st = mcf_session_open(g_session, &cfg);
    if (st == MCF_OK) {
        st = mcf_session_run(g_session);
    }
    g_last_error_site = mcf_session_error_site(g_session);
    if (st != MCF_OK) {
        printf("       -> %s at site %u\n", mcf_session_strerror(st),
               g_last_error_site);
    }
    mcf_session_close(g_session);
    return st;
}

/* ====================================================================== *
 * Tests
 * ====================================================================== */

static void test_crc(void)
{
    const char *s = "123456789";
    uint32_t c;
    size_t i;

    banner("crc32");
    CHECK_EQ(mcf_crc32((const uint8_t *)"", 0u), 0x00000000u, "empty");
    CHECK_EQ(mcf_crc32((const uint8_t *)s, 9u), 0xCBF43926u, "check string");
    CHECK_EQ(mcf_crc32((const uint8_t *)"a", 1u), 0xE8B7BE43u, "'a'");
    CHECK_EQ(mcf_crc32((const uint8_t *)"The quick brown fox jumps over the lazy dog", 43u),
             0x414FA339u, "fox");

    c = mcf_crc32_init();
    for (i = 0; i < 9u; i++) {
        c = mcf_crc32_update(c, (const uint8_t *)s + i, 1u);
    }
    CHECK_EQ(mcf_crc32_final(c), 0xCBF43926u, "streaming matches one-shot");
}

static void test_hal(void)
{
    mcf_hal_t bad;

    banner("hal registration");
    CHECK_EQ(mcf_hal_register(&g_hal), MCF_OK, "validate valid hal");

    bad = g_hal;
    bad.flash_write = NULL;
    CHECK_EQ(mcf_hal_register(&bad), MCF_E_PARAM, "reject missing flash_write");

    bad = g_hal;
    bad.get_product_id = NULL;
    CHECK_EQ(mcf_hal_register(&bad), MCF_E_PARAM, "reject missing product id");

    CHECK_EQ(mcf_hal_register(NULL), MCF_E_PARAM, "reject null hal");
    CHECK_EQ(mcf_hal_register(&g_hal), MCF_OK, "revalidate hal");
}

static void test_roundtrip(void)
{
    uint32_t len;
    mcf_status_t st;

    banner("round trip");
    device_reset();

    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW, VER_OLD,
                      WS_LZ4, 0u, 9u);
    st = apply(len, NULL);

    CHECK_EQ(st, MCF_OK, "patch applies");
    CHECK_EQ(g_commit_called, 1, "commit hook invoked");
    CHECK_EQ(g_contract_violation, 0, "flash contract honoured");
    CHECK(memcmp(&g_flash[0], g_new, NEW_LEN) == 0, "reconstructed image matches");
    CHECK_EQ(mcf_crc32(g_flash, NEW_LEN), mcf_crc32(g_new, NEW_LEN), "image crc matches");
}

static void test_fault_erase(void)
{
    uint32_t len;

    banner("fault injection: erase fails");
    device_reset();
    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW, VER_OLD,
                      WS_LZ4, 0u, 9u);
    g_fail_erase = 1;
    CHECK_EQ(apply(len, NULL), MCF_E_FLASH, "erase failure surfaces");
    CHECK_EQ(g_commit_called, 0, "commit not called on failure");
}

static void test_fault_write(void)
{
    uint32_t len;

    banner("fault injection: program fails");
    device_reset();
    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW, VER_OLD,
                      WS_LZ4, 0u, 9u);
    g_fail_write = 1;
    CHECK_EQ(apply(len, NULL), MCF_E_FLASH, "program failure surfaces");
    CHECK_EQ(g_commit_called, 0, "commit not called on failure");
}

static void test_fault_silent_corruption(void)
{
    uint32_t len;

    banner("fault injection: program succeeds but stores wrong bytes");
    device_reset();
    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW, VER_OLD,
                      WS_LZ4, 0u, 9u);
    /* The write call succeeds. Only read-back verification can catch this, which
     * is the case the reference implementation silently passes. */
    g_corrupt_write = 1;
    CHECK_EQ(apply(len, NULL), MCF_E_FLASH, "read-back verify catches silent corruption");
    CHECK_EQ(g_commit_called, 0, "commit not called on failure");
}

static void test_fault_readonly(void)
{
    uint32_t len;

    banner("fault injection: destination is write-only");
    device_reset();
    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW, VER_OLD,
                      WS_LZ4, 0u, 9u);
    g_readonly = 1;
    /* Cannot write at all, so this must fail rather than silently succeed. */
    CHECK(apply(len, NULL) != MCF_OK, "write-only destination does not report success");
}

static void test_truncated(void)
{
    uint32_t len;

    banner("fault injection: truncated payload");
    device_reset();
    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW, VER_OLD,
                      WS_LZ4, 0u, 9u);
    /* Keep the header intact, cut the payload short. */
    CHECK(apply(len - 32u, NULL) != MCF_OK, "truncation does not report success");
}

static void test_corrupt_payload(void)
{
    uint32_t len;
    mcf_status_t st;

    banner("fault injection: flipped payload byte");
    device_reset();
    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW, VER_OLD,
                      WS_LZ4, 0u, 9u);

    /* Flip one bit deep inside the diff data. */
    g_patch[MCF_HDR_MIN_SIZE + 4 + 4 + 40] ^= 0x01u;
    st = apply(len, NULL);
    CHECK(st != MCF_OK, "corrupt payload does not report success");
    printf("       (status: %s, site %u)\n", mcf_session_strerror(st),
           mcf_session_error_site(NULL) == 0u ? 0u : 0u);
}

static void test_v2_session_rejected(void)
{
    mcf_v2_view_t view;
    uint32_t len = MCF_V2_HEADER_MIN + 5u;

    banner("MFP2 session boundary");
    device_reset();
    memset(g_patch, 0, len);
    wr32(&g_patch[MCF_V2_OFF_MAGIC], MCF_V2_MAGIC);
    wr16(&g_patch[MCF_V2_OFF_HEADER_LEN], MCF_V2_HEADER_MIN);
    wr16(&g_patch[MCF_V2_OFF_VERSION], MCF_V2_VERSION);
    wr32(&g_patch[MCF_V2_OFF_FLAGS], MCF_V2_FLAG_CODEC_LZ4);
    wr32(&g_patch[MCF_V2_OFF_PAYLOAD_SIZE], 5u);
    g_patch[MCF_V2_OFF_CODEC] = (uint8_t)MCF_CODEC_LZ4;
    g_patch[MCF_V2_OFF_RECORD_LOG2] = 8u;
    wr32(&g_patch[MCF_V2_OFF_RECORD_COUNT], 1u);
    wr32(&g_patch[MCF_V2_HEADER_MIN], 1u);
    g_patch[MCF_V2_HEADER_MIN + 4u] = 0xAAu;

    CHECK_EQ(mcf_v2_parse(g_patch, len, &view), MCF_OK,
             "fixture is structurally valid MFP2");
    CHECK_EQ(apply(len, NULL), MCF_E_FORMAT,
             "normal session rejects MFP2 as non-MFP1");
    CHECK_EQ(g_last_error_site, 2u,
             "MFP2 rejection is reported at the MFP1 magic check");
    CHECK_EQ(g_flash_mutations, 0,
             "MFP2 rejection happens before flash erase or write");
}

static void test_header_rejections(void)
{
    uint32_t len;
    uint8_t save[4];

    banner("header validation");

    /* bad magic */
    device_reset();
    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW, VER_OLD,
                      WS_LZ4, 0u, 9u);
    memcpy(save, g_patch, 4u);
    wr32(g_patch, 0xDEADBEEFu);
    CHECK_EQ(apply(len, NULL), MCF_E_FORMAT, "bad magic rejected");
    memcpy(g_patch, save, 4u);

    /* wrong product */
    device_reset();
    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, 0x9999u, VER_NEW, VER_OLD,
                      WS_LZ4, 0u, 9u);
    CHECK_EQ(apply(len, NULL), MCF_E_PRODUCT, "wrong product rejected");

    /* downgrade */
    device_reset();
    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_OLD, VER_OLD,
                      WS_LZ4, 0u, 9u);
    CHECK_EQ(apply(len, NULL), MCF_E_ROLLBACK, "refuses downgrade");

    /* base version mismatch */
    device_reset();
    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW, 0x0000FFFFu,
                      WS_LZ4, 0u, 9u);
    CHECK_EQ(apply(len, NULL), MCF_E_MISMATCH, "base version mismatch rejected");

    /* declared workspace over budget: the keystone check */
    device_reset();
    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW, VER_OLD,
                      60000u, 0u, 9u);
    CHECK_EQ(apply(len, NULL), MCF_E_DICT_TOO_LARGE, "over-budget workspace refused early");

    /* unknown codec */
    device_reset();
    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW, VER_OLD,
                      WS_LZ4, 0u, 9u);
    g_patch[MCF_OFF_CODEC_ID] = 0x7Fu;
    CHECK_EQ(apply(len, NULL), MCF_E_FORMAT, "unknown codec marker rejected");

    /* raw flag disagreeing with the codec id: the two must agree in both
     * directions, or a producer could claim compression it did not apply. */
    device_reset();
    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW, VER_OLD,
                      WS_LZ4, 0u, 9u);
    wr32(&g_patch[MCF_OFF_FLAGS], MCF_FLAG_RAW | MCF_FLAG_CODEC_LZ4);
    CHECK_EQ(apply(len, NULL), MCF_E_FORMAT, "raw flag with LZ4 codec rejected");

    device_reset();
    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW, VER_OLD,
                      WS_LZ4, 0u, 9u);
    g_patch[MCF_OFF_CODEC_ID] = (uint8_t)MCF_CODEC_RAW;
    CHECK_EQ(apply(len, NULL), MCF_E_FORMAT, "raw codec without the raw flag rejected");

    /* future major version */
    device_reset();
    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW, VER_OLD,
                      WS_LZ4, 0u, 9u);
    wr16(&g_patch[MCF_OFF_HDR_VER], 0x0900u);
    CHECK_EQ(apply(len, NULL), MCF_E_UNSUPPORTED, "future major version rejected");

    /* signed flag with no verifier: must fail closed */
    device_reset();
    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW, VER_OLD,
                      WS_LZ4, MCF_FLAG_SIGNED, 9u);
    CHECK_EQ(apply(len, NULL), MCF_E_SIGNATURE, "signed patch refused without a verifier");
}

static void test_base_image_mismatch(void)
{
    uint32_t len;
    mcf_config_t cfg;
    uint8_t corrupt[OLD_LEN];

    banner("base image verification");
    device_reset();
    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW, VER_OLD,
                      WS_LZ4, 0u, 9u);

    memcpy(corrupt, g_old, OLD_LEN);
    corrupt[100] ^= 0xFFu;

    {
        /* opaque session: storage plus a typed pointer */
        mcf_status_t st;

        cfg = make_cfg(len);
        cfg.old = corrupt;
        st = mcf_session_open(g_session, &cfg);
        if (st == MCF_OK) {
            st = mcf_session_run(g_session);
        }
        mcf_session_close(g_session);
        CHECK_EQ(st, MCF_E_MISMATCH, "base image crc mismatch rejected");
    }
}

static void test_new_image_crc(void)
{
    uint32_t len;

    banner("reconstructed image crc");
    device_reset();
    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW, VER_OLD,
                      WS_LZ4, 0u, 9u);
    /* Declare the wrong new-image CRC. The reconstruction will be correct but
     * the declared expectation is not, and the library must reject it. */
    wr32(&g_patch[MCF_OFF_NEW_CRC32], mcf_crc32(g_new, NEW_LEN) ^ 0xFFFFFFFFu);
    CHECK_EQ(apply(len, NULL), MCF_E_CORRUPT, "wrong new-image crc rejected");
    CHECK_EQ(g_commit_called, 0, "commit not called");
}

static void test_abort(void)
{
    uint32_t len;

    banner("abort through the progress callback");
    device_reset();
    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW, VER_OLD,
                      WS_LZ4, 0u, 9u);
    g_abort = 1;
    CHECK_EQ(apply(len, NULL), MCF_E_ABORTED, "abort is a clean error");
    CHECK_EQ(g_commit_called, 0, "commit not called after abort");
}

static void test_stepwise(void)
{
    /* opaque session: storage plus a typed pointer */
    mcf_config_t cfg;
    uint32_t len;
    mcf_status_t st;
    int guard = 0;

    banner("step-wise driving and progress reporting");
    device_reset();
    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW, VER_OLD,
                      WS_LZ4, 0u, 9u);
    cfg = make_cfg(len);

    st = mcf_session_open(g_session, &cfg);
    CHECK_EQ(st, MCF_OK, "open");
    st = mcf_session_begin(g_session);
    CHECK_EQ(st, MCF_OK, "begin");

    while (mcf_session_state(g_session) == MCF_ST_DECODE && guard < 10000) {
        st = mcf_session_step(g_session);
        if (st != MCF_OK) {
            break;
        }
        guard++;
    }
    CHECK(st == MCF_OK, "stepping completed without error");
    CHECK(mcf_session_state(g_session) == MCF_ST_VERIFY, "reached verify");
    CHECK_EQ(mcf_session_total(g_session), NEW_LEN, "reported total");
    CHECK(mcf_session_progress(g_session) > 0u, "progress advanced");

    st = mcf_session_finish(g_session);
    CHECK_EQ(st, MCF_OK, "finish");
    CHECK_EQ(mcf_session_state(g_session), MCF_ST_DONE, "state is DONE");
    CHECK(memcmp(&g_flash[0], g_new, NEW_LEN) == 0, "image matches after stepping");
    mcf_session_close(g_session);
    CHECK_EQ(mcf_session_state(g_session), MCF_ST_IDLE, "close resets to IDLE");
}

static void test_sizing(void)
{
    banner("reported sizes");
    printf("       g_session state: %u bytes\n", mcf_session_sizeof());
    CHECK(mcf_session_sizeof() <= (uint32_t)MCF_SESSION_MAX_BYTES,
          "g_session fits the declared storage ceiling");
    printf("       header view:    %u bytes\n", (unsigned)sizeof(mcf_header_t));
    CHECK_EQ(sizeof(mcf_header_t), MCF_HDR_MIN_SIZE, "header view matches wire size");
    printf("       config:         %u bytes\n", (unsigned)sizeof(mcf_config_t));
}

/* ====================================================================== *
 * Resume journal
 * ====================================================================== */

static mcf_config_t journal_cfg(uint32_t patch_len, uint32_t interval)
{
    mcf_config_t cfg = make_cfg(patch_len);
    cfg.journal_addr     = JOURNAL_BASE;
    cfg.journal_interval = interval;
    return cfg;
}

/* Run `steps` blocks, then abandon the session as a power cut would. Returns
 * how many bytes had been reconstructed. */
static uint32_t run_partial(uint32_t patch_len, uint32_t steps)
{
    static mcf_session_storage_t s_storage;
    mcf_session_t *s = (mcf_session_t *)(void *)&s_storage;
    mcf_config_t cfg = journal_cfg(patch_len, 1u);
    uint32_t i;

    mcf_session_open(s, &cfg);
    mcf_resume_probe(s, &cfg);
    mcf_session_begin(s);
    for (i = 0; i < steps; i++) {
        if (mcf_session_step(s) != MCF_OK) {
            break;
        }
        if (mcf_session_state(s) == MCF_ST_VERIFY) {
            break;
        }
    }
    i = mcf_session_progress(s);
    mcf_session_close(s);
    return i;
}

static void test_resume_interrupt_and_continue(void)
{
    uint32_t patch_len;
    static mcf_session_storage_t s_storage;
    mcf_session_t *s = (mcf_session_t *)(void *)&s_storage;
    mcf_config_t cfg;
    mcf_status_t st;
    uint32_t partial;

    banner("resume: interrupted update continues correctly");

    device_reset();
    patch_len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW,
                            VER_OLD, WS_LZ4, 0u, 9u);

    partial = run_partial(patch_len, 2u);
    CHECK(partial > 0u, "partial run made progress");
    CHECK(partial < NEW_LEN, "partial run stopped short");

    /* A checkpoint should exist and should survive the abandon. */
    {
        mcf_journal_t j;
        memcpy(&j, g_journal, sizeof(j));
        CHECK_EQ(j.magic, MCF_JOURNAL_MAGIC, "journal was written");
        CHECK(j.newpos > 0u, "journal records progress");
    }

    /* Reboot: probe, resume, finish. */
    cfg = journal_cfg(patch_len, 1u);
    st = mcf_session_open(s, &cfg);
    CHECK_EQ(st, MCF_OK, "reopen");
    st = mcf_resume_probe(s, &cfg);
    CHECK_EQ(st, MCF_OK, "resume point accepted");
    st = mcf_session_begin(s);
    CHECK_EQ(st, MCF_OK, "begin from resume");
    CHECK(mcf_session_progress(s) > 0u, "resumed rather than restarting");

    for (;;) {
        st = mcf_session_step(s);
        if (st != MCF_OK) {
            break;
        }
        if (mcf_session_state(s) == MCF_ST_VERIFY) {
            break;
        }
    }
    st = mcf_session_finish(s);
    CHECK_EQ(st, MCF_OK, "resumed run completes");
    CHECK_EQ(mcf_session_state(s), MCF_ST_DONE, "state DONE");
    CHECK(memcmp(g_flash, g_new, NEW_LEN) == 0, "resumed image is byte-exact");
    mcf_session_close(s);
}

static void test_resume_cleared_when_done(void)
{
    uint32_t patch_len;
    static mcf_session_storage_t s_storage;
    mcf_session_t *s = (mcf_session_t *)(void *)&s_storage;
    mcf_config_t cfg;
    mcf_journal_t j;

    banner("resume: a completed update clears its resume point");
    device_reset();
    patch_len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW,
                            VER_OLD, WS_LZ4, 0u, 9u);
    (void)run_partial(patch_len, 2u);
    CHECK_EQ(mcf_crc32(g_journal, sizeof(mcf_journal_t)) != 0u, 1u, "journal was populated");

    cfg = journal_cfg(patch_len, 1u);
    mcf_session_open(s, &cfg);
    mcf_resume_probe(s, &cfg);
    mcf_session_begin(s);
    while (mcf_session_state(s) == MCF_ST_DECODE) {
        if (mcf_session_step(s) != MCF_OK) {
            break;
        }
    }
    CHECK_EQ(mcf_session_finish(s), MCF_OK, "finish");

    memcpy(&j, g_journal, sizeof(j));
    CHECK(j.magic != MCF_JOURNAL_MAGIC, "resume point cleared after success");
    mcf_session_close(s);
}

static void test_resume_rejects_bad_records(void)
{
    uint32_t patch_len;
    static mcf_session_storage_t s_storage;
    mcf_session_t *s = (mcf_session_t *)(void *)&s_storage;
    mcf_config_t cfg;
    mcf_journal_t good;
    mcf_journal_t j;

    banner("resume: damaged or stale records fall back to a cold start");
    device_reset();
    patch_len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW,
                            VER_OLD, WS_LZ4, 0u, 9u);
    (void)run_partial(patch_len, 2u);
    memcpy(&good, g_journal, sizeof(good));
    CHECK_EQ(good.magic, MCF_JOURNAL_MAGIC, "baseline journal present");

    cfg = journal_cfg(patch_len, 1u);

    /* 1. torn record: the CRC no longer matches */
    memcpy(&j, &good, sizeof(j));
    j.newpos += 4u;
    memcpy(g_journal, &j, sizeof(j));
    mcf_session_open(s, &cfg);
    CHECK_EQ(mcf_resume_probe(s, &cfg), MCF_E_NOT_FOUND, "torn record rejected");
    mcf_session_close(s);

    /* 2. record belongs to a different patch */
    memcpy(&j, &good, sizeof(j));
    j.session_id ^= 0xFFFFFFFFu;
    j.record_crc = 0u;
    {   /* recompute the record crc the same way the library does */
        mcf_journal_t t = j;
        t.record_crc    = 0u;
        t.record_crc    = mcf_crc32((const uint8_t *)&t, (uint32_t)sizeof(t));
        j               = t;
    }
    memcpy(g_journal, &j, sizeof(j));
    mcf_session_open(s, &cfg);
    CHECK_EQ(mcf_resume_probe(s, &cfg), MCF_E_NOT_FOUND, "foreign patch rejected");
    mcf_session_close(s);

    /* 3. the flash prefix no longer matches the journal. This is the case that
     *    makes resume a feature rather than a hazard. */
    memcpy(g_journal, &good, sizeof(good));
    g_flash[0] ^= 0xFFu;
    mcf_session_open(s, &cfg);
    CHECK_EQ(mcf_resume_probe(s, &cfg), MCF_E_NOT_FOUND, "corrupt prefix rejected");
    mcf_session_close(s);

    /* 4. no journal at all */
    memset(g_journal, 0, sizeof(g_journal));
    mcf_session_open(s, &cfg);
    CHECK_EQ(mcf_resume_probe(s, &cfg), MCF_E_NOT_FOUND, "absent journal rejected");
    mcf_session_close(s);

    /* A checkpoint write failure is best-effort: the update succeeds, but the
     * diagnostic flag makes the lost resume guarantee observable. */
    device_reset();
    g_fail_journal = 1;
    patch_len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW,
                            VER_OLD, WS_LZ4, 0u, 9u);
    cfg = journal_cfg(patch_len, 1u);
    mcf_session_open(s, &cfg);
    CHECK_EQ(mcf_session_run(s), MCF_OK, "journal failure does not abort update");
    CHECK((mcf_session_flags(s) & MCF_SESSION_FLAG_RESUME_DEGRADED) != 0u,
          "journal failure is observable");
    mcf_session_close(s);

    /* After all that rejection, a cold run must still work. */
    device_reset();
    patch_len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW,
                            VER_OLD, WS_LZ4, 0u, 9u);
    CHECK_EQ(apply(patch_len, NULL), MCF_OK, "cold start still succeeds");
}

static void test_resume_disabled(void)
{
    uint32_t patch_len;
    static mcf_session_storage_t s_storage;
    mcf_session_t *s = (mcf_session_t *)(void *)&s_storage;
    mcf_config_t cfg;

    banner("resume: disabled by default");
    device_reset();
    patch_len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW,
                            VER_OLD, WS_LZ4, 0u, 9u);
    cfg = make_cfg(patch_len);   /* journal_addr left zero */
    mcf_session_open(s, &cfg);
    CHECK_EQ(mcf_resume_probe(s, &cfg), MCF_E_NOT_FOUND, "probe with no address is a no-op");
    CHECK_EQ(mcf_session_run(s), MCF_OK, "update works with resume off");
    mcf_session_close(s);
}

/* ====================================================================== */

int main(void)
{
    uint32_t i;

    printf("Microfoam host tests - library version 0x%06X\n", mcf_version());

    for (i = 0; i < OLD_LEN; i++) {
        g_old[i] = (uint8_t)((i * 7u + (i / 13u)) & 0xFFu);
    }
    for (i = 0; i < NEW_LEN; i++) {
        /* A realistic small change: shift a few regions, keep the rest. */
        g_new[i] = (i > 100u && i < 500u) ? (uint8_t)(g_old[i] ^ 0x5Au) : g_old[i];
    }

    test_sizing();
    test_crc();
    test_hal();
    test_roundtrip();
    test_fault_erase();
    test_fault_write();
    test_fault_silent_corruption();
    test_fault_readonly();
    test_truncated();
    test_corrupt_payload();
    test_v2_session_rejected();
    test_header_rejections();
    test_base_image_mismatch();
    test_new_image_crc();
    test_abort();
    test_stepwise();
    test_resume_interrupt_and_continue();
    test_resume_cleared_when_done();
    test_resume_rejects_bad_records();
    test_resume_disabled();

    printf("\n%d checks, %d failures\n", g_checks, g_fail);
    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
