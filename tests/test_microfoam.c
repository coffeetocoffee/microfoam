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
#include "patch_fixture.h"

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

/* The HAL compatibility entry points are deliberately deprecated in the public
 * header, and this suite is the one caller that must keep exercising them. The
 * diagnostic is silenced only around those calls, so an accidental new use
 * anywhere else in the tree still fails the -Werror build. */
#if defined(__GNUC__) || defined(__clang__)
#  define DEPRECATED_CALLS_BEGIN                                   \
        _Pragma("GCC diagnostic push")                             \
        _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
#  define DEPRECATED_CALLS_END _Pragma("GCC diagnostic pop")
#elif defined(_MSC_VER)
#  define DEPRECATED_CALLS_BEGIN \
        __pragma(warning(push)) __pragma(warning(disable : 4996))
#  define DEPRECATED_CALLS_END __pragma(warning(pop))
#else
#  define DEPRECATED_CALLS_BEGIN
#  define DEPRECATED_CALLS_END
#endif

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

/* The allocator records what it was asked for. mcf_ctx_size() promises a
 * number equal to this request, and a promise checked against a value the
 * test itself computes is not checked at all - so the comparison is made
 * against what the session actually requested at run time. */
static uint32_t g_last_alloc_size;
static uint32_t g_alloc_calls;

static void    *h_alloc(void *ctx, uint32_t size)
{
    (void)ctx;
    g_last_alloc_size = size;
    g_alloc_calls++;
    return malloc(size);
}
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
    g_last_alloc_size = 0;
    g_alloc_calls = 0;
    memset(g_flash, 0xFF, sizeof(g_flash));
}

/* ---------------------------------------------------------------------- *
 * Patch construction. The builder itself lives in patch_fixture.h so that this
 * suite and the reentrancy suite describe exactly one format. These two
 * little-endian writers stay local because the v2 tests below use them
 * directly to stamp header fields.
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

/* Adapts the shared builder to the call sites below, which all write into the
 * file-scope g_patch buffer. The two signatures are otherwise identical. */
static uint32_t build_patch(uint8_t *out, const uint8_t *old, uint32_t old_len,
                            const uint8_t *newb, uint32_t new_len, uint32_t product,
                            uint32_t new_ver, uint32_t old_ver, uint32_t workspace_req,
                            uint32_t flags, uint32_t block_log2)
{
    return mcf_fx_build_patch(out, (uint32_t)sizeof(g_patch), old, old_len,
                              newb, new_len, product, new_ver, old_ver,
                              workspace_req, flags, block_log2);
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
    uint8_t   ws[64];

    DEPRECATED_CALLS_BEGIN

    banner("hal registration (deprecated compatibility helper)");
    CHECK_EQ(mcf_hal_register(&g_hal), MCF_OK, "validate valid hal");

    bad = g_hal;
    bad.flash_write = NULL;
    CHECK_EQ(mcf_hal_register(&bad), MCF_E_PARAM, "reject missing flash_write");

    bad = g_hal;
    bad.get_product_id = NULL;
    CHECK_EQ(mcf_hal_register(&bad), MCF_E_PARAM, "reject missing product id");

    CHECK_EQ(mcf_hal_register(NULL), MCF_E_PARAM, "reject null hal");
    CHECK_EQ(mcf_hal_register(&g_hal), MCF_OK, "revalidate hal");

    /* The static-workspace helper is retained for source compatibility only.
     * Its contract is a flat refusal: it must never appear to succeed, because
     * a caller that believed it had configured a workspace would discover
     * otherwise much later, on a different path, with an unrelated code. */
    banner("deprecated static workspace helper");
    CHECK_EQ(mcf_hal_set_static_workspace(&g_hal, ws, (uint32_t)sizeof(ws)),
             MCF_E_UNSUPPORTED, "static workspace helper refuses to configure");
    CHECK_EQ(mcf_hal_set_static_workspace(NULL, ws, (uint32_t)sizeof(ws)),
             MCF_E_PARAM, "null hal rejected before the refusal");
    CHECK_EQ(mcf_hal_set_static_workspace(&g_hal, NULL, (uint32_t)sizeof(ws)),
             MCF_E_PARAM, "null workspace rejected before the refusal");
    CHECK_EQ(mcf_hal_set_static_workspace(&g_hal, ws, 0u),
             MCF_E_PARAM, "zero-size workspace rejected before the refusal");

    DEPRECATED_CALLS_END
}

static void test_roundtrip(void)
{
    uint32_t len;
    mcf_status_t st;
    mcf_config_t cfg;
    uint32_t predicted;

    banner("round trip");
    device_reset();

    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW, VER_OLD,
                      WS_LZ4, 0u, 9u);

    /* Ask what the run will cost before running it, then check the answer
     * against what the allocator was actually asked for. If the two ever
     * drift, the published memory contract is wrong and this fails. */
    cfg = make_cfg(len);
    predicted = mcf_ctx_size(&cfg);
    CHECK(predicted != 0u, "a runnable configuration is sizable");
    CHECK(g_alloc_calls == 0u, "sizing allocates nothing");

    st = apply(len, NULL);

    CHECK_EQ(st, MCF_OK, "patch applies");
    CHECK_EQ(g_alloc_calls, 1u, "the run allocated exactly once");
    CHECK_EQ(g_last_alloc_size, predicted, "mcf_ctx_size matches the run's allocation");
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
    uint32_t len = MCF_V2_HEADER_MIN + 21u;

    banner("MFP2 session boundary");
    device_reset();
    memset(g_patch, 0, len);
    wr32(&g_patch[MCF_V2_OFF_MAGIC], MCF_V2_MAGIC);
    wr16(&g_patch[MCF_V2_OFF_HEADER_LEN], MCF_V2_HEADER_MIN);
    wr16(&g_patch[MCF_V2_OFF_VERSION], MCF_V2_VERSION);
    wr32(&g_patch[MCF_V2_OFF_FLAGS], MCF_V2_EXEC_REQUIRED_FLAGS);
    wr32(&g_patch[MCF_V2_OFF_PAYLOAD_SIZE], 21u);
    g_patch[MCF_V2_OFF_CODEC] = (uint8_t)MCF_CODEC_LZ4;
    g_patch[MCF_V2_OFF_RECORD_LOG2] = MCF_V2_RECORD_LOG2_MIN;
    memset(&g_patch[MCF_V2_OFF_KEY_ID], 0x42, MCF_V2_KEY_ID_SIZE);
    memset(&g_patch[MCF_V2_OFF_NONCE_PREFIX], 0x24, MCF_V2_NONCE_PREFIX_SIZE);
    wr32(&g_patch[MCF_V2_OFF_RECORD_COUNT], 1u);
    wr32(&g_patch[MCF_V2_HEADER_MIN], 1u);
    g_patch[MCF_V2_HEADER_MIN + 4u] = 0xAAu;
    memset(&g_patch[MCF_V2_HEADER_MIN + 5u], 0x5A, MCF_V2_RECORD_TAG_SIZE);

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

/* mcf_ctx_size() is the published cost query, so its contract is checked
 * directly: the refusal cases must all report zero, and the number it returns
 * for a valid configuration must move with the inputs that actually move the
 * cost (block size, codec). */
static void test_ctx_size(void)
{
    uint32_t len;
    uint32_t base;
    mcf_config_t cfg;

    banner("mcf_ctx_size");
    device_reset();

    len = build_patch(g_patch, g_old, OLD_LEN, g_new, NEW_LEN, PRODUCT, VER_NEW, VER_OLD,
                      WS_LZ4, 0u, 9u);
    cfg = make_cfg(len);
    base = mcf_ctx_size(&cfg);

    CHECK(base != 0u, "valid configuration is sizable");
    CHECK(g_alloc_calls == 0u, "sizing does not allocate");
    CHECK_EQ(g_flash_mutations, 0, "sizing writes no flash");

    /* The budget is an output of this query, not an input: a configuration
     * over budget must still report its true cost, or the caller can never
     * learn what to set the budget to. */
    cfg = make_cfg(len);
    cfg.ram_budget = 64u;
    CHECK_EQ(mcf_ctx_size(&cfg), base, "budget does not cap the reported cost");

    /* A larger block size costs more: the two block buffers scale with it. */
    cfg = make_cfg(len);
    cfg.block_size = 1024u;
    CHECK(mcf_ctx_size(&cfg) > base, "a larger block size reports a larger cost");

    /* A smaller block size costs less, down to the point where the patch's
     * new_size clamps it. */
    cfg = make_cfg(len);
    cfg.block_size = 256u;
    CHECK(mcf_ctx_size(&cfg) < base, "a smaller block size reports a smaller cost");

    /* Refusals are all zero, because a runnable session never costs zero. */
    CHECK_EQ(mcf_ctx_size(NULL), 0u, "null config is unsizable");

    cfg = make_cfg(len);
    cfg.hal = NULL;
    CHECK_EQ(mcf_ctx_size(&cfg), 0u, "null hal is unsizable");

    cfg = make_cfg(len);
    cfg.patch = NULL;
    CHECK_EQ(mcf_ctx_size(&cfg), 0u, "null patch is unsizable");

    cfg = make_cfg(len);
    cfg.patch_size = 4u;
    CHECK_EQ(mcf_ctx_size(&cfg), 0u, "truncated patch is unsizable");

    cfg = make_cfg(len);
    cfg.block_size = 500u; /* not a power of two */
    CHECK_EQ(mcf_ctx_size(&cfg), 0u, "non-power-of-two block size is unsizable");

    /* A patch the session would refuse on codec grounds is unsizable, not
     * silently sized for a codec that will never run. The patch declares LZ4;
     * a configuration demanding LZMA is rejected during header validation. */
    cfg = make_cfg(len);
    cfg.codec = MCF_CODEC_LZMA;
    CHECK_EQ(mcf_ctx_size(&cfg), 0u, "codec-mismatched patch is unsizable");

    /* The rejected-patch case must not have mutated anything. */
    CHECK_EQ(g_flash_mutations, 0, "no sizing path touched flash");
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

    /* Three steps, not two: two lands on a byte offset that happens to be
     * both block-aligned and erase-block-aligned, which would hide the
     * erase-accounting bug below. Three steps stops mid-block, which is the
     * state a real power cut leaves behind. */
    partial = run_partial(patch_len, 3u);
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

    /* Prove the precondition before asserting the cleanup. Without this the
     * test passes whenever no checkpoint was ever written - the "cleared"
     * assertion is satisfied by a journal that was never populated - and the
     * CRC != 0 check that used to stand here could not detect that, because a
     * CRC over arbitrary bytes is essentially never zero. */
    memcpy(&j, g_journal, sizeof(j));
    CHECK_EQ(j.magic, MCF_JOURNAL_MAGIC, "a resume point was written");
    CHECK(j.newpos > 0u, "the resume point records progress");

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

/* BSDIFF43 applies a triple's seek *after* its diff and extra bytes, so the
 * seek positions the base cursor for the next triple, not its own. This is the
 * case that distinguishes the two orderings: a triple with both a diff and a
 * nonzero seek. Get it backwards and the base is read from the wrong place, the
 * reconstruction is silently wrong, and only the whole-image CRC notices. */
static void test_seek_positions_next_triple(void)
{
    static uint8_t delta[MCF_FX_SCRATCH];
    uint8_t *p = delta;
    uint32_t len;
    uint32_t i;

    banner("delta engine: a seek positions the base for the next triple");
    device_reset();

    /* old[i] = i % 251 gives a base whose bytes at 0 and at 768 differ, which is
     * what makes the two orderings observable at all. */
    for (i = 0; i < OLD_LEN; i++) {
        g_old[i] = (uint8_t)(i % 251u);
    }
    CHECK(memcmp(&g_old[0], &g_old[768], 256u) != 0,
          "the base bytes at 0 and 768 differ, so the ordering is observable");

    /* new = old[0..255] ++ old[1024..1279]: two diff triples reading
     * non-contiguous base regions, so the first carries a nonzero seek (its
     * diff advances oldpos by 256, then the seek advances it by 768 to 1024,
     * where the second triple reads). An engine that applied the seek first
     * would read the first triple from 768 instead of 0. */
    for (i = 0; i < 256u; i++) {
        g_new[i]        = g_old[i];
        g_new[256u + i] = g_old[1024u + i];
    }

    p = mcf_fx_put_ctrl(p, 256, 0, 768);
    for (i = 0; i < 256u; i++) {
        *p++ = (uint8_t)(g_new[i] - g_old[i]);
    }
    p = mcf_fx_put_ctrl(p, 256, 0, 0);
    for (i = 0; i < 256u; i++) {
        *p++ = (uint8_t)(g_new[256u + i] - g_old[1024u + i]);
    }

    len = mcf_fx_build_patch_from_delta(g_patch, (uint32_t)sizeof(g_patch),
                                        delta, (uint32_t)(p - delta),
                                        g_old, OLD_LEN, g_new, 512u,
                                        PRODUCT, VER_NEW, VER_OLD, WS_LZ4, 0u, 9u);
    CHECK(len > 0u, "a patch with a seek on a diff-bearing triple builds");

    CHECK_EQ(apply(len, NULL), MCF_OK,
             "a delta with a seek on a diff-bearing triple applies");
    CHECK(memcmp(&g_flash[0], g_new, 512u) == 0,
          "the reconstructed image is byte-exact");
}

static void test_small_image_framing(void)
{
    static mcf_session_storage_t storage;
    mcf_session_t *s = (mcf_session_t *)(void *)&storage;
    mcf_config_t cfg;
    uint32_t patch_len;
    uint32_t i;

    banner("small images: framing is capped at new_size");
    device_reset();
    for (i = 0u; i < 512u; i++) {
        g_old[i] = (uint8_t)((i * 7u + 3u) & 0xFFu);
    }
    for (i = 0u; i < 256u; i++) {
        g_new[i] = (uint8_t)((i * 5u + 11u) & 0xFFu);
    }

    /* The requested/default framing is 1024, but new_size is 256. The builder
     * must cap its actual frame to 256 (and declare log2=8), because the device
     * clamps its decode window to min(cfg.block_size, new_size). Without that
     * cap no device configuration can apply the patch: the delta's control
     * triples make its decompressed stream larger than the 256-byte window. */
    patch_len = mcf_fx_build_patch(g_patch, (uint32_t)sizeof(g_patch),
                                   g_old, 512u, g_new, 256u,
                                   PRODUCT, VER_NEW, VER_OLD, WS_LZ4, 0u, 10u);
    CHECK(patch_len > 0u, "a small-image patch builds");
    CHECK_EQ(g_patch[MCF_OFF_BLOCK_LOG2], 8u,
             "small-image framing declares the capped exponent");

    cfg = make_cfg(patch_len);
    cfg.old = g_old;
    cfg.old_size = 512u;
    cfg.block_size = 1024u;
    cfg.ram_budget = 4096u;
    CHECK_EQ(mcf_session_open(s, &cfg), MCF_OK, "small-image session opens");
    CHECK_EQ(mcf_session_run(s), MCF_OK,
             "small-image patch applies with the default device window");
    CHECK(memcmp(g_flash, g_new, 256u) == 0,
          "small-image reconstruction is byte-exact");
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
    test_ctx_size();
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

    /* Last: it rewrites the shared old/new fixtures with a delta of its own. */
    test_seek_positions_next_triple();
    test_small_image_framing();

    printf("\n%d checks, %d failures\n", g_checks, g_fail);
    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
