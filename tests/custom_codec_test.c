/* SPDX-License-Identifier: MIT */
#include "microfoam.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLASH_BASE 0x08010000u
#define FLASH_SIZE 4096u
#define PRODUCT_ID 0x1234u
#define OLD_VERSION 1u
#define NEW_VERSION 2u
#define CUSTOM_ID ((mcf_codec_id_t)0x80u)
#define OTHER_ID ((mcf_codec_id_t)0x81u)
#define WORKSPACE_SIZE 16u

/* The reconstructed image must be at least as large as one BSDIFF43 control
 * triple (24 bytes), because the session clamps its block size to new_size and
 * the engine buffers the triple in that block. A one-byte image would make the
 * triple unbufferable and fail every codec identically, which would prove
 * nothing about the codec under test. */
#define IMAGE_SIZE 32u

typedef struct test_codec {
    uint32_t mode;
    uint32_t consumed;
    uint32_t produced;
} test_codec_t;

enum {
    MODE_PASS = 0u,
    MODE_INIT_FAIL = 1u,
    MODE_DECODE_FAIL = 2u,
    MODE_FINISH_FAIL = 3u
};

static uint8_t g_flash[FLASH_SIZE];
static uint8_t g_old[IMAGE_SIZE];
static uint8_t g_new[IMAGE_SIZE];
static uint8_t g_delta[24u + IMAGE_SIZE];
static uint8_t g_patch[256];
static uint32_t g_codec_mode;
static uint32_t g_init_calls;
static uint32_t g_decode_calls;
static uint32_t g_finish_calls;
static uint32_t g_destroy_calls;
static uint32_t g_alloc_calls;
static uint32_t g_free_calls;
static uint32_t g_codec_ws;
static const uint8_t *g_seen_props;
static uint32_t g_seen_props_len;
static uint32_t g_checks;
static uint32_t g_failures;

#define CHECK(condition, label) do { \
    g_checks++; \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", (label), __FILE__, __LINE__); \
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

/* BSDIFF43 sign-magnitude offset. The magnitude is held in a 64-bit type so
 * that every shift below is defined: shifting a 32-bit value by 32 or more is
 * undefined behaviour, and on x86 the count wraps, stamping a copy of the low
 * byte into byte 4. That silently turns a valid control triple into a corrupt
 * one, which is why this helper was never exercised until a case drove the
 * engine past the codec. */
static void put_offset(uint8_t *p, int32_t value)
{
    uint64_t magnitude = (uint64_t)(value < 0 ? -value : value);
    uint32_t i;
    for (i = 0u; i < 8u; i++) {
        p[i] = (uint8_t)(magnitude >> (i * 8u));
    }
    if (value < 0) {
        p[7] = (uint8_t)(p[7] | 0x80u);
    }
}

static int32_t flash_erase(void *ctx, uint32_t addr, uint32_t len)
{
    uint32_t off;
    (void)ctx;
    if (addr < FLASH_BASE) return MCF_E_FLASH;
    off = addr - FLASH_BASE;
    if (off > FLASH_SIZE || len > FLASH_SIZE - off) return MCF_E_FLASH;
    memset(&g_flash[off], 0xFF, len);
    return MCF_OK;
}

static int32_t flash_write(void *ctx, uint32_t addr, const uint8_t *p, uint32_t len)
{
    uint32_t off;
    (void)ctx;
    if (addr < FLASH_BASE) return MCF_E_FLASH;
    off = addr - FLASH_BASE;
    if (off > FLASH_SIZE || len > FLASH_SIZE - off) return MCF_E_FLASH;
    memcpy(&g_flash[off], p, len);
    return MCF_OK;
}

static int32_t flash_read(void *ctx, uint32_t addr, uint8_t *p, uint32_t len)
{
    uint32_t off;
    (void)ctx;
    if (addr < FLASH_BASE) return MCF_E_IO;
    off = addr - FLASH_BASE;
    if (off > FLASH_SIZE || len > FLASH_SIZE - off) return MCF_E_IO;
    memcpy(p, &g_flash[off], len);
    return (int32_t)len;
}

static uint32_t flash_block_size(void *ctx) { (void)ctx; return 256u; }
static uint32_t product_id(void *ctx) { (void)ctx; return PRODUCT_ID; }
static uint32_t fw_version(void *ctx) { (void)ctx; return OLD_VERSION; }
static void *alloc_(void *ctx, uint32_t size)
{
    (void)ctx;
    g_alloc_calls++;
    return malloc(size);
}
static void free_(void *ctx, void *ptr)
{
    (void)ctx;
    g_free_calls++;
    free(ptr);
}

static const mcf_hal_t g_hal = {
    .flash_erase = flash_erase,
    .flash_write = flash_write,
    .flash_read = flash_read,
    .flash_block_size = flash_block_size,
    .alloc = alloc_,
    .free = free_,
    .get_product_id = product_id,
    .get_fw_version = fw_version
};

static uint32_t codec_workspace(const uint8_t *props, uint32_t props_len)
{
    g_seen_props = props;
    g_seen_props_len = props_len;
    return g_codec_ws;
}

static int32_t codec_init(mcf_codec_t **out, const uint8_t *props,
                          uint32_t props_len, uint8_t *workspace)
{
    test_codec_t *codec = (test_codec_t *)(void *)workspace;
    (void)props;
    (void)props_len;
    g_init_calls++;
    if (g_codec_mode == MODE_INIT_FAIL) return MCF_E_UNSUPPORTED;
    memset(codec, 0, sizeof(*codec));
    codec->mode = g_codec_mode;
    *out = (mcf_codec_t *)(void *)codec;
    return MCF_OK;
}

static int32_t codec_decode(mcf_codec_t *handle, uint8_t *out, uint32_t cap,
                            uint32_t *produced, const uint8_t *in,
                            uint32_t in_avail, uint32_t *consumed)
{
    test_codec_t *codec = (test_codec_t *)(void *)handle;
    g_decode_calls++;
    if (codec->mode == MODE_DECODE_FAIL) return MCF_E_IO;
    {
        uint32_t n = (in_avail < cap) ? in_avail : cap;
        memcpy(out, in, n);
        *produced = n;
        *consumed = n;
        codec->produced += n;
        codec->consumed += n;
    }
    return MCF_OK;
}

static int32_t codec_finish(mcf_codec_t *handle)
{
    test_codec_t *codec = (test_codec_t *)(void *)handle;
    g_finish_calls++;
    return (codec->mode == MODE_FINISH_FAIL) ? MCF_E_CORRUPT : MCF_OK;
}

static void codec_destroy(mcf_codec_t *handle)
{
    (void)handle;
    g_destroy_calls++;
}

static mcf_codec_ops_t codec_ops(const char *name, mcf_codec_id_t id)
{
    mcf_codec_ops_t ops;
    ops.name = name;
    ops.id = id;
    ops.workspace_size = codec_workspace;
    ops.init = codec_init;
    ops.decode = codec_decode;
    ops.finish = codec_finish;
    ops.destroy = codec_destroy;
    ops.ctx = NULL;
    return ops;
}

/* Build a patch declaring `codec_id`. `props_len` is the leading parameter
 * block that the codec id carries in the v1 container: 4 for LZ4 (the content
 * size), 9 for LZMA, 0 for RAW and for every custom id. The payload CRC covers
 * the stream *after* the props block, not the props block itself, which is why
 * the two are written separately here. */
static uint32_t build_patch_ex(uint8_t codec_id, uint32_t flags, uint32_t props_len)
{
    uint32_t i;
    uint32_t delta_len = (uint32_t)sizeof(g_delta);
    uint32_t payload_size = props_len + delta_len;
    memset(g_patch, 0, sizeof(g_patch));
    memset(g_delta, 0, sizeof(g_delta));
    memset(g_flash, 0xFF, sizeof(g_flash));
    memset(g_old, 0x11, sizeof(g_old));
    for (i = 0u; i < sizeof(g_new); i++) g_new[i] = (uint8_t)(g_old[i] + i + 1u);
    put_offset(&g_delta[0], (int32_t)sizeof(g_new));
    put_offset(&g_delta[8], 0);
    put_offset(&g_delta[16], 0);
    for (i = 0u; i < sizeof(g_new); i++) g_delta[24u + i] = (uint8_t)(i + 1u);

    wr32(&g_patch[MCF_OFF_MAGIC], MCF_HDR_MAGIC);
    wr16(&g_patch[MCF_OFF_HDR_LEN], (uint16_t)MCF_HDR_MIN_SIZE);
    wr16(&g_patch[MCF_OFF_HDR_VER], (uint16_t)((MCF_HDR_VER_MAJOR << 8) | MCF_HDR_VER_MINOR));
    wr32(&g_patch[MCF_OFF_FLAGS], flags);
    wr32(&g_patch[MCF_OFF_PRODUCT_ID], PRODUCT_ID);
    wr32(&g_patch[MCF_OFF_FW_VERSION], NEW_VERSION);
    wr32(&g_patch[MCF_OFF_OLD_SIZE], (uint32_t)sizeof(g_old));
    wr32(&g_patch[MCF_OFF_NEW_SIZE], (uint32_t)sizeof(g_new));
    wr32(&g_patch[MCF_OFF_PAYLOAD_SIZE], payload_size);
    wr32(&g_patch[MCF_OFF_OLD_CRC32], mcf_crc32(g_old, (uint32_t)sizeof(g_old)));
    wr32(&g_patch[MCF_OFF_NEW_CRC32], mcf_crc32(g_new, (uint32_t)sizeof(g_new)));
    wr32(&g_patch[MCF_OFF_PAYLOAD_CRC32], mcf_crc32(g_delta, delta_len));
    wr32(&g_patch[MCF_OFF_WORKSPACE_REQ], g_codec_ws);
    wr32(&g_patch[MCF_OFF_OLD_VERSION], OLD_VERSION);
    g_patch[MCF_OFF_CODEC_ID] = codec_id;
    g_patch[MCF_OFF_BLOCK_LOG2] = 8u;
    /* The props block is left zeroed; only its length is load-bearing here,
     * because the codec that would interpret it is the one under test. */
    memcpy(&g_patch[MCF_HDR_MIN_SIZE + props_len], g_delta, delta_len);
    return MCF_HDR_MIN_SIZE + payload_size;
}

static uint32_t build_patch(void)
{
    return build_patch_ex((uint8_t)CUSTOM_ID, 0u, 0u);
}

static mcf_status_t run_case(mcf_codec_ops_t *ops, uint32_t patch_size,
                             uint32_t ram_budget, mcf_session_t *session,
                             mcf_session_storage_t *storage, mcf_config_t *cfg)
{
    mcf_status_t status;
    memset(cfg, 0, sizeof(*cfg));
    cfg->hal = &g_hal;
    cfg->patch = g_patch;
    cfg->patch_size = patch_size;
    cfg->old = g_old;
    cfg->old_size = (uint32_t)sizeof(g_old);
    cfg->dst_addr = FLASH_BASE;
    cfg->codec = MCF_CODEC_AUTO;
    cfg->block_size = 32u;
    cfg->ram_budget = ram_budget;
    cfg->codecs = ops;
    cfg->codec_count = 1u;
    session = (mcf_session_t *)(void *)storage;
    status = mcf_session_open(session, cfg);
    if (status == MCF_OK) status = mcf_session_run(session);
    return status;
}

static void test_descriptor_validation(void)
{
    mcf_codec_ops_t ops = codec_ops("custom", CUSTOM_ID);
    mcf_codec_ops_t bad = ops;
    CHECK(mcf_codec_register(&ops) == MCF_OK, "valid descriptor accepted");
    bad.decode = NULL;
    CHECK(mcf_codec_register(&bad) == MCF_E_PARAM, "missing decode rejected");
    bad = ops;
    bad.id = MCF_CODEC_AUTO;
    CHECK(mcf_codec_register(&bad) == MCF_E_PARAM, "reserved codec id rejected");
    CHECK(mcf_codec_register(NULL) == MCF_E_PARAM, "null descriptor rejected");

    /* Every required member is required; a descriptor is a contract, and a
     * missing callback must be refused at registration rather than discovered
     * as a null call in the middle of an update. */
    bad = ops;
    bad.name = NULL;
    CHECK(mcf_codec_register(&bad) == MCF_E_PARAM, "missing name rejected");
    bad = ops;
    bad.workspace_size = NULL;
    CHECK(mcf_codec_register(&bad) == MCF_E_PARAM, "missing workspace_size rejected");
    bad = ops;
    bad.init = NULL;
    CHECK(mcf_codec_register(&bad) == MCF_E_PARAM, "missing init rejected");
    bad = ops;
    bad.finish = NULL;
    CHECK(mcf_codec_register(&bad) == MCF_E_PARAM, "missing finish rejected");
    bad = ops;
    bad.destroy = NULL;
    CHECK(mcf_codec_register(&bad) == MCF_E_PARAM, "missing destroy rejected");

    /* The reserved gap between the built-in range and the custom range. Both
     * edges are checked, because an off-by-one here would let a codec claim an
     * id that a future format revision assigns to a built-in. */
    bad = ops;
    bad.id = MCF_CODEC_MAX;
    CHECK(mcf_codec_register(&bad) == MCF_E_PARAM, "id at MCF_CODEC_MAX rejected");
    bad = ops;
    bad.id = (mcf_codec_id_t)0x40u;
    CHECK(mcf_codec_register(&bad) == MCF_E_PARAM, "id inside the reserved gap rejected");
    bad = ops;
    bad.id = MCF_CODEC_CUSTOM_MIN;
    CHECK(mcf_codec_register(&bad) == MCF_OK, "id at MCF_CODEC_CUSTOM_MIN accepted");
}

static void test_failures(void)
{
    const uint32_t modes[] = { MODE_INIT_FAIL, MODE_DECODE_FAIL, MODE_FINISH_FAIL };
    const mcf_status_t expected[] = { MCF_E_UNSUPPORTED, MCF_E_IO, MCF_E_CORRUPT };
    const uint32_t expected_site[] = { 16u, 17u, 18u };
    uint32_t i;
    uint32_t patch_size;

    for (i = 0u; i < 3u; i++) {
        mcf_codec_ops_t ops = codec_ops("custom-failure", CUSTOM_ID);
        mcf_session_storage_t storage;
        mcf_session_t *session = (mcf_session_t *)(void *)&storage;
        mcf_config_t cfg;
        mcf_status_t status;
        uint32_t destroyed_before = g_destroy_calls;
        uint32_t freed_before = g_free_calls;
        g_codec_mode = modes[i];
        g_codec_ws = WORKSPACE_SIZE;
        patch_size = build_patch();
        status = run_case(&ops, patch_size, 1024u, session, &storage, &cfg);
        CHECK(status == expected[i], "provider status propagates without remapping");
        CHECK(mcf_session_state(session) == MCF_ST_FAILED, "provider failure marks session failed");
        CHECK(mcf_session_error_site(session) == expected_site[i], "provider stage is recorded");
        /* Exactly one release: the failure funnel frees the workspace, and the
         * close that follows must not free it a second time. `>=` here would be
         * an assertion that cannot fail - the counter only ever grows - which is
         * the "counter that can never move" defect this suite exists to avoid. */
        CHECK(g_free_calls == freed_before + 1u, "workspace is released exactly once on provider failure");
        if (modes[i] != MODE_INIT_FAIL) {
            CHECK(g_destroy_calls == destroyed_before + 1u, "initialized codec is destroyed on failure");
        } else {
            CHECK(g_destroy_calls == destroyed_before, "failed init without handle is not destroyed");
        }
        mcf_session_close(session);
    }
}

static void test_workspace_limit(void)
{
    mcf_codec_ops_t ops = codec_ops("custom-budget", CUSTOM_ID);
    mcf_session_storage_t storage;
    mcf_session_t *session = (mcf_session_t *)(void *)&storage;
    mcf_config_t cfg;
    uint32_t patch_size;
    uint32_t init_before = g_init_calls;
    uint32_t alloc_before = g_alloc_calls;
    g_codec_mode = MODE_PASS;
    g_codec_ws = 64u;
    patch_size = build_patch();
    CHECK(run_case(&ops, patch_size, 95u, session, &storage, &cfg) == MCF_E_DICT_TOO_LARGE,
          "actual codec workspace cannot exceed configured budget");
    CHECK(g_init_calls == init_before, "codec init is skipped after budget rejection");
    CHECK(g_alloc_calls == alloc_before, "allocation is skipped after budget rejection");
    CHECK(mcf_session_error_site(session) == 14u, "workspace rejection has workspace diagnostic");
    mcf_session_close(session);
}

static void test_success_path(void)
{
    mcf_codec_ops_t ops = codec_ops("custom-pass", CUSTOM_ID);
    mcf_session_storage_t storage;
    mcf_session_t *session = (mcf_session_t *)(void *)&storage;
    mcf_config_t cfg;
    uint32_t patch_size;
    uint32_t init_before = g_init_calls;
    uint32_t finish_before = g_finish_calls;
    uint32_t destroy_before = g_destroy_calls;

    /* The one case that runs a custom codec to completion. Without it the suite
     * would only ever observe custom codecs failing, and a codec that fails
     * everywhere would pass. The pass-through codec yields the delta verbatim,
     * so the reconstructed image must equal the one the patch declares. */
    g_codec_mode = MODE_PASS;
    g_codec_ws = WORKSPACE_SIZE;
    g_seen_props = NULL;
    g_seen_props_len = 99u; /* deliberately wrong, to prove it is overwritten */
    patch_size = build_patch();

    CHECK(run_case(&ops, patch_size, 1024u, session, &storage, &cfg) == MCF_OK,
          "custom codec completes a full update");
    CHECK(mcf_session_state(session) == MCF_ST_DONE, "completed session reports done");
    CHECK(g_init_calls == init_before + 1u, "codec was initialized");
    CHECK(g_finish_calls == finish_before + 1u, "codec finish was called");
    CHECK(memcmp(g_flash, g_new, sizeof(g_new)) == 0,
          "reconstructed image matches the declared new image");

    /* The v1 container carries no parameter block for a custom id, so the codec
     * is told it has none. This is a wire-format constraint rather than an
     * omission: pinning it here stops a future props change from silently
     * reaching a codec written to ignore the argument. */
    CHECK(g_seen_props_len == 0u, "custom codec is handed no properties block");
    CHECK(g_seen_props != NULL, "custom codec is still handed a payload pointer");

    /* The codec outlives the run: destroy is the close path's job, so it must
     * not have happened yet, and must happen exactly once afterwards. */
    CHECK(g_destroy_calls == destroy_before, "codec is not destroyed before close");
    mcf_session_close(session);
    CHECK(g_destroy_calls == destroy_before + 1u, "codec is destroyed exactly once on close");
}

static void test_session_isolation(void)
{
    mcf_codec_ops_t ops_a = codec_ops("custom-a", CUSTOM_ID);
    mcf_codec_ops_t ops_b = codec_ops("custom-b", OTHER_ID);
    mcf_session_storage_t storage;
    mcf_session_t *session = (mcf_session_t *)(void *)&storage;
    mcf_config_t cfg;
    uint32_t patch_size;

    g_codec_mode = MODE_INIT_FAIL; /* reach the codec, then stop recognisably */
    g_codec_ws = WORKSPACE_SIZE;
    patch_size = build_patch(); /* declares CUSTOM_ID (0x80) */

    /* The patch's codec is listed in this table, so the session resolves it and
     * reaches codec init, where the injected failure is reported (site 16). */
    CHECK(run_case(&ops_a, patch_size, 1024u, session, &storage, &cfg) == MCF_E_UNSUPPORTED,
          "owning table resolves the codec");
    CHECK(mcf_session_error_site(session) == 16u, "owning table reaches codec init");
    mcf_session_close(session);

    /* The same patch against a table that lists a different id must be refused
     * during header validation (site 9): a codec table is per session, and one
     * session's registrations must not be visible to another. */
    CHECK(run_case(&ops_b, patch_size, 1024u, session, &storage, &cfg) == MCF_E_UNSUPPORTED,
          "foreign table does not resolve the codec");
    CHECK(mcf_session_error_site(session) == 9u, "foreign table fails at the header codec check");
    mcf_session_close(session);
}

static void test_builtin_shadowing(void)
{
    mcf_codec_ops_t shadow = codec_ops("lz4-shadow", MCF_CODEC_LZ4);
    mcf_session_storage_t storage;
    mcf_session_t *session = (mcf_session_t *)(void *)&storage;
    mcf_config_t cfg;
    uint32_t patch_size;

    /* A caller-owned descriptor may carry a built-in id, and the session table
     * is consulted before the built-ins. The patch below declares LZ4, so if
     * the built-in were chosen instead the session would proceed past init and
     * fail later with a different status and site. Reaching the injected init
     * failure (MCF_E_UNSUPPORTED, site 16) proves the table entry won. */
    g_codec_mode = MODE_INIT_FAIL;
    g_codec_ws = WORKSPACE_SIZE;
    patch_size = build_patch_ex((uint8_t)MCF_CODEC_LZ4, MCF_FLAG_CODEC_LZ4, 4u);

    CHECK(run_case(&shadow, patch_size, 1024u, session, &storage, &cfg) == MCF_E_UNSUPPORTED,
          "table entry shadows the built-in of the same id");
    CHECK(mcf_session_error_site(session) == 16u, "shadowing codec reaches its own init");
    mcf_session_close(session);
}

int main(void)
{
    g_codec_ws = WORKSPACE_SIZE;
    test_descriptor_validation();
    test_failures();
    test_workspace_limit();
    test_success_path();
    test_session_isolation();
    test_builtin_shadowing();
    printf("custom codec contract: %u checks, %u failures\n", g_checks, g_failures);
    return (g_failures == 0u) ? EXIT_SUCCESS : EXIT_FAILURE;
}
