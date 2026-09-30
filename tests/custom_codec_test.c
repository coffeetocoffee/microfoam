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
#define WORKSPACE_SIZE 16u

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
static uint8_t g_old[32];
static uint8_t g_new[32];
static uint8_t g_delta[56];
static uint8_t g_patch[256];
static uint32_t g_codec_mode;
static uint32_t g_init_calls;
static uint32_t g_decode_calls;
static uint32_t g_finish_calls;
static uint32_t g_destroy_calls;
static uint32_t g_alloc_calls;
static uint32_t g_free_calls;
static uint32_t g_codec_ws;
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

static void put_offset(uint8_t *p, int32_t value)
{
    uint32_t magnitude = (uint32_t)(value < 0 ? -value : value);
    uint32_t i;
    for (i = 0u; i < 8u; i++) {
        p[i] = (uint8_t)(magnitude >> (i * 8u));
    }
    if (value < 0) {
        p[7] |= 0x80u;
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
    (void)props;
    (void)props_len;
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

static mcf_codec_ops_t codec_ops(const char *name)
{
    mcf_codec_ops_t ops;
    ops.name = name;
    ops.id = CUSTOM_ID;
    ops.workspace_size = codec_workspace;
    ops.init = codec_init;
    ops.decode = codec_decode;
    ops.finish = codec_finish;
    ops.destroy = codec_destroy;
    ops.ctx = NULL;
    return ops;
}

static uint32_t build_patch(void)
{
    uint32_t i;
    uint32_t len = (uint32_t)sizeof(g_delta);
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
    wr32(&g_patch[MCF_OFF_PRODUCT_ID], PRODUCT_ID);
    wr32(&g_patch[MCF_OFF_FW_VERSION], NEW_VERSION);
    wr32(&g_patch[MCF_OFF_OLD_SIZE], (uint32_t)sizeof(g_old));
    wr32(&g_patch[MCF_OFF_NEW_SIZE], (uint32_t)sizeof(g_new));
    wr32(&g_patch[MCF_OFF_PAYLOAD_SIZE], len);
    wr32(&g_patch[MCF_OFF_OLD_CRC32], mcf_crc32(g_old, (uint32_t)sizeof(g_old)));
    wr32(&g_patch[MCF_OFF_NEW_CRC32], mcf_crc32(g_new, (uint32_t)sizeof(g_new)));
    wr32(&g_patch[MCF_OFF_PAYLOAD_CRC32], mcf_crc32(g_delta, len));
    wr32(&g_patch[MCF_OFF_WORKSPACE_REQ], g_codec_ws);
    wr32(&g_patch[MCF_OFF_OLD_VERSION], OLD_VERSION);
    g_patch[MCF_OFF_CODEC_ID] = (uint8_t)CUSTOM_ID;
    g_patch[MCF_OFF_BLOCK_LOG2] = 8u;
    memcpy(&g_patch[MCF_HDR_MIN_SIZE], g_delta, len);
    return MCF_HDR_MIN_SIZE + len;
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
    cfg->block_size = 64u;
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
    mcf_codec_ops_t ops = codec_ops("custom");
    mcf_codec_ops_t bad = ops;
    CHECK(mcf_codec_register(&ops) == MCF_OK, "valid descriptor accepted");
    bad.decode = NULL;
    CHECK(mcf_codec_register(&bad) == MCF_E_PARAM, "missing decode rejected");
    bad = ops;
    bad.id = MCF_CODEC_AUTO;
    CHECK(mcf_codec_register(&bad) == MCF_E_PARAM, "reserved codec id rejected");
    CHECK(mcf_codec_register(NULL) == MCF_E_PARAM, "null descriptor rejected");
}

static void test_custom_success(void)
{
    uint32_t patch_size;
    mcf_codec_ops_t ops_a = codec_ops("custom-a");
    mcf_codec_ops_t ops_b = codec_ops("custom-b");
    mcf_session_storage_t storage_a, storage_b;
    mcf_config_t cfg_a, cfg_b;
    mcf_session_t *session_a = (mcf_session_t *)(void *)&storage_a;
    mcf_session_t *session_b = (mcf_session_t *)(void *)&storage_b;
    mcf_status_t status;

    g_codec_mode = MODE_PASS;
    g_codec_ws = WORKSPACE_SIZE;
    patch_size = build_patch();
    memset(&cfg_a, 0, sizeof(cfg_a));
    cfg_a.hal = &g_hal; cfg_a.patch = g_patch; cfg_a.patch_size = patch_size;
    cfg_a.old = g_old; cfg_a.old_size = sizeof(g_old); cfg_a.dst_addr = FLASH_BASE;
    cfg_a.block_size = 64u; cfg_a.ram_budget = 1024u; cfg_a.codecs = &ops_a; cfg_a.codec_count = 1u;
    memset(&cfg_b, 0, sizeof(cfg_b));
    cfg_b.hal = &g_hal; cfg_b.patch = g_patch; cfg_b.patch_size = patch_size;
    cfg_b.old = g_old; cfg_b.old_size = sizeof(g_old); cfg_b.dst_addr = FLASH_BASE + 256u;
    cfg_b.block_size = 64u; cfg_b.ram_budget = 1024u; cfg_b.codecs = &ops_b; cfg_b.codec_count = 1u;

    CHECK(mcf_session_open(session_a, &cfg_a) == MCF_OK, "open first custom-codec session");
    CHECK(mcf_session_open(session_b, &cfg_b) == MCF_OK, "open second custom-codec session");
    status = mcf_session_run(session_a);
    fprintf(stderr, "first status=%d site=%u init=%u decode=%u finish=%u\n", (int)status,
            (unsigned)mcf_session_error_site(session_a), (unsigned)g_init_calls,
            (unsigned)g_decode_calls, (unsigned)g_finish_calls);
    CHECK(status == MCF_OK, "first custom codec session runs");
    CHECK(mcf_session_state(session_a) == MCF_ST_DONE, "first session completes");
    CHECK(memcmp(g_flash, g_new, sizeof(g_new)) == 0, "first custom codec output matches");
    CHECK(g_decode_calls > 0u, "custom decode callback was invoked");
    CHECK(g_init_calls > 0u, "custom init callback was invoked");

    status = mcf_session_run(session_b);
    CHECK(status == MCF_OK, "second session resolves its caller-owned descriptor");
    CHECK(mcf_session_state(session_b) == MCF_ST_DONE, "second session completes independently");
    CHECK(memcmp(&g_flash[256], g_new, sizeof(g_new)) == 0,
          "second custom codec output matches");
    mcf_session_close(session_a);
    mcf_session_close(session_b);
}

static void test_failures(void)
{
    const uint32_t modes[] = { MODE_INIT_FAIL, MODE_DECODE_FAIL, MODE_FINISH_FAIL };
    const mcf_status_t expected[] = { MCF_E_UNSUPPORTED, MCF_E_IO, MCF_E_CORRUPT };
    const uint32_t expected_site[] = { 16u, 17u, 18u };
    uint32_t i;
    uint32_t patch_size;

    for (i = 0u; i < 3u; i++) {
        mcf_codec_ops_t ops = codec_ops("custom-failure");
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
        if (status != expected[i]) {
            fprintf(stderr, "mode %u: got %d at site %u, want %d\n",
                    modes[i], (int)status, (unsigned)mcf_session_error_site(session),
                    (int)expected[i]);
        }
        CHECK(status == expected[i], "provider status propagates without remapping");
        CHECK(mcf_session_state(session) == MCF_ST_FAILED, "provider failure marks session failed");
        CHECK(mcf_session_error_site(session) == expected_site[i], "provider stage is recorded");
        CHECK(g_free_calls >= freed_before, "workspace cleanup is observable after provider failure");
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
    mcf_codec_ops_t ops = codec_ops("custom-budget");
    mcf_session_storage_t storage;
    mcf_session_t *session = (mcf_session_t *)(void *)&storage;
    mcf_config_t cfg;
    uint32_t patch_size;
    uint32_t init_before = g_init_calls;
    uint32_t alloc_before = g_alloc_calls;
    g_codec_mode = MODE_PASS;
    g_codec_ws = 64u;
    patch_size = build_patch();
    CHECK(run_case(&ops, patch_size, 160u, session, &storage, &cfg) == MCF_E_DICT_TOO_LARGE,
          "actual codec workspace cannot exceed configured budget");
    CHECK(g_init_calls == init_before, "codec init is skipped after budget rejection");
    CHECK(g_alloc_calls == alloc_before, "allocation is skipped after budget rejection");
    CHECK(mcf_session_error_site(session) == 14u, "workspace rejection has workspace diagnostic");
    mcf_session_close(session);
}

int main(void)
{
    g_codec_ws = WORKSPACE_SIZE;
    test_descriptor_validation();
    test_custom_success();
    test_failures();
    test_workspace_limit();
    printf("custom codec contract: %u checks, %u failures\n", g_checks, g_failures);
    return (g_failures == 0u) ? EXIT_SUCCESS : EXIT_FAILURE;
}
