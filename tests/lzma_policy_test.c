/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - LZMA parameter policy test.
 *
 * The properties block declares the decoder's context parameters and dictionary
 * size. A product configures a policy (mcf_config_t.lzma_max_dict and
 * lzma_max_lc_plus_lp) and the library must refuse a patch outside it during
 * header validation, with a specific code and stage, before anything is
 * allocated. This is what turns "the decoder needed more RAM than we have" from
 * an unreportable field failure into a named rejection.
 *
 * The patches here are deliberately not decodable: every case is rejected by
 * the header policy, so the codec is never initialized.
 */

#include "microfoam.h"
#include "mcf_lzma.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLASH_BASE 0x08010000u
#define FLASH_SIZE 8192u
#define PRODUCT_ID 0x1234u
#define OLD_VERSION 1u
#define NEW_VERSION 2u
#define OLD_LEN 32u
#define NEW_LEN 32u

/* Sites, mirrored from src/mcf_internal.h. The test asserts the *stage*, so a
 * rename in the header without updating this test is a build-visible change. */
#define SITE_HDR_LZMA_PROPS 33u
#define SITE_WORKSPACE 14u

static uint8_t g_flash[FLASH_SIZE];
static uint8_t g_old[OLD_LEN];
static uint8_t g_new[NEW_LEN];
static uint8_t g_patch[512];

static uint32_t g_checks;
static uint32_t g_failures;

#define CHECK(condition, label) do { \
    g_checks++; \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", (label), __FILE__, __LINE__); \
        g_failures++; \
    } \
} while (0)

static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
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

static uint32_t block_size(void *ctx) { (void)ctx; return 256u; }
static uint32_t product_id(void *ctx) { (void)ctx; return PRODUCT_ID; }
static uint32_t fw_version(void *ctx) { (void)ctx; return OLD_VERSION; }
static void *alloc_(void *ctx, uint32_t n) { (void)ctx; return malloc(n); }
static void free_(void *ctx, void *p) { (void)ctx; free(p); }

static const mcf_hal_t g_hal = {
    flash_erase, flash_write, flash_read, block_size, NULL,
    alloc_, free_, product_id, fw_version, NULL, NULL, NULL
};

/* Build a minimal LZMA patch: 9-byte properties plus a short non-empty stream.
 * `lc`/`lp`/`pb`/`dict_size` are what the policy check reads. */
static uint32_t build_lzma_patch(uint32_t encoded_props, uint32_t dict_size,
                                 uint32_t stream_len)
{
    uint32_t payload_len = MCF_LZMA_PROPS_LEN + stream_len;
    uint32_t i;

    memset(g_patch, 0, sizeof(g_patch));
    memset(g_flash, 0xFF, sizeof(g_flash));

    wr32(&g_patch[MCF_OFF_MAGIC], MCF_HDR_MAGIC);
    wr16(&g_patch[MCF_OFF_HDR_LEN], (uint16_t)MCF_HDR_MIN_SIZE);
    wr16(&g_patch[MCF_OFF_HDR_VER],
         (uint16_t)((MCF_HDR_VER_MAJOR << 8) | MCF_HDR_VER_MINOR));
    wr32(&g_patch[MCF_OFF_FLAGS], MCF_FLAG_CODEC_LZMA);
    wr32(&g_patch[MCF_OFF_PRODUCT_ID], PRODUCT_ID);
    wr32(&g_patch[MCF_OFF_FW_VERSION], NEW_VERSION);
    wr32(&g_patch[MCF_OFF_OLD_SIZE], OLD_LEN);
    wr32(&g_patch[MCF_OFF_NEW_SIZE], NEW_LEN);
    wr32(&g_patch[MCF_OFF_PAYLOAD_SIZE], payload_len);
    wr32(&g_patch[MCF_OFF_OLD_CRC32], mcf_crc32(g_old, OLD_LEN));
    wr32(&g_patch[MCF_OFF_NEW_CRC32], mcf_crc32(g_new, NEW_LEN));
    wr32(&g_patch[MCF_OFF_WORKSPACE_REQ], 16u * 1024u);
    wr32(&g_patch[MCF_OFF_OLD_VERSION], OLD_VERSION);
    g_patch[MCF_OFF_CODEC_ID] = (uint8_t)MCF_CODEC_LZMA;
    g_patch[MCF_OFF_BLOCK_LOG2] = 8u;

    /* Properties: encoded byte, dictionary, content size. */
    g_patch[MCF_HDR_MIN_SIZE] = (uint8_t)encoded_props;
    wr32(&g_patch[MCF_HDR_MIN_SIZE + 1u], dict_size);
    wr32(&g_patch[MCF_HDR_MIN_SIZE + 5u], 8u); /* declared delta length */

    for (i = 0u; i < stream_len; i++) {
        g_patch[MCF_HDR_MIN_SIZE + MCF_LZMA_PROPS_LEN + i] = (uint8_t)(0x10u + i);
    }
    wr32(&g_patch[MCF_OFF_PAYLOAD_CRC32],
         mcf_crc32(&g_patch[MCF_HDR_MIN_SIZE + MCF_LZMA_PROPS_LEN], stream_len));

    return MCF_HDR_MIN_SIZE + payload_len;
}

/* Run the patch held in g_patch and report status + site. */
static mcf_status_t run(const mcf_config_t *cfg_in, uint32_t *site_out)
{
    static mcf_session_storage_t storage;
    mcf_session_t *s = (mcf_session_t *)(void *)&storage;
    mcf_status_t   st;

    st = mcf_session_open(s, cfg_in);
    if (st == MCF_OK) {
        st = mcf_session_run(s);
    }
    if (site_out != NULL) {
        *site_out = mcf_session_error_site(s);
    }
    mcf_session_close(s);
    return st;
}

static mcf_config_t base_cfg(void)
{
    mcf_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.hal        = &g_hal;
    cfg.patch      = g_patch;
    cfg.old        = g_old;
    cfg.old_size   = OLD_LEN;
    cfg.dst_addr   = FLASH_BASE;
    cfg.codec      = MCF_CODEC_AUTO;
    cfg.block_size = 64u;
    cfg.ram_budget = 65536u;
    return cfg;
}

int main(void)
{
    uint32_t i;
    uint32_t site;
    mcf_config_t cfg;
    mcf_status_t st;

    for (i = 0u; i < OLD_LEN; i++) { g_old[i] = (uint8_t)(i * 3u + 1u); }
    for (i = 0u; i < NEW_LEN; i++) { g_new[i] = (uint8_t)(i * 5u + 7u); }

    /* lc=3 lp=0 pb=2 is the host tool's default: 3 + 0*9 + 2*45 = 93. */
    const uint32_t default_props = 3u + (2u * 45u);

    /* 1. No policy configured: the patch is accepted as far as the codec, which
     *    then fails on the junk stream. The point is that the header itself is
     *    not rejected - the policy is what changes the outcome, not the file. */
    cfg = base_cfg();
    cfg.patch_size = build_lzma_patch(default_props, 16384u, 24u);
    st = run(&cfg, &site);
    CHECK(st != MCF_OK, "an undecodable LZMA stream still fails somewhere");
    CHECK(site != SITE_HDR_LZMA_PROPS,
          "with no policy, the properties check does not reject");

    /* 2. Dictionary over the configured cap. */
    cfg = base_cfg();
    cfg.lzma_max_dict = 8192u;
    cfg.patch_size = build_lzma_patch(default_props, 32768u, 24u);
    st = run(&cfg, &site);
    CHECK(st == MCF_E_DICT_TOO_LARGE, "over-cap dictionary is refused");
    CHECK(site == SITE_WORKSPACE, "over-cap dictionary reports the workspace stage");

    /* 3. Dictionary at the cap is accepted by the policy. */
    cfg = base_cfg();
    cfg.lzma_max_dict = 16384u;
    cfg.patch_size = build_lzma_patch(default_props, 16384u, 24u);
    st = run(&cfg, &site);
    CHECK(site != SITE_WORKSPACE || st != MCF_E_DICT_TOO_LARGE,
          "dictionary exactly at the cap passes the policy");

    /* 4. Illegal encoded properties byte (>= 9*5*5). */
    cfg = base_cfg();
    cfg.patch_size = build_lzma_patch(9u * 5u * 5u, 16384u, 24u);
    st = run(&cfg, &site);
    CHECK(st == MCF_E_FORMAT, "out-of-range properties byte is refused");
    CHECK(site == SITE_HDR_LZMA_PROPS, "properties rejection has its own stage");

    /* 5. lc+lp over the configured cap. lc=4 lp=4 -> encoded 4 + 4*9 + 0*45. */
    cfg = base_cfg();
    cfg.lzma_max_lc_plus_lp = 4u;
    cfg.patch_size = build_lzma_patch(4u + (4u * 9u), 8192u, 24u);
    st = run(&cfg, &site);
    CHECK(st == MCF_E_FORMAT, "lc+lp over the cap is refused");
    CHECK(site == SITE_HDR_LZMA_PROPS, "lc+lp rejection has its own stage");

    /* 6. lc+lp within the cap passes the policy at the same dictionary. */
    cfg = base_cfg();
    cfg.lzma_max_lc_plus_lp = 4u;
    cfg.patch_size = build_lzma_patch(3u + (1u * 9u), 8192u, 24u);
    st = run(&cfg, &site);
    CHECK(site != SITE_HDR_LZMA_PROPS, "lc+lp at the cap passes the policy");

    /* 7. The decoded parameters are readable for field diagnostics. */
    {
        static mcf_session_storage_t storage;
        mcf_session_t *s = (mcf_session_t *)(void *)&storage;
        mcf_lzma_info_t info;

        cfg = base_cfg();
        cfg.patch_size = build_lzma_patch(default_props, 32768u, 24u);
        CHECK(mcf_session_open(s, &cfg) == MCF_OK, "open for the diagnostics query");
        (void)mcf_session_begin(s); /* expected to fail on the junk stream */
        CHECK(mcf_session_lzma_info(s, &info) == MCF_OK, "lzma info is available");
        CHECK(info.valid == 1u, "info is marked valid for an LZMA patch");
        CHECK(info.lc == 3u && info.pb == 2u, "info reports the decoded parameters");
        CHECK(info.dict_size == 32768u, "info reports the declared dictionary");
        mcf_session_close(s);
    }

    printf("lzma policy: %u checks, %u failures\n", g_checks, g_failures);
    return (g_failures == 0u) ? EXIT_SUCCESS : EXIT_FAILURE;
}
