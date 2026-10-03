/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - cross-implementation test.
 *
 * The host tool produces a patch; this applies it with the C library and checks
 * the result against the target image. Agreement between two independently
 * written implementations is evidence. A library tested only against its own
 * encoder is not.
 *
 * Usage: cross_test <old.bin> <new.bin> <patch.bin> [block_size] [ram_budget]
 *
 * block_size and ram_budget are optional and default to the values this test
 * has always used. They are arguments so that a documentation guard can drive
 * the same apply path with the exact configuration a README example shows, and
 * assert that the example actually works rather than assuming it does.
 */

#include "microfoam.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLASH_SIZE  262144u
#define FLASH_BASE  0x08010000u
#define FLASH_BLOCK 4096u
#define MAX_IMG     131072u

static uint8_t g_flash[FLASH_SIZE];
static uint8_t *g_old;
static uint8_t *g_new;
static uint8_t *g_patch;
static uint32_t g_old_len, g_new_len, g_patch_len;

static int32_t h_erase(void *c, uint32_t addr, uint32_t len)
{
    uint32_t off;
    (void)c;
    if ((addr % FLASH_BLOCK) || (len % FLASH_BLOCK)) {
        printf("  CONTRACT: erase addr=0x%X len=%u not block aligned\n", addr, len);
        return MCF_E_FLASH;
    }
    off = addr - FLASH_BASE;
    if (off + len > FLASH_SIZE) { return MCF_E_FLASH; }
    memset(&g_flash[off], 0xFF, len);
    return 0;
}

static int32_t h_write(void *c, uint32_t addr, const uint8_t *p, uint32_t len)
{
    uint32_t off;
    (void)c;
    off = addr - FLASH_BASE;
    if (((off % FLASH_BLOCK) + len) > FLASH_BLOCK) {
        printf("  CONTRACT: write crosses an erase block at 0x%X len=%u\n", addr, len);
        return MCF_E_FLASH;
    }
    if (off + len > FLASH_SIZE) { return MCF_E_FLASH; }
    memcpy(&g_flash[off], p, len);
    return MCF_OK;
}

static int32_t h_read(void *c, uint32_t addr, uint8_t *p, uint32_t len)
{
    uint32_t off;
    (void)c;
    off = addr - FLASH_BASE;
    if (off + len > FLASH_SIZE) { return MCF_E_IO; }
    memcpy(p, &g_flash[off], len);
    return (int32_t)len;
}

static uint32_t h_blk(void *c) { (void)c; return FLASH_BLOCK; }
static uint32_t h_product(void *c) { (void)c; return 0x1234u; }
static uint32_t h_version(void *c) { (void)c; return 0x00010000u; }
static void *h_alloc(void *c, uint32_t n) { (void)c; return malloc(n); }
static void h_free(void *c, void *p) { (void)c; free(p); }

static const mcf_hal_t g_hal = {
    h_erase, h_write, h_read, h_blk, NULL, h_alloc, h_free,
    h_product, h_version, NULL, NULL, NULL
};

static uint8_t *slurp(const char *path, uint32_t *len)
{
    FILE  *f = fopen(path, "rb");
    uint8_t *b;
    long   n;

    if (f == NULL) { return NULL; }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    b = (uint8_t *)malloc((size_t)n + 1u);
    if (b == NULL || fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); fclose(f); return NULL; }
    fclose(f);
    *len = (uint32_t)n;
    return b;
}

int main(int argc, char **argv)
{
    mcf_session_storage_t storage;
    mcf_session_t *s = (mcf_session_t *)(void *)&storage;
    mcf_config_t   cfg;
    mcf_status_t   st;
    int            ok = 1;
    uint32_t       cfg_block_size = 1024u;
    uint32_t       cfg_ram_budget = 65536u;

    if (argc != 4 && argc != 5 && argc != 6) {
        printf("usage: cross_test <old.bin> <new.bin> <patch.bin> "
               "[block_size] [ram_budget]\n");
        return 2;
    }
    if (argc >= 5) {
        cfg_block_size = (uint32_t)strtoul(argv[4], NULL, 0);
    }
    if (argc >= 6) {
        cfg_ram_budget = (uint32_t)strtoul(argv[5], NULL, 0);
    }

    g_old   = slurp(argv[1], &g_old_len);
    g_new   = slurp(argv[2], &g_new_len);
    g_patch = slurp(argv[3], &g_patch_len);
    if (g_old == NULL || g_new == NULL || g_patch == NULL) {
        printf("could not read inputs\n");
        return 2;
    }
    if (g_old_len > MAX_IMG || g_new_len > MAX_IMG || g_patch_len > MAX_IMG) {
        printf("input too large for this test harness\n");
        return 2;
    }

    printf("cross test: old=%u new=%u patch=%u (%.1f%% of new) "
           "block_size=%u ram_budget=%u\n",
           g_old_len, g_new_len, g_patch_len,
           (double)g_patch_len / (double)g_new_len * 100.0,
           cfg_block_size, cfg_ram_budget);

    memset(&cfg, 0, sizeof(cfg));
    cfg.hal        = &g_hal;
    cfg.patch      = g_patch;
    cfg.patch_size = g_patch_len;
    cfg.old        = g_old;
    cfg.old_size   = g_old_len;
    cfg.dst_addr   = FLASH_BASE;
    cfg.codec      = MCF_CODEC_AUTO;
    cfg.block_size = cfg_block_size;
    /* Host test: RAM is free by default. Must cover LZMA's probability table
     * (~16 KB at lc=3) + dictionary (16 KB default) + the two block buffers. */
    cfg.ram_budget = cfg_ram_budget;

    st = mcf_session_open(s, &cfg);
    if (st == MCF_OK) { st = mcf_session_run(s); }

    if (st != MCF_OK) {
        printf("FAIL: %s at site %u\n", mcf_session_strerror(st),
               mcf_session_error_site(s));
        ok = 0;
    } else if (mcf_session_state(s) != MCF_ST_DONE) {
        printf("FAIL: state is %d, expected DONE\n", (int)mcf_session_state(s));
        ok = 0;
    } else if (memcmp(g_flash, g_new, g_new_len) != 0) {
        uint32_t i;
        for (i = 0; i < g_new_len; i++) {
            if (g_flash[i] != g_new[i]) { break; }
        }
        printf("FAIL: image differs at offset %u (got 0x%02X want 0x%02X)\n",
               i, g_flash[i], g_new[i]);
        ok = 0;
    } else {
        printf("PASS: host tool and C library agree; %u bytes reconstructed, "
               "crc32 0x%08X\n", g_new_len, mcf_crc32(g_flash, g_new_len));
    }

    mcf_session_close(s);
    free(g_old);
    free(g_new);
    free(g_patch);
    return ok ? 0 : 1;
}
