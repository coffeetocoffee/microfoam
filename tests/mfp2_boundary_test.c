/* SPDX-License-Identifier: MIT */
/* MFP2 producer-to-parser boundary test; execution remains intentionally absent. */
#include "microfoam.h"
#include "microfoam_v2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLASH_SIZE 4096u
#define FLASH_BASE 0x08010000u
static uint8_t flash[FLASH_SIZE];
static unsigned mutations;

static int32_t erase_flash(void *ctx, uint32_t addr, uint32_t len)
{
    (void)ctx;
    (void)addr;
    (void)len;
    mutations++;
    return MCF_OK;
}
static int32_t write_flash(void *ctx, uint32_t addr, const uint8_t *p, uint32_t len)
{
    (void)ctx;
    (void)addr;
    (void)p;
    (void)len;
    mutations++;
    return MCF_OK;
}
static int32_t read_flash(void *ctx, uint32_t addr, uint8_t *p, uint32_t len)
{
    (void)ctx;
    (void)addr;
    (void)p;
    return (int32_t)len;
}
static uint32_t block_size(void *ctx) { (void)ctx; return 1024u; }
static uint32_t product(void *ctx) { (void)ctx; return 0x1234u; }
static uint32_t version(void *ctx) { (void)ctx; return 0x00010000u; }
static void *alloc_ram(void *ctx, uint32_t n) { (void)ctx; return malloc(n); }
static void free_ram(void *ctx, void *p) { (void)ctx; free(p); }

static const mcf_hal_t hal = {
    erase_flash, write_flash, read_flash, block_size, NULL,
    alloc_ram, free_ram, product, version, NULL, NULL, NULL
};

static uint8_t *read_file(const char *path, uint32_t *size)
{
    FILE *f = fopen(path, "rb");
    long n;
    uint8_t *p;
    if (f == NULL) return NULL;
    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET) != 0 || (unsigned long)n > UINT32_MAX) {
        fclose(f);
        return NULL;
    }
    p = (uint8_t *)malloc((size_t)n);
    if (p == NULL || fread(p, 1u, (size_t)n, f) != (size_t)n) {
        free(p);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *size = (uint32_t)n;
    return p;
}

int main(int argc, char **argv)
{
    uint32_t len;
    uint8_t *patch;
    mcf_v2_view_t view;
    mcf_session_storage_t storage;
    mcf_session_t *session = (mcf_session_t *)(void *)&storage;
    mcf_config_t cfg;
    mcf_status_t st;
    if (argc != 2 || (patch = read_file(argv[1], &len)) == NULL) return 2;
    if (mcf_v2_parse(patch, len, &view) != MCF_OK ||
        view.flags != MCF_V2_EXEC_REQUIRED_FLAGS || view.record_count == 0u) {
        free(patch);
        return 1;
    }
    memset(&cfg, 0, sizeof(cfg));
    cfg.hal = &hal;
    cfg.patch = patch;
    cfg.patch_size = len;
    cfg.old = flash;
    cfg.old_size = view.old_size;
    cfg.dst_addr = FLASH_BASE;
    cfg.ram_budget = 65536u;
    st = mcf_session_open(session, &cfg);
    if (st == MCF_OK) st = mcf_session_run(session);
    mcf_session_close(session);
    free(patch);
    if (st != MCF_E_FORMAT || mutations != 0u) {
        fprintf(stderr, "MFP2 boundary failed: status=%d mutations=%u\n", (int)st, mutations);
        return 1;
    }
    puts("MFP2 host patch parses; MFP1 session rejects before flash mutation");
    return 0;
}
