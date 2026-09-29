/* SPDX-License-Identifier: MIT */
#include "microfoam.h"
#include <string.h>
#include <stdlib.h>

static int32_t erase(void *ctx, uint32_t a, uint32_t n) { (void)ctx; (void)a; (void)n; return 0; }
static int32_t write_(void *ctx, uint32_t a, const uint8_t *p, uint32_t n) { (void)ctx; (void)a; (void)p; return (int32_t)n; }
static int32_t read_(void *ctx, uint32_t a, uint8_t *p, uint32_t n) { (void)ctx; (void)a; memset(p, 0, n); return (int32_t)n; }
static uint32_t block(void *ctx) { (void)ctx; return 1024u; }
static uint32_t product_a(void *ctx) { (void)ctx; return 0xA1u; }
static uint32_t product_b(void *ctx) { (void)ctx; return 0xB2u; }
static uint32_t version(void *ctx) { (void)ctx; return 1u; }
static void *alloc_(void *ctx, uint32_t n) { (void)ctx; return malloc(n); }
static void free_(void *ctx, void *p) { (void)ctx; free(p); }

int main(void)
{
    mcf_hal_t a = { erase, write_, read_, block, NULL, alloc_, free_, product_a, version, NULL, NULL, NULL };
    mcf_hal_t b = { erase, write_, read_, block, NULL, alloc_, free_, product_b, version, NULL, NULL, NULL };
    mcf_config_t ca, cb;
    mcf_session_storage_t sa_storage, sb_storage;
    mcf_session_t *sa = (mcf_session_t *)(void *)&sa_storage;
    mcf_session_t *sb = (mcf_session_t *)(void *)&sb_storage;
    memset(&ca, 0, sizeof(ca));
    memset(&cb, 0, sizeof(cb));
    ca.hal = &a;
    cb.hal = &b;
    if (mcf_session_open(sa, &ca) != MCF_OK || mcf_session_open(sb, &cb) != MCF_OK) return 1;
    mcf_session_close(sa);
    mcf_session_close(sb);
    return 0;
}
