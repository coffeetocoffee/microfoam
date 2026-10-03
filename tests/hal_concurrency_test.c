/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - reentrancy: two live sessions, interleaved step by step.
 *
 * The architecture claims (goal G4) that two sessions with distinct contexts
 * operate concurrently without interference, because all state lives in the
 * caller-owned mcf_session_t and there is no mutable global state. Opening two
 * sessions and closing them does not test that claim: the sessions never ran,
 * so nothing could have interfered. This suite drives both through the whole
 * decode, step by step, alternating between them, and asserts that each
 * reconstructed its own image into its own device with no cross-talk.
 *
 * Interleaving is what gives the test its power. A step on session B happens
 * between two steps on session A, so any state that leaked out of one session
 * into shared memory - a file-scope buffer, a static scratch area, a cached
 * codec pointer - would corrupt the other's output. A sequential run would not
 * expose it.
 */

#include "microfoam.h"
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

/* ---------------------------------------------------------------------- *
 * Two independent devices, each with its own flash, image pair, and identity.
 * Every HAL callback reaches its device through `ctx`, which is the whole point:
 * the library must route each session to the right device by context alone.
 * ---------------------------------------------------------------------- */

#define DEV_FLASH_SIZE 16384u
#define DEV_BASE       0x08010000u
#define DEV_BLOCK      1024u
#define IMG_LEN        2048u
#define PATCH_MAX      8192u
#define VER_OLD        0x00010000u
#define VER_NEW        0x00020000u

typedef struct dev {
    uint8_t  flash[DEV_FLASH_SIZE];
    uint8_t  old[IMG_LEN];
    uint8_t  new[IMG_LEN];
    uint8_t  patch[PATCH_MAX];
    uint32_t patch_len;
    uint32_t product;
    uint32_t version;
    int      contract_violation;
} mcf_test_dev_t;

static mcf_test_dev_t dev_a;
static mcf_test_dev_t dev_b;

static int32_t dev_erase(void *ctx, uint32_t addr, uint32_t len)
{
    mcf_test_dev_t *d = (mcf_test_dev_t *)ctx;
    uint32_t off;

    if (addr < DEV_BASE) {
        return MCF_E_FLASH;
    }
    off = addr - DEV_BASE;
    if ((addr % DEV_BLOCK) != 0u || (len % DEV_BLOCK) != 0u || len == 0u ||
        off + len > DEV_FLASH_SIZE) {
        d->contract_violation = 1;
        return MCF_E_FLASH;
    }
    memset(&d->flash[off], 0xFF, len);
    return MCF_OK;
}

static int32_t dev_write(void *ctx, uint32_t addr, const uint8_t *p, uint32_t len)
{
    mcf_test_dev_t *d = (mcf_test_dev_t *)ctx;
    uint32_t off;

    if (addr < DEV_BASE) {
        return MCF_E_FLASH;
    }
    off = addr - DEV_BASE;
    /* The library promises a write never crosses an erase-block boundary. */
    if (((addr - DEV_BASE) % DEV_BLOCK) + len > DEV_BLOCK ||
        off + len > DEV_FLASH_SIZE) {
        d->contract_violation = 1;
        return MCF_E_FLASH;
    }
    memcpy(&d->flash[off], p, len);
    return MCF_OK;
}

static int32_t dev_read(void *ctx, uint32_t addr, uint8_t *p, uint32_t len)
{
    mcf_test_dev_t *d = (mcf_test_dev_t *)ctx;
    uint32_t off;

    if (addr < DEV_BASE) {
        return MCF_E_IO;
    }
    off = addr - DEV_BASE;
    if (off + len > DEV_FLASH_SIZE) {
        return MCF_E_IO;
    }
    memcpy(p, &d->flash[off], len);
    return (int32_t)len;
}

static uint32_t dev_block_size(void *ctx) { (void)ctx; return DEV_BLOCK; }
static uint32_t dev_product(void *ctx) { return ((const mcf_test_dev_t *)ctx)->product; }
static uint32_t dev_version(void *ctx) { return ((const mcf_test_dev_t *)ctx)->version; }
static void    *dev_alloc(void *ctx, uint32_t n) { (void)ctx; return malloc(n); }
static void     dev_free(void *ctx, void *p) { (void)ctx; free(p); }

/* Positional initialisers, matching the rest of the suite: the public header
 * deliberately avoids designated-initialiser dependence for portability, and
 * MSVC's C mode is one of the targets that needs that. Field order is
 * erase, write, read, block_size, is_readonly, alloc, free, product, version,
 * verify, log, ctx. */
static const mcf_hal_t hal_a = {
    dev_erase, dev_write, dev_read, dev_block_size, NULL,
    dev_alloc, dev_free,
    dev_product, dev_version,
    NULL, NULL, &dev_a
};

static const mcf_hal_t hal_b = {
    dev_erase, dev_write, dev_read, dev_block_size, NULL,
    dev_alloc, dev_free,
    dev_product, dev_version,
    NULL, NULL, &dev_b
};

static void dev_init(mcf_test_dev_t *d, uint32_t product, uint8_t seed)
{
    uint32_t i;

    memset(d, 0, sizeof(*d));
    memset(d->flash, 0xFF, sizeof(d->flash));
    d->product = product;
    d->version = VER_OLD;
    for (i = 0; i < IMG_LEN; i++) {
        d->old[i] = (uint8_t)((i * seed) & 0xFFu);
        d->new[i] = d->old[i];
    }
    /* A bounded change, so the delta is small and the round trip is exact. */
    for (i = 256u; i < 1024u; i++) {
        d->new[i] = (uint8_t)(d->old[i] ^ (uint8_t)(seed + 0x5Au));
    }
    d->patch_len = mcf_fx_build_patch(d->patch, (uint32_t)sizeof(d->patch),
                                      d->old, IMG_LEN, d->new, IMG_LEN,
                                      product, VER_NEW, VER_OLD, 16u, 0u, 9u);
}

static mcf_config_t dev_cfg(const mcf_test_dev_t *d, const mcf_hal_t *hal)
{
    mcf_config_t cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.hal        = hal;
    cfg.patch      = d->patch;
    cfg.patch_size = d->patch_len;
    cfg.old        = d->old;
    cfg.old_size   = IMG_LEN;
    cfg.dst_addr   = DEV_BASE;
    cfg.codec      = MCF_CODEC_AUTO;
    cfg.block_size = 512u;
    cfg.ram_budget = 4096u;
    return cfg;
}

/* ---------------------------------------------------------------------- */

int main(void)
{
    mcf_session_storage_t storage_a;
    mcf_session_storage_t storage_b;
    mcf_session_t *sa = (mcf_session_t *)(void *)&storage_a;
    mcf_session_t *sb = (mcf_session_t *)(void *)&storage_b;
    mcf_config_t cfg_a;
    mcf_config_t cfg_b;
    int done_a = 0;
    int done_b = 0;
    int steps_a = 0;
    int steps_b = 0;
    int guard = 0;

    printf("reentrancy: two interleaved sessions\n");

    dev_init(&dev_a, 0xAAAAu, 3u);
    dev_init(&dev_b, 0xBBBBu, 7u);

    /* Both patches must be real, or the test would pass vacuously. */
    CHECK(dev_a.patch_len > 0u, "device A patch built");
    CHECK(dev_b.patch_len > 0u, "device B patch built");
    CHECK(memcmp(dev_a.old, dev_b.old, IMG_LEN) != 0, "the two base images differ");

    cfg_a = dev_cfg(&dev_a, &hal_a);
    cfg_b = dev_cfg(&dev_b, &hal_b);

    CHECK_EQ(mcf_session_open(sa, &cfg_a), MCF_OK, "open A");
    CHECK_EQ(mcf_session_open(sb, &cfg_b), MCF_OK, "open B");
    CHECK_EQ(mcf_session_begin(sa), MCF_OK, "begin A");
    CHECK_EQ(mcf_session_begin(sb), MCF_OK, "begin B");

    /* Alternate one step at a time. Each step of B runs between two steps of A,
     * so any state shared between sessions would corrupt one of the images. */
    while ((!done_a || !done_b) && guard < 100000) {
        if (!done_a) {
            CHECK_EQ(mcf_session_step(sa), MCF_OK, "step A");
            steps_a++;
            if (mcf_session_state(sa) != MCF_ST_DECODE) {
                done_a = 1;
            }
        }
        if (!done_b) {
            CHECK_EQ(mcf_session_step(sb), MCF_OK, "step B");
            steps_b++;
            if (mcf_session_state(sb) != MCF_ST_DECODE) {
                done_b = 1;
            }
        }
        guard++;
    }

    /* Interleaving only means something if each session actually took several
     * steps; a one-step session would never overlap the other. */
    CHECK(steps_a > 1, "session A ran more than one step");
    CHECK(steps_b > 1, "session B ran more than one step");

    CHECK_EQ(mcf_session_finish(sa), MCF_OK, "finish A");
    CHECK_EQ(mcf_session_finish(sb), MCF_OK, "finish B");

    CHECK_EQ(mcf_session_state(sa), MCF_ST_DONE, "A reached DONE");
    CHECK_EQ(mcf_session_state(sb), MCF_ST_DONE, "B reached DONE");

    /* Each device holds exactly its own reconstruction - the interference test. */
    CHECK(memcmp(dev_a.flash, dev_a.new, IMG_LEN) == 0, "device A holds its own image");
    CHECK(memcmp(dev_b.flash, dev_b.new, IMG_LEN) == 0, "device B holds its own image");
    CHECK(dev_a.contract_violation == 0, "device A flash contract honoured");
    CHECK(dev_b.contract_violation == 0, "device B flash contract honoured");

    mcf_session_close(sa);
    mcf_session_close(sb);
    CHECK_EQ(mcf_session_state(sa), MCF_ST_IDLE, "close A resets to IDLE");
    CHECK_EQ(mcf_session_state(sb), MCF_ST_IDLE, "close B resets to IDLE");

    printf("reentrancy: %d checks, %d failures\n", g_checks, g_fail);
    return (g_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
