/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - coverage-guided fuzz target for the MFP1 header parser.
 *
 * mcf_hdr_parse() consumes attacker-controlled bytes from the patch header, so
 * for every input it must never read out of bounds, never modify the buffer it
 * was handed, and never return a status outside the defined set. The
 * deterministic fault injection suite (test_microfoam.c) samples that space
 * with a fixed schedule; this target hands the same oracle to a coverage-guided
 * engine so the search follows the parser into structural corners a fixed
 * schedule will not reach.
 *
 * Two build modes share one oracle (v1_parse_fixture.h):
 *   - default: defines LLVMFuzzerTestOneInput for libFuzzer
 *     (clang -fsanitize=fuzzer).
 *   - MCF_FUZZ_STANDALONE: adds a main() that replays a built-in seed plus any
 *     file paths given on the command line, so the identical assertions run
 *     under any compiler. This is what the v1_fuzz_smoke ctest executes, and
 *     what makes the target verifiable on a machine without Clang.
 */
#include "v1_parse_fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Declared before use so -Wmissing-prototypes is satisfied; libFuzzer supplies
 * the definition of main() in the non-standalone build. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* Inputs larger than this are skipped rather than truncated. libFuzzer is run
 * with -max_len above this, so in practice only the standalone driver can
 * exceed it (a huge corpus file). */
#define MCF_FUZZ_MAX (1u << 20)

/* Fake HAL for fuzzing: all callbacks succeed with fixed values. */
static int32_t fake_hal_erase(void *ctx, uint32_t addr, uint32_t size)
{
    (void)ctx; (void)addr; (void)size;
    return MCF_OK;
}
static int32_t fake_hal_write(void *ctx, uint32_t addr, const uint8_t *data, uint32_t size)
{
    (void)ctx; (void)addr; (void)data; (void)size;
    return MCF_OK;
}
static uint32_t fake_hal_block_size(void *ctx)
{
    (void)ctx;
    return 4096u; /* typical block size */
}
static uint32_t fake_hal_product(void *ctx)
{
    (void)ctx;
    return 0x12345678u; /* must match fixture */
}
static uint32_t fake_hal_version(void *ctx)
{
    (void)ctx;
    return 1u; /* current fw_version; fixtures have fw_version=2 > this */
}

static const mcf_hal_t fake_hal = {
    .flash_erase = fake_hal_erase,
    .flash_write = fake_hal_write,
    .flash_block_size = fake_hal_block_size,
    .get_product_id = fake_hal_product,
    .get_fw_version = fake_hal_version,
    .verify = NULL, /* no signature verification */
    .log = NULL,    /* no logging */
    .ctx = NULL,
};

/* Returns 1 when the parser behaved correctly on this input, 0 when an
 * invariant was violated. Never crashes on its own: a violation is reported to
 * the caller, which decides whether to abort (fuzzer) or count it (driver). */
static int fuzz_check(const uint8_t *data, size_t size)
{
    static uint8_t work[MCF_FUZZ_MAX];
    static uint8_t want[MCF_FUZZ_MAX];
    mcf_hdr_view_t view;
    mcf_config_t cfg;
    mcf_status_t st;
    uint32_t site;

    if (size == 0u || size > (size_t)MCF_FUZZ_MAX) return 1;

    memcpy(work, data, size);
    memcpy(want, data, size);

    memset(&cfg, 0, sizeof(cfg));
    cfg.hal = &fake_hal;
    cfg.patch = work;
    cfg.patch_size = (uint32_t)size;
    cfg.old = NULL;
    cfg.old_size = 0u;
    cfg.dst_addr = 0u;
    cfg.codec = MCF_CODEC_AUTO;
    cfg.block_size = 256u;
    cfg.ram_budget = 4096u;

    st = mcf_hdr_parse(&fake_hal, &cfg, work, (uint32_t)size, &view, &site);

    if (!mcf_v1f_status_defined(st)) return 0;
    if (memcmp(work, want, size) != 0) return 0;
    if (st == MCF_OK) {
        if (!mcf_v1f_framing_ok(work, (uint32_t)size, &view)) return 0;
    }
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!fuzz_check(data, size)) {
        fprintf(stderr, "MFP1 parser invariant violated (size=%u)\n", (unsigned)size);
        abort();
    }
    return 0;
}

#ifdef MCF_FUZZ_STANDALONE
static int run_blob(const uint8_t *data, size_t size, const char *name)
{
    if (!fuzz_check(data, size)) {
        fprintf(stderr, "  FAIL  %s (size=%u)\n", name, (unsigned)size);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    static uint8_t buf[MCF_FUZZ_MAX];
    static uint8_t seed[1024];
    const uint32_t seed_len = MCF_V1F_VALID_SIZE;
    int failures = 0;
    int a;
    uint32_t i;

    /* Built-in seed: the minimal valid fixture, plus every truncation of it.
     * That covers the header-length and field-parsing boundaries. */
    mcf_v1f_build_valid(seed, (uint32_t)sizeof(seed));
    for (i = 0u; i <= seed_len; i++) {
        failures += run_blob(seed, (size_t)i, "<built-in truncation>");
    }

    /* Any files named on the command line: the CI job hands this the seeds the
     * host tool produced, so the same oracle runs over real MFP1 patches. */
    for (a = 1; a < argc; a++) {
        FILE *f = fopen(argv[a], "rb");
        size_t n;
        if (f == NULL) {
            fprintf(stderr, "  FAIL  cannot open %s\n", argv[a]);
            failures++;
            continue;
        }
        n = fread(buf, 1u, sizeof(buf), f);
        fclose(f);
        failures += run_blob(buf, n, argv[a]);
    }

    printf("v1 parser fuzz smoke: %s\n", failures == 0 ? "ok" : "FAILURES");
    return failures == 0 ? 0 : 1;
}
#endif /* MCF_FUZZ_STANDALONE */
