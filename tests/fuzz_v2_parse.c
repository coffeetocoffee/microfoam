/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - coverage-guided fuzz target for the MFP2 structural parser.
 *
 * mcf_v2_parse() consumes attacker-controlled bytes, so for every input it must
 * never read out of bounds, never modify the buffer it was handed, and never
 * return a status outside the defined set. The deterministic mutation loop in
 * v2_format_test.c samples that space with a fixed schedule; this target hands
 * the same oracle to a coverage-guided engine so the search follows the parser
 * into structural corners a fixed schedule will not reach.
 *
 * Two build modes share one oracle (v2_parse_fixture.h):
 *   - default: defines LLVMFuzzerTestOneInput for libFuzzer
 *     (clang -fsanitize=fuzzer).
 *   - MCF_FUZZ_STANDALONE: adds a main() that replays a built-in seed plus any
 *     file paths given on the command line, so the identical assertions run
 *     under any compiler. This is what the v2_fuzz_smoke ctest executes, and
 *     what makes the target verifiable on a machine without Clang.
 */
#include "v2_parse_fixture.h"

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

/* Returns 1 when the parser behaved correctly on this input, 0 when an
 * invariant was violated. Never crashes on its own: a violation is reported to
 * the caller, which decides whether to abort (fuzzer) or count it (driver). */
static int fuzz_check(const uint8_t *data, size_t size)
{
    static uint8_t work[MCF_FUZZ_MAX];
    static uint8_t want[MCF_FUZZ_MAX];
    mcf_v2_view_t view;
    mcf_status_t st;

    if (size == 0u || size > (size_t)MCF_FUZZ_MAX) return 1;

    memcpy(work, data, size);
    memcpy(want, data, size);
    st = mcf_v2_parse(work, (uint32_t)size, &view);

    if (!mcf_v2f_status_defined(st)) return 0;
    if (memcmp(work, want, size) != 0) return 0;
    if (st == MCF_OK) {
        if (!mcf_v2f_framing_ok(work, (uint32_t)size, &view)) return 0;
        if (!mcf_v2f_iterate_ok(work, (uint32_t)size, &view)) return 0;
    }
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!fuzz_check(data, size)) {
        fprintf(stderr, "MFP2 parser invariant violated (size=%u)\n", (unsigned)size);
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
    const uint32_t seed_len = MCF_V2_HEADER_MIN + 44u;
    int failures = 0;
    int a;
    uint32_t i;

    /* Built-in seed: the frozen-profile fixture, plus every truncation of it.
     * That alone covers the header-length and record-framing boundaries. */
    mcf_v2f_build_valid(seed, (uint32_t)sizeof(seed));
    for (i = 0u; i <= seed_len; i++) {
        failures += run_blob(seed, (size_t)i, "<built-in truncation>");
    }

    /* Any files named on the command line: the CI job hands this the seeds the
     * host tool produced, so the same oracle runs over real MFP2 patches. */
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

    printf("v2 parser fuzz smoke: %s\n", failures == 0 ? "ok" : "FAILURES");
    return failures == 0 ? 0 : 1;
}
#endif /* MCF_FUZZ_STANDALONE */
