/* SPDX-License-Identifier: MIT */
/* fe_pow22523 and fe_sqrt_ratio against known answers.
 *
 * Same technique that found both sc_reduce defects: feed inputs whose result is
 * known independently, and compare. Pass/fail against a signature tells you
 * nothing; a value comparison tells you which function is wrong.
 *
 * Reads lines of "<k> <u> <v>" with u and v as 64 hex chars, writes
 * "<k> <rc> <r>". See ed_pow_gen.py for the inputs and expectations.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mcf_ed25519.c"

static int hexval(char c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    return c - 'A' + 10;
}

static void from_hex(const char *h, uint8_t *out, int nbytes)
{
    int i;
    /* the file carries big-endian hex; fe is little-endian */
    for (i = 0; i < nbytes; i++) {
        out[i] = (uint8_t)(hexval(h[(nbytes - 1 - i) * 2]) * 16 +
                            hexval(h[(nbytes - 1 - i) * 2 + 1]));
    }
}

int main(int argc, char **argv)
{
    FILE *fin = fopen(argv[1], "r");
    FILE *fout = fopen(argv[2], "w");
    char  line[400];
    char  hu[140];
    char  hv[140];
    int   k = 0;

    if (!fin || !fout) { printf("io\n"); return 1; }
    while (fgets(line, sizeof(line), fin)) {
        uint8_t ub[32], vb[32], rb[32];
        fe u, v, r;
        int rc, i;

        if (sscanf(line, "%d %128s %128s", &k, hu, hv) != 3) { continue; }
        from_hex(hu, ub, 32);
        from_hex(hv, vb, 32);
        fe_unpack25519(u, ub);
        fe_unpack25519(v, vb);
        fe_0(r);
        rc = fe_sqrt_ratio(r, u, v);
        fe_pack25519(rb, r);
        fprintf(fout, "%d %d ", k, rc);
        for (i = 31; i >= 0; i--) { fprintf(fout, "%02x", rb[i]); }
        fprintf(fout, "\n");
    }
    fclose(fin);
    fclose(fout);
    return 0;
}
