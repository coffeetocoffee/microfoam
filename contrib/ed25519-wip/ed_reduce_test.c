/* SPDX-License-Identifier: MIT */
/* sc_reduce against unambiguous inputs: L itself, L+1, zero, 2^511, and a
 * value one below L. The expected results come from Python, so this tests the
 * shift and bit ordering rather than assuming it.
 *
 * Reads lines of "<k> <512-bit value as 64 hex chars>" from argv[1], writes
 * "<k> <result as 64 hex chars>".
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

int main(int argc, char **argv)
{
    FILE *fin = fopen(argv[1], "r");
    FILE *fout = fopen(argv[2], "w");
    char  line[256];
    char  hex[160];
    int   k = 0;

    if (!fin || !fout) { printf("io\n"); return 1; }
    while (fgets(line, sizeof(line), fin)) {
        uint8_t in[64];
        uint8_t out[32];
        int i;

        if (sscanf(line, "%d %128s", &k, hex) != 2) { continue; }
        /* the value is big-endian in the file; sc_reduce wants little-endian */
        for (i = 0; i < 64; i++) {
            in[i] = (uint8_t)(hexval(hex[(63 - i) * 2]) * 16 +
                               hexval(hex[(63 - i) * 2 + 1]));
        }
        memset(out, 0, sizeof(out));
        mcf_ed25519_sc_reduce(out, in);
        fprintf(fout, "%d ", k);
        for (i = 31; i >= 0; i--) { fprintf(fout, "%02x", out[i]); }
        fprintf(fout, "\n");
    }
    fclose(fin);
    fclose(fout);
    return 0;
}
