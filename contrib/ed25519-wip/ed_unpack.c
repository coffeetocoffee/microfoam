/* SPDX-License-Identifier: MIT */
/* Print the intermediates of ge_unpackneg for one fixed key.
 *
 * No command-line parsing: an earlier version of this probe parsed a hex key
 * with strtoul on a non-terminated substring, silently fed a mangled key, and
 * produced a confident but meaningless comparison.
 *
 * Output is one "name hex" pair per line, little-endian byte strings, which is
 * exactly the form the field arithmetic uses. Compare them with Python as
 * little-endian integers; do not eyeball them.
 */
#include <stdio.h>
#include <string.h>

#include "mcf_ed25519.c"

/* The key from the first conformance vector. */
static const char *KEY_HEX =
    "1e97198c52c611260ab21d027835b51907a3dc3503e86ad37331f173a915096a";

static int hexdig(char c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    return c - 'A' + 10;
}

static void put(const char *name, const uint8_t *b, int n)
{
    int i;
    printf("%s ", name);
    for (i = 0; i < n; i++) { printf("%02x", b[i]); }
    printf("\n");
}

static void pk(const char *name, const fe a)
{
    uint8_t o[32];
    fe_pack25519(o, a);
    put(name, o, 32);
}

int main(void)
{
    uint8_t key[32];
    ge      A;
    fe      num, den, t, chk;
    int      i;

    for (i = 0; i < 32; i++) {
        key[i] = (uint8_t)(hexdig(KEY_HEX[i * 2]) * 16 + hexdig(KEY_HEX[i * 2 + 1]));
    }
    put("key", key, 32);

    memset(&A, 0xA5, sizeof(A));
    fe_unpack25519(A.Y, key);
    pk("Y", A.Y);

    fe_sq(num, A.Y);
    fe_1(t);
    fe_sub(num, num, t);
    fe_carry(num);
    pk("num", num);

    fe_sq(den, A.Y);
    fe_mul(den, den, FE_D);
    fe_1(t);
    fe_add(den, den, t);
    fe_carry(den);
    pk("den", den);

    if (fe_sqrt_ratio(chk, num, den) == 1) {
        pk("sqrt", chk);
    } else {
        printf("sqrt FAIL\n");
    }

    if (ge_unpackneg(&A, key) == 0) {
        pk("unpackX", A.X);
        pk("unpackY", A.Y);
        pk("unpackZ", A.Z);
    } else {
        printf("unpackneg FAIL\n");
    }
    return 0;
}
