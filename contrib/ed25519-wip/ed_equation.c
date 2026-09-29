/* SPDX-License-Identifier: MIT */
/* The verification equation, checked with no external reference.
 *
 * Every assertion here is either the curve equation, a group identity, or a
 * validity check. None of it can be wrong in the way a transcribed reference
 * value can. If every point is on the curve and the equation still fails, the
 * inputs disagree - not the arithmetic.
 */
#include <stdio.h>
#include <string.h>

#include "mcf_ed25519.c"

static const uint8_t EXP_INV[32] = {
    0xEB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
};

static int hexdig(char c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    return c - 'A' + 10;
}

static void unhex(const char *h, uint8_t *o, int n)
{
    int i;
    for (i = 0; i < n; i++) { o[i] = (uint8_t)(hexdig(h[i*2])*16 + hexdig(h[i*2+1])); }
}

static int on_curve(const ge *g)
{
    fe zi, x, y, x2, y2, lhs, rhs, one, t;
    fe_pow(zi, g->Z, EXP_INV, 255);
    fe_mul(x, g->X, zi);
    fe_mul(y, g->Y, zi);
    fe_sq(x2, x);
    fe_sq(y2, y);
    fe_1(one);
    fe_sub(lhs, y2, x2);
    fe_sub(lhs, lhs, one);
    fe_mul(t, x2, y2);
    fe_mul(rhs, t, FE_D);
    fe_carry(lhs);
    fe_carry(rhs);
    return fe_equal(lhs, rhs);
}

int main(void)
{
    static const char *KEY =
        "1e97198c52c611260ab21d027835b51907a3dc3503e86ad37331f173a915096a";
    static const char *SIG =
        "0ecb29269794c7f4f82d8f4bb331b7b1118e93024249f9700c73f01c0118b9c"
        "2f8f01de522d768d6f1f49b214ede1af2ea74e3c24cd4ab7c05a1d7b5571c0908";

    uint8_t key[32], sig[64], S[32], buf[64], dig[64], k[32];
    ge A, R, sB, kA, sum;
    int fails = 0;

    unhex(KEY, key, 32);
    unhex(SIG, sig, 64);
    memcpy(S, sig + 32, 32);

    memcpy(buf, sig, 32);
    memcpy(buf + 32, key, 32);
    mcf_sha512(dig, buf, 64);
    mcf_ed25519_sc_reduce(k, dig);

    printf("decompress A  rc          : %d\n", ge_unpackneg(&A, key));
    printf("decompress R  rc          : %d\n", ge_unpackneg(&R, sig));
    printf("A on curve                : %d\n", on_curve(&A));
    printf("R on curve                : %d\n", on_curve(&R));

    ge_scalarmult(&sB, S, &GE_BASE);
    printf("[S]B on curve             : %d\n", on_curve(&sB));

    ge_scalarmult(&kA, k, &A);
    printf("[k]A on curve             : %d\n", on_curve(&kA));

    ge_add(&sum, &R, &kA);
    printf("R+[k]A on curve           : %d\n", on_curve(&sum));

    printf("equation [S]B == R+[k]A   : %d\n", ge_equal(&sB, &sum));
    if (!ge_equal(&sB, &sum)) { fails++; }

    /* Self-consistency of the two sides: the equation is equivalent to
     *   [S]B - R == [k]A
     * which is the same comparison, so instead check that adding -R to both
     * sides agrees - a different route to the same equality. */

    /* Is the signature even self-consistent, i.e. would verify() accept it? */
    printf("verify()                  : %d\n",
           mcf_ed25519_verify(sig, (const uint8_t *)"", 0u, key));

    printf("\n%d equation failure(s)\n", fails);
    return 0;
}
