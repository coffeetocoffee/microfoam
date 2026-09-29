/* SPDX-License-Identifier: MIT */
/* Stages 4 and 5 of the Ed25519 verification equation, for one fixed vector.
 *
 * Point decompression is already proven. What remains is [S]B, the scalar
 * multiplication of the base point, and the final comparison against R + [k]A.
 * Every value is printed as a little-endian byte string so Python can check it;
 * nothing here is meant to be compared by eye.
 */
#include <stdio.h>
#include <string.h>

#include "mcf_ed25519.c"

/* p - 2 = 2^255 - 21, little-endian. Needed only to turn projective
 * coordinates back to affine, which the verifier itself does not do. */
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

static void unhex(const char *h, uint8_t *out, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        out[i] = (uint8_t)(hexdig(h[i * 2]) * 16 + hexdig(h[i * 2 + 1]));
    }
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

static void point_affine(const char *tag, const ge *g)
{
    fe zi, x, y;
    uint8_t o[32];
    char nx[40], ny[40];

    fe_pow(zi, g->Z, EXP_INV, 255);
    fe_mul(x, g->X, zi);
    fe_mul(y, g->Y, zi);
    fe_pack25519(o, x);
    snprintf(nx, sizeof(nx), "%s_x", tag);
    put(nx, o, 32);
    fe_pack25519(o, y);
    snprintf(ny, sizeof(ny), "%s_y", tag);
    put(ny, o, 32);
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
    uint8_t one[32];

    unhex(KEY, key, 32);
    unhex(SIG, sig, 64);
    memcpy(S, sig + 32, 32);

    put("key", key, 32);
    put("R", sig, 32);
    put("S", S, 32);

    memcpy(buf, sig, 32);
    memcpy(buf + 32, key, 32);
    mcf_sha512(dig, buf, 64);
    put("sha", dig, 32);
    mcf_ed25519_sc_reduce(k, dig);
    put("k", k, 32);

    if (ge_unpackneg(&A, key) != 0) { printf("ERR unpackneg A\n"); return 1; }
    if (ge_unpackneg(&R, sig) != 0) { printf("ERR unpackneg R\n"); return 1; }

    ge_scalarmult(&sB, S, &GE_BASE);
    point_affine("SB", &sB);

    ge_scalarmult(&kA, k, &A);
    point_affine("kA", &kA);

    ge_add(&sum, &R, &kA);
    point_affine("sum", &sum);

    printf("ge_equal_SB_sum %d\n", ge_equal(&sB, &sum));

    /* independent scalars: [1]B must be B, [2]B must be 2B */
    memset(one, 0, sizeof(one));
    one[0] = 1;
    { ge q, r2; uint8_t two[32];
      ge_scalarmult(&q, one, &GE_BASE);
      printf("oneB_is_B %d\n", ge_equal(&q, &GE_BASE));
      memset(two, 0, sizeof(two)); two[0] = 2;
      ge_scalarmult(&r2, two, &GE_BASE);
      printf("twoB_is_2B %d\n", ge_equal(&r2, &q));
    }
    return 0;
}
