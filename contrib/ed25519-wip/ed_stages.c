/* SPDX-License-Identifier: MIT */
/* Stage-by-stage comparison of the Ed25519 verifier against ground truth.
 *
 * Verifying only pass/fail says "it fails" and not where. Each stage here is
 * independently checkable against a reference implementation, so a mismatch
 * localises the fault to one function. Stage 1 is SHA-512, stage 2 is the
 * scalar reduction, stage 3 is point decompression, stage 4 is scalar
 * multiplication, and the caller compares all of them.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* p - 2 = 2^255 - 21, little-endian. Needed only by this probe, to go from
 * projective coordinates back to affine. */
static const uint8_t EXP_INV[32] = {
    0xEB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
};
#include "mcf_ed25519.c"

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void hex(const char *tag, const uint8_t *p, int n)
{
    int i;
    printf("%s ", tag);
    for (i = 0; i < n; i++) { printf("%02x", p[i]); }
    printf("\n");
}

int main(int argc, char **argv)
{
    FILE    *f = fopen(argv[1], "rb");
    long     size;
    uint8_t *blob;
    uint32_t count, i, want = (uint32_t)atoi(argv[2]);
    size_t   off;
    uint8_t  buf[64];
    uint8_t  digest[64];
    uint8_t  k[32];
    ge       A;
    fe       zi, xa, ya;
    ge       sB, hram_pt;
    uint8_t  hram[32];
    uint8_t  one[32];

    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    blob = (uint8_t *)malloc((size_t)size);
    if (fread(blob, 1, (size_t)size, f) != (size_t)size) { return 1; }
    fclose(f);

    count = rd32(blob);
    off   = 4;
    for (i = 0; i < count; i++) {
        uint32_t ml = rd32(&blob[off]); off += 4;
        uint32_t kl = rd32(&blob[off]); off += 4;
        uint32_t sl = rd32(&blob[off]); off += 4;
        uint32_t ex = rd32(&blob[off]); off += 4;
        const uint8_t *msg = &blob[off]; off += ml;
        const uint8_t *key = &blob[off]; off += kl;
        const uint8_t *sig = &blob[off]; off += sl;
        int j;

        if (i != want) { continue; }
        printf("vector %u: msg_len=%u expect=%u sig[0]=%02x\n", i, ml, ex, sig[0]);

        /* Stage 1: SHA-512(R || A || msg) */
        memcpy(buf, sig, 32);
        memcpy(buf + 32, key, 32);
        mcf_sha512(digest, buf, 64);
        if (ml > 0u) { mcf_sha512(digest + 32, msg, ml); }
        hex("stage1_sha512_R_A_msg", digest, 32);

        /* Stage 2: sc_reduce */
        memcpy(hram, digest, 32);
        mcf_ed25519_sc_reduce(hram, digest);
        hex("stage2_sc_reduce", hram, 32);

        /* Stage 3: decompress the public key */
        memset(&A, 0xA5, sizeof(A));
        if (ge_unpackneg(&A, key) != 0) {
            printf("stage3_unpackneg FAILED\n");
            return 0;
        }
        fe_pow(zi, A.Z, (const uint8_t *)EXP_INV, 255);
        fe_mul(xa, A.X, zi);
        fe_mul(ya, A.Y, zi);
        fe_pack25519(buf, xa);
        hex("stage3_Ax", buf, 32);
        fe_pack25519(buf, ya);
        hex("stage3_Ay", buf, 32);

        /* Stage 4: [S]B */
        memset(&sB, 0xA5, sizeof(sB));
        ge_scalarmult(&sB, sig + 32, &GE_BASE);
        fe_pow(zi, sB.Z, EXP_INV, 255);
        fe_mul(xa, sB.X, zi);
        fe_mul(ya, sB.Y, zi);
        fe_pack25519(buf, xa);
        hex("stage4_SBx", buf, 32);
        fe_pack25519(buf, ya);
        hex("stage4_SBy", buf, 32);

        (void)hram_pt; (void)one; (void)j;
        printf("stage5_verify %d (expected %u)\n",
               mcf_ed25519_verify(sig, msg, ml, key), ex);
        return 0;
    }
    return 0;
}
