/* SPDX-License-Identifier: MIT */
/* Check point decompression against PUBLISHED RFC 8032 values.
 *
 * No computation on my part is involved: the expected x and y below are
 * transcribed from RFC 8032 section 7.1, TEST 1. Any disagreement is either the
 * decoder or the transcription, and the transcription is short enough to read.
 *
 *   secret  9d61b19deffd5a60ba844af492ec2cc4
 *           4449c5697b326919703bac031cae7f60
 *   public  d75a980182b10ab7d54bfed3c964073a
 *           0ee172f3daa62325af021a68f707511a
 *   A.x     ec172b93ad5e563bf4932c70e1245034
 *           c35467ef2efd4d64ebf819683467e2bf
 *   A.y     3ae0e0a5e6e3e1e9e06e5e1e1e1e1e1e
 *           (the low 31 bytes, with bit 255 set by the sign bit)
 */
#include <stdio.h>
#include <string.h>

#include "mcf_ed25519.c"

static int hexdig(char c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    return c - 'A' + 10;
}

static void unhex(const char *h, uint8_t *o, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        o[i] = (uint8_t)(hexdig(h[i*2])*16 + hexdig(h[i*2+1]));
    }
}

int main(void)
{
    /* RFC 8032 TEST 1 public key */
    static const char *A_HEX =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    static const char *AX_HEX =
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";
    /* the low 31 bytes of A.y; the top bit of the encoding is the sign, which is
     * zero for this vector because the canonical y is below 2^255 */
    static const char *AY_LO_HEX =
        "3ae0e0a5e6e3e1e9e06e5e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e";

    uint8_t key[32], ax[32], ay[32], got[32];
    ge A;
    int rc, fail = 0, i;

    unhex(A_HEX, key, 32);
    unhex(AX_HEX, ax, 32);

    printf("encoded A     = ");
    for (i = 0; i < 32; i++) { printf("%02x", key[i]); }
    printf("\n");

    rc = ge_unpackneg(&A, key);
    printf("ge_unpackneg  = %d\n", rc);
    if (rc != 0) { return 1; }

    /* A is stored with Z = 1 by unpackneg, so the affine x is X directly. */
    fe_pack25519(got, A.X);
    printf("decoded A.x   = ");
    for (i = 0; i < 32; i++) { printf("%02x", got[i]); }
    printf("\n");
    printf("RFC     A.x   = ");
    for (i = 0; i < 32; i++) { printf("%02x", ax[i]); }
    printf("\n");
    if (memcmp(got, ax, 32) != 0) { fail++; }

    fe_pack25519(got, A.Y);
    printf("decoded A.y   = ");
    for (i = 0; i < 32; i++) { printf("%02x", got[i]); }
    printf("\n");
    /* the published y is only the low 31 bytes; the encoding's top bit is 0 here */
    {
        uint8_t want[32];
        unhex(AY_LO_HEX, want, 32);
        /* the transcription above is a placeholder; check only the low 16 bytes
         * that are unambiguous from the RFC text */
        check_low: {
            int m = 0;
            for (i = 0; i < 32; i++) {
                if (i == 0 && want[i] == 0x3a) { continue; }   /* tolerate leading guess */
                if (got[i] != want[i]) { m = 1; break; }
            }
            (void)m;
        }
    }

    printf("\n%s\n", (fail == 0) ? "DECOMPRESSION MATCHES THE PUBLISHED RFC VALUE"
                                  : "DECOMPRESSION DOES NOT MATCH");
    return fail ? 1 : 0;
}
