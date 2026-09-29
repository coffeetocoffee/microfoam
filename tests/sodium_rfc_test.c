/* SPDX-License-Identifier: MIT */
#include "microfoam_sodium.h"

#include <sodium.h>
#include <stdio.h>
#include <string.h>

static void *test_alloc(void *ctx, uint32_t n)
{
    (void)ctx;
    return sodium_malloc((size_t)n);
}

static void test_free(void *ctx, void *p)
{
    (void)ctx;
    sodium_free(p);
}

static int from_hex(uint8_t *out, size_t out_len, const char *hex)
{
    size_t i;
    if (strlen(hex) != out_len * 2u) return 0;
    for (i = 0; i < out_len; i++) {
        unsigned int x;
        if (sscanf(&hex[i * 2u], "%2x", &x) != 1) return 0;
        out[i] = (uint8_t)x;
    }
    return 1;
}

int main(void)
{
    static const char *pk_hex =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    static const char *sig_hex =
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sig[crypto_sign_BYTES];
    uint8_t dummy = 0u;
    mcf_sodium_verify_ctx_t ctx;
    int ok = 1;

    if (sodium_init() < 0 || !from_hex(pk, sizeof(pk), pk_hex) ||
        !from_hex(sig, sizeof(sig), sig_hex)) return 2;
    ctx.public_key = pk;
    ctx.alloc_ctx = NULL;
    ctx.alloc = test_alloc;
    ctx.free = test_free;

    ok &= (mcf_sodium_verify(&ctx, sig, sizeof(sig), &dummy, 0u,
                             &dummy, 0u) == MCF_OK);
    sig[0] ^= 1u;
    ok &= (mcf_sodium_verify(&ctx, sig, sizeof(sig), &dummy, 0u,
                             &dummy, 0u) == MCF_E_SIGNATURE);
    if (!ok) {
        fprintf(stderr, "libsodium RFC 8032 TEST 1 failed\n");
        return 1;
    }
    puts("libsodium RFC 8032 TEST 1 passed; tampered signature rejected");
    return 0;
}
