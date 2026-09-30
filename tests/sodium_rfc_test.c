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
    uint8_t key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    uint8_t msg[] = "MFP2 authenticated record";
    uint8_t ad[] = {'M','C','F','2','R','E','C',0,'h','e','a','d','e','r'};
    uint8_t cipher[sizeof(msg) - 1u];
    uint8_t plain[sizeof(msg) - 1u];
    uint8_t tag[crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned long long clen = 0u;
    mcf_sodium_aead_ctx_t aead;
    mcf_sodium_verify_ctx_t ctx;
    int ok = 1;
    int check_no = 0;
#define CHECK(expr, label) do { \
    int passed = (expr); \
    check_no++; \
    if (!passed) { fprintf(stderr, "FAIL %d: %s\n", check_no, label); ok = 0; } \
} while (0)

    if (sodium_init() < 0 || !from_hex(pk, sizeof(pk), pk_hex) ||
        !from_hex(sig, sizeof(sig), sig_hex)) return 2;
    ctx.public_key = pk;
    ctx.alloc_ctx = NULL;
    ctx.alloc = test_alloc;
    ctx.free = test_free;

    CHECK(mcf_sodium_verify(&ctx, sig, sizeof(sig), &dummy, 0u,
                            &dummy, 0u) == MCF_OK, "Ed25519 valid signature");
    sig[0] ^= 1u;
    CHECK(mcf_sodium_verify(&ctx, sig, sizeof(sig), &dummy, 0u,
                            &dummy, 0u) == MCF_E_SIGNATURE, "Ed25519 tampered signature");

    memset(key, 0x31, sizeof(key));
    memset(nonce, 0x42, sizeof(nonce));
    aead.key = key;
    aead.nonce = nonce;
    CHECK(crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
              cipher, tag, &clen, msg, sizeof(msg) - 1u, ad, sizeof(ad) - 1u,
              NULL, nonce, key) == 0, "AEAD encrypt");
    CHECK(clen == (unsigned long long)crypto_aead_xchacha20poly1305_ietf_ABYTES,
          "detached encrypt reports the tag length");
    CHECK(mcf_sodium_xchacha20poly1305_decrypt(
              &aead, cipher, sizeof(cipher), tag, sizeof(tag), ad,
              sizeof(ad) - 1u, plain) == MCF_OK, "AEAD valid tag");
    CHECK(memcmp(plain, msg, sizeof(plain)) == 0, "AEAD plaintext round trip");
    tag[0] ^= 1u;
    memset(plain, 0xA5, sizeof(plain));
    CHECK(mcf_sodium_xchacha20poly1305_decrypt(
              &aead, cipher, sizeof(cipher), tag, sizeof(tag), ad,
              sizeof(ad) - 1u, plain) == MCF_E_AUTH, "AEAD tampered tag");
    /* libsodium wipes the plaintext output on authentication failure; the
     * contract the adapter documents is that no plaintext is exposed. */
    CHECK(plain[0] != msg[0], "AEAD failure exposes no plaintext");
#undef CHECK
    if (!ok) {
        fprintf(stderr, "libsodium RFC/tamper tests failed\n");
        return 1;
    }
    puts("libsodium RFC 8032 and MFP2 AEAD tamper tests passed");
    return 0;
}
