/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - libsodium adapter tests against published vectors.
 *
 * Two of the three constructions MFP2 depends on are ours to get right, not
 * libsodium's: the Ed25519ph domain separation and the XChaCha20-Poly1305
 * key/nonce/AAD assembly. A round-trip against the same library that produced
 * the ciphertext proves internal consistency and nothing else, so both are
 * pinned here to vectors published by the standards:
 *
 *   - RFC 8032 section 7.3, "TEST abc": Ed25519ph over the 3-byte message
 *     "abc", including the three-span streaming verify and the domain
 *     separation that makes it distinct from plain Ed25519.
 *   - draft-irtf-cfrg-xchacha-03 appendix A.1: AEAD_XCHACHA20_POLY1305 with
 *     the documented key, IV, AAD, ciphertext and tag.
 *
 * The remaining checks (round trip, tampered tag, tampered signature) cover
 * the adapter's own plumbing.
 */
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

/* RFC 8032 section 7.3, "TEST abc". */
static const char *ph_pk_hex =
    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";
static const char *ph_sig_hex =
    "98a70222f0b8121aa9d30f813d683f80"
    "9e462b469c7ff87639499bb94e6dae41"
    "31f85042463c2a355a2003d062adf5aa"
    "a10b8c61e636062aaad11c2a26083406";

/* draft-irtf-cfrg-xchacha-03 appendix A.1. */
static const char *aead_key_hex =
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
static const char *aead_nonce_hex =
    "404142434445464748494a4b4c4d4e4f5051525354555657";
static const char *aead_aad_hex = "50515253c0c1c2c3c4c5c6c7";
static const char *aead_pt_hex =
    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
    "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
    "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
    "637265656e20776f756c642062652069742e";
static const char *aead_ct_hex =
    "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
    "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
    "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
    "21f9664c97637da9768812f615c68b13b52e";
static const char *aead_tag_hex = "c0875924c1c7987947deafd8780acf49";

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

    /* --- RFC 8032 section 7.1, plain Ed25519 (the MFP1 path) -------------- */
    CHECK(mcf_sodium_verify(&ctx, sig, sizeof(sig), &dummy, 0u,
                            &dummy, 0u) == MCF_OK, "Ed25519 valid signature");
    sig[0] ^= 1u;
    CHECK(mcf_sodium_verify(&ctx, sig, sizeof(sig), &dummy, 0u,
                            &dummy, 0u) == MCF_E_SIGNATURE, "Ed25519 tampered signature");
    sig[0] ^= 1u;

    /* --- RFC 8032 section 7.3, Ed25519ph (the MFP2 path) ------------------ */
    {
        uint8_t ph_pk[crypto_sign_PUBLICKEYBYTES];
        uint8_t ph_sig[crypto_sign_BYTES];
        mcf_sodium_verify_ctx_t ph_ctx;
        static const uint8_t abc[3] = {'a', 'b', 'c'};

        if (!from_hex(ph_pk, sizeof(ph_pk), ph_pk_hex) ||
            !from_hex(ph_sig, sizeof(ph_sig), ph_sig_hex)) return 2;
        ph_ctx.public_key = ph_pk;
        ph_ctx.alloc_ctx = NULL;
        ph_ctx.alloc = test_alloc;
        ph_ctx.free = test_free;

        /* The whole message in one span. */
        CHECK(mcf_sodium_ed25519ph_verify3(&ph_ctx, ph_sig, sizeof(ph_sig),
                                           abc, sizeof(abc), NULL, 0u,
                                           NULL, 0u) == MCF_OK,
              "Ed25519ph RFC 8032 7.3 vector verifies");
        /* Split across all three spans: this exercises the streaming
         * concatenation, which is the part of the ph path that is ours. */
        CHECK(mcf_sodium_ed25519ph_verify3(&ph_ctx, ph_sig, sizeof(ph_sig),
                                           &abc[0], 1u, &abc[1], 1u,
                                           &abc[2], 1u) == MCF_OK,
              "Ed25519ph three-span split verifies");

        ph_sig[0] ^= 1u;
        CHECK(mcf_sodium_ed25519ph_verify3(&ph_ctx, ph_sig, sizeof(ph_sig),
                                           abc, sizeof(abc), NULL, 0u,
                                           NULL, 0u) == MCF_E_SIGNATURE,
              "Ed25519ph tampered signature rejected");
        ph_sig[0] ^= 1u;

        /* Domain separation: a valid Ed25519ph signature is NOT a valid plain
         * Ed25519 signature over the same message, because ph signs the
         * SHA-512(dom2 || SHA-512(M)) prehash. If this ever passes, the ph
         * adapter has silently degraded to plain Ed25519. */
        CHECK(mcf_sodium_verify(&ph_ctx, ph_sig, sizeof(ph_sig), abc,
                                sizeof(abc), NULL, 0u) == MCF_E_SIGNATURE,
              "Ed25519ph signature is not valid as plain Ed25519");
    }

    /* --- AEAD round trip through the adapter ------------------------------- */
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
    tag[0] ^= 1u;

    /* --- draft-irtf-cfrg-xchacha-03 A.1, published AEAD vector ------------- */
    {
        uint8_t vkey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
        uint8_t vnonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
        uint8_t vaad[12];
        uint8_t vpt[114];
        uint8_t vct[114];
        uint8_t vtag[crypto_aead_xchacha20poly1305_ietf_ABYTES];
        uint8_t vout[114];
        mcf_sodium_aead_ctx_t vaead;

        if (!from_hex(vkey, sizeof(vkey), aead_key_hex) ||
            !from_hex(vnonce, sizeof(vnonce), aead_nonce_hex) ||
            !from_hex(vaad, sizeof(vaad), aead_aad_hex) ||
            !from_hex(vpt, sizeof(vpt), aead_pt_hex) ||
            !from_hex(vct, sizeof(vct), aead_ct_hex) ||
            !from_hex(vtag, sizeof(vtag), aead_tag_hex)) return 2;
        vaead.key = vkey;
        vaead.nonce = vnonce;

        CHECK(mcf_sodium_xchacha20poly1305_decrypt(
                  &vaead, vct, sizeof(vct), vtag, sizeof(vtag), vaad,
                  sizeof(vaad), vout) == MCF_OK,
              "XChaCha20-Poly1305 published vector decrypts");
        CHECK(memcmp(vout, vpt, sizeof(vpt)) == 0,
              "XChaCha20-Poly1305 published plaintext matches");

        vtag[0] ^= 1u;
        CHECK(mcf_sodium_xchacha20poly1305_decrypt(
                  &vaead, vct, sizeof(vct), vtag, sizeof(vtag), vaad,
                  sizeof(vaad), vout) == MCF_E_AUTH,
              "published vector: tampered tag rejected");
        vtag[0] ^= 1u;

        /* The AAD is authenticated, which is what makes the per-record header
         * binding meaningful. */
        vaad[0] ^= 1u;
        CHECK(mcf_sodium_xchacha20poly1305_decrypt(
                  &vaead, vct, sizeof(vct), vtag, sizeof(vtag), vaad,
                  sizeof(vaad), vout) == MCF_E_AUTH,
              "published vector: tampered AAD rejected");
        vaad[0] ^= 1u;

        vct[0] ^= 1u;
        CHECK(mcf_sodium_xchacha20poly1305_decrypt(
                  &vaead, vct, sizeof(vct), vtag, sizeof(vtag), vaad,
                  sizeof(vaad), vout) == MCF_E_AUTH,
              "published vector: tampered ciphertext rejected");
        vct[0] ^= 1u;
    }

#undef CHECK
    if (!ok) {
        fprintf(stderr, "libsodium vector/tamper tests failed\n");
        return 1;
    }
    printf("libsodium published vectors and tamper tests passed (%d checks)\n",
           check_no);
    return 0;
}
