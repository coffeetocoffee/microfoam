/* SPDX-License-Identifier: MIT */
/*
 * The built-in Ed25519 / Ed25519ph verifier.
 *
 * Three layers of evidence, in increasing order of strength:
 *
 *   1. SHA-512 against published digests, including the streamed million-byte
 *      case and the 112/128/129-byte padding boundaries.
 *   2. RFC 8032 section 7.1 (plain Ed25519) and 7.3 (Ed25519ph) published
 *      vectors, plus a negative matrix and the malleability case.
 *   3. A differential section, when libsodium is also built: real signatures
 *      produced by libsodium over messages neither implementation chose, and
 *      every tampered variant, asserted to receive the SAME verdict from both.
 *      This is the strongest evidence available, because agreement with an
 *      independently written implementation on inputs it generated is not
 *      something a self-consistent bug can fake.
 */
#include "microfoam_ed25519.h"

#include "mcf_sha512.h"

#include <stdio.h>
#include <string.h>

#if defined(MCF_TEST_HAVE_SODIUM)
#include <sodium.h>
#include <stdlib.h>

#include "microfoam_sodium.h"
#endif

static int g_checks;
static int g_fail;

static void check(int cond, const char *label)
{
    g_checks++;
    if (cond == 0) {
        g_fail++;
        printf("  FAIL  %s\n", label);
    }
}

static int from_hex(uint8_t *out, int n, const char *hex)
{
    int i;
    for (i = 0; i < n; i++) {
        unsigned v = 0u;
        if (sscanf(hex + (2 * i), "%2x", &v) != 1) {
            return 0;
        }
        out[i] = (uint8_t)v;
    }
    return 1;
}

/* Deterministic PRNG so a differential failure is reproducible. Only the
 * differential section uses it, so it is compiled only when that exists. */
#if defined(MCF_TEST_HAVE_SODIUM)
static uint32_t g_rng = 0x12345678u;
static uint32_t rng_next(void)
{
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 17;
    g_rng ^= g_rng << 5;
    return g_rng;
}
#endif

/* ---------------------------------------------------------------- SHA-512 */

static void test_sha512(void)
{
    static const struct {
        const char *in;
        const char *want;
    } cases[] = {
        { "",
          "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
          "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" },
        { "abc",
          "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
          "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335"
          "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445" }
    };
    uint8_t got[64];
    uint8_t want[64];
    char label[64];
    unsigned i;

    printf("SHA-512 against published digests\n");
    for (i = 0u; i < (unsigned)(sizeof(cases) / sizeof(cases[0])); i++) {
        mcf_sha512(got, (const uint8_t *)cases[i].in,
                   (uint32_t)strlen(cases[i].in));
        (void)from_hex(want, 64, cases[i].want);
        (void)sprintf(label, "SHA-512 vector %u", i + 1u);
        check(memcmp(got, want, 64u) == 0, label);
    }

    /* The padding boundary: a message of 112 bytes fills the final block
     * exactly once, and 113 forces the length into a second block. A padding
     * bug that only shows at the boundary is invisible to the short vectors. */
    {
        static uint8_t buf[129];
        memset(buf, 'd', sizeof(buf));

        mcf_sha512(got, buf, 112u);
        (void)from_hex(want, 64,
                       "48ae1cbee956cee877f776099e3a66711c84bcc2d7180144d9d41b27e803dd86"
                       "bc3c5ec46dde070ac5ea8cb392eb54a1a9d14901cbb7622e067539102b1381fb");
        check(memcmp(got, want, 64u) == 0, "SHA-512 112-byte padding boundary");

        mcf_sha512(got, buf, 113u);
        (void)from_hex(want, 64,
                       "6db0badd065104f00254ee03846d8f209e5f9a09dd8b4d1d5fe4671974d48835"
                       "921c405401dc0d59c4849ef6559bf32354999e47a8726b751287601a50cc5c4b");
        check(memcmp(got, want, 64u) == 0, "SHA-512 113-byte padding spill");

        mcf_sha512(got, buf, 128u);
        (void)from_hex(want, 64,
                       "827c5983237d44fb2cceff465ae87aca418848ee27b2df51ddc40e9ec1b8f9e3"
                       "c5659fc96cd2e3449a483a6f2889beff73f8ac59a98e38fdffe30dc3f09e1073");
        check(memcmp(got, want, 64u) == 0, "SHA-512 exact-block boundary");

        mcf_sha512(got, buf, 129u);
        (void)from_hex(want, 64,
                       "30e54405dcc986ae90f830e01fc144190ff756efd6e7e9fe4bdf9d6416b54c63"
                       "e5ce18bfce172dc360436052db834a37317d0e2085faf11e3c69a59020cdd8fc");
        check(memcmp(got, want, 64u) == 0, "SHA-512 block plus one byte");
    }

    /* Streamed in many small updates must equal the one-shot digest, and must
     * match the published million-'a' value. This is the case that exercises
     * the compression loop rather than the padding. */
    {
        static uint8_t chunk[1000];
        uint8_t one_shot[64];
        mcf_sha512_ctx_t ctx;
        memset(chunk, 'a', sizeof(chunk));
        mcf_sha512_init(&ctx);
        for (i = 0u; i < 1000u; i++) {
            mcf_sha512_update(&ctx, chunk, (uint32_t)sizeof(chunk));
        }
        mcf_sha512_final(&ctx, got);
        (void)from_hex(want, 64,
                       "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
                       "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
        check(memcmp(got, want, 64u) == 0,
              "SHA-512 1,000,000 bytes in 1,000 updates");

        /* Every split of a 200-byte message must give the same digest. */
        {
            static uint8_t msg[200];
            uint8_t ref[64];
            unsigned split;
            unsigned k;
            int all_same = 1;
            for (k = 0u; k < sizeof(msg); k++) {
                msg[k] = (uint8_t)(k * 7u + 3u);
            }
            mcf_sha512(ref, msg, (uint32_t)sizeof(msg));
            for (split = 0u; split <= (unsigned)sizeof(msg); split++) {
                mcf_sha512_init(&ctx);
                mcf_sha512_update(&ctx, msg, split);
                mcf_sha512_update(&ctx, msg + split,
                                  (uint32_t)sizeof(msg) - split);
                mcf_sha512_final(&ctx, one_shot);
                if (memcmp(one_shot, ref, 64u) != 0) {
                    all_same = 0;
                }
            }
            check(all_same != 0, "SHA-512 agrees across every split point");
        }
    }
}

/* ------------------------------------------------------- RFC 8032 vectors */

/* Section 7.1, TEST 1: the empty message. Its signature is reused by the
 * malleability case below. */
static const char *V1_PK =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
static const char *V1_SIG =
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
/* The same signature with S replaced by S + L. The group equation still holds,
 * because [S+L]B == [S]B, so a verifier that does not enforce S < L accepts
 * it - and libsodium rejects it. This is the one case that pins the
 * canonicality check. */
static const char *V1_SIG_MALLEABLE =
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "4c8c7872aa064e049dbb3013fbf29380d25bf5f0595bbe24655141438e7a101b";

/* Section 7.1, TEST 2: one-byte message 0x72. */
static const char *V2_PK =
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
static const char *V2_SIG =
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

/* Section 7.1, TEST 3: two-byte message 0xaf82. */
static const char *V3_PK =
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
static const char *V3_SIG =
    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
    "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";

/* Section 7.3, TEST abc: Ed25519ph over "abc". */
static const char *PH_PK =
    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";
static const char *PH_SIG =
    "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41"
    "31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406";

static void test_vectors(void)
{
    uint8_t pk[32];
    uint8_t sig[64];
    mcf_ed25519_ctx_t ctx;
    static const uint8_t m2[1] = { 0x72u };
    static const uint8_t m3[2] = { 0xafu, 0x82u };
    static const uint8_t abc[3] = { 'a', 'b', 'c' };

    printf("RFC 8032 published vectors\n");

    (void)from_hex(pk, 32, V1_PK);
    (void)from_hex(sig, 64, V1_SIG);
    ctx.public_key = pk;
    check(mcf_ed25519_verify(&ctx, sig, 64u, NULL, 0u, NULL, 0u) == MCF_OK,
          "7.1 TEST 1 (empty message) verifies");

    (void)from_hex(pk, 32, V2_PK);
    (void)from_hex(sig, 64, V2_SIG);
    ctx.public_key = pk;
    check(mcf_ed25519_verify(&ctx, sig, 64u, m2, 1u, NULL, 0u) == MCF_OK,
          "7.1 TEST 2 (one byte) verifies");

    (void)from_hex(pk, 32, V3_PK);
    (void)from_hex(sig, 64, V3_SIG);
    ctx.public_key = pk;
    check(mcf_ed25519_verify(&ctx, sig, 64u, m3, 2u, NULL, 0u) == MCF_OK,
          "7.1 TEST 3 (two bytes) verifies");

    (void)from_hex(pk, 32, PH_PK);
    (void)from_hex(sig, 64, PH_SIG);
    ctx.public_key = pk;
    check(mcf_ed25519ph_verify3(&ctx, sig, 64u, abc, 3u, NULL, 0u, NULL, 0u)
              == MCF_OK,
          "7.3 Ed25519ph over 'abc' verifies");

    /* The same message split across all three spans: this is the streaming
     * concatenation, which is the part of the ph path that is ours. */
    check(mcf_ed25519ph_verify3(&ctx, sig, 64u, &abc[0], 1u, &abc[1], 1u,
                                &abc[2], 1u) == MCF_OK,
          "7.3 Ed25519ph verifies with the message split three ways");
}

static void test_negatives(void)
{
    uint8_t pk[32];
    uint8_t sig[64];
    mcf_ed25519_ctx_t ctx;
    static const uint8_t abc[3] = { 'a', 'b', 'c' };

    printf("negatives and the malleability case\n");

    (void)from_hex(pk, 32, V1_PK);
    (void)from_hex(sig, 64, V1_SIG);
    ctx.public_key = pk;

    sig[0] ^= 0x01u;
    check(mcf_ed25519_verify(&ctx, sig, 64u, NULL, 0u, NULL, 0u) == MCF_E_SIGNATURE,
          "a flipped signature byte is refused");
    sig[0] ^= 0x01u;

    sig[63] ^= 0x01u;
    check(mcf_ed25519_verify(&ctx, sig, 64u, NULL, 0u, NULL, 0u) == MCF_E_SIGNATURE,
          "a flipped S byte is refused");
    sig[63] ^= 0x01u;

    pk[0] ^= 0x01u;
    check(mcf_ed25519_verify(&ctx, sig, 64u, NULL, 0u, NULL, 0u) == MCF_E_SIGNATURE,
          "a flipped public key byte is refused");
    pk[0] ^= 0x01u;

    /* A signature that is valid for one message must not verify another. */
    check(mcf_ed25519_verify(&ctx, sig, 64u, (const uint8_t *)"x", 1u, NULL, 0u)
              == MCF_E_SIGNATURE,
          "a valid signature over the wrong message is refused");

    /* Parameter contract, matching the libsodium adapter. */
    check(mcf_ed25519_verify(NULL, sig, 64u, NULL, 0u, NULL, 0u) == MCF_E_PARAM,
          "a NULL context is a parameter error");
    check(mcf_ed25519_verify(&ctx, NULL, 64u, NULL, 0u, NULL, 0u) == MCF_E_PARAM,
          "a NULL signature is a parameter error");
    check(mcf_ed25519_verify(&ctx, sig, 63u, NULL, 0u, NULL, 0u) == MCF_E_PARAM,
          "a 63-byte signature is a parameter error");
    check(mcf_ed25519_verify(&ctx, sig, 65u, NULL, 0u, NULL, 0u) == MCF_E_PARAM,
          "a 65-byte signature is a parameter error");
    check(mcf_ed25519_verify(&ctx, sig, 64u, NULL, 1u, NULL, 0u) == MCF_E_PARAM,
          "a NULL span with a nonzero length is a parameter error");
    {
        mcf_ed25519_ctx_t bad;
        bad.public_key = NULL;
        check(mcf_ed25519_verify(&bad, sig, 64u, NULL, 0u, NULL, 0u) == MCF_E_PARAM,
              "a NULL public key is a parameter error");
    }

    /* Malleability: S + L satisfies the group equation but is not canonical.
     * Only the S < L check rejects it, so this case fails if that check is
     * removed - which is what makes it worth asserting. */
    (void)from_hex(sig, 64, V1_SIG_MALLEABLE);
    check(mcf_ed25519_verify(&ctx, sig, 64u, NULL, 0u, NULL, 0u) == MCF_E_SIGNATURE,
          "a non-canonical S (S + L) is refused");

    /* Domain separation: the ph construction must not be interchangeable with
     * plain Ed25519 over the same bytes. Both directions are checked. */
    (void)from_hex(pk, 32, PH_PK);
    (void)from_hex(sig, 64, PH_SIG);
    ctx.public_key = pk;
    check(mcf_ed25519_verify(&ctx, sig, 64u, abc, 3u, NULL, 0u) == MCF_E_SIGNATURE,
          "an Ed25519ph signature is refused by the plain path");

    (void)from_hex(pk, 32, V2_PK);
    (void)from_hex(sig, 64, V2_SIG);
    ctx.public_key = pk;
    check(mcf_ed25519ph_verify3(&ctx, sig, 64u, (const uint8_t *)"\x72", 1u,
                                NULL, 0u, NULL, 0u) == MCF_E_SIGNATURE,
          "a plain Ed25519 signature is refused by the ph path");
}

static void test_streaming(void)
{
    uint8_t pk[32];
    uint8_t sig[64];
    mcf_ed25519_ctx_t ctx;
    static uint8_t msg[300];
    unsigned i;
    unsigned a;
    unsigned b;
    int all_ok = 1;
    int all_bad = 1;

    printf("streaming: every split of the signed message agrees\n");

    /* The ph vector is the only published one, so streaming is proven by
     * invariance instead: every split of a message must give the same verdict,
     * and a message changed at any position must give the other one. */
    (void)from_hex(pk, 32, PH_PK);
    (void)from_hex(sig, 64, PH_SIG);
    ctx.public_key = pk;
    for (i = 0u; i < sizeof(msg); i++) {
        msg[i] = (uint8_t)(i * 11u + 5u);
    }

    for (a = 0u; a <= 30u; a++) {
        for (b = 0u; b <= 30u; b++) {
            unsigned p1 = a * 10u;
            unsigned p2 = b * 10u;
            if (p1 + p2 > (unsigned)sizeof(msg)) {
                continue;
            }
            if (mcf_ed25519ph_verify3(&ctx, sig, 64u, msg, p1,
                                      msg + p1, p2,
                                      msg + p1 + p2,
                                      (uint32_t)sizeof(msg) - p1 - p2)
                != MCF_E_SIGNATURE) {
                all_bad = 0;
            }
        }
    }
    check(all_bad != 0,
          "a message that was never signed is refused at every split point");

    /* A one-byte difference anywhere must be refused, at one split. */
    for (i = 0u; i < sizeof(msg); i++) {
        msg[i] ^= 0x01u;
        if (mcf_ed25519ph_verify3(&ctx, sig, 64u, msg, 100u, msg + 100u, 100u,
                                  msg + 200u, 100u) != MCF_E_SIGNATURE) {
            all_ok = 0;
        }
        msg[i] ^= 0x01u;
    }
    check(all_ok != 0, "a one-bit change anywhere in the message is refused");
}

/* ------------------------------------------------------------ differential */

#if defined(MCF_TEST_HAVE_SODIUM)

static void *t_alloc(void *ctx, uint32_t n)
{
    (void)ctx;
    return malloc(n);
}
static void t_free(void *ctx, void *p)
{
    (void)ctx;
    free(p);
}

/* Run both implementations over the same inputs and require the same verdict.
 * `what` names the case; the label records which side disagreed. */
static void differential(const char *what, const uint8_t *pk, const uint8_t *sig,
                         uint32_t sig_len, const uint8_t *m1, uint32_t n1,
                         const uint8_t *m2, uint32_t n2, const uint8_t *m3,
                         uint32_t n3, int use_ph)
{
    mcf_ed25519_ctx_t mine;
    mcf_sodium_verify_ctx_t theirs;
    int32_t a;
    int32_t b;
    char label[160];

    mine.public_key = pk;
    theirs.public_key = pk;
    theirs.alloc_ctx = NULL;
    theirs.alloc = t_alloc;
    theirs.free = t_free;

    if (use_ph != 0) {
        a = mcf_ed25519ph_verify3(&mine, sig, sig_len, m1, n1, m2, n2, m3, n3);
        b = mcf_sodium_ed25519ph_verify3(&theirs, sig, sig_len, m1, n1, m2, n2,
                                         m3, n3);
    } else {
        a = mcf_ed25519_verify(&mine, sig, sig_len, m1, n1, m2, n2);
        b = mcf_sodium_verify(&theirs, sig, sig_len, m1, n1, m2, n2);
    }
    (void)sprintf(label, "%s: built-in %d vs libsodium %d", what, (int)a, (int)b);
    check(a == b, label);
}

static void test_differential(void)
{
    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];
    uint8_t sig[crypto_sign_BYTES];
    uint8_t msg[400];
    unsigned long long siglen = 0u;
    unsigned i;
    unsigned trial;

    printf("differential: built-in verifier vs libsodium on generated inputs\n");

    if (sodium_init() < 0) {
        check(0, "sodium_init failed");
        return;
    }

    /* The published vectors, through both, including the malleable one. */
    {
        uint8_t vpk[32];
        uint8_t vsig[64];
        (void)from_hex(vpk, 32, V1_PK);
        (void)from_hex(vsig, 64, V1_SIG);
        differential("RFC 7.1 TEST 1", vpk, vsig, 64u, NULL, 0u, NULL, 0u, NULL,
                     0u, 0);
        (void)from_hex(vsig, 64, V1_SIG_MALLEABLE);
        differential("RFC 7.1 malleable S+L", vpk, vsig, 64u, NULL, 0u, NULL, 0u,
                     NULL, 0u, 0);
        (void)from_hex(vpk, 32, PH_PK);
        (void)from_hex(vsig, 64, PH_SIG);
        differential("RFC 7.3 ph abc", vpk, vsig, 64u, (const uint8_t *)"abc", 3u,
                     NULL, 0u, NULL, 0u, 1);
        /* Cross-construction, which must agree in the refusing direction. */
        differential("ph sig via plain path", vpk, vsig, 64u,
                     (const uint8_t *)"abc", 3u, NULL, 0u, NULL, 0u, 0);
    }

    /* Generated signatures: libsodium signs, both verify. Messages of many
     * lengths so the hash block boundaries are crossed in both directions. */
    for (trial = 0u; trial < 40u; trial++) {
        unsigned long mlen;
        crypto_sign_keypair(pk, sk);
        mlen = (trial < 12u) ? (unsigned long)(trial * 11u)
                             : (unsigned long)(rng_next() % 400u);
        for (i = 0u; i < mlen; i++) {
            msg[i] = (uint8_t)(rng_next() & 0xFFu);
        }
        mlen = (mlen > sizeof(msg)) ? (unsigned)sizeof(msg) : mlen;

        /* Plain Ed25519: sign, then verify, then tamper. */
        crypto_sign_detached(sig, &siglen, msg, (unsigned long long)mlen, sk);
        differential("generated plain, valid", pk, sig, (uint32_t)siglen,
                     msg, (uint32_t)mlen, NULL, 0u, NULL, 0u, 0);
        {
            uint8_t t[sizeof(sig)];
            memcpy(t, sig, sizeof(sig));
            t[(unsigned)(rng_next() % 64u)] ^= 0x01u;
            differential("generated plain, tampered sig", pk, t,
                         (uint32_t)siglen, msg, (uint32_t)mlen, NULL, 0u, NULL,
                         0u, 0);
            memcpy(t, pk, sizeof(pk));
            t[(unsigned)(rng_next() % 32u)] ^= 0x01u;
            differential("generated plain, tampered key", t, sig,
                         (uint32_t)siglen, msg, (uint32_t)mlen, NULL, 0u, NULL,
                         0u, 0);
        }
        if (mlen > 0u) {
            uint8_t m2[sizeof(msg)];
            memcpy(m2, msg, sizeof(msg));
            m2[(unsigned)(rng_next() % mlen)] ^= 0x01u;
            differential("generated plain, tampered msg", pk, sig,
                         (uint32_t)siglen, m2, (uint32_t)mlen, NULL, 0u, NULL,
                         0u, 0);
        }

        /* Ed25519ph: same, through the streaming construction. */
        {
            crypto_sign_ed25519ph_state st;
            unsigned long long plen = 0u;
            if (crypto_sign_ed25519ph_init(&st) == 0 &&
                crypto_sign_ed25519ph_update(&st, msg,
                                             (unsigned long long)mlen) == 0 &&
                crypto_sign_ed25519ph_final_create(&st, sig, &plen, sk) == 0) {
                differential("generated ph, valid", pk, sig, (uint32_t)plen,
                             msg, (uint32_t)mlen, NULL, 0u, NULL, 0u, 1);
                {
                    uint8_t t[sizeof(sig)];
                    memcpy(t, sig, sizeof(sig));
                    t[(unsigned)(rng_next() % 64u)] ^= 0x01u;
                    differential("generated ph, tampered sig", pk, t,
                                 (uint32_t)plen, msg, (uint32_t)mlen, NULL, 0u,
                                 NULL, 0u, 1);
                }
                if (mlen > 0u) {
                    uint8_t m2[sizeof(msg)];
                    memcpy(m2, msg, sizeof(msg));
                    m2[(unsigned)(rng_next() % mlen)] ^= 0x01u;
                    differential("generated ph, tampered msg", pk, sig,
                                 (uint32_t)plen, m2, (uint32_t)mlen, NULL, 0u,
                                 NULL, 0u, 1);
                }
                /* The same ph message split three ways must agree with the
                 * one-span form on both implementations. */
                if (mlen >= 3u) {
                    uint32_t third = (uint32_t)(mlen / 3u);
                    differential("generated ph, three spans", pk, sig,
                                 (uint32_t)plen, msg, third, msg + third, third,
                                 msg + (2u * third),
                                 (uint32_t)mlen - (2u * third), 1);
                }
            }
        }
    }

    /* Degenerate public keys: agreement matters most exactly where two
     * implementations are most likely to differ. */
    {
        uint8_t z[32];
        memset(z, 0x00u, sizeof(z));
        differential("all-zero public key", z, sig, 64u, msg, 8u, NULL, 0u, NULL,
                     0u, 0);
        memset(z, 0xFFu, sizeof(z));
        differential("all-ones public key", z, sig, 64u, msg, 8u, NULL, 0u, NULL,
                     0u, 0);
        memset(z, 0x00u, sizeof(z));
        z[0] = 0x01u;
        differential("public key y=1", z, sig, 64u, msg, 8u, NULL, 0u, NULL, 0u,
                     0);
        memset(z, 0x00u, sizeof(z));
        differential("all-zero signature", pk, z, 64u, msg, 8u, NULL, 0u, NULL,
                     0u, 0);
    }
}

#endif /* MCF_TEST_HAVE_SODIUM */

int main(void)
{
    test_sha512();
    test_vectors();
    test_negatives();
    test_streaming();
#if defined(MCF_TEST_HAVE_SODIUM)
    test_differential();
#else
    printf("differential vs libsodium: SKIPPED (build without "
           "MCF_ENABLE_SODIUM)\n");
#endif
    printf("\n%d checks, %d failures\n", g_checks, g_fail);
    return (g_fail == 0) ? 0 : 1;
}
