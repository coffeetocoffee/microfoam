/* SPDX-License-Identifier: MIT */
/*
 * Built-in Ed25519 and Ed25519ph verification.
 *
 * The field and group arithmetic is TweetNaCl's, reached through
 * src/mcf_tn_glue.h. What this file contributes is the verification equation and
 * the two hash constructions, because TweetNaCl implements neither Ed25519ph nor
 * a streaming hash:
 *
 *   Ed25519    h = SHA-512(R || A || M)
 *   Ed25519ph  h = SHA-512(dom2(1, "") || R || A || SHA-512(M))
 *
 * Both then reduce `h` modulo L and check the same equation:
 *
 *   valid  <=>  [S]B == R + [h]A   <=>   encode([S]B + [h](-A)) == R
 *
 * `mcf_tn_unpackneg` yields -A, which is why the two scalar multiples are summed
 * rather than subtracted.
 *
 * No secret material is handled: the public key, the signature and the message
 * are all public, and the hashes are functions of those. There is therefore no
 * constant-time requirement here and nothing to wipe, which is worth stating
 * because it is the opposite of the signing side.
 */
#include "microfoam_ed25519.h"

#include "mcf_sha512.h"
#include "mcf_tn_glue.h"

#include <string.h>

#define MCF_ED25519_PK_LEN  32u
#define MCF_ED25519_SIG_LEN 64u

/* RFC 8032 section 2: dom2(x, y) = "SigEd25519 no Ed25519 collisions"
 *                                 || octet(x) || octet(len(y)) || y
 * For Ed25519ph, x = 1 and the context y is empty: 32 + 1 + 1 = 34 bytes.
 *
 * Getting this wrong makes every VALID signature fail. It cannot make an invalid
 * one pass, because the same prefix is hashed on both sides of the comparison -
 * which is why this needs no negative test of its own, only the positive vectors
 * and the cross-construction check. Confirmed by sabotage: flipping the final
 * byte to 0x01 fails the ph vectors and the differential, and nothing else. */
static const uint8_t MCF_DOM2_PH[34] = {
    'S','i','g','E','d','2','5','5','1','9',' ','n','o',' ','E','d',
    '2','5','5','1','9',' ','c','o','l','l','i','s','i','o','n','s',
    0x01u, 0x00u
};

/* Argument checks common to both entry points, matching the libsodium
 * adapter's contract so a caller can swap providers without changing what it
 * must handle. Kept identical on purpose: the differential test asserts the two
 * agree verdict-for-verdict, and a provider returning MCF_E_PARAM where the
 * other returned MCF_E_SIGNATURE would be a divergence. */
static int32_t check_args(const void *ctx, const uint8_t *sig, uint32_t sig_len,
                          const uint8_t *p1, uint32_t n1,
                          const uint8_t *p2, uint32_t n2,
                          const uint8_t *p3, uint32_t n3)
{
    const mcf_ed25519_ctx_t *v = (const mcf_ed25519_ctx_t *)ctx;
    if (v == NULL || v->public_key == NULL || sig == NULL ||
        sig_len != MCF_ED25519_SIG_LEN ||
        (p1 == NULL && n1 != 0u) || (p2 == NULL && n2 != 0u) ||
        (p3 == NULL && n3 != 0u)) {
        return MCF_E_PARAM;
    }
    return MCF_OK;
}

/* RFC 8032 requires S < L. TweetNaCl's own crypto_sign_open does NOT enforce
 * this and libsodium does, so a signature carrying S + L satisfies the group
 * equation - [S+L]B == [S]B - and is accepted by one implementation while the
 * other rejects it. Both halves were confirmed by execution. Enforcing it here
 * is what keeps this verifier's verdicts identical to the vetted provider's, and
 * ed25519_test pins the case directly.
 *
 * The test is arithmetic rather than a constant-time compare: S is zero-extended
 * into 64 bytes and reduced modulo L, so the result equals S exactly when S was
 * already below L. Both values are public. */
static int s_is_canonical(const uint8_t s[32])
{
    uint8_t wide[64];
    uint32_t i;
    uint32_t diff = 0u;

    for (i = 0u; i < 64u; i++) {
        wide[i] = 0u;
    }
    for (i = 0u; i < 32u; i++) {
        wide[i] = s[i];
    }
    mcf_tn_reduce(wide);
    for (i = 0u; i < 32u; i++) {
        diff |= (uint32_t)(wide[i] ^ s[i]);
    }
    return (diff == 0u) ? 1 : 0;
}

/* Shared tail: given the 64-byte challenge hash, evaluate the equation. */
static int32_t finish(const mcf_ed25519_ctx_t *v, const uint8_t *sig,
                      uint8_t challenge[64])
{
    mcf_tn_gf p[4];
    mcf_tn_gf q[4];
    uint8_t encoded[32];

    if (s_is_canonical(&sig[32]) == 0) {
        return MCF_E_SIGNATURE;
    }

    /* A public key that will not decompress is not a curve point, and no
     * signature can be valid against it. This is a signature failure rather than
     * a parameter error: the caller supplied a well-formed length and a
     * malformed value, which is the same verdict libsodium returns. */
    if (mcf_tn_unpackneg(q, v->public_key) != 0) {
        return MCF_E_SIGNATURE;
    }

    mcf_tn_reduce(challenge);

    mcf_tn_scalarmult(p, q, challenge);  /* p = [h](-A)        */
    mcf_tn_scalarbase(q, &sig[32]);      /* q = [S]B           */
    mcf_tn_add(p, q);                    /* p = [S]B + [h](-A) */
    mcf_tn_pack(encoded, p);

    if (mcf_tn_verify32(encoded, sig) != 0) {
        return MCF_E_SIGNATURE;
    }
    return MCF_OK;
}

int32_t mcf_ed25519_verify(void *ctx, const uint8_t *sig, uint32_t sig_len,
                           const uint8_t *part1, uint32_t part1_len,
                           const uint8_t *part2, uint32_t part2_len)
{
    const mcf_ed25519_ctx_t *v = (const mcf_ed25519_ctx_t *)ctx;
    mcf_sha512_ctx_t h;
    uint8_t challenge[64];
    int32_t r;

    r = check_args(ctx, sig, sig_len, part1, part1_len, part2, part2_len,
                   NULL, 0u);
    if (r != MCF_OK) {
        return r;
    }

    mcf_sha512_init(&h);
    mcf_sha512_update(&h, sig, 32u);                           /* R */
    mcf_sha512_update(&h, v->public_key, MCF_ED25519_PK_LEN);  /* A */
    mcf_sha512_update(&h, part1, part1_len);
    mcf_sha512_update(&h, part2, part2_len);
    mcf_sha512_final(&h, challenge);

    return finish(v, sig, challenge);
}

int32_t mcf_ed25519ph_verify3(void *ctx, const uint8_t *sig, uint32_t sig_len,
                              const uint8_t *part1, uint32_t part1_len,
                              const uint8_t *part2, uint32_t part2_len,
                              const uint8_t *part3, uint32_t part3_len)
{
    const mcf_ed25519_ctx_t *v = (const mcf_ed25519_ctx_t *)ctx;
    mcf_sha512_ctx_t h;
    uint8_t prehash[64];
    uint8_t challenge[64];
    int32_t r;

    r = check_args(ctx, sig, sig_len, part1, part1_len, part2, part2_len,
                   part3, part3_len);
    if (r != MCF_OK) {
        return r;
    }

    /* PH(M) = SHA-512(M), streamed: the spans are never held together. */
    mcf_sha512_init(&h);
    mcf_sha512_update(&h, part1, part1_len);
    mcf_sha512_update(&h, part2, part2_len);
    mcf_sha512_update(&h, part3, part3_len);
    mcf_sha512_final(&h, prehash);

    /* dom2 || R || A || PH(M). The prefix goes FIRST, before R - which is why a
     * ph verifier cannot be built by handing TweetNaCl's crypto_sign_open a
     * prehashed message: the prefix has to precede bytes that function controls
     * internally, so it cannot be injected by choosing the message. */
    mcf_sha512_init(&h);
    mcf_sha512_update(&h, MCF_DOM2_PH, (uint32_t)sizeof(MCF_DOM2_PH));
    mcf_sha512_update(&h, sig, 32u);                           /* R */
    mcf_sha512_update(&h, v->public_key, MCF_ED25519_PK_LEN);  /* A */
    mcf_sha512_update(&h, prehash, 64u);                       /* PH(M) */
    mcf_sha512_final(&h, challenge);

    return finish(v, sig, challenge);
}
