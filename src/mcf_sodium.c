/* SPDX-License-Identifier: MIT */
#include "microfoam_sodium.h"

#include <sodium.h>
#include <string.h>

int32_t mcf_sodium_verify(void *ctx, const uint8_t *sig, uint32_t sig_len,
                         const uint8_t *part1, uint32_t part1_len,
                         const uint8_t *part2, uint32_t part2_len)
{
    mcf_sodium_verify_ctx_t *v = (mcf_sodium_verify_ctx_t *)ctx;
    uint8_t *message;
    uint32_t total;
    int r;

    if (v == NULL || v->public_key == NULL || v->alloc == NULL ||
        v->free == NULL || sig == NULL || sig_len != crypto_sign_BYTES ||
        (part1 == NULL && part1_len != 0u) ||
        (part2 == NULL && part2_len != 0u) ||
        part1_len > UINT32_MAX - part2_len) {
        return MCF_E_PARAM;
    }
    if (sodium_init() < 0) {
        return MCF_E_SIGNATURE;
    }
    total = part1_len + part2_len;
    message = (uint8_t *)v->alloc(v->alloc_ctx, (total == 0u) ? 1u : total);
    if (message == NULL) {
        return MCF_E_NOMEM;
    }
    if (part1_len != 0u) memcpy(message, part1, part1_len);
    if (part2_len != 0u) memcpy(message + part1_len, part2, part2_len);
    r = crypto_sign_verify_detached(sig, message, (unsigned long long)total,
                                    v->public_key);
    sodium_memzero(message, (total == 0u) ? 1u : total);
    v->free(v->alloc_ctx, message);
    return (r == 0) ? MCF_OK : MCF_E_SIGNATURE;
}

int32_t mcf_sodium_xchacha20poly1305_decrypt(void *ctx,
                                             const uint8_t *ciphertext,
                                             uint32_t ciphertext_len,
                                             const uint8_t *tag,
                                             uint32_t tag_len,
                                             const uint8_t *ad,
                                             uint32_t ad_len,
                                             uint8_t *plaintext)
{
    const mcf_sodium_aead_ctx_t *a = (const mcf_sodium_aead_ctx_t *)ctx;
    if (a == NULL || a->key == NULL || a->nonce == NULL || tag == NULL ||
        tag_len != crypto_aead_xchacha20poly1305_ietf_ABYTES ||
        (ciphertext == NULL && ciphertext_len != 0u) ||
        (plaintext == NULL && ciphertext_len != 0u) ||
        (ad == NULL && ad_len != 0u)) return MCF_E_PARAM;
    if (sodium_init() < 0) return MCF_E_UNSUPPORTED;
    return crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
        plaintext, NULL, ciphertext, (unsigned long long)ciphertext_len, tag,
        ad, (unsigned long long)ad_len, a->nonce, a->key) == 0
        ? MCF_OK : MCF_E_AUTH;
}

int32_t mcf_sodium_ed25519ph_verify3(void *ctx, const uint8_t *sig,
                                     uint32_t sig_len, const uint8_t *part1,
                                     uint32_t part1_len, const uint8_t *part2,
                                     uint32_t part2_len, const uint8_t *part3,
                                     uint32_t part3_len)
{
    const mcf_sodium_verify_ctx_t *v = (const mcf_sodium_verify_ctx_t *)ctx;
    crypto_sign_ed25519ph_state state;
    if (v == NULL || v->public_key == NULL || sig == NULL ||
        sig_len != crypto_sign_BYTES || (part1 == NULL && part1_len != 0u) ||
        (part2 == NULL && part2_len != 0u) ||
        (part3 == NULL && part3_len != 0u)) return MCF_E_PARAM;
    if (sodium_init() < 0) return MCF_E_SIGNATURE;
    if (crypto_sign_ed25519ph_init(&state) != 0 ||
        (part1_len != 0u && crypto_sign_ed25519ph_update(&state, part1, part1_len) != 0) ||
        (part2_len != 0u && crypto_sign_ed25519ph_update(&state, part2, part2_len) != 0) ||
        (part3_len != 0u && crypto_sign_ed25519ph_update(&state, part3, part3_len) != 0)) {
        sodium_memzero(&state, sizeof(state));
        return MCF_E_SIGNATURE;
    }
    {
        int32_t result = (crypto_sign_ed25519ph_final_verify(&state, sig, v->public_key) == 0)
                       ? MCF_OK : MCF_E_SIGNATURE;
        sodium_memzero(&state, sizeof(state));
        return result;
    }
}
