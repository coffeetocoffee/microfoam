/* SPDX-License-Identifier: MIT */
#ifndef MICROFOAM_SODIUM_H
#define MICROFOAM_SODIUM_H

#include "microfoam.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Context for the optional libsodium adapters. The public key must point to
 * exactly crypto_sign_PUBLICKEYBYTES immutable bytes for the adapter lifetime.
 * The two signed-message spans are copied into one temporary buffer. */
typedef struct mcf_sodium_verify_ctx {
    const uint8_t *public_key;
    void *alloc_ctx;
    void *(*alloc)(void *ctx, uint32_t size);
    void (*free)(void *ctx, void *ptr);
} mcf_sodium_verify_ctx_t;

typedef struct mcf_sodium_aead_ctx {
    const uint8_t *key;
    const uint8_t *nonce;
} mcf_sodium_aead_ctx_t;

/* Return MCF_OK only when libsodium accepts the Ed25519 signature. */
int32_t mcf_sodium_verify(void *ctx, const uint8_t *sig, uint32_t sig_len,
                         const uint8_t *part1, uint32_t part1_len,
                         const uint8_t *part2, uint32_t part2_len);

/* Detached XChaCha20-Poly1305 decryption. ciphertext remains untouched; the
 * caller supplies an output buffer at least ciphertext_len bytes long. */
int32_t mcf_sodium_xchacha20poly1305_decrypt(void *ctx,
                                             const uint8_t *ciphertext,
                                             uint32_t ciphertext_len,
                                             const uint8_t *tag,
                                             uint32_t tag_len,
                                             const uint8_t *ad,
                                             uint32_t ad_len,
                                             uint8_t *plaintext);

/* Streaming Ed25519ph verification of three concatenated message spans. */
int32_t mcf_sodium_ed25519ph_verify3(void *ctx, const uint8_t *sig,
                                     uint32_t sig_len, const uint8_t *part1,
                                     uint32_t part1_len, const uint8_t *part2,
                                     uint32_t part2_len, const uint8_t *part3,
                                     uint32_t part3_len);

#ifdef __cplusplus
}
#endif

#endif /* MICROFOAM_SODIUM_H */
