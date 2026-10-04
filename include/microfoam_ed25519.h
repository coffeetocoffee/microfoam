/* SPDX-License-Identifier: MIT */
#ifndef MICROFOAM_ED25519_H
#define MICROFOAM_ED25519_H

#include "microfoam.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Context for the built-in Ed25519 verifiers. The public key must point to
 * exactly 32 immutable bytes for the context's lifetime.
 *
 * Unlike the libsodium adapter there is no alloc/free pair, and that is the
 * point: these verifiers stream the signed message instead of concatenating it
 * into one buffer, so verifying a patch never costs RAM proportional to the
 * patch. A caller with a 35 KB firmware payload does not need 35 KB free. */
typedef struct mcf_ed25519_ctx {
    const uint8_t *public_key;
} mcf_ed25519_ctx_t;

/* Ed25519 (RFC 8032) over the two concatenated spans, matching
 * mcf_verify_fn. Return MCF_OK only when the signature is valid. */
int32_t mcf_ed25519_verify(void *ctx, const uint8_t *sig, uint32_t sig_len,
                           const uint8_t *part1, uint32_t part1_len,
                           const uint8_t *part2, uint32_t part2_len);

/* Ed25519ph (RFC 8032) over three concatenated spans, matching
 * mcf_v2_verify_fn. The message is pre-hashed, so the spans are streamed and
 * never held in full. */
int32_t mcf_ed25519ph_verify3(void *ctx, const uint8_t *sig, uint32_t sig_len,
                              const uint8_t *part1, uint32_t part1_len,
                              const uint8_t *part2, uint32_t part2_len,
                              const uint8_t *part3, uint32_t part3_len);

#ifdef __cplusplus
}
#endif

#endif /* MICROFOAM_ED25519_H */
