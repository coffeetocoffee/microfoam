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
