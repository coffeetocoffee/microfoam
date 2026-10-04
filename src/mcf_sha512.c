/* SPDX-License-Identifier: MIT */
#include "mcf_sha512.h"

#include "mcf_tn_glue.h"

#include <string.h>

#define MCF_SHA512_BLOCK 128u

void mcf_sha512_init(mcf_sha512_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    mcf_tn_iv(ctx->state);
    ctx->buflen = 0u;
    ctx->total  = 0u;
}

void mcf_sha512_update(mcf_sha512_ctx_t *ctx, const uint8_t *data, uint32_t len)
{
    if (ctx == NULL || data == NULL || len == 0u) {
        return;
    }
    ctx->total += (uint64_t)len;
    while (len > 0u) {
        uint32_t space = MCF_SHA512_BLOCK - ctx->buflen;
        uint32_t take  = (len < space) ? len : space;
        memcpy(&ctx->buf[ctx->buflen], data, (size_t)take);
        ctx->buflen += take;
        data        += take;
        len         -= take;
        if (ctx->buflen == MCF_SHA512_BLOCK) {
            mcf_tn_hashblocks(ctx->state, ctx->buf, (unsigned long long)MCF_SHA512_BLOCK);
            ctx->buflen = 0u;
        }
    }
}

void mcf_sha512_final(mcf_sha512_ctx_t *ctx, uint8_t out[64])
{
    uint64_t bits;
    uint64_t high;
    uint32_t i;

    if (ctx == NULL || out == NULL) {
        return;
    }

    /* The length is a 128-bit big-endian bit count. The low 64 bits are
     * total*8; the high 64 bits are total >> 61. Splitting it this way rather
     * than writing a single 64-bit field is the correct FIPS 180-4 form, and
     * getting it wrong was one of the in-house defects. */
    bits = ctx->total << 3;
    high = ctx->total >> 61;

    /* buflen is always < 128 here: update() compresses as soon as it fills. */
    ctx->buf[ctx->buflen++] = 0x80u;

    if (ctx->buflen > 112u) {
        while (ctx->buflen < MCF_SHA512_BLOCK) {
            ctx->buf[ctx->buflen++] = 0u;
        }
        mcf_tn_hashblocks(ctx->state, ctx->buf, (unsigned long long)MCF_SHA512_BLOCK);
        ctx->buflen = 0u;
    }
    while (ctx->buflen < 112u) {
        ctx->buf[ctx->buflen++] = 0u;
    }
    for (i = 0u; i < 8u; i++) {
        ctx->buf[112u + i] = (uint8_t)(high >> (56u - (8u * i)));
    }
    for (i = 0u; i < 8u; i++) {
        ctx->buf[120u + i] = (uint8_t)(bits >> (56u - (8u * i)));
    }

    mcf_tn_hashblocks(ctx->state, ctx->buf, (unsigned long long)MCF_SHA512_BLOCK);

    for (i = 0u; i < 64u; i++) {
        out[i] = ctx->state[i];
    }
}

void mcf_sha512(uint8_t out[64], const uint8_t *data, uint32_t len)
{
    mcf_sha512_ctx_t ctx;
    mcf_sha512_init(&ctx);
    mcf_sha512_update(&ctx, data, len);
    mcf_sha512_final(&ctx, out);
}
