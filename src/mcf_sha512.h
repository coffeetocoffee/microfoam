/* SPDX-License-Identifier: MIT */
/*
 * Streaming SHA-512, used by the Ed25519 verifiers.
 *
 * The compression function and initial state come from TweetNaCl's public
 * `crypto_hashblocks`, which is a reviewed implementation. This file adds only
 * the streaming and padding layer, because TweetNaCl's `crypto_hash` is
 * one-shot: Ed25519ph has to hash a firmware image far too large to hold in one
 * buffer, and MFP1's signed message is a patch payload of the same order.
 * Buffering is what this library exists to avoid.
 *
 * Writing the compression function again is what the rejected in-house verifier
 * did, and its hand-written SHA-512 shipped two defects - a K table with 64 of
 * the 80 round constants, and the message length written into the high half of
 * the 16-byte length field. Reusing the vendored one removes that whole class.
 *
 * Padding follows FIPS 180-4: 0x80, zeros to 112 mod 128, then the message
 * length in bits as a 128-bit big-endian integer.
 */
#ifndef MCF_SHA512_H
#define MCF_SHA512_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mcf_sha512_ctx {
    uint8_t  state[64];  /*!< TweetNaCl keeps the state as 64 big-endian bytes. */
    uint8_t  buf[128];
    uint32_t buflen;
    uint64_t total;      /*!< Bytes absorbed so far. */
} mcf_sha512_ctx_t;

void mcf_sha512_init(mcf_sha512_ctx_t *ctx);
void mcf_sha512_update(mcf_sha512_ctx_t *ctx, const uint8_t *data, uint32_t len);
void mcf_sha512_final(mcf_sha512_ctx_t *ctx, uint8_t out[64]);

/* One-shot convenience; `out` and `data` may not overlap. */
void mcf_sha512(uint8_t out[64], const uint8_t *data, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* MCF_SHA512_H */
