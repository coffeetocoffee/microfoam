/* SPDX-License-Identifier: MIT */
/* Microfoam - Ed25519 verification, private interface. */

#ifndef MCF_ED25519_H
#define MCF_ED25519_H

#include "microfoam.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Verify a 64-byte Ed25519 signature over `msg` under `public_key`.
 * Returns 1 when the signature is valid, 0 otherwise, including for NULL
 * arguments and malformed encodings.
 *
 * Cost: roughly 15-25 ms on a Cortex-M0 at 48 MHz, a few ms on an M4. It runs
 * once per firmware update, so a slower exact-integer path is preferable to a
 * faster one that is hard to review. */
int mcf_ed25519_verify(const uint8_t sig[64], const uint8_t *msg, uint32_t msg_len,
                       const uint8_t public_key[32]);

/* SHA-512, exposed for the format tests. Not part of the firmware API. */
void mcf_sha512(uint8_t out[64], const uint8_t *msg, uint32_t len);

/* Reduce a 64-byte value modulo the group order L.
 * `in` is a little-endian 64-byte integer; `out` receives 32 little-endian
 * bytes. The sizes differ deliberately and are spelled out so a caller cannot
 * hand a 32-byte buffer to a function that reads 64. */
void mcf_ed25519_sc_reduce(uint8_t out[32], const uint8_t in[64]);

#ifdef __cplusplus
}
#endif

#endif /* MCF_ED25519_H */
