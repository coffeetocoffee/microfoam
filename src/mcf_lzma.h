/* SPDX-License-Identifier: MIT */
/* Microfoam - LZMA decoder, private interface. */

#ifndef MCF_LZMA_H
#define MCF_LZMA_H

#include "microfoam.h"

#include <stdint.h>

/* Container properties, 9 bytes, little-endian:
 *
 *   0     encoded properties, pb*45 + lp*9 + lc
 *   1..4  dictionary size
 *   5..8  exact decompressed length
 *
 * The dictionary size is part of the stream's meaning, not a tuning knob: a
 * match that reaches further back than the dictionary cannot be resolved, so the
 * host tool must compress with a dictionary the device can actually hold. The
 * declared value is what the device allocates, and what the header's
 * workspace_req is checked against.
 *
 * The decoder is the vendored LZMA SDK (third_party/lzma-sdk, public domain).
 * mcf_lzma_workspace() reports the exact cost of both the SDK's probability
 * table and its dictionary, so the declared figure and the allocated figure
 * cannot disagree.
 */
#define MCF_LZMA_PROPS_LEN 9u

/* Fixed size reserved for the decoder's state object at the head of the
 * workspace. Pinning it to a constant - rather than sizeof(struct) - makes the
 * workspace figure identical on 32-bit and 64-bit targets, so the host tool can
 * compute the same number the device will, and a struct that outgrows the
 * reservation fails the build instead of the field. */
#define MCF_LZMA_STATE_BYTES 256u

/* Workspace in bytes needed to decode a payload described by `props`, or 0 if
 * the properties are malformed. Must not allocate. */
uint32_t mcf_lzma_workspace(const uint8_t *props, uint32_t props_len);

/* `workspace` must be at least mcf_lzma_workspace(props, props_len) bytes.
 * Places all decoder state within it; performs no other allocation. */
int32_t mcf_lzma_init(mcf_codec_t **out, const uint8_t *props, uint32_t props_len,
                      uint8_t *workspace);

/* Input ownership.
 *
 * The LZMA range coder is stateful across calls, so unlike LZ4 the decoder
 * keeps its own cursor. The caller passes the same base pointer and total
 * length on every call; `in` and `in_avail` are used only to establish that
 * state on the first call. `consumed` reports the bytes taken during *this*
 * call, for progress accounting only.
 *
 * Sliding a shrinking window past the decoder is not supported: it would
 * invalidate the coder's position. The session passes the payload base and its
 * full length, so this is not a burden on an integrator.
 */
int32_t mcf_lzma_decode(mcf_codec_t *codec,
                        uint8_t *out, uint32_t cap, uint32_t *produced,
                        const uint8_t *in, uint32_t in_avail, uint32_t *consumed);

/* MCF_OK only when the decoder produced exactly the declared content size,
 * MCF_E_TRUNCATED otherwise. Same contract as the LZ4 codec. */
int32_t mcf_lzma_finish(mcf_codec_t *codec);

/* Releases the SDK's decoder state. The workspace itself is caller-owned. */
void mcf_lzma_destroy(mcf_codec_t *codec);

extern const mcf_codec_ops_t mcf_codec_lzma_ops;

#endif /* MCF_LZMA_H */
