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
 */
#define MCF_LZMA_PROPS_LEN 9u

typedef struct mcf_lzma {
    uint16_t *probs;
    uint8_t  *dict;
    uint8_t  *dict_end;

    uint32_t dict_size;
    uint32_t dict_pos;      /*!< Write cursor within the ring.            */
    uint32_t content_size;  /*!< Exact decompressed length from props.    */

    /* Range decoder. */
    const uint8_t *in;
    uint32_t       in_pos;
    uint32_t       in_size;
    uint32_t       range;
    uint32_t       code;

    /* LZ state. */
    uint32_t state;
    uint32_t rep0, rep1, rep2, rep3;
    uint32_t produced;   /*!< Decompressed bytes emitted so far. */
    uint32_t pending;   /*!< Match bytes still to emit from a cut match. */
    uint32_t lc, lp, pb;
    uint32_t pb_mask, lp_mask;
    uint8_t  done;           /*!< The end marker was decoded.        */
    uint8_t  input_exhausted;/*!< The caller ran out of input.       */
} mcf_lzma_t;

uint32_t mcf_lzma_workspace(const uint8_t *props, uint32_t props_len);
int32_t  mcf_lzma_init(mcf_codec_t **out, const uint8_t *props, uint32_t props_len,
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
int32_t  mcf_lzma_decode(mcf_codec_t *codec,
                         uint8_t *out, uint32_t cap, uint32_t *produced,
                         const uint8_t *in, uint32_t in_avail, uint32_t *consumed);
int32_t  mcf_lzma_finish(mcf_codec_t *codec);
void     mcf_lzma_destroy(mcf_codec_t *codec);

extern const mcf_codec_ops_t mcf_codec_lzma_ops;

#endif /* MCF_LZMA_H */
