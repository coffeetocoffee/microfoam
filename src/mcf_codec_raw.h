/* SPDX-License-Identifier: MIT */
/* Microfoam - raw codec private interface. Not part of the public API. */

#ifndef MCF_CODEC_RAW_H
#define MCF_CODEC_RAW_H

#include "microfoam.h"

/* The payload is the delta stream verbatim. There is no compression framing and
 * therefore no properties block (props_len is 0). This exists for patches too
 * small for a codec's framing overhead to pay for itself: on a tiny delta, LZ4's
 * per-block headers cost more than they save.
 *
 * There is nothing to validate at finish(): the delta stream's own control
 * triples must reach exactly new_size, so a truncated or corrupt raw payload is
 * caught by the engine (MCF_E_TRUNCATED / MCF_E_CORRUPT) and by the whole-image
 * CRC, exactly as for a compressed payload. The state block only counts bytes
 * for diagnostics. */
typedef struct mcf_raw {
    const mcf_codec_ops_t *ops;
    uint32_t produced; /*!< Bytes handed to the caller so far. */
} mcf_raw_t;

extern const mcf_codec_ops_t mcf_codec_raw_ops;

uint32_t mcf_raw_workspace(const uint8_t *props, uint32_t props_len);
int32_t mcf_raw_init(mcf_codec_t **out, const uint8_t *props, uint32_t props_len,
                     uint8_t *workspace);
int32_t mcf_raw_decode(mcf_codec_t *codec,
                       uint8_t *out, uint32_t cap, uint32_t *produced,
                       const uint8_t *in, uint32_t in_avail, uint32_t *consumed);
int32_t mcf_raw_finish(mcf_codec_t *codec);
void    mcf_raw_destroy(mcf_codec_t *codec);

/* The device's raw state block, in bytes. The host tool writes this figure into
 * workspace_req for a raw patch. */
#define MCF_RAW_WORKSPACE_BYTES 16u

#endif /* MCF_CODEC_RAW_H */
