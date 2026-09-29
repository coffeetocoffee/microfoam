/* SPDX-License-Identifier: MIT */
/* Microfoam - LZ4 codec private interface. Not part of the public API. */

#ifndef MCF_CODEC_LZ4_H
#define MCF_CODEC_LZ4_H

#include "microfoam.h"

typedef struct mcf_lz4 {
    const mcf_codec_ops_t *ops;
    uint32_t content_size; /*!< Declared decompressed length, from properties. */
    uint32_t produced;     /*!< Bytes decoded so far.                          */
    uint8_t  done;         /*!< The end-of-stream marker has been seen.        */
} mcf_lz4_t;

extern const mcf_codec_ops_t mcf_codec_lz4_ops;

uint32_t mcf_lz4_workspace(const uint8_t *props, uint32_t props_len);
int32_t mcf_lz4_init(mcf_codec_t **out, const uint8_t *props, uint32_t props_len,
                     uint8_t *workspace);
int32_t mcf_lz4_decode(mcf_codec_t *codec,
                      uint8_t *out, uint32_t cap, uint32_t *produced,
                      const uint8_t *in, uint32_t in_avail, uint32_t *consumed);
int32_t mcf_lz4_finish(mcf_codec_t *codec);
void    mcf_lz4_destroy(mcf_codec_t *codec);

#endif /* MCF_CODEC_LZ4_H */
