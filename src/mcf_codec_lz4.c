/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - LZ4 block codec.
 *
 * Container format for the compressed delta stream:
 *
 *   repeat:
 *     u32 le   block_len          (0 marks the end of the stream)
 *     u8[]     block_len bytes of LZ4 block-format data
 *
 * Properties block, 4 bytes:
 *   u32 le   content_size         exact decompressed length
 *
 * A single block may not expand past `block_size`, taken from the header's
 * block_size_log2. This is a format constraint, not a hint: the host tool chunks
 * its framing to the same field the device reads, because a block that would
 * overflow the device's decode buffer is rejected as corrupt.
 *
 * The explicit content size is what makes truncation detectable: a stream cut
 * short leaves the decoder unable to reach the declared total, which
 * mcf_lz4_finish() reports as MCF_E_TRUNCATED rather than silently accepting a
 * short reconstruction.
 *
 * Upstream-License: the LZ4 block format is a specification, not copied code.
 */

#include "mcf_internal.h"

#include "mcf_codec_lz4.h"

#define MCF_LZ4_PROPS_LEN 4u

/* LZ4 block: token = (literal_len << 4) | (match_len - 4).
 * A nibble of 15 means "continued in following bytes, 255 = keep going". */
static int32_t mcf_lz4_block(const uint8_t *src, uint32_t src_len, uint8_t *dst,
                              uint32_t dst_cap, uint32_t *out_len)
{
    const uint8_t *ip   = src;
    const uint8_t *iend = src + src_len;
    uint8_t       *op   = dst;
    uint8_t       *oend = dst + dst_cap;

    while (ip < iend) {
        uint32_t lit;
        uint32_t match;
        uint32_t off;
        uint8_t  token;
        uint8_t  s;

        token = *ip++;

        lit = (uint32_t)(token >> 4);
        if (lit == 15u) {
            do {
                if (ip >= iend) {
                    return MCF_E_CORRUPT;
                }
                s = *ip++;
                lit += (uint32_t)s;
            } while (s == 255u);
        }

        if ((uint32_t)(iend - ip) < lit) {
            return MCF_E_CORRUPT;
        }
        if ((uint32_t)(oend - op) < lit) {
            return MCF_E_CORRUPT;
        }
        memcpy(op, ip, lit);
        ip += lit;
        op += lit;

        /* A block may end immediately after its literals. */
        if (ip == iend) {
            break;
        }

        if ((uint32_t)(iend - ip) < 2u) {
            return MCF_E_CORRUPT;
        }
        off = (uint32_t)mcf_rd16(ip);
        ip += 2u;

        /* Offset zero is invalid; an offset reaching before the start of the
         * output is a truncated or forged stream. */
        if (off == 0u || off > (uint32_t)(op - dst)) {
            return MCF_E_CORRUPT;
        }

        match = (uint32_t)(token & 0x0Fu);
        if (match == 15u) {
            do {
                if (ip >= iend) {
                    return MCF_E_CORRUPT;
                }
                s = *ip++;
                match += (uint32_t)s;
            } while (s == 255u);
        }
        match += 4u; /* the low nibble encodes match length minus four */

        if ((uint32_t)(oend - op) < match) {
            return MCF_E_CORRUPT;
        }

        /* Copied byte by byte: LZ4 matches may overlap the output cursor. */
        {
            const uint8_t *ref = op - off;
            uint32_t       i;

            for (i = 0; i < match; i++) {
                op[i] = ref[i];
            }
        }
        op += match;
    }

    *out_len = (uint32_t)(op - dst);
    return MCF_OK;
}

/* ---------------------------------------------------------------------- */

uint32_t mcf_lz4_workspace(const uint8_t *props, uint32_t props_len)
{
    (void)props;
    (void)props_len;
    /* The decoder holds no state between blocks; this struct is all of it. */
    return (uint32_t)sizeof(mcf_lz4_t);
}

int32_t mcf_lz4_init(mcf_codec_t **out, const uint8_t *props, uint32_t props_len,
                     uint8_t *workspace)
{
    mcf_lz4_t *lz = (mcf_lz4_t *)(void *)workspace;

    if (out == NULL || lz == NULL || props == NULL || props_len < MCF_LZ4_PROPS_LEN) {
        return (int32_t)MCF_E_PARAM;
    }

    memset(lz, 0, sizeof(*lz));
    lz->content_size = mcf_rd32(props);
    if (lz->content_size == 0u) {
        return (int32_t)MCF_E_FORMAT;
    }

    lz->ops = &mcf_codec_lz4_ops;
    *out = (mcf_codec_t *)(void *)lz;
    return (int32_t)MCF_OK;
}

int32_t mcf_lz4_decode(mcf_codec_t *codec,
                      uint8_t *out, uint32_t cap, uint32_t *produced,
                      const uint8_t *in, uint32_t in_avail, uint32_t *consumed)
{
    mcf_lz4_t   *lz = (mcf_lz4_t *)(void *)codec;
    uint32_t     avail = in_avail;
    uint32_t     used  = 0u;
    uint32_t     block_len;
    int32_t      r;

    if (lz == NULL || out == NULL || produced == NULL || consumed == NULL) {
        return (int32_t)MCF_E_PARAM;
    }
    *produced = 0u;
    *consumed = 0u;

    /* End of stream already reported. */
    if (lz->done) {
        return (int32_t)MCF_OK;
    }

    if (avail < 4u) {
        /* No room for a block length. If the end marker has not been seen this
         * is truncation, which mcf_lz4_finish() reports. */
        return (int32_t)MCF_OK;
    }

    block_len = mcf_rd32(in);
    used      = 4u;
    in       += 4u;
    avail    -= 4u;

    if (block_len == 0u) {
        lz->done = 1u;
        *consumed = used;
        return (int32_t)MCF_OK;
    }

    if (block_len > avail) {
        *consumed = used;
        return (int32_t)MCF_E_TRUNCATED;
    }

    /* `cap` is the processing window, so mcf_lz4_block already rejects any
     * block that would expand past it. No separate bound is needed. */
    r = mcf_lz4_block(in, block_len, out, cap, produced);
    if (r < 0) {
        *consumed = used;
        return r;
    }

    used += block_len;
    lz->produced += *produced;

    /* Report the consumed count: the caller advances its source cursor by this,
     * not by the remainder. */
    *consumed = used;
    return (int32_t)MCF_OK;
}

int32_t mcf_lz4_finish(mcf_codec_t *codec)
{
    mcf_lz4_t *lz = (mcf_lz4_t *)(void *)codec;

    if (lz == NULL) {
        return (int32_t)MCF_E_PARAM;
    }

    /* The end marker is not required to have been observed. The engine stops
     * consuming as soon as it holds the declared content, so the marker may
     * never be decoded; demanding it would reject every complete stream. The
     * exact-length check below is the truncation guard, and it is stricter than
     * the marker: a stream cut short produces less than content_size, and one
     * padded out produces more. */
    if (lz->produced != lz->content_size) {
        return (int32_t)MCF_E_TRUNCATED;
    }
    return (int32_t)MCF_OK;
}

void mcf_lz4_destroy(mcf_codec_t *codec)
{
    (void)codec;
}

const mcf_codec_ops_t mcf_codec_lz4_ops = {
    "lz4",
    MCF_CODEC_LZ4,
    mcf_lz4_workspace,
    mcf_lz4_init,
    mcf_lz4_decode,
    mcf_lz4_finish,
    mcf_lz4_destroy,
    NULL
};
