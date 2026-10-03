/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - shared MFP1 patch-construction fixture (test-only).
 *
 * Two suites build a valid patch by hand: the fault-injection suite
 * (test_microfoam.c) and the reentrancy suite (hal_concurrency_test.c). Keeping
 * one builder means they cannot drift into describing different formats. The
 * output is byte-identical to host/microfoam.py's, which is what lets the C
 * suites stand in for the host tool without shelling out to Python.
 *
 * The delta is emitted as many control triples of one chunk each rather than a
 * single giant triple: a resume checkpoint can only be taken at a triple
 * boundary, so the fixture must have interior boundaries the way real firmware
 * deltas do. The LZ4 stream is chunked to exactly block_size, matching the
 * device's decode buffer - a format constraint, not a convenience, because the
 * device rejects a block that would overflow that buffer.
 */
#ifndef MCF_PATCH_FIXTURE_H
#define MCF_PATCH_FIXTURE_H

#include "microfoam.h"

#include <string.h>

/* Output bytes of a control triple per chunk of reconstructed image. */
#define MCF_FX_CHUNK 256u

/* Scratch for the delta and the framed stream. Generous for the image sizes
 * these suites use; the builder returns 0 rather than overflowing it. */
#define MCF_FX_SCRATCH 8192u

static inline void mcf_fx_wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static inline void mcf_fx_wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

/* BSDIFF43 sign-magnitude control triple. */
static inline uint8_t *mcf_fx_put_ctrl(uint8_t *p, int32_t x, int32_t y, int32_t seek)
{
    int32_t vals[3];
    int     i;

    vals[0] = x; vals[1] = y; vals[2] = seek;
    for (i = 0; i < 3; i++) {
        uint64_t m    = (uint64_t)(vals[i] < 0 ? -vals[i] : vals[i]);
        uint8_t  sign = (vals[i] < 0) ? 0x80u : 0x00u;
        int      b;

        for (b = 0; b < 8; b++) {
            uint8_t byte = (uint8_t)((m >> (8 * b)) & 0xFFu);
            if (b == 7) {
                byte = (uint8_t)((byte & 0x7Fu) | sign);
            }
            *p++ = byte;
        }
    }
    return p;
}

/* One LZ4 block containing only literals. High nibble of the token is the
 * literal length, 15 meaning "continued in the following bytes". */
static inline uint8_t *mcf_fx_lz4_literal_block(uint8_t *p, const uint8_t *data,
                                                uint32_t n)
{
    if (n < 15u) {
        *p++ = (uint8_t)(n << 4);
    } else {
        uint32_t rem = n - 15u;
        *p++ = 0xF0u;
        while (rem >= 255u) {
            *p++ = 0xFFu;
            rem -= 255u;
        }
        *p++ = (uint8_t)rem;
    }
    memcpy(p, data, n);
    return p + n;
}

/*
 * Build a valid patch into `out` (`out` must have room for the header plus the
 * framed stream; `out_cap` is checked). `newb` is reconstructed as
 * old[i] + delta[i]. Returns the patch length, or 0 if it would not fit.
 */
static inline uint32_t mcf_fx_build_patch(uint8_t *out, uint32_t out_cap,
                                          const uint8_t *old, uint32_t old_len,
                                          const uint8_t *newb, uint32_t new_len,
                                          uint32_t product, uint32_t new_ver,
                                          uint32_t old_ver, uint32_t workspace_req,
                                          uint32_t flags, uint32_t block_log2)
{
    static uint8_t delta[MCF_FX_SCRATCH];
    static uint8_t stream[MCF_FX_SCRATCH];
    uint32_t block_size = 1u << block_log2;
    uint32_t delta_len = 0;
    uint32_t sp = 0;
    uint32_t off;
    uint32_t n;

    if (out == NULL || block_log2 == 0u || block_log2 > 20u) {
        return 0u;
    }

    for (off = 0; off < new_len; off += MCF_FX_CHUNK) {
        n = new_len - off;
        if (n > MCF_FX_CHUNK) {
            n = MCF_FX_CHUNK;
        }
        if (delta_len + 24u + n > MCF_FX_SCRATCH) {
            return 0u;
        }
        mcf_fx_put_ctrl(delta + delta_len, (int32_t)n, 0, 0);
        delta_len += 24;
        {
            uint32_t k;
            for (k = 0; k < n; k++) {
                uint8_t base = ((off + k) < old_len) ? old[off + k] : 0u;
                delta[delta_len++] = (uint8_t)(newb[off + k] - base);
            }
        }
    }

    /* LZ4 framing: one literal block per block_size slice, then the end marker. */
    for (off = 0; off < delta_len; off += block_size) {
        uint32_t m = delta_len - off;
        uint8_t *blk;
        uint8_t *end;

        if (m > block_size) {
            m = block_size;
        }
        /* The block body goes *after* the 4-byte length prefix, not on top of
         * it. Writing the body at &stream[sp] and then stamping the length at
         * &stream[sp] clobbers the token byte. */
        if (sp + 4u + m + 8u > MCF_FX_SCRATCH) {
            return 0u;
        }
        blk = &stream[sp + 4u];
        end = mcf_fx_lz4_literal_block(blk, &delta[off], m);
        mcf_fx_wr32(&stream[sp], (uint32_t)(end - blk));
        sp += 4u + (uint32_t)(end - blk);
    }
    if (sp + 4u > MCF_FX_SCRATCH) {
        return 0u;
    }
    mcf_fx_wr32(&stream[sp], 0u);
    sp += 4u;

    if (out_cap < MCF_HDR_MIN_SIZE + 4u + sp) {
        return 0u;
    }

    memset(out, 0, MCF_HDR_MIN_SIZE);
    mcf_fx_wr32(&out[MCF_OFF_MAGIC], MCF_HDR_MAGIC);
    mcf_fx_wr16(&out[MCF_OFF_HDR_LEN], (uint16_t)MCF_HDR_MIN_SIZE);
    mcf_fx_wr16(&out[MCF_OFF_HDR_VER],
                (uint16_t)((MCF_HDR_VER_MAJOR << 8) | MCF_HDR_VER_MINOR));
    mcf_fx_wr32(&out[MCF_OFF_FLAGS], flags | MCF_FLAG_CODEC_LZ4);
    mcf_fx_wr32(&out[MCF_OFF_PRODUCT_ID], product);
    mcf_fx_wr32(&out[MCF_OFF_FW_VERSION], new_ver);
    mcf_fx_wr32(&out[MCF_OFF_OLD_SIZE], old_len);
    mcf_fx_wr32(&out[MCF_OFF_NEW_SIZE], new_len);
    mcf_fx_wr32(&out[MCF_OFF_PAYLOAD_SIZE], 4u + sp);
    mcf_fx_wr32(&out[MCF_OFF_OLD_CRC32], mcf_crc32(old, old_len));
    mcf_fx_wr32(&out[MCF_OFF_NEW_CRC32], mcf_crc32(newb, new_len));
    mcf_fx_wr32(&out[MCF_OFF_PAYLOAD_CRC32], mcf_crc32(stream, sp));
    mcf_fx_wr32(&out[MCF_OFF_WORKSPACE_REQ], workspace_req);
    mcf_fx_wr32(&out[MCF_OFF_OLD_VERSION], old_ver);
    out[MCF_OFF_CODEC_ID]   = (uint8_t)MCF_CODEC_LZ4;
    out[MCF_OFF_BLOCK_LOG2] = (uint8_t)block_log2;
    mcf_fx_wr16(&out[MCF_OFF_RESERVED], 0u);

    mcf_fx_wr32(&out[MCF_HDR_MIN_SIZE], delta_len);       /* codec properties */
    memcpy(&out[MCF_HDR_MIN_SIZE + 4], stream, sp);

    return (uint32_t)MCF_HDR_MIN_SIZE + 4u + sp;
}

#endif /* MCF_PATCH_FIXTURE_H */
