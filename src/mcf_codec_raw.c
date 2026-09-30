/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - raw (uncompressed) codec.
 *
 * The payload is the BSDIFF43 delta stream verbatim: no compression framing, no
 * properties block, no per-block headers. A patch may declare this when the
 * delta is too small for a codec's framing overhead to pay for itself, or when
 * the producer knows the delta is incompressible.
 *
 * What this does not do
 * ---------------------
 * It does not weaken any integrity check. The header still carries old/new/
 * payload CRCs and the payload CRC still covers these bytes; the delta engine
 * still bounds-checks every control triple; the whole-image CRC still runs
 * against flash. A truncated raw payload fails in the engine as MCF_E_TRUNCATED
 * rather than passing silently, because the control triples must reconstruct
 * exactly new_size bytes.
 *
 * Input convention matches LZ4: the engine hands a sliding window, so `decode`
 * is stateless and copies from the current (input, avail) pair.
 */

#include "mcf_internal.h"

#include "mcf_codec_raw.h"

#include <string.h>

uint32_t mcf_raw_workspace(const uint8_t *props, uint32_t props_len)
{
    (void)props;
    (void)props_len;
    /* Never 0: the session treats a zero workspace requirement as a malformed
     * patch. The state block is where sizeof(mcf_raw_t) is checked. */
    return (uint32_t)sizeof(mcf_raw_t);
}

int32_t mcf_raw_init(mcf_codec_t **out, const uint8_t *props, uint32_t props_len,
                     uint8_t *workspace)
{
    mcf_raw_t *raw = (mcf_raw_t *)(void *)workspace;

    /* Raw has no properties; the parser reports props_len 0 and passes props
     * pointing at the payload. Accepting either NULL or non-NULL here keeps the
     * codec usable from a direct caller. */
    (void)props;
    (void)props_len;

    if (out == NULL || raw == NULL) {
        return (int32_t)MCF_E_PARAM;
    }
    memset(raw, 0, sizeof(*raw));
    raw->ops = &mcf_codec_raw_ops;
    *out = (mcf_codec_t *)(void *)raw;
    return (int32_t)MCF_OK;
}

int32_t mcf_raw_decode(mcf_codec_t *codec,
                       uint8_t *out, uint32_t cap, uint32_t *produced,
                       const uint8_t *in, uint32_t in_avail, uint32_t *consumed)
{
    mcf_raw_t *raw = (mcf_raw_t *)(void *)codec;
    uint32_t   n;

    if (raw == NULL || out == NULL || produced == NULL || consumed == NULL ||
        (in == NULL && in_avail != 0u)) {
        return (int32_t)MCF_E_PARAM;
    }
    *produced = 0u;
    *consumed = 0u;

    n = (in_avail < cap) ? in_avail : cap;
    if (n != 0u) {
        memcpy(out, in, n);
    }
    raw->produced += n;
    *produced = n;
    *consumed = n;
    return (int32_t)MCF_OK;
}

int32_t mcf_raw_finish(mcf_codec_t *codec)
{
    if (codec == NULL) {
        return (int32_t)MCF_E_PARAM;
    }
    /* Nothing to assert here: whether the delta reconstructed the right image is
     * the engine's and the whole-image CRC's judgement, not the codec's. A raw
     * payload that ended early leaves the engine short of new_size and it
     * reports MCF_E_TRUNCATED; one that ran long is bounded by the same check. */
    return (int32_t)MCF_OK;
}

void mcf_raw_destroy(mcf_codec_t *codec)
{
    (void)codec;
}

const mcf_codec_ops_t mcf_codec_raw_ops = {
    "raw",
    MCF_CODEC_RAW,
    mcf_raw_workspace,
    mcf_raw_init,
    mcf_raw_decode,
    mcf_raw_finish,
    mcf_raw_destroy,
    NULL
};
