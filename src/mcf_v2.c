/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - MFP2 structural inspection.
 *
 * Scope: this file parses and validates the MFP2 container shape only. It does
 * not decrypt, decode, reconstruct, or write flash, and it is not a session
 * path. v2 execution is deliberately deferred; see docs/format-v2-design.md for
 * the proposal and the decisions that gate it.
 *
 * What "structural" means here, precisely:
 *   - every header field is read at its fixed offset, little-endian
 *   - the TLV area is walked and unknown critical TLVs are rejected
 *   - the record area is walked once and must frame exactly payload_size bytes
 *     into exactly record_count records, with no trailing bytes
 *   - encrypted record framing includes one detached AEAD tag per record
 *     (framing validation does not itself authenticate those tags)
 *
 * The record walk happens in full during mcf_v2_parse(), so a caller that gets
 * MCF_OK holds a patch whose framing is known good. mcf_v2_next_record() is
 * then a linear cursor over that validated area, not a re-scan.
 */

#include "microfoam_v2.h"
#include "mcf_internal.h"

/* TLV area: u16 type, u16 flags, u32 length, value, zero padding to 4 bytes.
 * Bit 0 of flags means critical. Type 1 is the only critical type defined so
 * far, so any other critical type is an extension this build cannot honour and
 * the patch is rejected rather than half-understood. */
static mcf_status_t mcf_v2_walk_tlvs(const uint8_t *p, uint32_t n)
{
    uint32_t off = 0u;

    while (off < n) {
        uint16_t type;
        uint16_t flags;
        uint32_t len;

        if (n - off < 8u) {
            return MCF_E_FORMAT;
        }
        type  = mcf_rd16(&p[off]);
        flags = mcf_rd16(&p[off + 2u]);
        len   = mcf_rd32(&p[off + 4u]);
        if (len > n - off - 8u) {
            return MCF_E_FORMAT;
        }
        if ((flags & 1u) != 0u && type != 1u) {
            return MCF_E_FORMAT;
        }
        off += 8u + len;
        while ((off & 3u) != 0u) {
            if (off >= n || p[off] != 0u) {
                return MCF_E_FORMAT;
            }
            off++;
        }
    }
    return (off == n) ? MCF_OK : MCF_E_FORMAT;
}

/* Walk the record area once: `record_count` records of
 *   u32 length, payload[length], tag[16] (encrypted only)
 * which together must consume exactly `payload_size` bytes. This is what makes
 * record_count meaningful rather than advisory, and it is why a validated view
 * needs no further framing checks. */
static mcf_status_t mcf_v2_walk_records(const uint8_t *records,
                                        uint32_t payload_size,
                                        uint32_t record_count,
                                        uint32_t record_log2,
                                        int encrypted)
{
    uint32_t pos = 0u;
    uint32_t i;

    for (i = 0u; i < record_count; i++) {
        uint32_t len;

        if (payload_size - pos < 4u) {
            return MCF_E_FORMAT;
        }
        len = mcf_rd32(&records[pos]);
        pos += 4u;
        if (len == 0u || len > (1u << record_log2) || len > payload_size - pos) {
            return MCF_E_FORMAT;
        }
        pos += len;
        if (encrypted) {
            if (payload_size - pos < MCF_V2_RECORD_TAG_SIZE) {
                return MCF_E_FORMAT;
            }
            pos += MCF_V2_RECORD_TAG_SIZE;
        }
    }
    /* Exactly consumed. A short area means a missing record; a long one means
     * bytes no record claims. Both are malformed framing. */
    return (pos == payload_size) ? MCF_OK : MCF_E_FORMAT;
}

mcf_status_t mcf_v2_parse(const uint8_t *patch, uint32_t patch_size,
                          mcf_v2_view_t *out)
{
    uint32_t flags;
    uint16_t header_len;
    uint16_t tlv_len;
    uint8_t codec;
    uint32_t records;
    uint32_t payload_size;
    uint8_t log2;
    mcf_status_t st;

    if (patch == NULL || out == NULL || patch_size < MCF_V2_HEADER_MIN) {
        return MCF_E_PARAM;
    }
    memset(out, 0, sizeof(*out));
    if (mcf_rd32(&patch[MCF_V2_OFF_MAGIC]) != MCF_V2_MAGIC) return MCF_E_FORMAT;
    header_len = mcf_rd16(&patch[MCF_V2_OFF_HEADER_LEN]);
    if (header_len < MCF_V2_HEADER_MIN || header_len > MCF_V2_HEADER_MAX ||
        header_len > patch_size || (header_len & 3u) != 0u) return MCF_E_FORMAT;
    if (mcf_rd16(&patch[MCF_V2_OFF_VERSION]) != MCF_V2_VERSION) return MCF_E_UNSUPPORTED;
    flags = mcf_rd32(&patch[MCF_V2_OFF_FLAGS]);
    if ((flags & ~MCF_V2_KNOWN_FLAGS) != 0u) return MCF_E_FORMAT;
    if ((flags & (MCF_V2_FLAG_SIGNED | MCF_V2_FLAG_ENCRYPTED | MCF_V2_FLAG_CODEC_LZ4)) !=
        (MCF_V2_FLAG_SIGNED | MCF_V2_FLAG_ENCRYPTED | MCF_V2_FLAG_CODEC_LZ4) ||
        (flags & (MCF_V2_FLAG_CODEC_LZMA | MCF_V2_FLAG_RESUME_CHUNKS)) != 0u) {
        return MCF_E_UNSUPPORTED;
    }
    /* Encrypted records carry a detached tag after each ciphertext. Their
     * framing is safe to validate independently; authentication is performed
     * by the sodium adapter before plaintext is consumed. */
    if (mcf_rd32(&patch[MCF_V2_OFF_RESERVED]) != 0u ||
        mcf_rd32(&patch[MCF_V2_OFF_RESERVED + 4u]) != 0u ||
        memcmp(&patch[MCF_V2_OFF_HEADER_DIGEST], "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16u) != 0) {
        return MCF_E_FORMAT;
    }
    tlv_len = mcf_rd16(&patch[MCF_V2_OFF_TLV_LEN]);
    if ((uint32_t)tlv_len != (uint32_t)header_len - MCF_V2_HEADER_MIN) {
        return MCF_E_FORMAT;
    }
    st = mcf_v2_walk_tlvs(&patch[MCF_V2_HEADER_MIN], tlv_len);
    if (st != MCF_OK) {
        return st;
    }
    codec = patch[MCF_V2_OFF_CODEC];
    if (codec != (uint8_t)MCF_CODEC_LZ4) return MCF_E_UNSUPPORTED;
    if (mcf_rd32(&patch[MCF_V2_OFF_CODEC_PROFILE]) != 0u) return MCF_E_UNSUPPORTED;
    log2 = patch[MCF_V2_OFF_RECORD_LOG2];
    if (log2 < MCF_V2_RECORD_LOG2_MIN || log2 > MCF_V2_RECORD_LOG2_MAX) return MCF_E_FORMAT;
    if (memcmp(&patch[MCF_V2_OFF_KEY_ID], "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", MCF_V2_KEY_ID_SIZE) == 0 ||
        memcmp(&patch[MCF_V2_OFF_NONCE_PREFIX + MCF_V2_NONCE_PREFIX_SIZE], "\0\0\0\0\0\0\0\0", 8u) != 0) {
        return MCF_E_FORMAT;
    }
    records = mcf_rd32(&patch[MCF_V2_OFF_RECORD_COUNT]);
    if (records == 0u) return MCF_E_FORMAT;
    payload_size = mcf_rd32(&patch[MCF_V2_OFF_PAYLOAD_SIZE]);
    if (payload_size > patch_size - header_len) {
        return MCF_E_TRUNCATED;
    }
    if (payload_size != patch_size - header_len) {
        return MCF_E_FORMAT;
    }

    /* The record area must frame exactly. Done here, not lazily, so a validated
     * view is a guarantee rather than an invitation to re-scan. */
    st = mcf_v2_walk_records(&patch[header_len], payload_size, records, log2,
                             (flags & MCF_V2_FLAG_ENCRYPTED) != 0u);
    if (st != MCF_OK) {
        return st;
    }

    out->header_len = header_len;
    out->version = MCF_V2_VERSION;
    out->flags = flags;
    out->product_id = mcf_rd32(&patch[MCF_V2_OFF_PRODUCT]);
    out->fw_version = mcf_rd32(&patch[MCF_V2_OFF_FW_VERSION]);
    out->old_size = mcf_rd32(&patch[MCF_V2_OFF_OLD_SIZE]);
    out->new_size = mcf_rd32(&patch[MCF_V2_OFF_NEW_SIZE]);
    out->payload_size = payload_size;
    out->workspace_req = mcf_rd32(&patch[MCF_V2_OFF_WORKSPACE]);
    out->old_version = mcf_rd32(&patch[MCF_V2_OFF_OLD_VERSION]);
    out->codec_id = codec;
    out->record_log2 = log2;
    out->tlv_len = tlv_len;
    out->record_count = records;
    out->codec_profile = mcf_rd32(&patch[MCF_V2_OFF_CODEC_PROFILE]);
    out->tlvs = &patch[MCF_V2_HEADER_MIN];
    out->records = &patch[header_len];
    return MCF_OK;
}

mcf_status_t mcf_v2_next_record(const mcf_v2_view_t *view, const uint8_t *patch,
                                uint32_t patch_size, uint32_t *offset,
                                mcf_v2_record_t *out)
{
    uint32_t pos;
    uint32_t end;
    uint32_t len;
    uint32_t index;

    if (view == NULL || patch == NULL || offset == NULL || out == NULL) return MCF_E_PARAM;

    end = (uint32_t)view->header_len + view->payload_size;
    if (end > patch_size) return MCF_E_TRUNCATED;

    /* Linear cursor. *offset == 0 starts the walk; afterwards *offset is the
     * byte position the previous call left off at, and the record index is
     * carried in out->index. The framing was validated by mcf_v2_parse(), so
     * this only has to bound-check. */
    if (*offset == 0u) {
        pos = (uint32_t)view->header_len;
        index = 0u;
    } else {
        if (*offset < view->header_len || *offset > end) return MCF_E_FORMAT;
        pos = *offset;
        index = out->index + 1u;
    }
    if (pos == end) {
        return MCF_E_NOT_FOUND;
    }
    if (index >= view->record_count) {
        return MCF_E_FORMAT;
    }
    if (end - pos < 4u) {
        return MCF_E_FORMAT;
    }

    len = mcf_rd32(&patch[pos]);
    pos += 4u;
    if (len == 0u || len > (1u << view->record_log2) || len > end - pos) {
        return MCF_E_FORMAT;
    }
    out->index = index;
    out->data = &patch[pos];
    out->data_len = len;
    pos += len;
    if ((view->flags & MCF_V2_FLAG_ENCRYPTED) != 0u) {
        if (end - pos < MCF_V2_RECORD_TAG_SIZE) return MCF_E_FORMAT;
        out->tag = &patch[pos];
        out->tag_len = MCF_V2_RECORD_TAG_SIZE;
        pos += MCF_V2_RECORD_TAG_SIZE;
    } else {
        out->tag = NULL;
        out->tag_len = 0u;
    }
    *offset = pos;
    return MCF_OK;
}
