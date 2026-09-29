/* SPDX-License-Identifier: MIT */
#include "microfoam_v2.h"
#include "mcf_internal.h"

static int critical_tlv_unknown(const uint8_t *p, uint32_t n)
{
    uint32_t off = 0u;
    uint16_t type;
    uint16_t flags;
    uint32_t len;
    while (off < n) {
        if (n - off < 8u) return 1;
        type = mcf_rd16(&p[off]);
        flags = mcf_rd16(&p[off + 2u]);
        len = mcf_rd32(&p[off + 4u]);
        if (len > n - off - 8u) return 1;
        if ((flags & 1u) != 0u && type != 1u) return 1;
        off += 8u + len;
        while ((off & 3u) != 0u) {
            if (off >= n || p[off] != 0u) return 1;
            off++;
        }
    }
    return off != n;
}

mcf_status_t mcf_v2_parse(const uint8_t *patch, uint32_t patch_size,
                          mcf_v2_view_t *out)
{
    uint32_t flags;
    uint16_t header_len;
    uint16_t tlv_len;
    uint8_t codec;
    uint32_t records;
    uint8_t log2;

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
    if ((flags & MCF_V2_FLAG_CODEC_LZ4) != 0u &&
        (flags & MCF_V2_FLAG_CODEC_LZMA) != 0u) return MCF_E_FORMAT;
    if ((flags & MCF_V2_FLAG_ENCRYPTED) != 0u) return MCF_E_UNSUPPORTED;
    if (mcf_rd32(&patch[MCF_V2_OFF_RESERVED]) != 0u ||
        mcf_rd32(&patch[MCF_V2_OFF_RESERVED + 4u]) != 0u ||
        memcmp(&patch[MCF_V2_OFF_HEADER_DIGEST], "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16u) != 0) {
        return MCF_E_FORMAT;
    }
    tlv_len = mcf_rd16(&patch[MCF_V2_OFF_TLV_LEN]);
    if ((uint32_t)tlv_len != (uint32_t)header_len - MCF_V2_HEADER_MIN ||
        critical_tlv_unknown(&patch[MCF_V2_HEADER_MIN], tlv_len) != 0) return MCF_E_FORMAT;
    codec = patch[MCF_V2_OFF_CODEC];
    if (codec != (uint8_t)MCF_CODEC_LZ4 && codec != (uint8_t)MCF_CODEC_LZMA &&
        codec < (uint8_t)MCF_CODEC_CUSTOM_MIN) return MCF_E_UNSUPPORTED;
    if ((codec == (uint8_t)MCF_CODEC_LZ4) && !(flags & MCF_V2_FLAG_CODEC_LZ4)) return MCF_E_FORMAT;
    if ((codec == (uint8_t)MCF_CODEC_LZMA) && !(flags & MCF_V2_FLAG_CODEC_LZMA)) return MCF_E_FORMAT;
    log2 = patch[MCF_V2_OFF_RECORD_LOG2];
    if (log2 < 8u || log2 > 16u) return MCF_E_FORMAT;
    records = mcf_rd32(&patch[MCF_V2_OFF_RECORD_COUNT]);
    if (records == 0u) return MCF_E_FORMAT;
    if (mcf_rd32(&patch[MCF_V2_OFF_PAYLOAD_SIZE] ) > patch_size - header_len) return MCF_E_TRUNCATED;
    out->header_len = header_len;
    out->version = MCF_V2_VERSION;
    out->flags = flags;
    out->product_id = mcf_rd32(&patch[MCF_V2_OFF_PRODUCT]);
    out->fw_version = mcf_rd32(&patch[MCF_V2_OFF_FW_VERSION]);
    out->old_size = mcf_rd32(&patch[MCF_V2_OFF_OLD_SIZE]);
    out->new_size = mcf_rd32(&patch[MCF_V2_OFF_NEW_SIZE]);
    out->payload_size = mcf_rd32(&patch[MCF_V2_OFF_PAYLOAD_SIZE]);
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
    if ((view->flags & MCF_V2_FLAG_ENCRYPTED) != 0u) return MCF_E_UNSUPPORTED;
    end = (uint32_t)view->header_len + view->payload_size;
    if (end > patch_size) return MCF_E_TRUNCATED;
    pos = (*offset == 0u) ? (uint32_t)view->header_len : *offset;
    if (pos == end) return MCF_E_NOT_FOUND;
    if (pos < view->header_len || pos > end || end - pos < 4u) return MCF_E_TRUNCATED;
    index = 0u;
    {
        uint32_t scan = (uint32_t)view->header_len;
        while (scan < pos) {
            uint32_t prior;
            if (end - scan < 4u) return MCF_E_TRUNCATED;
            prior = mcf_rd32(&patch[scan]);
            if (prior == 0u || prior > end - scan - 4u) return MCF_E_FORMAT;
            scan += 4u + prior;
            index++;
        }
        if (scan != pos || index >= view->record_count) return MCF_E_FORMAT;
    }
    len = mcf_rd32(&patch[pos]);
    pos += 4u;
    if (len == 0u || len > (1u << view->record_log2) || len > end - pos) return MCF_E_FORMAT;
    out->index = index;
    out->data = &patch[pos];
    out->data_len = len;
    out->tag = NULL;
    out->tag_len = 0u;
    pos += len;
    *offset = pos;
    return MCF_OK;
}
