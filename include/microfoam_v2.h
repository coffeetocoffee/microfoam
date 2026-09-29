/* SPDX-License-Identifier: MIT */
#ifndef MICROFOAM_V2_H
#define MICROFOAM_V2_H

#include "microfoam.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MCF_V2_MAGIC 0x3250464Du /* MFP2 */
#define MCF_V2_HEADER_MIN 192u
#define MCF_V2_HEADER_MAX 4096u
#define MCF_V2_VERSION 0x0200u
#define MCF_V2_FLAG_SIGNED 0x00000001u
#define MCF_V2_FLAG_ENCRYPTED 0x00000002u
#define MCF_V2_FLAG_CODEC_LZMA 0x00000004u
#define MCF_V2_FLAG_CODEC_LZ4 0x00000008u
#define MCF_V2_FLAG_RESUME_CHUNKS 0x00000010u
#define MCF_V2_KNOWN_FLAGS (MCF_V2_FLAG_SIGNED | MCF_V2_FLAG_ENCRYPTED | \
                           MCF_V2_FLAG_CODEC_LZMA | MCF_V2_FLAG_CODEC_LZ4 | \
                           MCF_V2_FLAG_RESUME_CHUNKS)
#define MCF_V2_RECORD_TAG_SIZE 16u

/* Fixed v2 offsets. */
#define MCF_V2_OFF_MAGIC 0u
#define MCF_V2_OFF_HEADER_LEN 4u
#define MCF_V2_OFF_VERSION 6u
#define MCF_V2_OFF_FLAGS 8u
#define MCF_V2_OFF_PRODUCT 12u
#define MCF_V2_OFF_FW_VERSION 16u
#define MCF_V2_OFF_OLD_SIZE 20u
#define MCF_V2_OFF_NEW_SIZE 24u
#define MCF_V2_OFF_PAYLOAD_SIZE 28u
#define MCF_V2_OFF_OLD_CRC 32u
#define MCF_V2_OFF_NEW_CRC 36u
#define MCF_V2_OFF_PAYLOAD_CRC 40u
#define MCF_V2_OFF_WORKSPACE 44u
#define MCF_V2_OFF_OLD_VERSION 48u
#define MCF_V2_OFF_CODEC 52u
#define MCF_V2_OFF_RECORD_LOG2 53u
#define MCF_V2_OFF_TLV_LEN 54u
#define MCF_V2_OFF_SIGNATURE 56u
#define MCF_V2_OFF_KEY_ID 120u
#define MCF_V2_OFF_NONCE_PREFIX 136u
#define MCF_V2_OFF_RECORD_COUNT 160u
#define MCF_V2_OFF_CODEC_PROFILE 164u
#define MCF_V2_OFF_RESERVED 168u
#define MCF_V2_OFF_HEADER_DIGEST 176u

typedef struct mcf_v2_view {
    uint16_t header_len;
    uint16_t version;
    uint32_t flags;
    uint32_t product_id;
    uint32_t fw_version;
    uint32_t old_size;
    uint32_t new_size;
    uint32_t payload_size;
    uint32_t workspace_req;
    uint32_t old_version;
    uint8_t codec_id;
    uint8_t record_log2;
    uint16_t tlv_len;
    uint32_t record_count;
    uint32_t codec_profile;
    const uint8_t *tlvs;
    const uint8_t *records;
} mcf_v2_view_t;

typedef struct mcf_v2_record {
    uint32_t index;
    const uint8_t *data;
    uint32_t data_len;
    const uint8_t *tag;
    uint32_t tag_len;
} mcf_v2_record_t;

/* Structural parser only. It never decrypts, decodes, or writes flash. */
mcf_status_t mcf_v2_parse(const uint8_t *patch, uint32_t patch_size,
                          mcf_v2_view_t *out);

/* Iterate unencrypted records. Encrypted records are rejected until the v2 AEAD
 * provider is implemented. Pass *offset=MCF_V2_HEADER_MIN on first call. */
mcf_status_t mcf_v2_next_record(const mcf_v2_view_t *view, const uint8_t *patch,
                                uint32_t patch_size, uint32_t *offset,
                                mcf_v2_record_t *out);

#ifdef __cplusplus
}
#endif

#endif /* MICROFOAM_V2_H */
