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
#define MCF_V2_FLAG_CODEC_LZMA 0x00000004u /* Reserved; forbidden in executable v2 profile. */
#define MCF_V2_FLAG_CODEC_LZ4 0x00000008u
#define MCF_V2_FLAG_RESUME_CHUNKS 0x00000010u
#define MCF_V2_KNOWN_FLAGS (MCF_V2_FLAG_SIGNED | MCF_V2_FLAG_ENCRYPTED | \
                           MCF_V2_FLAG_CODEC_LZMA | MCF_V2_FLAG_CODEC_LZ4 | \
                           MCF_V2_FLAG_RESUME_CHUNKS)
#define MCF_V2_EXEC_REQUIRED_FLAGS (MCF_V2_FLAG_SIGNED | MCF_V2_FLAG_ENCRYPTED | \
                                    MCF_V2_FLAG_CODEC_LZ4)
#define MCF_V2_RECORD_TAG_SIZE 16u
#define MCF_V2_RECORD_LOG2_MIN 8u
#define MCF_V2_RECORD_LOG2_MAX 13u
#define MCF_V2_RECORD_MAX_SIZE (1u << MCF_V2_RECORD_LOG2_MAX)
#define MCF_V2_KEY_ID_SIZE 16u
#define MCF_V2_KEY_SIZE 32u
#define MCF_V2_NONCE_PREFIX_SIZE 16u
#define MCF_V2_NONCE_SIZE 24u
#define MCF_V2_AEAD_AD_PREFIX "MCF2REC\0"
#define MCF_V2_SIGNATURE_DOMAIN "MCF2SIG\0"

/* Fixed v2 offsets. These remain the wire layout; do not pack a C struct over it. */
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

/* Key-provider contract for the future execution API (declaration only).
 * On MCF_OK, provide exactly 32 key bytes in out_key. The output buffer is
 * library-owned, writable, and must be wiped by the caller immediately after
 * the operation that needs the key; implementations must wipe every internal
 * key copy on every exit path using a non-optimizable zeroization primitive.
 * The callback context and provider must remain valid for the full operation.
 * No key is retained across operations or stored in the patch/configuration. */
typedef mcf_status_t (*mcf_v2_key_provider_fn)(void *ctx,
                                               const uint8_t key_id[MCF_V2_KEY_ID_SIZE],
                                               uint8_t out_key[MCF_V2_KEY_SIZE]);

/* Structural parser only; never decrypts, decodes, verifies signatures, or
 * writes flash, and is not a session path. A successful parse means only that
 * the container shape is valid, not that the patch is authentic or acceptable.
 * The inspection parser may inspect the currently supported structural subset;
 * this is not permission to execute an unsigned, plaintext, or non-LZ4 patch. */
mcf_status_t mcf_v2_parse(const uint8_t *patch, uint32_t patch_size,
                          mcf_v2_view_t *out);

/* Linear iteration over an unencrypted record area that mcf_v2_parse() has
 * already validated.
 *
 * Call with *offset == 0 to start; thereafter pass the same `out` back in and
 * the function advances by carrying the record index in `out->index`. Returns
 * MCF_E_NOT_FOUND when the area is exhausted. */
mcf_status_t mcf_v2_next_record(const mcf_v2_view_t *view, const uint8_t *patch,
                                uint32_t patch_size, uint32_t *offset,
                                mcf_v2_record_t *out);

#ifdef __cplusplus
}
#endif

#endif /* MICROFOAM_V2_H */
