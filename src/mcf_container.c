/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - patch container: header parse and validation.
 *
 * Validation happens exactly once, here. Everything downstream operates on the
 * mcf_hdr_view_t produced by this file and trusts it. See docs/architecture.md
 * sections 7.4 and 13.4.
 */

#include "mcf_internal.h"

/* The convenience view must agree with the on-wire offsets byte for byte. The
 * C reference asserts this; the Python host tool asserts the same table, and a
 * mismatch fails the build rather than corrupting a field. */
typedef char mcf_hdr_size_ok[(sizeof(mcf_header_t) == MCF_HDR_MIN_SIZE) ? 1 : -1];
typedef char mcf_hdr_off_magic[offsetof(mcf_header_t, magic) == MCF_OFF_MAGIC ? 1 : -1];
typedef char mcf_hdr_off_ver[offsetof(mcf_header_t, hdr_ver) == MCF_OFF_HDR_VER ? 1 : -1];
typedef char mcf_hdr_off_crc[offsetof(mcf_header_t, new_crc32) == MCF_OFF_NEW_CRC32 ? 1 : -1];
typedef char mcf_hdr_off_ws[offsetof(mcf_header_t, workspace_req) == MCF_OFF_WORKSPACE_REQ ? 1 : -1];
typedef char mcf_hdr_off_sig[offsetof(mcf_header_t, signature) == MCF_OFF_SIGNATURE ? 1 : -1];

/* ---------------------------------------------------------------------- *
 * Signature verification.
 *
 * Fails closed. Without a verifier supplied through the HAL there is no way to
 * check a signature, so a patch that claims to be signed is rejected rather than
 * accepted unverified. Integrators supply mcf_verify_fn backed by a vetted
 * cryptographic provider or hardware root of trust.
 * ---------------------------------------------------------------------- */
mcf_status_t mcf_hdr_verify(const mcf_hal_t *hal, mcf_verify_fn verify,
                            void *verify_ctx, const uint8_t *patch,
                            const mcf_hdr_view_t *v)
{
    int32_t r;

    if (verify == NULL && hal != NULL) {
        verify = hal->verify;
        verify_ctx = hal->ctx;
    }
    if (verify == NULL) {
        return MCF_E_SIGNATURE;
    }

    /* The signed format is header[0..55] followed by the compressed stream;
     * codec properties and the signature field are excluded. */
    {
        uint32_t stream_len = v->payload_size - v->props_len;
        r = verify(verify_ctx, &patch[MCF_OFF_SIGNATURE],
                   (uint32_t)MCF_SIG_SIZE, patch,
                   (uint32_t)MCF_SIGNED_HEADER_LEN, v->payload, stream_len);
    }
    if (r < 0) {
        return MCF_E_SIGNATURE;
    }
    return MCF_OK;
}

/* ---------------------------------------------------------------------- */

mcf_status_t mcf_hdr_parse(const mcf_hal_t *hal, const mcf_config_t *cfg,
                           const uint8_t *patch, uint32_t patch_size,
                           mcf_hdr_view_t *out, uint32_t *site)
{
    const uint8_t *h;
    uint32_t        payload_avail;
    uint32_t        props_len;
    uint32_t        cur_version;
    uint32_t        block_size;
    uint32_t        budget;

    *site = MCF_SITE_HDR_MAGIC;
    memset(out, 0, sizeof(*out));

    if (patch == NULL || hal == NULL || cfg == NULL) {
        return MCF_E_PARAM;
    }

    budget = cfg->ram_budget;

    if (patch_size < MCF_HDR_MIN_SIZE) {
        *site = MCF_SITE_HDR_TRUNCATED;
        return MCF_E_TRUNCATED;
    }

    h = patch;

    /* 1. magic */
    if (mcf_rd32(&h[MCF_OFF_MAGIC]) != MCF_HDR_MAGIC) {
        *site = MCF_SITE_HDR_MAGIC;
        return MCF_E_FORMAT;
    }

    out->hdr_len = mcf_rd16(&h[MCF_OFF_HDR_LEN]);
    out->hdr_ver = mcf_rd16(&h[MCF_OFF_HDR_VER]);

    /* 2. major version */
    *site = MCF_SITE_HDR_VER;
    if ((uint16_t)(out->hdr_ver >> 8) != (uint16_t)MCF_HDR_VER_MAJOR) {
        return MCF_E_UNSUPPORTED;
    }

    /* 3. header length bounds */
    *site = MCF_SITE_HDR_LEN;
    if (out->hdr_len < MCF_HDR_MIN_SIZE || out->hdr_len > MCF_HDR_MAX_SIZE ||
        (uint32_t)out->hdr_len > patch_size) {
        return MCF_E_FORMAT;
    }

    /* 4. product binding */
    *site = MCF_SITE_HDR_PRODUCT;
    out->product_id = mcf_rd32(&h[MCF_OFF_PRODUCT_ID]);
    if (out->product_id != hal->get_product_id(hal->ctx)) {
        return MCF_E_PRODUCT;
    }

    /* 5. anti-rollback */
    *site = MCF_SITE_HDR_ROLLBACK;
    cur_version = hal->get_fw_version(hal->ctx);
    out->fw_version = mcf_rd32(&h[MCF_OFF_FW_VERSION]);
    if (out->fw_version <= cur_version) {
        return MCF_E_ROLLBACK;
    }

    /* 6. base image version pinning */
    *site = MCF_SITE_HDR_OLDVER;
    out->old_version = mcf_rd32(&h[MCF_OFF_OLD_VERSION]);
    if (out->old_version != cur_version) {
        return MCF_E_MISMATCH;
    }

    out->flags         = mcf_rd32(&h[MCF_OFF_FLAGS]);
    out->old_size      = mcf_rd32(&h[MCF_OFF_OLD_SIZE]);
    out->new_size      = mcf_rd32(&h[MCF_OFF_NEW_SIZE]);
    out->payload_size  = mcf_rd32(&h[MCF_OFF_PAYLOAD_SIZE]);
    out->old_crc32     = mcf_rd32(&h[MCF_OFF_OLD_CRC32]);
    out->new_crc32     = mcf_rd32(&h[MCF_OFF_NEW_CRC32]);
    out->payload_crc32 = mcf_rd32(&h[MCF_OFF_PAYLOAD_CRC32]);
    out->workspace_req = mcf_rd32(&h[MCF_OFF_WORKSPACE_REQ]);
    out->codec_id      = h[MCF_OFF_CODEC_ID];
    out->block_log2    = h[MCF_OFF_BLOCK_LOG2];

    /* Reserved bits and codec markers are part of the wire contract. Reject
     * values that a newer producer could otherwise make ambiguous. */
    *site = MCF_SITE_HDR_CODEC;
    if (mcf_rd16(&h[MCF_OFF_RESERVED]) != 0u ||
        (out->flags & ~(MCF_FLAG_SIGNED | MCF_FLAG_RAW |
                        MCF_FLAG_CODEC_LZMA | MCF_FLAG_CODEC_LZ4)) != 0u ||
        (out->flags & MCF_FLAG_RAW) != 0u ||
        ((out->flags & MCF_FLAG_CODEC_LZ4) != 0u &&
         out->codec_id != (uint8_t)MCF_CODEC_LZ4) ||
        ((out->flags & MCF_FLAG_CODEC_LZMA) != 0u &&
         out->codec_id != (uint8_t)MCF_CODEC_LZMA)) {
        return MCF_E_FORMAT;
    }

    /* 7. codec must be known to this build, and must match what the caller
     *    asked for unless the caller said AUTO. */
    *site = MCF_SITE_HDR_CODEC;
    if (out->codec_id == (uint8_t)MCF_CODEC_AUTO ||
        (out->codec_id >= (uint8_t)MCF_CODEC_MAX &&
         out->codec_id < (uint8_t)MCF_CODEC_CUSTOM_MIN)) {
        return MCF_E_UNSUPPORTED;
    }
    if (cfg->codec != MCF_CODEC_AUTO && cfg->codec != (mcf_codec_id_t)out->codec_id) {
        return MCF_E_UNSUPPORTED;
    }
    if (mcf_codec_lookup(cfg, (mcf_codec_id_t)out->codec_id) == NULL) {
        return MCF_E_UNSUPPORTED;
    }

    /* 8. sizes self-consistent, and the payload must actually be present */
    *site = MCF_SITE_HDR_SIZES;
    if (out->old_size == 0u || out->new_size == 0u || out->payload_size == 0u) {
        return MCF_E_FORMAT;
    }
    payload_avail = patch_size - (uint32_t)out->hdr_len;
    if (out->payload_size > payload_avail) {
        *site = MCF_SITE_HDR_TRUNCATED;
        return MCF_E_TRUNCATED;
    }

    if (out->block_log2 < 8u || out->block_log2 > 20u) {
        *site = MCF_SITE_HDR_SIZES;
        return MCF_E_FORMAT;
    }
    block_size = 1u << out->block_log2;

    /* 9. The keystone check. The patch declares the workspace it needs. If that
     *    does not fit the budget the session is refused *before* any allocation
     *    is attempted, rather than failing to allocate part-way through. */
    *site = MCF_SITE_WORKSPACE;
    if (out->workspace_req > budget) {
        return MCF_E_DICT_TOO_LARGE;
    }
    if (block_size > (budget - out->workspace_req) / 2u) {
        return MCF_E_DICT_TOO_LARGE;
    }

    /* Split the payload into codec properties and compressed stream. */
    props_len = mcf_codec_props_len((mcf_codec_id_t)out->codec_id);
    if (props_len > out->payload_size) {
        *site = MCF_SITE_HDR_SIZES;
        return MCF_E_FORMAT;
    }
    out->props              = &h[out->hdr_len];
    out->props_len          = props_len;
    out->payload            = &h[(uint32_t)out->hdr_len + props_len];
    out->payload_stream_len = out->payload_size - props_len;
    if (out->payload_stream_len == 0u) {
        *site = MCF_SITE_HDR_SIZES;
        return MCF_E_FORMAT;
    }

    *site = MCF_SITE_NONE;
    return MCF_OK;
}
