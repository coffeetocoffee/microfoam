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
/* Resume support is not a wire flag: the journal lives in caller NVM and is
 * enabled by configuration, like MFP1's. The flag name is reserved and MUST
 * NOT be set in an executable v2 patch; the parser rejects it. */
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
    /* Largest single record ciphertext the framing walk observed; execution
     * uses it to size the inner decode window. Zero until parse succeeds. */
    uint32_t record_max_block;
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

/* Implemented key-provider contract for the MFP2 execution API.
 * On MCF_OK, provide exactly 32 key bytes in out_key. The output buffer is
 * library-owned, writable, and is wiped by the session after the operation;
 * implementations must wipe every internal key copy on every exit path using
 * a non-optimizable zeroization primitive. The callback context and provider
 * must remain valid for the full operation. No key is retained across
 * operations or stored in the patch/configuration. */
typedef mcf_status_t (*mcf_v2_key_provider_fn)(void *ctx,
                                               const uint8_t key_id[MCF_V2_KEY_ID_SIZE],
                                               uint8_t out_key[MCF_V2_KEY_SIZE]);

/* Ed25519ph verifier for the exact three-span MFP2 signed message. */
typedef int32_t (*mcf_v2_verify_fn)(void *ctx, const uint8_t *sig, uint32_t sig_len,
                                    const uint8_t *part1, uint32_t part1_len,
                                    const uint8_t *part2, uint32_t part2_len,
                                    const uint8_t *part3, uint32_t part3_len);

/* Detached XChaCha20-Poly1305-IETF record authentication/decryption. */
typedef int32_t (*mcf_v2_aead_fn)(void *ctx, const uint8_t *key,
                                  const uint8_t nonce[MCF_V2_NONCE_SIZE],
                                  const uint8_t *ciphertext, uint32_t ciphertext_len,
                                  const uint8_t *tag, uint32_t tag_len,
                                  const uint8_t *ad, uint32_t ad_len,
                                  uint8_t *plaintext);

typedef struct mcf_v2_config {
    const mcf_hal_t *hal;
    const uint8_t *patch;
    uint32_t patch_size;
    const uint8_t *old;
    uint32_t old_size;
    mcf_read_fn old_read;
    void *old_ctx;
    uint32_t dst_addr;
    uint32_t block_size;
    uint32_t ram_budget;
    void *workspace;
    uint32_t workspace_size;
    mcf_v2_key_provider_fn key_provider;
    void *key_ctx;
    mcf_v2_verify_fn verify;
    void *verify_ctx;
    mcf_v2_aead_fn aead;
    void *aead_ctx;
    mcf_progress_fn progress;
    void *progress_ctx;
    mcf_commit_fn commit;
    void *commit_ctx;

    /* Resume support, MFP1-compatible in shape. Both zero disables it, which
     * is the default; the session then behaves exactly as before.
     *
     * journal_addr designates a small NVM region of at least
     * sizeof(mcf_v2_journal_t) bytes. It must be block-aligned and must not
     * overlap the destination region (checked by mcf_v2_session_open) or the
     * journal record itself is erased/programmed through the same HAL as
     * normal flash. journal_interval is the number of blocks between
     * checkpoints; zero selects 32. */
    uint32_t journal_addr;
    uint32_t journal_interval;
} mcf_v2_config_t;

/* Resume journal, MFP2. Written only at triple boundaries the positioned
 * resume can return to; the record is self-contained so a probe never has to
 * trust anything it cannot re-derive.
 *
 * The resume point is (d_off, out_off, old_off, phase, remaining, seek): the
 * next unconsumed decompressed byte, the output offset at that instant (an
 * erase block boundary), the base-image cursor, the engine phase with its
 * outstanding counts, and the current triple's seek when it has not yet been
 * applied - a point that may be mid-triple. record_index names the record whose
 * plaintext contains d_off; a resume re-feeds the codec from that record and
 * drops (d_off - record base) decompressed bytes. Everything below out_off is
 * left exactly as the interrupted run left it; the block at out_off is erased
 * and rewritten whole. */
typedef struct mcf_v2_journal {
    uint32_t magic;         /*!< MCF_V2_JOURNAL_MAGIC, or 0 if never written.  */
    uint32_t session_id;    /*!< CRC-32 of the patch header.                   */
    uint32_t out_off;       /*!< Output bytes already programmed; block-aligned.*/
    uint32_t old_off;       /*!< Base-image cursor at the resume point.        */
    uint32_t d_off;         /*!< Decompressed offset of the next delta byte.   */
    uint32_t record_index;  /*!< Record whose plaintext contains d_off.        */
    uint32_t record_base_d; /*!< Decoded offset where that record's plaintext
                             *    begins - the feed's coordinate base.         */
    uint32_t phase;         /*!< Engine phase at the resume point.             */
    uint32_t diff_remaining;/*!< Diff bytes still to apply.                    */
    uint32_t extra_remaining;/*!< Literal bytes still to copy.                 */
    uint32_t seek;          /*!< Current triple's seek, still to be applied.   */
    uint32_t prefix_crc32;  /*!< CRC-32 of the reconstructed prefix on flash.  */
    uint32_t record_crc;    /*!< CRC-32 of the twelve fields above.            */
} mcf_v2_journal_t;

#define MCF_V2_JOURNAL_MAGIC 0x32504A52u /* 'RJP2', little-endian */

/* Caller-owned bounded v2 session. The implementation authenticates the whole
 * container, decrypts records into the supplied workspace, then hands the
 * authenticated LZ4 stream to the unchanged MFP1 engine. Resume is opt-in via
 * cfg->journal_addr (see mcf_v2_resume_probe); with it disabled the session
 * behaves exactly as a cold run. */
typedef struct mcf_v2_session {
    mcf_session_storage_t inner_storage;
    mcf_session_t *inner;
    const mcf_v2_config_t *cfg;
    uint8_t *scratch;
    uint32_t scratch_len;
    uint32_t state;
    mcf_status_t status;
    uint32_t site;
    uint32_t flags;
    uint8_t key[MCF_V2_KEY_SIZE];
    mcf_config_t inner_cfg;

    /* Resume state. Set by mcf_v2_resume_probe(); consumed by begin(). */
    int      resume_positioned;
    uint32_t resume_out_off;    /*!< Output bytes already programmed.         */
    int32_t  resume_old_off;    /*!< Base-image cursor at the point.          */
    uint32_t resume_d_off;      /*!< Decompressed offset of the next byte.    */
    uint32_t resume_record;     /*!< Record whose plaintext contains it.      */
    uint32_t resume_record_base_d; /*!< Decoded base of that record.          */
    uint32_t resume_phase;      /*!< Engine phase at the point.               */
    int32_t  resume_diff_remaining; /*!< Diff bytes still to apply.          */
    int32_t  resume_extra_remaining;/*!< Literal bytes still to copy.         */
    int32_t  resume_seek;       /*!< Current triple's seek, still to apply.   */

    uint32_t session_id;        /*!< CRC-32 of the patch header.              */
    uint32_t journal_interval;  /*!< Blocks between checkpoints; 0 disables.  */
    uint32_t next_ckpt_out;     /*!< Output offset of the next checkpoint.    */
    uint32_t flash_block;       /*!< Erase granularity, from the HAL.         */

    /* Streaming feed state. The framed LZ4 stream is decrypted one record at a
     * time into `win` and consumed as the engine asks for it, so the whole
     * payload is never resident. `win` is win_cap bytes: two maximum-size
     * records plus the four-byte terminal marker, enough for the sliding
     * window and to synthesise the end-of-stream block. */
    uint8_t *win;
    uint32_t win_cap;
    uint32_t win_base;          /*!< Framed-stream offset of `win[0]`.        */
    uint32_t win_len;           /*!< Framed-stream bytes currently in `win`.  */
    uint32_t win_end;           /*!< Set once the terminal marker is appended. */
    uint32_t cur_record;        /*!< Next record to decrypt into the window.  */
    uint32_t feed_off;          /*!< Framing offset of that record's length.  */
    uint32_t hdr_len;           /*!< Real MFP2 header length; AAD rebuild.    */
    uint8_t *ad;                /*!< AAD buffer: "MCF2REC\0" + header body
                                 *    (signature and payload-CRC zeroed) +
                                 *    index + length. Lives in the workspace.  */
    uint32_t ad_len;            /*!< 16 + header_len.                          */
    uint8_t  nonce_pre[MCF_V2_NONCE_SIZE];
    uint32_t d_base;            /*!< Decoded offset the next record starts at.*/

    /* Recently decrypted records, so the checkpoint can name the record
     * containing an engine position without resident plaintext. The engine
     * trails the feed by at most one window, so the containing record is
     * always among the newest few. `ring[0]` is the oldest entry. */
    struct {
        uint32_t index;         /*!< Record index, or 0xFFFFFFFF if empty.    */
        uint32_t base_d;        /*!< Decoded offset its plaintext starts at.  */
        uint32_t dlen;          /*!< Decoded length of its plaintext.         */
    } ring[4];

    mcf_v2_view_t view;         /*!< Parsed container view; valid after open().*/
} mcf_v2_session_t;

#define MCF_V2_SESSION_FLAG_RESUME_DEGRADED 0x00000001u

mcf_status_t mcf_v2_session_open(mcf_v2_session_t *s, const mcf_v2_config_t *cfg);

/* Probe the configured journal region for a usable resume point. On MCF_OK the
 * session will resume from it on the next begin(); any other return means
 * "start clean" and leaves the session cold-startable. Must be called between
 * open() and begin() when journaling is configured. */
mcf_status_t mcf_v2_resume_probe(mcf_v2_session_t *s);

/* Clear the journal region (no-op when journaling is disabled). Called
 * automatically on a successful finish; exposed for integrators that want to
 * discard a resume point early. */
mcf_status_t mcf_v2_resume_clear(mcf_v2_session_t *s);
mcf_status_t mcf_v2_session_begin(mcf_v2_session_t *s);
mcf_status_t mcf_v2_session_step(mcf_v2_session_t *s);
mcf_status_t mcf_v2_session_finish(mcf_v2_session_t *s);
mcf_status_t mcf_v2_session_run(mcf_v2_session_t *s);
void mcf_v2_session_close(mcf_v2_session_t *s);
mcf_state_t mcf_v2_session_state(const mcf_v2_session_t *s);
mcf_status_t mcf_v2_session_status(const mcf_v2_session_t *s);

/* Session flags: MCF_V2_SESSION_FLAG_RESUME_DEGRADED is set when a checkpoint
 * could not be written and resumability was lost; the update itself continues
 * best-effort, mirroring MFP1. */
uint32_t mcf_v2_session_flags(const mcf_v2_session_t *s);

/* Output bytes programmed so far, in absolute output coordinates (a resumed
 * session starts at the resume point's out_off, not at zero). */
uint32_t mcf_v2_session_progress(const mcf_v2_session_t *s);

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
