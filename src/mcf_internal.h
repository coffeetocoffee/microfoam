/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - internal definitions shared across translation units.
 * Not part of the public interface. Do not include from application code.
 */

#ifndef MCF_INTERNAL_H
#define MCF_INTERNAL_H

#include "microfoam.h"

#include <limits.h>
#include <string.h>

/* ------------------------------------------------------------------------ *
 * Error sites. Stable numeric identifiers for field diagnostics; reported
 * through mcf_session_error_site() and recorded alongside the status.
 * ------------------------------------------------------------------------ */
#define MCF_SITE_NONE            0u
#define MCF_SITE_CONFIG          1u
#define MCF_SITE_HDR_MAGIC       2u
#define MCF_SITE_HDR_VER         3u
#define MCF_SITE_HDR_LEN         4u
#define MCF_SITE_HDR_PRODUCT     5u
#define MCF_SITE_HDR_ROLLBACK    6u
#define MCF_SITE_HDR_OLDVER      7u
#define MCF_SITE_HDR_SIZES       8u
#define MCF_SITE_HDR_CODEC       9u
#define MCF_SITE_HDR_SIGNATURE   10u
#define MCF_SITE_HDR_CRC         11u
#define MCF_SITE_HDR_TRUNCATED   12u
#define MCF_SITE_BASE_CRC        13u
#define MCF_SITE_WORKSPACE       14u
#define MCF_SITE_ALIGN           15u
#define MCF_SITE_CODEC_INIT      16u
#define MCF_SITE_CODEC_DECODE    17u
#define MCF_SITE_CODEC_FINISH    18u
#define MCF_SITE_READ_CTRL       19u
#define MCF_SITE_READ_DIFF       20u
#define MCF_SITE_READ_EXTRA      21u
#define MCF_SITE_SANITY_DIFF     22u
#define MCF_SITE_SANITY_EXTRA    23u
#define MCF_SITE_SANITY_SEEK     24u
#define MCF_SITE_OLD_READ        25u
#define MCF_SITE_FLASH_ERASE     26u
#define MCF_SITE_FLASH_WRITE     27u
#define MCF_SITE_FLASH_VERIFY    28u
#define MCF_SITE_PROGRESS        29u
#define MCF_SITE_NEW_CRC         30u
#define MCF_SITE_COMMIT          31u
#define MCF_SITE_STATE           32u

/* ------------------------------------------------------------------------ *
 * Little-endian scalar reads. The parser never depends on host byte order.
 * ------------------------------------------------------------------------ */
static inline uint32_t mcf_rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static inline uint16_t mcf_rd16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8));
}

/* ------------------------------------------------------------------------ *
 * Validated view of a patch header. Populated once, then trusted.
 * ------------------------------------------------------------------------ */
typedef struct mcf_hdr_view {
    uint16_t hdr_len;
    uint16_t hdr_ver;
    uint32_t flags;
    uint32_t product_id;
    uint32_t fw_version;
    uint32_t old_size;
    uint32_t new_size;
    uint32_t payload_size;
    uint32_t old_crc32;
    uint32_t new_crc32;
    uint32_t payload_crc32;
    uint32_t workspace_req;
    uint32_t old_version;
    uint8_t  codec_id;
    uint8_t  block_log2;
    const uint8_t *props;   /*!< Codec properties, at the head of the payload. */
    uint32_t       props_len;
    const uint8_t *payload; /*!< First byte of the compressed delta stream.    */
    uint32_t       payload_stream_len;
} mcf_hdr_view_t;

/* Parse and validate. `hal` supplies product id and running version. Returns
 * MCF_OK, or the specific reason for rejection with *site set. Performs no
 * allocation and writes no flash. */
mcf_status_t mcf_hdr_parse(const mcf_hal_t *hal, const mcf_config_t *cfg,
                           const uint8_t *patch, uint32_t patch_size,
                           mcf_hdr_view_t *out, uint32_t *site);

/* Verify the signature over header[0..MCF_SIGNED_HEADER_LEN) + compressed
 * payload stream using the HAL's configured provider; absent hooks fail closed. */
mcf_status_t mcf_hdr_verify(const mcf_hal_t *hal, mcf_verify_fn verify,
                            void *verify_ctx, const uint8_t *patch,
                            const mcf_hdr_view_t *v);

/* ------------------------------------------------------------------------ *
 * Delta engine - BSDIFF43 control loop. Codec-agnostic, allocation-free,
 * holds no static state, and is resumable: a single call performs at most
 * out_cap bytes of work so a caller can step it.
 * ------------------------------------------------------------------------ */

/* Refill the engine's raw buffer with decompressed delta bytes. Sets *n to the
 * number produced and *eof once the stream is fully consumed. */
typedef int32_t (*mcf_refill_fn)(void *ctx, uint8_t *buf, uint32_t cap, uint32_t *n, int *eof);
/* Emit reconstructed bytes. */
typedef int32_t (*mcf_emit_fn)(void *ctx, const uint8_t *p, uint32_t len);
/* Read `len` base-image bytes at `off`. */
typedef int32_t (*mcf_base_read_fn)(void *ctx, uint32_t off, uint8_t *p, uint32_t len);

typedef struct mcf_engine_io {
    mcf_refill_fn    refill;
    mcf_emit_fn      emit;
    mcf_base_read_fn base_read;
    /* Called before a refill when the buffer holds consumed bytes. The session
     * compacts the buffer and advances its record of which compressed-stream
     * position raw[0] corresponds to; the engine cannot do that itself because
     * only the session knows the compressed stream's position. May be NULL, in
     * which case the engine compacts in place. */
    void          (*shift)(void *ctx, uint32_t consumed);
    /* Points at the session's record of which compressed-stream position
     * raw[0] corresponds to. The engine needs it to name a resume point. */
    uint32_t       *raw_origin;
    void            *ctx;
    uint32_t        *site; /*!< Set to a MCF_SITE_* value on failure. */
} mcf_engine_io_t;

typedef enum mcf_engine_phase {
    MCF_EP_CTRL  = 0, /*!< Awaiting the next control triple.          */
    MCF_EP_DIFF  = 1, /*!< Consuming diff bytes for the current triple. */
    MCF_EP_EXTRA = 2, /*!< Consuming literal bytes.                    */
    MCF_EP_DONE  = 3  /*!< newpos has reached newsize.                 */
} mcf_engine_phase_t;

typedef struct mcf_engine {
    const mcf_engine_io_t *io;

    /* Caller-owned buffers, owned by the session. `raw` receives decompressed
     * delta bytes from the codec, so it is not const. */
    uint8_t       *raw;
    uint32_t       raw_cap;
    uint8_t       *out;
    uint32_t       out_cap;

    /* Consumption cursor into raw. */
    uint32_t raw_pos;
    uint32_t raw_len;
    int      raw_eof;

    mcf_engine_phase_t phase;
    int32_t  diff_remaining;
    int32_t  extra_remaining;

    /* Output bytes to reconstruct and throw away before emitting anything.
     * Used when resuming: the prefix on flash is already correct, so the
     * engine re-derives it from the start of the stream and discards it rather
     * than programming it a second time. */
    int32_t  discard;

    /* Entry state of the triple currently being applied. Written the moment a
     * control triple is consumed, so a session that checkpoints here can resume
     * by re-reading that triple from its start - at most one triple of
     * redundant work, and never a resume into the middle of a diff.
     *
     * `safe` means the engine is between triples, so the compressed position of
     * the next control header is meaningful to the caller. */
    uint32_t tri_payload;   /*!< Compressed offset of this triple's header. */
    int32_t  tri_newpos;    /*!< Output position at the triple's start.     */
    int32_t  tri_oldpos;    /*!< Base cursor, before the triple's seek.    */
    int      safe;          /*!< Between triples, position is resumable.    */

    int32_t  newpos;
    int32_t  oldpos;
    int32_t  old_size;
    uint32_t newsize;
} mcf_engine_t;

/* Initialise against caller-owned buffers. No allocation. */
void mcf_engine_init(mcf_engine_t *e, const mcf_engine_io_t *io, uint8_t *raw,
                     uint32_t raw_cap, uint8_t *out, uint32_t out_cap,
                     int32_t old_size, uint32_t new_size);

/* Perform at most out_cap bytes of work. Returns MCF_OK while more remains and
 * sets *finished once the reconstruction is complete. */
mcf_status_t mcf_engine_step(mcf_engine_t *e, int *finished);

/* Restart the stream and discard the first skip output bytes, which are
 * already present and correct in the destination. */
void mcf_engine_resume(mcf_engine_t *e, uint32_t skip);

/* ------------------------------------------------------------------------ *
 * Codec registry. Write-once during initialisation, read-only thereafter.
 * Holds configuration, not session state.
 * ------------------------------------------------------------------------ */
const mcf_codec_ops_t *mcf_codec_lookup(const mcf_config_t *cfg,
                                        mcf_codec_id_t id);

/* Properties block size per codec, used to split the payload into properties
 * and compressed stream. */
uint32_t mcf_codec_props_len(mcf_codec_id_t id);

/* ------------------------------------------------------------------------ *
 * HAL and workspace
 * ------------------------------------------------------------------------ */
void *mcf_ws_alloc(const mcf_hal_t *hal, uint8_t *static_ws,
                   uint32_t static_ws_size, uint32_t size);
void  mcf_ws_free(const mcf_hal_t *hal, void *ptr);

/* ------------------------------------------------------------------------ *
 * Logging
 * ------------------------------------------------------------------------ */
void mcf_log_emit(const mcf_hal_t *hal, int level, uint32_t site, mcf_status_t st);

#define MCF_LOG(hal, site, st) mcf_log_emit((hal), 0, (site), (st))

/* ------------------------------------------------------------------------ *
 * Session internals
 * ------------------------------------------------------------------------ */

/* Bookkeeping for the compressed-stream cursor, owned by the session so the
 * refill adapter needs no allocation of its own. */
typedef struct mcf_sess_io {
    uint32_t payload_pos; /*!< Bytes consumed from the codec stream. */
    uint32_t raw_origin;  /*!< Compressed position that engine.raw[0] maps to. */
    int32_t  stream_end;  /*!< The codec reported end of stream.     */
} mcf_sess_io_t;

struct mcf_session {
    const mcf_hal_t    *hal;
    const mcf_config_t *cfg;

    mcf_state_t  state;
    mcf_status_t status;
    uint32_t     site;
    uint32_t     flags;

    mcf_hdr_view_t hdr;
    uint32_t       flash_block;      /*!< Erase granularity, from the HAL.     */
    uint32_t       dst_erased_upto; /*!< Address up to which erase is done.   */
    uint32_t       dst_written;      /*!< Bytes programmed into the target.    */

    /* Workspace, one contiguous block:
     *   [0                    , block_size)          engine input  (delta)
     *   [block_size           , block_size)          engine output (result)
     *   [2*block_size        , workspace_req)       codec state + data
     * Allocated once in begin(), released on every exit path. */
    uint8_t *raw;        /*!< Engine input buffer.                          */
    uint8_t *work;       /*!< Engine output buffer.                         */
    uint8_t *codec_ws;   /*!< Codec state and data.                        */
    uint32_t block_size;
    uint32_t ws_size;

    const mcf_codec_ops_t *ops;
    mcf_codec_t           *codec;

    mcf_sess_io_t io;
    mcf_engine_io_t eio;

    /* Resume state. `resumable` is set by mcf_resume_probe() and consumed by
     * mcf_session_begin(). */
    int      resumable;
    uint32_t resume_newpos;
    uint32_t journal_interval;
    uint32_t blocks_since_ckpt;
    uint32_t ckpt_prefix_crc; /*!< Running CRC of the reconstructed prefix. */
    uint32_t session_id;

    mcf_engine_t engine;
    int          engine_finished;
};
#endif /* MCF_INTERNAL_H */
