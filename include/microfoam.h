/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - firmware delta update library for resource-constrained microcontrollers.
 * Tiny bubbles. Tiny footprint. Full-strength upgrade.
 *
 * This header is the complete public interface. It contains declarations only;
 * no implementation, no macros that hide control flow, and no dependency on any
 * standard header beyond <stdint.h> and <stddef.h>.
 *
 * Upstream-License: the delta algorithm is derived from bsdiff/bspatch,
 *   Copyright 2003-2005 Colin Percival, Copyright 2012 Matthew Endsley
 *   (BSD 2-Clause). See LICENSE and docs/architecture.md section 20.3.
 */

#ifndef MICROFOAM_H
#define MICROFOAM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ======================================================================== *
 * 1. Version
 * ======================================================================== */

#define MCF_VERSION_MAJOR 1u
#define MCF_VERSION_MINOR 3u
#define MCF_VERSION_PATCH 0u

/* Packed as (major << 16) | (minor << 8) | patch. */
uint32_t mcf_version(void);

/* ======================================================================== *
 * 2. Compile-time configuration
 * ======================================================================== */

/* Upper bound on the storage a session needs, in bytes.
 *
 * mcf_session_sizeof() never returns more than this. The definition exists so a
 * caller with no heap can declare static session storage; see MCF_SESSION_DECLARE.
 *
 * The default of 512 is sized for a 64-bit host build, where pointers are 8
 * bytes. On a 32-bit MCU the real figure is roughly half that, and mcf_session_sizeof()
 * reports it exactly. Lower this once you have measured - the library enforces
 * the relationship with a static assertion, so lowering it too far fails the
 * build rather than silently overflowing your buffer. */
#ifndef MCF_SESSION_MAX_BYTES
#define MCF_SESSION_MAX_BYTES 512u
#endif

/* Default processing block size in bytes. Must be a power of two. */
#ifndef MCF_DEFAULT_BLOCK_SIZE
#define MCF_DEFAULT_BLOCK_SIZE 1024u
#endif

/* Signature field size in bytes. An Ed25519 signature is 64 bytes (R||S); the
 * public key is 32. Conflating the two silently shifts the payload. */
#define MCF_SIG_SIZE 64u

/* ======================================================================== *
 * 3. Status codes
 * ======================================================================== */

/*
 * Every failure returns a distinct negative code. Zero means success and means
 * only success - there is no value that denotes both "succeeded" and "failed".
 *
 * A function returning int32_t yields a non-negative byte count on success and
 * a negative mcf_status_t on failure.
 */
typedef enum mcf_status {
    MCF_OK                =   0, /*!< Success.                                          */
    MCF_E_PARAM           =  -1, /*!< Invalid argument or null pointer.                 */
    MCF_E_STATE           =  -2, /*!< Call is not valid in the current session state.   */
    MCF_E_NOMEM           =  -3, /*!< Workspace allocation failed.                      */
    MCF_E_FORMAT          =  -4, /*!< Bad magic, version, or header length.            */
    MCF_E_UNSUPPORTED     =  -5, /*!< Unknown codec, architecture, or feature flag.    */
    MCF_E_DICT_TOO_LARGE  =  -6, /*!< Patch needs more RAM than ram_budget allows.     */
    MCF_E_PRODUCT         =  -7, /*!< Patch was not built for this product.             */
    MCF_E_MISMATCH        =  -8, /*!< Base image version or CRC does not match.        */
    MCF_E_CORRUPT         =  -9, /*!< Payload decode or integrity failure.              */
    MCF_E_TRUNCATED       = -10, /*!< Patch is shorter than the header declares.        */
    MCF_E_SIGNATURE       = -11, /*!< Signature verification failed.                    */
    MCF_E_ROLLBACK        = -12, /*!< fw_version is not newer than the running image.   */
    MCF_E_FLASH           = -13, /*!< Erase, program, or verify failed.                 */
    MCF_E_IO              = -14, /*!< Underlying source or sink read failed.            */
    MCF_E_ABORTED         = -15, /*!< Cancelled through the progress callback.          */
    MCF_E_COMMIT          = -16, /*!< The integrator's commit hook rejected the image.   */
    MCF_E_NOT_FOUND       = -17, /*!< No such session, state, or registered codec.      */
    MCF_E_MAX             = -18
} mcf_status_t;

/* ======================================================================== *
 * 4. Callback types
 * ======================================================================== */

/* Read `len` bytes at absolute offset `off` from a source image.
 * Return exactly `len` on success, or a negative mcf_status_t on failure. */
typedef int32_t (*mcf_read_fn)(void *ctx, uint32_t off, uint8_t *buf, uint32_t len);

/* Progress notification. Return non-zero to abort the session with
 * MCF_E_ABORTED. Invoked once per processed block. */
typedef int32_t (*mcf_progress_fn)(void *ctx, uint32_t done, uint32_t total);

/* Invoked once, after the reconstructed image has passed its CRC. Return
 * non-zero to reject the image; the session then ends in MCF_E_COMMIT. */
typedef int32_t (*mcf_commit_fn)(void *ctx);

/* Signature verification hook. The signed message is the concatenation of
 * header[0..55] and the compressed payload stream. */
typedef int32_t (*mcf_verify_fn)(void *ctx, const uint8_t *sig, uint32_t sig_len,
                                 const uint8_t *part1, uint32_t part1_len,
                                 const uint8_t *part2, uint32_t part2_len);

/* Diagnostic sink. `level` is 0 for errors and 1 for informational output. */
typedef void (*mcf_log_fn)(void *ctx, int level, const char *msg);

/* ======================================================================== *
 * 5. Hardware Abstraction Layer
 * ======================================================================== */

/*
 * The single platform-dependent surface. Register one instance at startup with
 * mcf_hal_register(). The pointer is retained, not copied, so the instance must
 * outlive every session; a static const instance in flash is the intended use.
 *
 * Flash contract
 * --------------
 * The library never issues an unaligned or block-crossing operation:
 *
 *   erase  - `len` is always a whole multiple of flash_block_size() and
 *            `addr` is aligned to it. Return MCF_OK on success, or a negative
 *            mcf_status_t on failure. Positive counts are not valid here.
 *   write  - `len` is always a multiple of the device's program granularity and
 *            never crosses a flash block boundary. The library buffers across
 *            erase-block boundaries, so a write may be called repeatedly for a
 *            single logical block. Return MCF_OK on success, or a negative
 *            mcf_status_t on failure. Positive counts are not valid here.
 *   read   - optional. May be NULL when the region is directly addressable and
 *            the destination is not. Return exactly `len` on success, or a
 *            negative mcf_status_t on failure.
 *
 * The library performs read-back verification after programming unless
 * flash_is_readonly() reports the region cannot be read.
 */
typedef struct mcf_hal {
    /* ---- flash (required) ---- */
    int32_t  (*flash_erase)(void *ctx, uint32_t addr, uint32_t len);
    int32_t  (*flash_write)(void *ctx, uint32_t addr, const uint8_t *p, uint32_t len);
    int32_t  (*flash_read)(void *ctx, uint32_t addr, uint8_t *p, uint32_t len);
    uint32_t (*flash_block_size)(void *ctx);

    /* optional */
    int32_t  (*flash_is_readonly)(void *ctx, uint32_t addr, uint32_t len);

    /* ---- memory ---- */

    /* Workspace allocation. Required unless each session supplies its own
     * static workspace in mcf_config_t. Returning NULL is reported as
     * MCF_E_NOMEM, never as a fault. */
    void    *(*alloc)(void *ctx, uint32_t size);
    void     (*free)(void *ctx, void *ptr);

    /* ---- device identity ---- */

    /* Product/board identifier this unit was provisioned with. The patch
     * header's product_id must match, or the session ends in MCF_E_PRODUCT. */
    uint32_t (*get_product_id)(void *ctx);

    /* Currently running firmware version. The patch header's fw_version must
     * be strictly greater, or the session ends in MCF_E_ROLLBACK. */
    uint32_t (*get_fw_version)(void *ctx);

    /* ---- optional services ---- */

    /* NULL rejects signed patches. Supply a vetted provider callback to verify. */
    mcf_verify_fn verify;

    /* NULL disables logging. */
    mcf_log_fn log;

    /* Passed as the first argument to every callback above. */
    void *ctx;
} mcf_hal_t;

/* Validate a HAL description. Deprecated compatibility helper; the HAL is now
 * supplied per session through mcf_config_t.hal and is not stored globally. */
mcf_status_t mcf_hal_register(const mcf_hal_t *hal);

/* Deprecated: static workspace is now supplied in each mcf_config_t. This
 * function returns MCF_E_UNSUPPORTED and is retained for source compatibility. */
mcf_status_t mcf_hal_set_static_workspace(const mcf_hal_t *hal, void *bytes, uint32_t size);

/* ======================================================================== *
 * 6. Codecs
 * ======================================================================== */

typedef enum mcf_codec_id {
    MCF_CODEC_AUTO = 0, /*!< Smallest workspace that fits ram_budget.        */
    MCF_CODEC_LZ4  = 1,
    MCF_CODEC_LZMA = 2,
    MCF_CODEC_RAW  = 3, /*!< Payload is the delta verbatim, uncompressed.    */
    MCF_CODEC_MAX  = 4,
    MCF_CODEC_CUSTOM_MIN = 0x80
} mcf_codec_id_t;

typedef struct mcf_codec mcf_codec_t;

/*
 * decode() contract.
 *
 * `cap` and `in_avail` are inputs; `produced` and `consumed` are outputs. They
 * are deliberately separate parameters rather than a single in/out length
 * pointer: with an in/out pointer, a caller that zero-initialises the variable
 * silently gets zero capacity and the codec produces nothing, which looks like
 * a corrupt stream rather than a misuse. That is exactly the kind of silent
 * failure this library exists to avoid, so the interface does not permit it.
 *
 * Returns MCF_OK and sets both outputs, or a negative status. Returning fewer
 * bytes than `cap` is normal and means the stream or the declared content size
 * ended.
 */
typedef struct mcf_codec_ops {
    const char *name;
    mcf_codec_id_t id;

    /* Return the workspace in bytes needed to decode a payload described by
     * `props`. Must not allocate. Called before any allocation is attempted. */
    uint32_t (*workspace_size)(const uint8_t *props, uint32_t props_len);

    /* `workspace` is at least workspace_size() bytes. The codec places its state
     * at the head of it and returns the handle from `*out_handle`, so no
     * separate allocation is needed. Return MCF_OK and a non-NULL handle, or a
     * negative mcf_status_t. */
    int32_t (*init)(mcf_codec_t **out_handle, const uint8_t *props,
                    uint32_t props_len, uint8_t *workspace);

    /* Return MCF_OK and set both output counts within the supplied capacities,
     * or return a negative mcf_status_t. `consumed == 0` with `produced == 0`
     * is only valid when the stream has ended; otherwise the session rejects it
     * as a corrupt/non-progressing codec. */
    int32_t (*decode)(mcf_codec_t *c,
                      uint8_t *out, uint32_t cap, uint32_t *produced,
                      const uint8_t *in, uint32_t in_avail, uint32_t *consumed);

    /* Return MCF_OK only when the codec produced the complete declared stream,
     * or a negative mcf_status_t. The session maps failures to the codec-finish
     * diagnostic stage. */
    int32_t (*finish)(mcf_codec_t *c);

    /* Release codec state. Called after init succeeded, including all later
     * session failure paths. It must not report an error. */
    void    (*destroy)(mcf_codec_t *c);
    void   *ctx; /*!< Passed to every callback above. */
} mcf_codec_ops_t;

/* Validate a custom codec descriptor. The descriptor is not copied or stored;
 * provide it through mcf_config_t.codecs for the sessions that may use it. */
mcf_status_t mcf_codec_register(const mcf_codec_ops_t *ops);

/* ======================================================================== *
 * 7. Patch container format (v1)
 * ======================================================================== */

/*
 * On-wire layout. All integers are little-endian at fixed offsets with no
 * padding. The structure below is a convenience view for host-side tooling and
 * debugging; the device parser performs explicit little-endian reads and does
 * not depend on this type's memory layout. The two are cross-checked by a
 * static assertion in src/mcf_container.c.
 */

#define MCF_HDR_MAGIC       0x3150464Du /* 'MFP1' */
#define MCF_HDR_MIN_SIZE    120u
#define MCF_HDR_MAX_SIZE    288u
#define MCF_HDR_VER_MAJOR   1u
#define MCF_HDR_VER_MINOR   0u

/* Header flag bits. */
#define MCF_FLAG_SIGNED     0x00000001u /*!< payload carries a valid signature   */
#define MCF_FLAG_RAW        0x00000002u /*!< payload is not compressed           */
#define MCF_FLAG_CODEC_LZMA 0x00000004u
#define MCF_FLAG_CODEC_LZ4  0x00000008u

/* Fixed field offsets. */
#define MCF_OFF_MAGIC          0u
#define MCF_OFF_HDR_LEN        4u
#define MCF_OFF_HDR_VER        6u
#define MCF_OFF_FLAGS          8u
#define MCF_OFF_PRODUCT_ID     12u
#define MCF_OFF_FW_VERSION     16u
#define MCF_OFF_OLD_SIZE       20u
#define MCF_OFF_NEW_SIZE       24u
#define MCF_OFF_PAYLOAD_SIZE   28u
#define MCF_OFF_OLD_CRC32      32u
#define MCF_OFF_NEW_CRC32      36u
#define MCF_OFF_PAYLOAD_CRC32  40u
#define MCF_OFF_WORKSPACE_REQ  44u
#define MCF_OFF_OLD_VERSION    48u
#define MCF_OFF_CODEC_ID       52u
#define MCF_OFF_BLOCK_LOG2     53u
#define MCF_OFF_RESERVED       54u
#define MCF_OFF_SIGNATURE      56u

/* The region covered by the signature: header[0 .. MCF_OFF_SIGNATURE) followed
 * by the payload. The signature field itself is excluded. */
#define MCF_SIGNED_HEADER_LEN  (MCF_OFF_SIGNATURE)

typedef struct mcf_header {
    uint32_t magic;
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
    uint8_t  block_size_log2;
    uint16_t reserved;
    uint8_t  signature[MCF_SIG_SIZE];
} mcf_header_t;

/* ======================================================================== *
 * 8. Session configuration
 * ======================================================================== */

/*
 * Zero initialise, then set fields. Unused callbacks may be left NULL.
 *
 * Size is 56 bytes on a 32-bit target. Prefer a static const instance in flash
 * over a stack local on memory-constrained parts:
 *
 *     static uint8_t workspace[WORKSPACE_BYTES];
 *     static const mcf_config_t cfg = { .patch = (const uint8_t *)PATCH_ADDR,
 *         .workspace = workspace, .workspace_size = sizeof(workspace), ... };
 *
 * Field meanings
 * --------------
 * hal                 Hardware callbacks for this session. Must remain valid
 *                     for the whole session; separate sessions may use distinct
 *                     HAL instances concurrently.
 * patch / patch_size  The received patch, including its header. Must remain
 *                     valid for the whole session.
 * old                 Base image address, or NULL to use old_read.
 * old_size            Length of the base image, as declared by the header.
 * old_read            Source for the base image when it is not directly
 *                     addressable - external flash, a filesystem, or an image
 *                     decrypted on demand. Ignored when old is non-NULL.
 * dst_addr            Where the reconstructed image is written, through the
 *                     HAL flash interface.
 * codec               Requested codec, or MCF_CODEC_AUTO to accept any codec
 *                     whose workspace fits ram_budget.
 * block_size          Processing window in bytes; 0 selects
 *                     MCF_DEFAULT_BLOCK_SIZE. Must be a power of two.
 * ram_budget          Hard ceiling in bytes on total dynamic workspace. The
 *                     library returns MCF_E_DICT_TOO_LARGE rather than
 *                     exceeding it. This is the enforcement point for the
 *                     patch's declared workspace_req.
 * progress            Optional; see mcf_progress_fn.
 * commit              Optional; see mcf_commit_fn.
 * verify / verify_ctx Optional per-session crypto provider override; falls back
 *                     to the HAL verifier when NULL. Signed patches fail closed
 *                     when neither verifier is configured.
 */
typedef struct mcf_config {
    const mcf_hal_t  *hal;
    const uint8_t *patch;
    uint32_t       patch_size;

    uint32_t       old_size;
    const uint8_t *old;
    mcf_read_fn    old_read;
    void          *old_ctx;

    uint32_t       dst_addr;

    mcf_codec_id_t codec;
    uint32_t       block_size;
    uint32_t       ram_budget;

    mcf_progress_fn progress;
    void          *progress_ctx;
    mcf_commit_fn   commit;
    void          *commit_ctx;

    /* Resume support. Both zero disables it, which is the default.
     *
     * journal_addr must be block-aligned and must not overlap the destination
     * region; both are checked by begin() and reported as MCF_E_PARAM. The
     * region must be at least sizeof(mcf_journal_t) bytes (20 bytes in v1).
     *
     * journal_interval is the number of blocks between checkpoints. Zero selects
     * 32. A very small value costs an erase and a program per block, which on
     * most parts is the most expensive operation in the library. */
    uint32_t       journal_addr;
    uint32_t       journal_interval;

    /* Optional caller-owned workspace for heapless operation. This buffer is
     * private to this session; separate sessions require separate buffers. */
    void          *workspace;
    uint32_t       workspace_size;

    /* Optional per-session signature verifier. When NULL, the HAL verifier is
     * used. This permits crypto context to remain separate from flash context. */
    mcf_verify_fn  verify;
    void          *verify_ctx;

    /* Optional LZMA policy. A patch's properties block declares lc/lp/pb and a
     * dictionary size, and the device must not accept parameters it cannot
     * afford or does not intend to run. These are checked during header
     * validation, before anything is allocated:
     *
     *   lzma_max_dict        0 = no limit. A patch whose declared dictionary is
     *                        larger is rejected with MCF_E_DICT_TOO_LARGE.
     *   lzma_max_lc_plus_lp  0 = no limit. The literals-context sum drives the
     *                        probability table size (768 << (lc + lp) entries).
     *                        A patch over this is rejected with MCF_E_FORMAT.
     *
     * Set both on a deployed product to bound the decoder's resident cost by
     * policy rather than only by the reported workspace figure. */
    uint32_t       lzma_max_dict;
    uint32_t       lzma_max_lc_plus_lp;

    /* Optional caller-owned codec table. Built-ins remain available; entries
     * here override a matching codec id for this session only. */
    const mcf_codec_ops_t *codecs;
    uint32_t       codec_count;
} mcf_config_t;

/* ======================================================================== *
 * 8b. Resume journal
 * ======================================================================== */

/*
 * A resume point, so an interrupted restore need not start over.
 *
 * The v1 record is exactly 20 bytes (five little-endian uint32_t fields).
 *
 * The record is written at a triple boundary in the delta stream and read back
 * after a reset. It is deliberately small - 20 bytes - and fits inside one
 * erase block of most small parts.
 *
 * What it proves, and what it does not:
 *
 *   - `record_crc` detects a torn or corrupted write.
 *   - `prefix_crc32` is compared against a fresh read of the reconstructed
 *     prefix, so flash corruption between power cycles is detected.
 *   - `session_id` is derived from the patch header, so a journal left behind
 *     by one patch cannot be used to resume a different one.
 *
 * It is *not* an authenticity control. The journal lives in NVM the device
 * itself writes; an attacker who can write that NVM has already won. The threat
 * this addresses is corruption and interruption, not forgery.
 */
#define MCF_JOURNAL_MAGIC 0x4D434A52u /* 'RCJM', little-endian */

typedef struct mcf_journal {
    uint32_t magic;        /*!< MCF_JOURNAL_MAGIC, or 0 if never written. */
    uint32_t session_id;   /*!< CRC-32 of the patch header.               */
    uint32_t newpos;       /*!< Output bytes already programmed.          */
    uint32_t prefix_crc32; /*!< CRC-32 of the reconstructed prefix.       */
    uint32_t record_crc;   /*!< CRC-32 of the four fields above.          */
} mcf_journal_t;

/* ======================================================================== *
 * 9. Session
 * ======================================================================== */

typedef enum mcf_state {
    MCF_ST_IDLE       = 0,
    MCF_ST_HEADER     = 1,  /*!< Parsing and validating the patch header.   */
    MCF_ST_VALIDATE   = 2,  /*!< Product, version, and signature checks.   */
    MCF_ST_ALLOC      = 3,  /*!< Workspace allocation.                     */
    MCF_ST_DECODE     = 4,  /*!< Decompressing into the block buffer.      */
    MCF_ST_APPLY      = 5,  /*!< Applying the delta to the block buffer.    */
    MCF_ST_WRITEBACK  = 6,  /*!< Erasing, programming, verifying.           */
    MCF_ST_VERIFY     = 7,  /*!< Whole-image CRC.                          */
    MCF_ST_COMMIT     = 8,
    MCF_ST_DONE       = 9,
    MCF_ST_FAILED     = 10
} mcf_state_t;

#define MCF_SESSION_FLAG_RESUME_DEGRADED 0x00000001u


typedef struct mcf_session mcf_session_t;

/* Storage with the alignment a session requires. */
typedef union mcf_session_storage {
    uint32_t align_u32;
    uint64_t align_u64;
    void    *align_ptr;
    uint8_t  bytes[MCF_SESSION_MAX_BYTES];
} mcf_session_storage_t;

/* Exact storage a session needs, in bytes. Never exceeds
 * MCF_SESSION_MAX_BYTES. Use this for pool or heap allocation; use
 * MCF_SESSION_DECLARE when there is no heap. */
uint32_t mcf_session_sizeof(void);

/* Declare static session storage plus a ready-to-use pointer.
 *
 *     MCF_SESSION_DECLARE(s_upgrade);
 *     mcf_session_run(s_upgrade);
 *
 * `name` becomes a `mcf_session_t *`, so it is passed wherever a session
 * pointer is expected. */
#define MCF_SESSION_DECLARE(name)                                             \
    mcf_session_storage_t name##__storage;                                    \
    mcf_session_t *const name = (mcf_session_t *)(void *)&name##__storage

/* --- lifecycle --------------------------------------------------------- */

/* Initialise a session against a validated configuration. Does not allocate,
 * does not touch flash. The configuration and cfg->hal must outlive the session. */
mcf_status_t mcf_session_open(mcf_session_t *s, const mcf_config_t *cfg);

/* Validate the patch, verify the base image, and allocate workspace. On
 * success the session is ready to step. Safe to call again after a failed
 * begin(), once the cause is corrected. */
mcf_status_t mcf_session_begin(mcf_session_t *s);

/* Advance by one block. Returns MCF_OK, or a negative status on failure or
 * completion. Bounded work: at most one block is read, decoded, applied, and
 * written per call. */
mcf_status_t mcf_session_step(mcf_session_t *s);

/* Verify the reconstructed image and invoke the commit hook. Only meaningful
 * once the session reports MCF_ST_DONE. */
mcf_status_t mcf_session_finish(mcf_session_t *s);

/* Run begin, step, and finish to completion. Equivalent to the three calls
 * above in a loop; provided for integrations that do not need to step. */
mcf_status_t mcf_session_run(mcf_session_t *s);

/* --- resume ------------------------------------------------------------ */

/* Look for a valid resume point recorded by a previous run of this session.
 *
 * Must be called after mcf_session_open() and before mcf_session_begin(). It
 * parses and validates the patch header, reads the journal, checks that the
 * record belongs to this patch, and verifies the reconstructed prefix against
 * the flash that is actually there.
 *
 * Returns MCF_OK when a usable resume point was found and the session is now
 * positioned to continue, and MCF_E_NOT_FOUND when there is none - which is not
 * an error, just a cold start. Any other negative value is a genuine problem
 * with the journal region or the patch.
 *
 * With journal_addr left zero this always returns MCF_E_NOT_FOUND.
 */
mcf_status_t mcf_resume_probe(mcf_session_t *s, const mcf_config_t *cfg);

/* Discard any stored resume point. Called automatically when a session reaches
 * MCF_ST_DONE or fails, so a completed or abandoned update does not leave a
 * stale resume point behind. */
mcf_status_t mcf_resume_clear(mcf_session_t *s);

/* Release workspace and reset to MCF_ST_IDLE. Safe to call from any state,
 * and safe to call on a session that was never opened. */
void mcf_session_close(mcf_session_t *s);

/* --- queries ----------------------------------------------------------- */

mcf_state_t  mcf_session_state(const mcf_session_t *s);

/* The status that caused the session to fail, or MCF_OK if it has not. */
mcf_status_t mcf_session_status(const mcf_session_t *s);

/* Bytes reconstructed so far, out of the total expected. */
uint32_t mcf_session_progress(const mcf_session_t *s);
uint32_t mcf_session_total(const mcf_session_t *s);

/* Session diagnostics. RESUME_DEGRADED means the update continued successfully
 * but a journal checkpoint failed and no further resume point will be kept. */
uint32_t mcf_session_flags(const mcf_session_t *s);

/* Stable identifier for the failing stage, for field diagnostics. Correlates
 * with the line numbers in the source. */
uint32_t mcf_session_error_site(const mcf_session_t *s);
const char *mcf_session_strerror(mcf_status_t status);

/* Decoded LZMA properties of the patch a session is working on. Populated by
 * mcf_session_begin() when the patch's codec is LZMA; `valid` is 0 otherwise.
 * Exists so a field failure can be diagnosed with the parameters that were in
 * play, which the status code alone does not convey. */
typedef struct mcf_lzma_info {
    uint8_t  valid;
    uint8_t  lc;
    uint8_t  lp;
    uint8_t  pb;
    uint32_t dict_size;
    uint32_t workspace;  /*!< What the device computed for these parameters. */
} mcf_lzma_info_t;

mcf_status_t mcf_session_lzma_info(const mcf_session_t *s, mcf_lzma_info_t *out);

/* ======================================================================== *
 * 10. Utilities
 * ======================================================================== */

/* CRC-32 (IEEE 802.3, reflected, polynomial 0xEDB88320, init/final 0xFFFFFFFF).
 *
 * Streaming form, for verifying an image larger than available RAM:
 *
 *     uint32_t c = mcf_crc32_init();
 *     while (...) c = mcf_crc32_update(c, chunk, chunk_len);
 *     if (mcf_crc32_final(c) != expected) { ... }
 *
 * The one-shot form wraps these three. Exposed because the container format is
 * defined in terms of it and callers need it to verify images independently.
 */
uint32_t mcf_crc32_init(void);
uint32_t mcf_crc32_update(uint32_t crc, const uint8_t *buf, uint32_t len);
uint32_t mcf_crc32_final(uint32_t crc);
uint32_t mcf_crc32(const uint8_t *buf, uint32_t len);

/* ======================================================================== *
 * 11. Convenience
 * ======================================================================== */

/* Human-readable name of a codec, or "?" for an unknown id. */
const char *mcf_codec_name(mcf_codec_id_t id);

#ifdef __cplusplus
}
#endif

#endif /* MICROFOAM_H */
