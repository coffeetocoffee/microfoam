/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - session state machine.
 *
 * This is the layer the reference implementation does not have, and its absence
 * is why the reference error handling is per-function ad hoc rather than
 * systematic. Here every state transition is explicit, every failure funnels
 * through one function, and resources are released on every path.
 *
 * Invariant: a session in MCF_ST_DONE has produced an image whose CRC was
 * verified by reading it back from flash. No other state is reported as
 * success.
 */

#include "mcf_internal.h"

/* Compile-time enforcement of the public storage promise. If a future codec
 * needs a larger state block this fails the build rather than silently
 * overflowing an integrator's static session. */
typedef char mcf_session_fits[(sizeof(struct mcf_session) <= MCF_SESSION_MAX_BYTES) ? 1 : -1];

uint32_t mcf_session_sizeof(void)
{
    return (uint32_t)sizeof(struct mcf_session);
}

/* ---------------------------------------------------------------------- *
 * Failure funnel. The single exit for every error in the session. Records the
 * status and site, releases everything, and moves to MCF_ST_FAILED.
 * ---------------------------------------------------------------------- */
static mcf_status_t mcf_fail(mcf_session_t *s, mcf_status_t st, uint32_t site)
{
    s->status = st;
    s->site   = site;
    s->state  = MCF_ST_FAILED;

    if (s->codec != NULL && s->ops != NULL && s->ops->destroy != NULL) {
        s->ops->destroy(s->codec);
    }
    mcf_ws_free(s->hal, s->raw);
    s->codec    = NULL;
    s->raw      = NULL;
    s->work     = NULL;
    s->codec_ws = NULL;

    MCF_LOG(s->hal, site, st);
    return st;
}

/* ---------------------------------------------------------------------- *
 * I/O adapters bridging the engine to the session.
 * ---------------------------------------------------------------------- */

/* Refill the engine's input buffer by decompressing one codec block. */
static int32_t mcf_sess_refill(void *ctx, uint8_t *buf, uint32_t cap, uint32_t *n, int *eof)
{
    mcf_session_t *s   = (mcf_session_t *)ctx;
    const uint8_t *src;
    uint32_t       avail;
    uint32_t       produced;
    uint32_t       consumed;
    int32_t        r;

    *n   = 0u;
    *eof = 0;

    if (s->io.stream_end) {
        *eof = 1;
        return 0;
    }

    /* A stateless codec is handed the sliding window: the current position and
     * the bytes remaining from it. A codec with internal state across calls -
     * an LZMA range coder, for instance - cannot use this and defines its own
     * input convention; see src/mcf_lzma.h. LZ4 is stateless. */
    src   = s->hdr.payload + s->io.payload_pos;
    avail = s->hdr.payload_stream_len - s->io.payload_pos;
    if (avail == 0u) {
        s->io.stream_end = 1;
        *eof = 1;
        return 0;
    }

    /* The bytes about to be produced correspond to this compressed offset.
     * The engine needs it to name a resume point. */
    s->io.raw_origin = s->io.payload_pos;

    r = s->ops->decode(s->codec, buf, cap, &produced, src, avail, &consumed);
    if (r != MCF_OK) {
        s->site = MCF_SITE_CODEC_DECODE;
        return (r < 0) ? r : (int32_t)MCF_E_CORRUPT;
    }
    if (produced > cap || consumed > avail || (produced == 0u && consumed == 0u && avail != 0u)) {
        s->site = MCF_SITE_CODEC_DECODE;
        return (int32_t)MCF_E_CORRUPT;
    }
    s->io.payload_pos += consumed;
    *n = produced;

    if (produced == 0u) {
        s->io.stream_end = 1;
        *eof = 1;
    }
    return 0;
}

/* Emit reconstructed bytes: erase, program, and verify, in chunks that never
 * cross an erase-block boundary. */
static int32_t mcf_sess_emit(void *ctx, const uint8_t *p, uint32_t len)
{
    mcf_session_t  *s   = (mcf_session_t *)ctx;
    const mcf_hal_t *hal = s->hal;
    uint8_t          verify[32];

    while (len > 0u) {
        uint32_t addr;
        uint32_t chunk;
        int32_t  r;

        addr = s->cfg->dst_addr + s->dst_written;

        /* Erase on demand, one whole block at a time. Erasing beyond the end of
         * the image is harmless and keeps the contract simple: the erase length
         * is always a whole number of blocks. */
        if (addr >= s->dst_erased_upto) {
            uint32_t start = addr & ~(s->flash_block - 1u);
            uint32_t end   = start + s->flash_block;

            r = hal->flash_erase(hal->ctx, start, end - start);
            if (r != MCF_OK) {
                s->site = MCF_SITE_FLASH_ERASE;
                return (r < 0) ? r : (int32_t)MCF_E_FLASH;
            }
            s->dst_erased_upto = end;
        }

        /* Never write across an erase-block boundary. dst_addr is validated
         * block-aligned and flash_block is a power of two, so a chunk no larger
         * than flash_block always lands inside one block. */
        chunk = (len > s->flash_block) ? s->flash_block : len;
        if ((s->dst_erased_upto - addr) < chunk) {
            chunk = s->dst_erased_upto - addr;
        }
        if (chunk == 0u) {
            s->site = MCF_SITE_FLASH_ERASE;
            return (int32_t)MCF_E_FLASH;
        }

        r = hal->flash_write(hal->ctx, addr, p, chunk);
        if (r != MCF_OK) {
            s->site = MCF_SITE_FLASH_WRITE;
            return (r < 0) ? r : (int32_t)MCF_E_FLASH;
        }

        /* Read-back verification in small chunks. This uses a local buffer, not
         * the engine's output buffer: comparing the output buffer against
         * itself would always succeed. */
        if (hal->flash_is_readonly == NULL ||
            hal->flash_is_readonly(hal->ctx, addr, chunk) == 0) {
            uint32_t off;

            if (hal->flash_read == NULL) {
                s->site = MCF_SITE_FLASH_VERIFY;
                return (int32_t)MCF_E_FLASH;
            }
            for (off = 0; off < chunk; off += (uint32_t)sizeof(verify)) {
                uint32_t n = chunk - off;
                if (n > (uint32_t)sizeof(verify)) {
                    n = (uint32_t)sizeof(verify);
                }
                r = hal->flash_read(hal->ctx, addr + off, verify, n);
                if (r < 0) {
                    s->site = MCF_SITE_FLASH_VERIFY;
                    return r;
                }
                if ((uint32_t)r != n) {
                    s->site = MCF_SITE_FLASH_VERIFY;
                    return (int32_t)MCF_E_IO;
                }
                if (memcmp(verify, &p[off], n) != 0) {
                    s->site = MCF_SITE_FLASH_VERIFY;
                    return (int32_t)MCF_E_FLASH;
                }
            }
        }

        s->dst_written += chunk;
        p += chunk;
        len -= chunk;
    }
    return 0;
}

/* Compact the engine's input buffer and keep raw_origin consistent with it.
 * Called by the engine through mcf_engine_io_t.shift. */
static void mcf_sess_shift(void *ctx, uint32_t consumed)
{
    mcf_session_t *s = (mcf_session_t *)ctx;
    uint32_t       rem = s->engine.raw_len - s->engine.raw_pos;

    if (rem > 0u) {
        memmove(s->engine.raw, &s->engine.raw[s->engine.raw_pos], rem);
    }
    s->engine.raw_len = rem;
    s->engine.raw_pos  = 0u;
    s->io.raw_origin += consumed;
}

/* Unified base-image access over the direct-memory and callback paths. */
static int32_t mcf_sess_base_read(void *ctx, uint32_t off, uint8_t *p, uint32_t len)
{
    mcf_session_t *s = (mcf_session_t *)ctx;

    if (s->cfg->old_read != NULL) {
        return s->cfg->old_read(s->cfg->old_ctx, off, p, len);
    }
    if (s->cfg->old == NULL) {
        return (int32_t)MCF_E_PARAM;
    }
    memcpy(p, &s->cfg->old[off], len);
    return (int32_t)len;
}

/* ---------------------------------------------------------------------- *
 * Resume journal
 * ---------------------------------------------------------------------- */

#define MCF_JOURNAL_DEFAULT_INTERVAL 32u

static uint32_t mcf_journal_crc(const mcf_journal_t *j)
{
    /* Over the six fields, with record_crc treated as zero. */
    mcf_journal_t t = *j;
    t.record_crc    = 0u;
    return mcf_crc32((const uint8_t *)&t, (uint32_t)sizeof(t));
}

static int32_t mcf_journal_read(const mcf_config_t *cfg, const mcf_hal_t *hal,
                                mcf_journal_t *j)
{

    if (hal == NULL || hal->flash_read == NULL) {
        return (int32_t)MCF_E_PARAM;
    }
    {
        int32_t got = hal->flash_read(hal->ctx, cfg->journal_addr, (uint8_t *)j,
                                      (uint32_t)sizeof(*j));
        if (got < 0) {
            return (int32_t)MCF_E_IO;
        }
        if ((uint32_t)got != (uint32_t)sizeof(*j)) {
            return (int32_t)MCF_E_IO;
        }
    }
    return (int32_t)MCF_OK;
}

static int32_t mcf_journal_write(const mcf_config_t *cfg, const mcf_hal_t *hal,
                                 mcf_journal_t *j)
{
    int32_t r;

    j->record_crc = mcf_journal_crc(j);

    /* Erase then program: a journal update is a fresh record, not a patch. */
    r = hal->flash_erase(hal->ctx, cfg->journal_addr, (uint32_t)sizeof(*j));
    if (r != MCF_OK) {
        return (r < 0) ? r : (int32_t)MCF_E_FLASH;
    }
    r = hal->flash_write(hal->ctx, cfg->journal_addr, (const uint8_t *)j,
                         (uint32_t)sizeof(*j));
    if (r != MCF_OK) {
        return (r < 0) ? r : (int32_t)MCF_E_FLASH;
    }
    if (hal->flash_read != NULL) {
        uint8_t back[sizeof(mcf_journal_t)];
        r = hal->flash_read(hal->ctx, cfg->journal_addr, back, (uint32_t)sizeof(back));
        if (r < 0) {
            return r;
        }
        if ((uint32_t)r != (uint32_t)sizeof(back)) {
            return (int32_t)MCF_E_IO;
        }
        if (memcmp(back, j, sizeof(back)) != 0) {
            return (int32_t)MCF_E_FLASH;
        }
    }
    return (int32_t)MCF_OK;
}

/* CRC of the reconstructed image prefix currently in flash. Streamed, so the
 * cost does not scale with RAM. */
static int32_t mcf_prefix_crc(const mcf_config_t *cfg, const mcf_hal_t *hal,
                              uint32_t len, uint32_t *out)
{
    uint32_t crc = mcf_crc32_init();
    uint32_t off = 0u;
    uint8_t  tmp[64];

    if (hal->flash_read == NULL) {
        return (int32_t)MCF_E_PARAM;
    }
    while (off < len) {
        uint32_t n = len - off;
        int32_t  r;
        if (n > (uint32_t)sizeof(tmp)) {
            n = (uint32_t)sizeof(tmp);
        }
        r = hal->flash_read(hal->ctx, cfg->dst_addr + off, tmp, n);
        if (r < 0) {
            return r;
        }
        if ((uint32_t)r != n) {
            return (int32_t)MCF_E_IO;
        }
        crc = mcf_crc32_update(crc, tmp, n);
        off += n;
    }
    *out = mcf_crc32_final(crc);
    return (int32_t)MCF_OK;
}

mcf_status_t mcf_resume_clear(mcf_session_t *s)
{
    mcf_journal_t   j;
    mcf_config_t    cfg;
    const mcf_hal_t *hal;
    int32_t         r;

    if (s == NULL || s->cfg == NULL) {
        return MCF_E_PARAM;
    }
    cfg = *s->cfg;
    hal = s->hal;
    if (cfg.journal_addr == 0u || hal == NULL) {
        return MCF_OK;
    }
    memset(&j, 0, sizeof(j));
    r = mcf_journal_write(&cfg, hal, &j);
    if (r < 0) {
        return (mcf_status_t)r;
    }
    s->resumable = 0;
    return MCF_OK;
}

mcf_status_t mcf_resume_probe(mcf_session_t *s, const mcf_config_t *cfg)
{
    mcf_journal_t   j;
    mcf_hdr_view_t  v;
    const mcf_hal_t *hal;
    uint32_t        site  = MCF_SITE_NONE;
    uint32_t        crc   = 0u;
    uint32_t        sid;
    mcf_status_t    st;
    int32_t         r;

    if (s == NULL || cfg == NULL) {
        return MCF_E_PARAM;
    }
    s->resumable = 0;

    hal = s->hal;
    if (hal == NULL || cfg->journal_addr == 0u) {
        return MCF_E_NOT_FOUND;
    }

    /* The journal is only meaningful alongside a patch that parses, so parse
     * first and bail out early on a bad one. */
    st = mcf_hdr_parse(hal, cfg, cfg->patch, cfg->patch_size, &v, &site);
    if (st != MCF_OK) {
        return st;
    }
    sid = mcf_crc32(cfg->patch, (uint32_t)v.hdr_len);

    r = mcf_journal_read(cfg, hal, &j);
    if (r < 0) {
        return (mcf_status_t)r;
    }

    /* Every rejection below means "start clean", not "fail": a stale or
     * damaged resume point is an ordinary condition after a power cut. */
    if (j.magic != MCF_JOURNAL_MAGIC || j.record_crc != mcf_journal_crc(&j)) {
        return MCF_E_NOT_FOUND;
    }
    if (j.session_id != sid) {
        return MCF_E_NOT_FOUND;
    }
    if (j.newpos == 0u || j.newpos >= v.new_size) {
        return MCF_E_NOT_FOUND;
    }

    /* The prefix on flash must match what the journal claims. This is the check
     * that makes resume a feature rather than a hazard. */
    r = mcf_prefix_crc(cfg, hal, j.newpos, &crc);
    if (r < 0) {
        return (mcf_status_t)r;
    }
    if (crc != j.prefix_crc32) {
        return MCF_E_NOT_FOUND;
    }

    s->resumable        = 1;
    s->resume_newpos    = j.newpos;
    s->session_id       = sid;
    return MCF_OK;
}

/* Write a checkpoint, if one is due. Called from mcf_session_step. */
static mcf_status_t mcf_checkpoint(mcf_session_t *s)
{
    mcf_journal_t   j;
    const mcf_hal_t *hal = s->hal;
    mcf_config_t    cfg = *s->cfg;
    int32_t         r;

    s->blocks_since_ckpt++;

    /* Journaling is off unless an address was configured. Without this check a
     * session with resume disabled would still checkpoint, and because
     * journal_addr is 0 that means erasing and programming address zero. */
    if (s->cfg->journal_addr == 0u || s->journal_interval == 0u) {
        return MCF_OK;
    }
    if (!s->engine.safe) {
        return MCF_OK;   /* between triples only; try again next block */
    }
    if (s->blocks_since_ckpt < s->journal_interval) {
        return MCF_OK;
    }
    if (s->engine.newpos <= 0 || (uint32_t)s->engine.newpos >= s->hdr.new_size) {
        return MCF_OK;
    }

    memset(&j, 0, sizeof(j));
    j.magic        = MCF_JOURNAL_MAGIC;
    j.session_id   = s->session_id;
    j.newpos       = (uint32_t)s->engine.newpos;

    r = mcf_prefix_crc(&cfg, hal, j.newpos, &j.prefix_crc32);
    if (r < 0) {
        /* A checkpoint that cannot be written is not a reason to abandon the
         * update; the restore simply will not be resumable. */
        s->journal_interval = 0u;
        s->flags |= MCF_SESSION_FLAG_RESUME_DEGRADED;
        return MCF_OK;
    }

    r = mcf_journal_write(&cfg, hal, &j);
    if (r < 0) {
        s->journal_interval = 0u;
        s->flags |= MCF_SESSION_FLAG_RESUME_DEGRADED;
        return MCF_OK;
    }

    s->blocks_since_ckpt = 0u;
    return MCF_OK;
}

/* ---------------------------------------------------------------------- *
 * Lifecycle
 * ---------------------------------------------------------------------- */

mcf_status_t mcf_session_open(mcf_session_t *s, const mcf_config_t *cfg)
{
    if (s == NULL || cfg == NULL) {
        return MCF_E_PARAM;
    }
    memset(s, 0, sizeof(*s));
    if (cfg->hal == NULL || cfg->hal->flash_erase == NULL ||
        cfg->hal->flash_write == NULL || cfg->hal->flash_block_size == NULL ||
        cfg->hal->get_product_id == NULL || cfg->hal->get_fw_version == NULL ||
        ((cfg->hal->alloc == NULL) != (cfg->hal->free == NULL))) {
        return MCF_E_PARAM;
    }
    s->cfg    = cfg;
    s->hal    = cfg->hal;
    s->state  = MCF_ST_IDLE;
    s->status = MCF_OK;
    s->flags  = 0u;
    return MCF_OK;
}

mcf_status_t mcf_session_begin(mcf_session_t *s)
{
    mcf_status_t st;
    uint32_t     site = MCF_SITE_NONE;
    uint32_t     ws_total;
    uint32_t     blk;
    uint32_t     need;

    if (s == NULL || s->cfg == NULL) {
        return MCF_E_PARAM;
    }
    if (s->state != MCF_ST_IDLE) {
        return mcf_fail(s, MCF_E_STATE, MCF_SITE_STATE);
    }
    if (s->hal == NULL) {
        return mcf_fail(s, MCF_E_PARAM, MCF_SITE_CONFIG);
    }

    s->state = MCF_ST_HEADER;
    s->flash_block = s->hal->flash_block_size(s->hal->ctx);
    if (s->flash_block == 0u || (s->flash_block & (s->flash_block - 1u)) != 0u) {
        return mcf_fail(s, MCF_E_PARAM, MCF_SITE_ALIGN);
    }

    /* 1. Parse and validate the container. The only place the header is
     *    interpreted; everything below trusts the result. */
    st = mcf_hdr_parse(s->hal, s->cfg, s->cfg->patch, s->cfg->patch_size, &s->hdr, &site);
    if (st != MCF_OK) {
        return mcf_fail(s, st, site);
    }

    s->state      = MCF_ST_VALIDATE;
    s->ops        = mcf_codec_lookup(s->cfg, (mcf_codec_id_t)s->hdr.codec_id);
    s->block_size = (s->cfg->block_size != 0u) ? s->cfg->block_size : MCF_DEFAULT_BLOCK_SIZE;
    if (s->block_size > s->hdr.new_size) {
        s->block_size = s->hdr.new_size;
    }
    if ((s->block_size & (s->block_size - 1u)) != 0u) {
        return mcf_fail(s, MCF_E_PARAM, MCF_SITE_ALIGN);
    }

    /* 2. Signature, when the patch claims to be signed. Fails closed: with no
     *    verifier available the patch is rejected, never accepted unverified. */
    if ((s->hdr.flags & MCF_FLAG_SIGNED) != 0u) {
        st = mcf_hdr_verify(s->hal, s->cfg->verify, s->cfg->verify_ctx,
                            s->cfg->patch, &s->hdr);
        if (st != MCF_OK) {
            return mcf_fail(s, st, MCF_SITE_HDR_SIGNATURE);
        }
    }

    /* 3. Payload integrity, for every patch, signed or not. Streamed in small
     *    chunks so the cost does not scale with patch size. */
    {
        uint32_t crc = mcf_crc32_init();
        uint32_t off = 0u;
        uint8_t  tmp[64];

        while (off < s->hdr.payload_stream_len) {
            uint32_t n = s->hdr.payload_stream_len - off;
            if (n > (uint32_t)sizeof(tmp)) {
                n = (uint32_t)sizeof(tmp);
            }
            crc = mcf_crc32_update(crc, &s->hdr.payload[off], n);
            off += n;
        }
        if (mcf_crc32_final(crc) != s->hdr.payload_crc32) {
            return mcf_fail(s, MCF_E_CORRUPT, MCF_SITE_HDR_CRC);
        }
    }

    /* 4. The base image must be what the patch was built against. */
    if (s->cfg->old == NULL && s->cfg->old_read == NULL) {
        return mcf_fail(s, MCF_E_PARAM, MCF_SITE_CONFIG);
    }
    if (s->cfg->old_size != s->hdr.old_size) {
        return mcf_fail(s, MCF_E_MISMATCH, MCF_SITE_BASE_CRC);
    }
    {
        uint32_t crc = mcf_crc32_init();
        if (s->cfg->old != NULL) {
            crc = mcf_crc32_update(crc, s->cfg->old, s->hdr.old_size);
        } else {
            uint8_t  tmp[64];
            uint32_t off = 0u;
            while (off < s->hdr.old_size) {
                uint32_t n = s->hdr.old_size - off;
                if (n > (uint32_t)sizeof(tmp)) {
                    n = (uint32_t)sizeof(tmp);
                }
                {
                    int32_t got = s->cfg->old_read(s->cfg->old_ctx, off, tmp, n);
                    if (got < 0 || (uint32_t)got != n) {
                        return mcf_fail(s, MCF_E_IO, MCF_SITE_OLD_READ);
                    }
                }
                crc = mcf_crc32_update(crc, tmp, n);
                off += n;
            }
        }
        if (mcf_crc32_final(crc) != s->hdr.old_crc32) {
            return mcf_fail(s, MCF_E_MISMATCH, MCF_SITE_BASE_CRC);
        }
    }

    /* 5. Destination must start on an erase boundary so the write path can
     *    guarantee block-aligned, non-crossing writes. */
    if ((s->cfg->dst_addr & (s->flash_block - 1u)) != 0u) {
        return mcf_fail(s, MCF_E_PARAM, MCF_SITE_ALIGN);
    }

    /* 6. Workspace: engine input block, engine output block, codec workspace.
     *
     *    The declared value was checked against ram_budget during header
     *    parsing, which gives a fast rejection before any allocation. The
     *    allocation size is then taken from the codec's own requirement rather
     *    than from the declaration, so a header that under-declares cannot
     *    cause an allocation smaller than the codec needs. */
    s->state = MCF_ST_ALLOC;
    blk      = s->block_size;
    need     = s->ops->workspace_size(s->hdr.props, s->hdr.props_len);
    if (need == 0u) {
        return mcf_fail(s, MCF_E_FORMAT, MCF_SITE_WORKSPACE);
    }
    ws_total = (2u * blk) + need;
    if (ws_total > s->cfg->ram_budget) {
        return mcf_fail(s, MCF_E_DICT_TOO_LARGE, MCF_SITE_WORKSPACE);
    }

    s->raw = (uint8_t *)mcf_ws_alloc(s->hal,
                                     (uint8_t *)(uintptr_t)s->cfg->workspace,
                                     s->cfg->workspace_size, ws_total);
    if (s->raw == NULL) {
        return mcf_fail(s, MCF_E_NOMEM, MCF_SITE_WORKSPACE);
    }
    s->work     = &s->raw[blk];
    s->codec_ws = &s->raw[2u * blk];
    s->ws_size  = ws_total;

    /* 7. Codec init. The codec places its state at the head of its workspace. */
    s->codec = NULL;
    st = s->ops->init(&s->codec, s->hdr.props, s->hdr.props_len, s->codec_ws);
    if (st != MCF_OK || s->codec == NULL) {
        if (st >= MCF_OK) {
            st = MCF_E_CORRUPT;
        }
        return mcf_fail(s, st, MCF_SITE_CODEC_INIT);
    }

    /* 8. Engine. */
    s->state           = MCF_ST_DECODE;
    s->dst_erased_upto = 0u;
    s->dst_written     = 0u;
    s->engine_finished = 0;
    s->io.payload_pos  = 0u;
    s->io.stream_end   = 0;

    s->eio.refill    = mcf_sess_refill;
    s->eio.emit      = mcf_sess_emit;
    s->eio.base_read = mcf_sess_base_read;
    s->eio.shift     = mcf_sess_shift;
    s->eio.raw_origin = &s->io.raw_origin;
    s->eio.ctx       = (void *)s;
    s->eio.site      = &s->site;

    mcf_engine_init(&s->engine, &s->eio, s->raw, blk, s->work, blk,
                    (int32_t)s->hdr.old_size, s->hdr.new_size);

    /* Resume support. The session id identifies the patch, so a journal left by
     * one patch can never be used to resume another. It is computed here on
     * every path, not only when probing: a cold-start run has to record a
     * meaningful id or the checkpoint it writes can never be resumed from. */
    s->session_id = mcf_crc32(s->cfg->patch, (uint32_t)s->hdr.hdr_len);
    s->journal_interval = (s->cfg->journal_addr != 0u)
                              ? ((s->cfg->journal_interval != 0u)
                                     ? s->cfg->journal_interval
                                     : MCF_JOURNAL_DEFAULT_INTERVAL)
                              : 0u;
    s->blocks_since_ckpt = 0u;

    if (s->resumable) {
        /* The prefix on flash is already correct, so the engine re-derives it
         * from the start of the stream and discards it instead of programming
         * it again. The decoder therefore restarts from the beginning. */
        s->io.payload_pos  = 0u;
        s->io.raw_origin   = 0u;
        s->io.stream_end   = 0;
        s->dst_written     = s->resume_newpos;
        s->dst_erased_upto = s->cfg->dst_addr + s->resume_newpos;
        mcf_engine_resume(&s->engine, s->resume_newpos);
        s->resumable = 0;
    }
    return MCF_OK;
}

mcf_status_t mcf_session_step(mcf_session_t *s)
{
    int      finished = 0;
    int32_t  r;

    if (s == NULL) {
        return MCF_E_PARAM;
    }
    if (s->state == MCF_ST_FAILED) {
        return s->status;
    }
    if (s->state == MCF_ST_DONE) {
        return MCF_OK;
    }
    if (s->state != MCF_ST_DECODE) {
        return mcf_fail(s, MCF_E_STATE, MCF_SITE_STATE);
    }

    s->site = MCF_SITE_NONE;
    r = (int32_t)mcf_engine_step(&s->engine, &finished);
    if (r < 0) {
        return mcf_fail(s, (mcf_status_t)r,
                        (s->site != MCF_SITE_NONE) ? s->site : MCF_SITE_CODEC_DECODE);
    }

    /* Progress and abort. A non-zero return is a clean, defined outcome, not a
     * forced watchdog reset. */
    if (s->cfg->progress != NULL) {
        if (s->cfg->progress(s->cfg->progress_ctx, s->dst_written, s->hdr.new_size) != 0) {
            return mcf_fail(s, MCF_E_ABORTED, MCF_SITE_PROGRESS);
        }
    }

    if (finished) {
        s->engine_finished = 1;
        s->state           = MCF_ST_VERIFY;
        return MCF_OK;
    }

    (void)mcf_checkpoint(s);
    return MCF_OK;
}

mcf_status_t mcf_session_finish(mcf_session_t *s)
{
    int32_t r;

    if (s == NULL) {
        return MCF_E_PARAM;
    }
    if (s->state == MCF_ST_FAILED) {
        return s->status;
    }
    if (!s->engine_finished) {
        return mcf_fail(s, MCF_E_STATE, MCF_SITE_STATE);
    }

    /* 1. The codec must have produced exactly the content the patch declared.
     *    A patch cut short is rejected here rather than yielding a short
     *    image. */
    s->state = MCF_ST_VERIFY;
    r = s->ops->finish(s->codec);
    if (r != MCF_OK) {
        return mcf_fail(s, (r < 0) ? (mcf_status_t)r : MCF_E_CORRUPT,
                        MCF_SITE_CODEC_FINISH);
    }

    /* 2. Whole-image CRC, read back from flash rather than trusted from the
     *    buffer that was just written. */
    if (s->hal->flash_read == NULL) {
        return mcf_fail(s, MCF_E_FLASH, MCF_SITE_FLASH_VERIFY);
    }
    {
        uint32_t crc = mcf_crc32_init();
        uint32_t off = 0u;
        uint8_t  tmp[64];

        while (off < s->hdr.new_size) {
            uint32_t n = s->hdr.new_size - off;
            if (n > (uint32_t)sizeof(tmp)) {
                n = (uint32_t)sizeof(tmp);
            }
            r = s->hal->flash_read(s->hal->ctx, s->cfg->dst_addr + off, tmp, n);
            if (r < 0) {
                return mcf_fail(s, MCF_E_IO, MCF_SITE_FLASH_VERIFY);
            }
            if ((uint32_t)r != n) {
                return mcf_fail(s, MCF_E_IO, MCF_SITE_FLASH_VERIFY);
            }
            crc = mcf_crc32_update(crc, tmp, n);
            off += n;
        }
        if (mcf_crc32_final(crc) != s->hdr.new_crc32) {
            return mcf_fail(s, MCF_E_CORRUPT, MCF_SITE_NEW_CRC);
        }
    }

    /* 3. Commit hook. The integrator decides whether to swap; the library only
     *    guarantees the image is verified before this point. */
    s->state = MCF_ST_COMMIT;
    if (s->cfg->commit != NULL && s->cfg->commit(s->cfg->commit_ctx) != 0) {
        return mcf_fail(s, MCF_E_COMMIT, MCF_SITE_COMMIT);
    }

    s->state  = MCF_ST_DONE;
    s->status = MCF_OK;
    /* A finished update must not leave a resume point behind, or a later patch
     * could try to continue from a completed one. */
    (void)mcf_resume_clear(s);
    return MCF_OK;
}

mcf_status_t mcf_session_run(mcf_session_t *s)
{
    mcf_status_t st;

    if ((st = mcf_session_begin(s)) != MCF_OK) {
        return st;
    }
    for (;;) {
        if ((st = mcf_session_step(s)) != MCF_OK) {
            return st;
        }
        if (s->state == MCF_ST_VERIFY) {
            break;
        }
    }
    return mcf_session_finish(s);
}

void mcf_session_close(mcf_session_t *s)
{
    if (s == NULL) {
        return;
    }
    if (s->codec != NULL && s->ops != NULL && s->ops->destroy != NULL) {
        s->ops->destroy(s->codec);
    }
    mcf_ws_free(s->hal, s->raw);
    s->codec           = NULL;
    s->raw             = NULL;
    s->work            = NULL;
    s->codec_ws        = NULL;
    s->state           = MCF_ST_IDLE;
    s->status          = MCF_OK;
    s->site            = MCF_SITE_NONE;
    s->engine_finished = 0;
    s->dst_written     = 0u;
    s->dst_erased_upto = 0u;
}

/* ---------------------------------------------------------------------- *
 * Queries
 * ---------------------------------------------------------------------- */

mcf_state_t mcf_session_state(const mcf_session_t *s)
{
    return (s != NULL) ? s->state : MCF_ST_IDLE;
}

mcf_status_t mcf_session_status(const mcf_session_t *s)
{
    return (s != NULL) ? s->status : MCF_E_PARAM;
}

uint32_t mcf_session_progress(const mcf_session_t *s)
{
    return (s != NULL) ? s->dst_written : 0u;
}

uint32_t mcf_session_total(const mcf_session_t *s)
{
    return (s != NULL) ? s->hdr.new_size : 0u;
}

uint32_t mcf_session_flags(const mcf_session_t *s)
{
    return (s != NULL) ? s->flags : 0u;
}

uint32_t mcf_session_error_site(const mcf_session_t *s)
{
    return (s != NULL) ? s->site : MCF_SITE_NONE;
}

mcf_status_t mcf_session_lzma_info(const mcf_session_t *s, mcf_lzma_info_t *out)
{
    if (s == NULL || out == NULL) {
        return MCF_E_PARAM;
    }
    memset(out, 0, sizeof(*out));
    if (s->hdr.codec_id != (uint8_t)MCF_CODEC_LZMA) {
        return MCF_E_NOT_FOUND;
    }
    out->valid     = 1u;
    out->lc        = s->hdr.lzma_lc;
    out->lp        = s->hdr.lzma_lp;
    out->pb        = s->hdr.lzma_pb;
    out->dict_size = s->hdr.lzma_dict;
    /* The device's own figure for these parameters. Callers compare it against
     * their budget; it is what the session would allocate. */
    out->workspace = s->ws_size;
    return MCF_OK;
}
