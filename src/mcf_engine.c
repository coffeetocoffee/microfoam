/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - BSDIFF43 delta application engine.
 *
 * Codec-agnostic, allocation-free, no static state, and resumable: a single call
 * performs at most out_cap bytes of work so the caller can step it and service a
 * watchdog between blocks.
 *
 * Upstream-License: BSD 2-Clause.
 *   Derived from bspatch by Matthew Endsley (2012), itself derived from bsdiff
 *   by Colin Percival (2003-2005). See LICENSE for the full notice.
 *
 * Deliberate differences from the upstream reference:
 *   - 32-bit clean. The control triple is range-checked into int32 on decode, so
 *     no 64-bit arithmetic appears in the loop body.
 *   - Every base-image access is bounds-checked before use, so a malformed seek
 *     degrades to the defined "zero outside the base image" behaviour instead of
 *     an out-of-bounds read.
 *   - Every failure returns a distinct status. No path reports success after an
 *     error, and the per-byte read in the reference hot loop is replaced with a
 *     single bounded batch read.
 */

#include "mcf_internal.h"

/* ---------------------------------------------------------------------- *
 * BSDIFF43 offset encoding: little-endian, top bit is a sign flag, magnitude
 * occupies the low 55 bits. This is not the two's-complement encoding used by
 * Colin Percival's original bsdiff, so patches are not interchangeable between
 * the two formats.
 * ---------------------------------------------------------------------- */
static int64_t mcf_offtin(const uint8_t *buf)
{
    uint64_t y;
    int      i;

    y = 0u;
    for (i = 7; i >= 0; i--) {
        y = (y << 8) | (uint64_t)buf[i];
    }
    y &= UINT64_C(0x007FFFFFFFFFFFFF); /* magnitude only */
    if ((buf[7] & 0x80u) != 0u) {
        y = UINT64_C(0) - y;
    }
    return (int64_t)y;
}

static int mcf_offtin_i32(const uint8_t *buf, int32_t *out)
{
    int64_t v = mcf_offtin(buf);

    if (v < (int64_t)INT32_MIN || v > (int64_t)INT32_MAX) {
        return -1;
    }
    *out = (int32_t)v;
    return 0;
}

/* ---------------------------------------------------------------------- */

void mcf_engine_init(mcf_engine_t *e, const mcf_engine_io_t *io, uint8_t *raw,
                     uint32_t raw_cap, uint8_t *out, uint32_t out_cap,
                     int32_t old_size, uint32_t new_size)
{
    memset(e, 0, sizeof(*e));
    e->io       = io;
    e->raw      = raw;
    e->raw_cap  = raw_cap;
    e->out      = out;
    e->out_cap  = out_cap;
    e->old_size = old_size;
    e->newsize  = new_size;
    e->phase    = MCF_EP_CTRL;
}

/* Ensure at least `want` bytes are contiguous in raw, refilling as needed.
 * Returns the number available, or a negative status. */
static int32_t mcf_engine_ensure(mcf_engine_t *e, uint32_t want)
{
    while ((e->raw_len - e->raw_pos) < want) {
        uint32_t n    = 0u;
        int      eof  = 0;

        if (e->raw_pos > 0u) {
            uint32_t consumed = e->raw_pos;

            if (e->io->shift != NULL) {
                e->io->shift(e->io->ctx, consumed);
            } else {
                uint32_t rem = e->raw_len - consumed;
                if (rem > 0u) {
                    memmove(e->raw, &e->raw[consumed], rem);
                }
                e->raw_len = rem;
                e->raw_pos = 0u;
            }
        }

        if (e->raw_eof) {
            if (e->raw_len >= want) {
                break;
            }
            *e->io->site = MCF_SITE_READ_DIFF;
            return (int32_t)MCF_E_TRUNCATED;
        }

        {
            int32_t refill_status = e->io->refill(e->io->ctx, &e->raw[e->raw_len],
                                                  e->raw_cap - e->raw_len, &n, &eof);
            if (refill_status < 0) {
                return refill_status;
            }
            if (refill_status != MCF_OK) {
                *e->io->site = MCF_SITE_READ_DIFF;
                return (int32_t)MCF_E_CORRUPT;
            }
        }
        if (eof) {
            e->raw_eof = 1;
        }
        if (n == 0u) {
            if (eof) {
                if (e->raw_len >= want) {
                    break;
                }
                /* The stream ended without enough data to continue. */
                *e->io->site = MCF_SITE_READ_DIFF;
                return (int32_t)MCF_E_TRUNCATED;
            }
            /* A refill that produces nothing and is not at EOF would spin. */
            *e->io->site = MCF_SITE_READ_DIFF;
            return (int32_t)MCF_E_CORRUPT;
        }
        e->raw_len += n;
    }
    return (int32_t)(e->raw_len - e->raw_pos);
}

/* ---------------------------------------------------------------------- */

/* Mark the engine as being between triples: nothing is partially consumed, so
 * a session may capture a resumable point. */
static void mcf_engine_mark_safe(mcf_engine_t *e)
{
    e->safe = 1;
}

void mcf_engine_resume(mcf_engine_t *e, uint32_t skip)
{
    /* Restart the stream from the beginning and discard `skip` bytes of output.
     *
     * The alternative - seeking the decompressor to a recorded byte offset - is
     * not expressible in this interface. A decompressed-stream position and a
     * compressed-stream position are different coordinate systems, and the
     * compressed one is only meaningful at a codec block boundary, which the
     * delta engine knows nothing about. Doing it properly needs a rewind entry
     * in the codec vtable; until that exists, re-deriving the prefix is the only
     * correct option, and it is cheap: the work saved is the flash programming
     * of the prefix, which is the expensive part.
     */
    e->newpos          = 0;
    e->oldpos          = 0;
    e->diff_remaining  = 0;
    e->extra_remaining = 0;
    e->raw_pos         = 0u;
    e->raw_len         = 0u;
    e->raw_eof         = 0;
    e->phase           = MCF_EP_CTRL;
    e->safe            = 0;
    e->discard         = (int32_t)skip;
    e->in_discard      = 0u;
    e->pending_seek    = 0;
}

void mcf_engine_resume_at(mcf_engine_t *e, uint32_t out_off, int32_t old_off,
                          uint32_t in_skip, mcf_engine_phase_t phase,
                          int32_t diff_remaining, int32_t extra_remaining,
                          int32_t seek)
{
    /* Positioning resume: the caller has arranged for the fed stream to begin
     * at the frame boundary the resume point recorded and states how many
     * decompressed bytes to drop before the byte that point named. Unlike
     * mcf_engine_resume(), nothing is re-derived: the engine restarts in the
     * exact recorded phase - which may be mid-triple, so the remaining diff
     * and literal counts are restored too, along with the current triple's
     * seek if it had not been applied yet. Output coordinates remain absolute,
     * so the engine stops at the original newsize and never rewrites anything
     * below out_off. */
    e->newpos          = (int32_t)out_off;
    e->oldpos          = old_off;
    e->diff_remaining  = diff_remaining;
    e->extra_remaining = extra_remaining;
    e->raw_pos         = 0u;
    e->raw_len         = 0u;
    e->raw_eof         = 0;
    e->phase           = phase;
    e->safe            = 0;
    e->discard         = 0;
    e->in_discard      = in_skip;
    e->stop_at         = 0u;
    e->pending_seek    = seek;
}

mcf_status_t mcf_engine_step(mcf_engine_t *e, int *finished)
{
    uint32_t budget = e->out_cap; /* bounded work per call */

    *finished = 0;

    /* Consume-and-drop the positioning prefix first, if any. Charged against
     * the step budget like every other unit of work, so a single call still
     * cannot run longer than out_cap bytes; a short remainder simply continues
     * on the next step. */
    while (e->in_discard > 0u && budget > 0u) {
        int32_t  avail = mcf_engine_ensure(e, 1u);
        uint32_t n;

        if (avail < 0) {
            return (mcf_status_t)avail;
        }
        n = (uint32_t)avail;
        if (n > budget) {
            n = budget;
        }
        if (n > e->in_discard) {
            n = e->in_discard;
        }
        e->raw_pos    += n;
        e->in_discard -= n;
        budget        -= n;
    }
    if (e->in_discard > 0u) {
        return MCF_OK;
    }

    if (e->newpos >= (int32_t)e->newsize) {
        e->phase  = MCF_EP_DONE;
        mcf_engine_mark_safe(e);
        *finished = 1;
        return MCF_OK;
    }

    while (budget > 0u) {
        /* The requested stop offset was reached exactly on a previous pass. */
        if (e->stop_at != 0u && (uint32_t)e->newpos >= e->stop_at) {
            e->stop_at = 0u;
            return MCF_OK;
        }
        switch (e->phase) {

        case MCF_EP_CTRL: {
            uint8_t  ctl[24];
            int32_t  x, y, seek;
            int32_t  avail;
            uint32_t i;

            /* Apply the previous triple's seek before reading the next header.
             * BSDIFF43 applies a triple's seek after its diff and extra bytes,
             * so it positions the base cursor for the *next* triple, not its
             * own. Deferring it to here is what makes that so: by the time the
             * next header is read, the previous triple's bytes have all been
             * consumed. The value is part of the resumable state, so a
             * checkpoint taken in between carries it across a restart. */
            if (e->pending_seek != 0) {
                int32_t prev = e->pending_seek;

                if (prev > 0) {
                    if (e->oldpos > (INT32_MAX - prev)) {
                        *e->io->site = MCF_SITE_SANITY_SEEK;
                        return MCF_E_CORRUPT;
                    }
                } else if (e->oldpos < (INT32_MIN - prev)) {
                    *e->io->site = MCF_SITE_SANITY_SEEK;
                    return MCF_E_CORRUPT;
                }
                e->oldpos += prev;
                e->pending_seek = 0;
            }

            /* About to consume a header, so the current position is no longer a
             * safe place to resume from. */
            e->safe = 0;

            avail = mcf_engine_ensure(e, (uint32_t)sizeof(ctl));
            if (avail < 0) {
                return (mcf_status_t)avail;
            }
            if ((uint32_t)avail < (uint32_t)sizeof(ctl)) {
                *e->io->site = MCF_SITE_READ_CTRL;
                return MCF_E_TRUNCATED;
            }
            for (i = 0; i < (uint32_t)sizeof(ctl); i++) {
                ctl[i] = e->raw[e->raw_pos + i];
            }
            e->raw_pos += (uint32_t)sizeof(ctl);

            if (mcf_offtin_i32(&ctl[0], &x) != 0 || mcf_offtin_i32(&ctl[8], &y) != 0 ||
                mcf_offtin_i32(&ctl[16], &seek) != 0) {
                *e->io->site = MCF_SITE_SANITY_DIFF;
                return MCF_E_CORRUPT;
            }
            if (x < 0 || y < 0) {
                *e->io->site = MCF_SITE_SANITY_DIFF;
                return MCF_E_CORRUPT;
            }
            /* Bound check in int64 so the check itself cannot overflow; the
             * engine loop itself stays 32-bit. */
            if ((int64_t)e->newpos + (int64_t)x + (int64_t)y > (int64_t)e->newsize) {
                *e->io->site = MCF_SITE_SANITY_EXTRA;
                return MCF_E_CORRUPT;
            }

            e->diff_remaining  = x;
            e->extra_remaining = y;
            e->phase           = (x > 0) ? MCF_EP_DIFF : MCF_EP_EXTRA;

            /* Hold the seek for the next triple. Its overflow bound is checked
             * where it is applied, against the cursor as it then stands. */
            e->pending_seek = seek;
            e->safe = 0;
            break;
        }

        case MCF_EP_DIFF: {
            int32_t  avail;
            uint32_t n;
            uint32_t i;
            int64_t  lo, hi;

            if (e->diff_remaining == 0) {
                e->phase = MCF_EP_EXTRA;
                break;
            }

            avail = mcf_engine_ensure(e, 1u);
            if (avail < 0) {
                return (mcf_status_t)avail;
            }
            n = (uint32_t)avail;
            if (n > budget) {
                n = budget;
            }
            if ((int32_t)n > e->diff_remaining) {
                n = (uint32_t)e->diff_remaining;
            }
            if (e->stop_at != 0u && (uint32_t)e->newpos < e->stop_at &&
                n > e->stop_at - (uint32_t)e->newpos) {
                n = e->stop_at - (uint32_t)e->newpos;
            }

            /* Fetch the overlapping base-image run in one call rather than one
             * call per byte. The base bytes land in out[]; the delta bytes are
             * still intact in raw[] and are combined in the pass below. */
            lo = (int64_t)e->oldpos;
            hi = lo + (int64_t)n;
            if (lo < 0) {
                lo = 0;
            }
            if (hi > (int64_t)e->old_size) {
                hi = (int64_t)e->old_size;
            }
            if (hi > lo) {
                uint32_t base_off = (uint32_t)(lo - (int64_t)e->oldpos);
                uint32_t base_len = (uint32_t)(hi - lo);
                int32_t  got = e->io->base_read(e->io->ctx, (uint32_t)lo, &e->out[base_off],
                                                base_len);
                if (got < 0) {
                    *e->io->site = MCF_SITE_OLD_READ;
                    return MCF_E_IO;
                }
                if ((uint32_t)got != base_len) {
                    *e->io->site = MCF_SITE_OLD_READ;
                    return MCF_E_IO;
                }
            }

            for (i = 0; i < n; i++) {
                int64_t o = (int64_t)e->oldpos + (int64_t)i;
                uint8_t delta = e->raw[e->raw_pos + i];
                uint8_t base  = 0u;

                if (o >= 0 && o < (int64_t)e->old_size) {
                    base = e->out[i];
                }
                e->out[i] = (uint8_t)(delta + base);
            }

            e->raw_pos         += n;
            e->diff_remaining -= (int32_t)n;
            e->oldpos         += (int32_t)n;
            e->newpos         += (int32_t)n;
            budget            -= n;

            /* emit() reports the specific status from the sink, e.g.
             * MCF_E_FLASH for a failed program. Flattening it to MCF_E_IO would
             * hide the one fact the integrator most needs to see.
             *
             * While resuming, the leading `discard` bytes are already correct
             * in the destination and must not be programmed again. A block can
             * straddle the boundary, so the skip is partial. */
            if (e->discard >= (int32_t)n) {
                e->discard -= (int32_t)n;
            } else {
                uint32_t skip = (uint32_t)e->discard;
                int32_t  rc;
                e->discard = 0;
                rc = e->io->emit(e->io->ctx, &e->out[skip], n - skip);
                if (rc < 0) {
                    return (mcf_status_t)rc;
                }
            }

            if (e->diff_remaining == 0) {
                e->phase = MCF_EP_EXTRA;
                /* If the triple has no extra segment either, the next thing
                 * the engine will do is read a control header, so this is a
                 * genuine boundary. Marking it here matters: the step budget
                 * can run out exactly on this transition, and a caller that
                 * only checked for the CTRL phase would then never see a safe
                 * point to checkpoint at. */
                if (e->extra_remaining == 0) {
                    mcf_engine_mark_safe(e);
                }
            }
            if (e->stop_at != 0u && (uint32_t)e->newpos >= e->stop_at) {
                e->stop_at = 0u;
                return MCF_OK;
            }
            if (e->newpos >= (int32_t)e->newsize) {
                e->phase  = MCF_EP_DONE;
                mcf_engine_mark_safe(e);
                *finished = 1;
                return MCF_OK;
            }
            break;
        }

        case MCF_EP_EXTRA: {
            int32_t  avail;
            uint32_t n;

            if (e->extra_remaining == 0) {
                if (e->newpos >= (int32_t)e->newsize) {
                    e->phase  = MCF_EP_DONE;
                    mcf_engine_mark_safe(e);
                    *finished = 1;
                    return MCF_OK;
                }
                e->phase = MCF_EP_CTRL;
                mcf_engine_mark_safe(e);
                break;
            }

            avail = mcf_engine_ensure(e, 1u);
            if (avail < 0) {
                return (mcf_status_t)avail;
            }
            n = (uint32_t)avail;
            if (n > budget) {
                n = budget;
            }
            if ((int32_t)n > e->extra_remaining) {
                n = (uint32_t)e->extra_remaining;
            }
            if (e->stop_at != 0u && (uint32_t)e->newpos < e->stop_at &&
                n > e->stop_at - (uint32_t)e->newpos) {
                n = e->stop_at - (uint32_t)e->newpos;
            }

            memcpy(e->out, &e->raw[e->raw_pos], n);
            e->raw_pos += n;

            e->extra_remaining -= (int32_t)n;
            e->newpos           += (int32_t)n;
            budget              -= n;

            if (e->discard >= (int32_t)n) {
                e->discard -= (int32_t)n;
            } else {
                uint32_t skip = (uint32_t)e->discard;
                int32_t  rc;
                e->discard = 0;
                rc = e->io->emit(e->io->ctx, &e->out[skip], n - skip);
                if (rc < 0) {
                    return (mcf_status_t)rc;
                }
            }

            if (e->extra_remaining == 0) {
                if (e->newpos >= (int32_t)e->newsize) {
                    e->phase  = MCF_EP_DONE;
                    mcf_engine_mark_safe(e);
                    *finished = 1;
                    return MCF_OK;
                }
                e->phase = MCF_EP_CTRL;
                mcf_engine_mark_safe(e);
            }
            if (e->stop_at != 0u && (uint32_t)e->newpos >= e->stop_at) {
                e->stop_at = 0u;
                return MCF_OK;
            }
            break;
        }

        case MCF_EP_DONE:
        default:
            *e->io->site = MCF_SITE_STATE;
            return MCF_E_STATE;
        }
    }

    return MCF_OK;
}
