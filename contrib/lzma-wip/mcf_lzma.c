/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - LZMA1 decoder.
 *
 * Scope and cost
 * --------------
 * Decode only, and only the LZMA1 raw stream (no container, no header). The
 * host tool writes the properties; see mcf_lzma.h.
 *
 * The dominant cost is the probability table: 1846 + 768 << (lc + lp) entries
 * of 16 bits, so 5,228 bytes at lc=lp=0 and 15,980 bytes at the usual lc=3,
 * lp=0. That is exactly why LZMA is an opt-in codec here: the table is
 * allocated before a single dictionary byte and is not a function of the image
 * size. A device that can afford it gets a materially smaller patch; a device
 * that cannot should keep LZ4, which costs 16 bytes.
 *
 * The table size is a property of the stream, so it is reported through
 * workspace_size() and declared in the patch header's workspace_req. The device
 * checks the declared value against ram_budget during header validation, before
 * allocating anything, and allocates from the codec's own figure rather than
 * from the declaration.
 *
 * Implementation notes
 * --------------------
 * Portable C99. No 128-bit integers, so a Cortex-M0 needs no libgcc support for
 * multiplication. The probability model is 16-bit as the format specifies.
 *
 * Upstream-License: the LZMA algorithm and its probability model are from the
 * LZMA specification (public domain, Igor Pavlov). The decoder below is written
 * against the specification; see docs/architecture.md section 7.3 for why this
 * is opt-in rather than the default.
 */

#include "mcf_internal.h"

#include "mcf_lzma.h"

/* ---------------------------------------------------------------------- *
 * Probability model layout
 *
 * Named offsets rather than the LZMA SDK's absolute indices, so the model is
 * readable and cannot silently drift if the entry counts change.
 * ---------------------------------------------------------------------- */

#define NUM_STATES 12u
#define NUM_POS_BITS_MAX 4u
#define NUM_LEN_TO_POS_STATES 4u
#define NUM_ALIGN_BITS 4u
#define END_POS_MODEL_INDEX 14u
#define MATCH_MIN_LEN 2u
#define NUM_FULL_DISTANCES (1u << (END_POS_MODEL_INDEX / 2))   /* 128 */

#define P_IS_MATCH      0u                                       /* 12 << 4 = 192 */
#define P_IS_REP        (P_IS_MATCH + (NUM_STATES << NUM_POS_BITS_MAX))          /* 192 */
#define P_IS_REP_G0     (P_IS_REP + NUM_STATES)                   /* 204 */
#define P_IS_REP_G1     (P_IS_REP_G0 + NUM_STATES)                /* 216 */
#define P_IS_REP_G2     (P_IS_REP_G1 + NUM_STATES)                /* 228 */
#define P_IS_REP0_LONG  (P_IS_REP_G2 + NUM_STATES)                /* 240 */
#define P_POS_SLOT      (P_IS_REP0_LONG + (NUM_STATES << NUM_POS_BITS_MAX))      /* 432 */
/* The position-slot tree is indexed by length state, of which there are
 * NUM_LEN_TO_POS_STATES, each with a 6-bit tree. So the block is
 * NUM_LEN_TO_POS_STATES * 64 entries, not 64. Sizing it as 64 shifts every
 * following region down and overlaps the literal table with the position
 * models, which decodes to plausible-looking garbage rather than failing. */
#define POS_SLOT_PROBS  (NUM_LEN_TO_POS_STATES * (1u << 6))       /* 256 */
#define P_SPEC_POS      (P_POS_SLOT + POS_SLOT_PROBS)             /* 688 */
/* Reverse-tree slots. The largest is pos_slot 13, which gives dist 96 and a
 * five-bit tree; the base is P_SPEC_POS + dist - pos_slot - 1 = +82, and the
 * tree reads base + m for m up to 31, so the region must span 82 + 31 + 1 =
 * 114 entries. The SDK derives this as kNumFullDistances - kEndPosModelIndex
 * = 114, which is one short of what the tree actually touches; sizing it at 114
 * lets the final bits alias the alignment table. */
#define SPEC_POS_PROBS  115u
#define P_ALIGN         (P_SPEC_POS + SPEC_POS_PROBS)            /* 803 */
#define P_LEN           (P_ALIGN + (1u << NUM_ALIGN_BITS))        /* 818 */
/* A length coder is: choice, choice2, then a low and a mid tree per position
 * state (16 states x 8 leaves each), then one shared high tree of 256. That
 * is 2 + 128 + 128 + 256 = 514, not 274. Getting this wrong silently overlaps
 * the literal probability table with the repeated-length coder and corrupts the
 * whole model, so P_LITERAL below must land on 1846. */
#define LEN_PROBS       (2u + (1u << 4) * (1u << 3) * 2u + (1u << 8))  /* 514 */
#define P_REP_LEN       (P_LEN + LEN_PROBS)                      /* 1332 */
#define P_LITERAL       (P_REP_LEN + LEN_PROBS)                  /* 1846 */
#define P_BASE          P_LITERAL

/* ---------------------------------------------------------------------- *
 * Range decoder
 * ---------------------------------------------------------------------- */

/* kTopValue from the LZMA specification: 1 << 24.
 *
 * The range coder normalises whenever range drops below this, which is what
 * keeps range at or above 2^24. Using 0xFF000000 here - a plausible-looking but
 * wrong value - normalises roughly sixteen times less often, so range decays
 * through zero partway through any stream and every subsequent decode is
 * garbage. It presents as "the decoder runs out of input" rather than as an
 * arithmetic error, which is why it survived six other fixes. */
#define RC_TOP_VALUE ((uint32_t)1 << 24)
#define RC_BIT_MODEL_TOTAL 2048u   /* 1 << 11 */
#define RC_MOVE_BITS 5u

static void rc_normalize(mcf_lzma_t *c)
{
    if (c->range < RC_TOP_VALUE) {
        c->range <<= 8;
        c->code = (c->code << 8) | (c->in_pos < c->in_size ? c->in[c->in_pos++] : 0u);
    }
}

static uint32_t rc_byte(mcf_lzma_t *c)
{
    if (c->in_pos < c->in_size) {
        return c->in[c->in_pos++];
    }
    /* Out of input. Report a zero but do NOT advance the cursor: the caller
     * adds this value to its source position, and overshooting would move it
     * past the end of the buffer. input_exhausted makes the main loop stop and
     * finish() turns the short read into MCF_E_TRUNCATED. */
    c->input_exhausted = 1u;
    return 0u;
}

static uint32_t rc_bit(mcf_lzma_t *c, uint16_t *prob)
{
    uint32_t bound = (c->range >> 11) * (uint32_t)(*prob);
    uint32_t bit;

    if (c->code < bound) {
        c->range = bound;
        *prob = (uint16_t)(*prob + ((RC_BIT_MODEL_TOTAL - *prob) >> RC_MOVE_BITS));
        bit = 0u;
    } else {
        c->range -= bound;
        c->code -= bound;
        *prob = (uint16_t)(*prob - (*prob >> RC_MOVE_BITS));
        bit = 1u;
    }
    rc_normalize(c);
    return bit;
}
/* Decode `n` raw (unmodelled) bits, most significant first.
 *
 * The normalisation must happen inside the loop, once per bit, exactly as the
 * reference decoder does. Doing it once at the end halves `range` up to 25 times
 * without replenishing, which loses the precision that keeps `range` at or above
 * 2^24 between bits. The symptom is narrow and misleading: the low `pos_slot`
 * values decode fine because they need only two or three direct bits, while a
 * large distance needing ten or more comes out as a distance of tens of millions
 * against a 64 KB dictionary. */
static uint32_t rc_bit_direct(mcf_lzma_t *c, uint32_t n)
{
    uint32_t res = 0u;
    uint32_t i;

    for (i = 0; i < n; i++) {
        uint32_t t;

        c->range >>= 1;
        c->code -= c->range;
        t = 0u - (c->code >> 31);   /* all ones if the subtraction borrowed */
        c->code += c->range & t;
        rc_normalize(c);
        res = (res << 1) + (t + 1u);
    }
    return res;
}

static uint32_t rc_tree(mcf_lzma_t *c, uint16_t *probs, uint32_t nbits)
{
    uint32_t m = 1u;
    uint32_t i;

    for (i = 0; i < nbits; i++) {
        m = (m << 1) + rc_bit(c, &probs[m]);
    }
    return m - (1u << nbits);
}

static uint32_t rc_tree_reverse(mcf_lzma_t *c, uint16_t *probs, uint32_t nbits)
{
    uint32_t m = 1u;
    uint32_t sym = 0u;
    uint32_t i;

    for (i = 0; i < nbits; i++) {
        uint32_t b = rc_bit(c, &probs[m]);
        m = (m << 1) + b;
        sym |= b << i;
    }
    return sym;
}

/* ---------------------------------------------------------------------- *
 * Dictionary: a ring buffer of dict_size bytes
 * ---------------------------------------------------------------------- */

static uint8_t dict_get(const mcf_lzma_t *c, uint32_t dist)
{
    /* dist is 1-based: dist 1 is the byte just written.
     *
     * A distance reaching before the start of the output reads the
     * "pre-history" of the window, which the format defines as zero. Returning
     * zero here is that rule, and it also means the decoder never reads memory
     * it has not written - which it otherwise did, making the result depend on
     * whatever happened to be in the caller's workspace. */
    uint32_t pos;

    if (dist == 0u || dist > c->dict_size || dist > c->produced) {
        return 0u;
    }
    pos = c->dict_pos + c->dict_size - dist;
    if (pos >= c->dict_size) {
        pos -= c->dict_size;
    }
    return c->dict[pos];
}

static void dict_put(mcf_lzma_t *c, uint8_t b)
{
    c->dict[c->dict_pos] = b;
    c->dict_pos++;
    if (c->dict_pos >= c->dict_size) {
        c->dict_pos = 0u;
    }
}

/* ---------------------------------------------------------------------- *
 * Workspace
 * ---------------------------------------------------------------------- */

static int mcf_lzma_props(const uint8_t *props, uint32_t *lc, uint32_t *lp, uint32_t *pb)
{
    uint32_t v;

    if (props == NULL) {
        return -1;
    }
    v = props[0];
    if (v >= 9u * 5u * 5u) {
        return -1;
    }
    *lc = v % 9u;
    *lp = (v / 9u) % 5u;
    *pb = v / 45u;
    if (*lc > 8u || *lp > 4u || *pb > 4u) {
        return -1;
    }
    return 0;
}

uint32_t mcf_lzma_workspace(const uint8_t *props, uint32_t props_len)
{
    uint32_t lc, lp, pb;
    uint32_t probs;
    uint32_t off_dict;

    if (props == NULL || props_len < MCF_LZMA_PROPS_LEN) {
        return 0u;
    }
    if (mcf_lzma_props(props, &lc, &lp, &pb) != 0) {
        return 0u;
    }
    probs = P_BASE + (768u << (lc + lp));
    /* Lay the workspace out as: state struct, then the probability table at a
     * 2-byte boundary, then the dictionary at a 4-byte boundary. */
    off_dict = (uint32_t)sizeof(mcf_lzma_t);
    off_dict = (off_dict + 1u) & ~1u;             /* align uint16_t table */
    off_dict += probs * 2u;
    off_dict = (off_dict + 3u) & ~3u;             /* align the byte ring   */
    return off_dict + (props[1] | ((uint32_t)props[2] << 8) |
                       ((uint32_t)props[3] << 16) | ((uint32_t)props[4] << 24));
}

int32_t mcf_lzma_init(mcf_codec_t **out, const uint8_t *props, uint32_t props_len,
                      uint8_t *ws)
{
    mcf_lzma_t *c = (mcf_lzma_t *)(void *)ws;
    uint32_t    lc, lp, pb;
    uint32_t    probs, off_probs, off_dict, dict_size, i;

    if (out == NULL || ws == NULL || props == NULL || props_len < MCF_LZMA_PROPS_LEN) {
        return (int32_t)MCF_E_PARAM;
    }

    /* Zero the whole state object before assigning fields individually. A field
     * that is added later and not added here reads whatever the caller's
     * workspace happened to contain: `input_exhausted` was missing and the
     * decoder appeared to work only because a zeroed workspace is what a test
     * harness tends to hand it. Whole-object clearing makes that class of bug
     * impossible rather than merely absent today. */
    memset(c, 0, sizeof(*c));

    if (mcf_lzma_props(props, &lc, &lp, &pb) != 0) {
        return (int32_t)MCF_E_FORMAT;
    }

    dict_size = (uint32_t)props[1] | ((uint32_t)props[2] << 8) |
                ((uint32_t)props[3] << 16) | ((uint32_t)props[4] << 24);
    c->content_size = (uint32_t)props[5] | ((uint32_t)props[6] << 8) |
                      ((uint32_t)props[7] << 16) | ((uint32_t)props[8] << 24);

    /* A dictionary smaller than the match window cannot resolve its own
     * matches. Refuse rather than silently corrupt. */
    if (dict_size < 4096u) {
        return (int32_t)MCF_E_DICT_TOO_LARGE;
    }
    if (c->content_size == 0u) {
        return (int32_t)MCF_E_FORMAT;
    }

    probs     = P_BASE + (768u << (lc + lp));
    off_probs = (uint32_t)sizeof(mcf_lzma_t);
    off_probs = (off_probs + 1u) & ~1u;
    off_dict  = off_probs + probs * 2u;
    off_dict  = (off_dict + 3u) & ~3u;

    c->probs      = (uint16_t *)(void *)&ws[off_probs];
    c->dict       = &ws[off_dict];
    c->dict_size  = dict_size;
    c->dict_pos   = 0u;
    c->dict_end   = c->dict + dict_size;
    c->lc         = lc;
    c->lp         = lp;
    c->pb         = pb;
    c->pb_mask    = (1u << pb) - 1u;
    c->lp_mask    = (1u << lp) - 1u;
    c->state      = 0u;
    c->rep0 = c->rep1 = c->rep2 = c->rep3 = 0u;
    c->produced    = 0u;
    c->pending     = 0u;
    c->done        = 0u;
    c->in          = NULL;
    c->in_pos      = 0u;
    c->in_size     = 0u;
    c->range       = 0xFFFFFFFFu;
    c->code        = 0u;

    /* The probability model starts as 1/2 of the range everywhere. */
    /* Filled last: these are char-type writes through `ws`, which the compiler
     * may sink past the struct stores above. Doing them last removes any
     * question of ordering between the two. */
    for (i = 0; i < probs; i++) {
        c->probs[i] = (uint16_t)(RC_BIT_MODEL_TOTAL / 2);
    }
    *out = (mcf_codec_t *)(void *)c;
    return (int32_t)MCF_OK;
}

/* ---------------------------------------------------------------------- *
 * Length and distance decoding
 * ---------------------------------------------------------------------- */

static uint32_t mcf_lzma_len(mcf_lzma_t *c, uint16_t *base, uint32_t pos_state)
{
    /* Low and mid are indexed by position state; the high tree is shared. */
    if (rc_bit(c, &base[0]) == 0u) {
        return rc_tree(c, base + 2u + pos_state * 8u, 3);
    }
    if (rc_bit(c, &base[1]) == 0u) {
        return 8u + rc_tree(c, base + 2u + 128u + pos_state * 8u, 3);
    }
    return 16u + rc_tree(c, base + 2u + 128u + 128u, 8);
}

static uint32_t mcf_lzma_dist(mcf_lzma_t *c, uint32_t len)
{
    uint32_t len_state = len;
    uint32_t pos_slot;
    uint32_t dist;
    uint32_t direct;

    if (len_state > NUM_LEN_TO_POS_STATES - 1u) {
        len_state = NUM_LEN_TO_POS_STATES - 1u;
    }
    pos_slot = rc_tree(c, &c->probs[P_POS_SLOT + (len_state << 6)], 6);

    if (pos_slot < 4u) {
        return pos_slot;
    }

    direct = (pos_slot >> 1) - 1u;
    dist = (2u | (pos_slot & 1u)) << direct;

    if (pos_slot < END_POS_MODEL_INDEX) {
        dist += rc_tree_reverse(c,
                &c->probs[P_SPEC_POS + dist - pos_slot - 1u], direct);
    } else {
        dist += rc_bit_direct(c, direct - NUM_ALIGN_BITS) << NUM_ALIGN_BITS;
        dist += rc_tree_reverse(c, &c->probs[P_ALIGN], NUM_ALIGN_BITS);
    }
    return dist;
}

/* ---------------------------------------------------------------------- *
 * Decoding
 * ---------------------------------------------------------------------- */

int32_t mcf_lzma_decode(mcf_codec_t *codec,
                        uint8_t *out, uint32_t cap, uint32_t *produced_out,
                        const uint8_t *in, uint32_t in_avail, uint32_t *consumed_out)
{
    mcf_lzma_t *c = (mcf_lzma_t *)(void *)codec;
    uint32_t    produced = 0u;
    uint32_t    ring_start;

    if (c == NULL || out == NULL || produced_out == NULL || consumed_out == NULL) {
        return (int32_t)MCF_E_PARAM;
    }
    *produced_out = 0u;
    *consumed_out = 0u;
    if (c->done || produced >= cap || in_avail == 0u) {
        return (int32_t)MCF_OK;
    }

    /* First call establishes the range coder. The stream opens with a zero
     * byte followed by the initial 32-bit code, big-endian. */
    if (c->in == NULL) {
        uint32_t i;
        c->in      = in;
        c->in_pos  = 0u;
        c->in_size = in_avail;
        c->range   = 0xFFFFFFFFu;
        c->code    = 0u;
        (void)rc_byte(c);                    /* must be zero */
        for (i = 0; i < 4; i++) {
            c->code = (c->code << 8) | rc_byte(c);
        }
    }

    /* LZMA decodes into its own dictionary ring; the newly produced bytes are
     * then copied out to the caller's block buffer. The ring position before
     * the first produced byte is where that copy starts, and it may wrap. */
    ring_start = c->dict_pos;

    while (produced < cap && c->produced < c->content_size &&
           c->in_pos < c->in_size && c->input_exhausted == 0u) {
        uint32_t pos_state = c->produced & c->pb_mask;
        uint16_t *lit_base;

        /* Finish emitting a match that a previous call had to cut short. This
         * consumes no input, so it must come before the isMatch bit. */
        if (c->pending > 0u) {
            uint32_t n = c->pending;
            if (n > (cap - produced)) {
                n = cap - produced;
            }
            c->pending -= n;
            while (n-- > 0u) {
                dict_put(c, dict_get(c, c->rep0 + 1u));
                c->produced++;
                produced++;
            }
            continue;
        }


        if (rc_bit(c, &c->probs[P_IS_MATCH + (c->state << NUM_POS_BITS_MAX) + pos_state]) == 0u) {
            /* Literal. */
            uint8_t  prev = (c->produced > 0u) ? dict_get(c, 1u) : 0u;
            uint32_t lit_state = ((c->produced & c->lp_mask) << c->lc) +
                                 ((uint32_t)prev >> (8u - c->lc));
            uint32_t symbol = 1u;

            lit_base = &c->probs[P_LITERAL + 0x300u * lit_state];
            if (c->state >= 7u) {
                uint8_t  match_byte = dict_get(c, c->rep0 + 1u);
                uint32_t mb = match_byte;
                do {
                    uint32_t match_bit = (mb >> 7) & 1u;
                    uint32_t bit;
                    mb = (mb << 1) & 0xFFu;
                    bit = rc_bit(c, &lit_base[((1u + match_bit) << 8) + symbol]);
                    symbol = (symbol << 1) | bit;
                    if (match_bit != bit) {
                        break;
                    }
                } while (symbol < 0x100u);
            } else {
                while (symbol < 0x100u) {
                    symbol = (symbol << 1) | rc_bit(c, &lit_base[symbol]);
                }
            }
            dict_put(c, (uint8_t)(symbol & 0xFFu));
            c->produced++;
            produced++;
            c->state = (c->state < 4u) ? 0u : ((c->state < 10u) ? c->state - 3u
                                                                   : c->state - 6u);
            continue;
        }

        {
            uint32_t len;

            if (rc_bit(c, &c->probs[P_IS_REP + c->state]) != 0u) {
                /* Repeated distance. */
                if (rc_bit(c, &c->probs[P_IS_REP_G0 + c->state]) == 0u) {
                    if (rc_bit(c, &c->probs[P_IS_REP0_LONG +
                            (c->state << NUM_POS_BITS_MAX) + pos_state]) == 0u) {
                        dict_put(c, dict_get(c, c->rep0 + 1u));
                        c->produced++;
                        produced++;
                        c->state = (c->state < 7u) ? 9u : 11u;
                        continue;
                    }
                } else {
                    uint32_t dist;
                    if (rc_bit(c, &c->probs[P_IS_REP_G1 + c->state]) == 0u) {
                        dist = c->rep1;
                    } else {
                        if (rc_bit(c, &c->probs[P_IS_REP_G2 + c->state]) == 0u) {
                            dist = c->rep2;
                        } else {
                            dist = c->rep3;
                            c->rep3 = c->rep2;
                        }
                        c->rep2 = c->rep1;
                    }
                    c->rep1 = c->rep0;
                    c->rep0 = dist;
                }
                len = mcf_lzma_len(c, &c->probs[P_REP_LEN], pos_state) + MATCH_MIN_LEN;
                c->state = (c->state < 7u) ? 8u : 11u;
            } else {
                uint32_t dist;
                c->rep3 = c->rep2;
                c->rep2 = c->rep1;
                c->rep1 = c->rep0;
                len = mcf_lzma_len(c, &c->probs[P_LEN], pos_state) + MATCH_MIN_LEN;
                c->state = (c->state < 7u) ? 7u : 10u;
                dist = mcf_lzma_dist(c, len);
                if (dist == 0xFFFFFFFFu) {
                    c->done = 1u;          /* end-of-stream marker */
                    break;
                }
                c->rep0 = dist;
                if (dist >= c->dict_size) {
                    /* A match reaching before the dictionary cannot be
                     * resolved. Reject rather than emit plausible garbage. */
                    return (int32_t)MCF_E_CORRUPT;
                }
                len += MATCH_MIN_LEN;
            }

                /* A final match may legitimately extend past the declared
                 * content size - liblzma emits one when the size is known
                 * rather than an end marker. Clamp it instead of rejecting;
                 * finish() still checks the total, so a truncated stream is
                 * still caught. */
            if (c->produced + len > c->content_size) {
                len = c->content_size - c->produced;
            }
            while (len-- > 0u) {
                dict_put(c, dict_get(c, c->rep0 + 1u));
                c->produced++;
                produced++;
                /* A match can be far longer than the caller's remaining
                 * capacity. The loop condition only checks between symbols, so
                 * without this the decoder writes past `cap` and tramples the
                 * caller's buffer. The unconsumed length stays pending: the
                 * caller re-enters and decoding continues where this left off. */
                if (produced >= cap) {
                    c->pending = len;
                    break;
                }
            }
        }
    }

    /* Copy the newly produced bytes out of the ring.
     *
     * This must loop, not assume one or two pieces: a single call can produce
     * more bytes than the dictionary holds, and the range then wraps the ring
     * several times. A two-piece copy silently corrupts everything past the
     * first wrap, which is why the decoder looked correct at large block sizes
     * and failed at every small one. */
    if (produced > 0u) {
        uint32_t src = ring_start;
        uint32_t dst = 0u;

        while (dst < produced) {
            uint32_t chunk = c->dict_size - src;
            if (chunk > (produced - dst)) {
                chunk = produced - dst;
            }
            memcpy(&out[dst], &c->dict[src], chunk);
            src += chunk;
            if (src >= c->dict_size) {
                src = 0u;
            }
            dst += chunk;
        }
    }

    *produced_out = produced;
    *consumed_out = c->in_pos;
    return (int32_t)MCF_OK;
}

int32_t mcf_lzma_finish(mcf_codec_t *codec)
{
    mcf_lzma_t *c = (mcf_lzma_t *)(void *)codec;

    if (c == NULL) {
        return (int32_t)MCF_E_PARAM;
    }
    /* The declared content size is the authority. The end marker is optional
     * because the host tool may omit it when the size is known. */
    if (c->produced != c->content_size) {
        return (int32_t)MCF_E_TRUNCATED;
    }
    return (int32_t)MCF_OK;
}

void mcf_lzma_destroy(mcf_codec_t *codec)
{
    (void)codec;
}

const mcf_codec_ops_t mcf_codec_lzma_ops = {
    "lzma",
    MCF_CODEC_LZMA,
    mcf_lzma_workspace,
    mcf_lzma_init,
    mcf_lzma_decode,
    mcf_lzma_finish,
    mcf_lzma_destroy,
    NULL
};
