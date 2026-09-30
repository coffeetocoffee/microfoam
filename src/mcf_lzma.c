/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - LZMA1 decoder adapter.
 *
 * Wraps the vendored LZMA SDK decoder (third_party/lzma-sdk, public domain,
 * Igor Pavlov) behind the Microfoam codec vtable. The decoder is the reviewed
 * upstream implementation; everything in this file is glue: a bounded
 * allocator that serves the SDK's probability table and dictionary from the
 * caller's workspace, and the streaming input convention documented in
 * mcf_lzma.h.
 *
 * Cost model. The dominant term is the probability table: the SDK allocates
 * 2 bytes per entry, with entries = 1984 + (768 << (lc + lp)). That is 16,256
 * bytes at the common lc=3, lp=0 and 3,968 bytes at lc=lp=0. The second term is
 * the dictionary, rounded up by the SDK's own mask ladder. The patch header's
 * workspace_req declares this so the device can refuse before allocating
 * anything; the session then allocates from this file's own figure, so a patch
 * that under-declares cannot cause an undersized allocation.
 *
 * No dynamic memory beyond the caller's workspace, no global state, C99 only.
 */

#include "mcf_internal.h"

#include "mcf_lzma.h"

#include "LzmaDec.h"

#include <stddef.h>

/* SDK constants we must mirror exactly for the workspace computation. These
 * are #defines in LzmaDec.c (not exported), so they are repeated here and
 * cross-checked by tests/lzma_conformance_test.c: the allocation the SDK makes
 * and the figure workspace_size() reports must agree. */
#define MCF_LZMA_NUM_BASE_PROBS 1984u
#define MCF_LZMA_LIT_SIZE       0x300u

#define MCF_LZMA_MAX_ALLOCS 4u

typedef struct mcf_lzma {
    CLzmaDec sdk;
    ISzAlloc alloc; /*!< Bounded allocator handed to the SDK. */

    uint8_t *ws;      /*!< Workspace base, owned by the session.  */
    uint32_t ws_size; /*!< Bytes available from `ws`.              */
    uint32_t ws_used; /*!< Bump cursor.                            */

    uint32_t alloc_mark[MCF_LZMA_MAX_ALLOCS];
    void    *alloc_ptr[MCF_LZMA_MAX_ALLOCS];
    uint32_t alloc_count;

    uint32_t content_size; /*!< Exact decompressed length, from props. */
    uint32_t produced;     /*!< Bytes emitted so far.                  */

    const uint8_t *in; /*!< Stream base, fixed on the first call.  */
    uint32_t       in_size;
    uint32_t       in_pos;

    uint8_t started;
    uint8_t done;
    uint8_t input_exhausted;
    uint8_t reserved;
} mcf_lzma_t;

/* The workspace figure must be identical on every target so the host tool's
 * declared workspace_req matches what the device will allocate. sizeof() would
 * differ between 32- and 64-bit builds, so the state block is pinned to a
 * constant and checked here. */
typedef char mcf_lzma_state_fits[
    (sizeof(mcf_lzma_t) <= MCF_LZMA_STATE_BYTES) ? 1 : -1];

/* ---------------------------------------------------------------------- *
 * Little-endian scalar reads (the shared header's helpers are static inline
 * in mcf_internal.h, but these names are kept local for clarity).
 * ---------------------------------------------------------------------- */

static uint32_t mcf_lzma_rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* ---------------------------------------------------------------------- *
 * Bounded bump allocator.
 *
 * The SDK allocates at most two objects - the probability table, then the
 * dictionary - and frees them in reverse order. A bump cursor with a small
 * record stack implements that exactly, and returning NULL (which the SDK
 * reports as SZ_ERROR_MEM) is the failure mode when the workspace is too
 * small. That is the check that turns an over-budget patch into
 * MCF_E_NOMEM/MCF_E_DICT_TOO_LARGE instead of a crash.
 * ---------------------------------------------------------------------- */

static mcf_lzma_t *mcf_lzma_from_alloc(ISzAllocPtr p)
{
    uintptr_t base = (uintptr_t)(const void *)p;

    base -= (uintptr_t)offsetof(mcf_lzma_t, alloc);
    return (mcf_lzma_t *)(void *)base;
}

static void *mcf_lzma_alloc_cb(ISzAllocPtr p, size_t size)
{
    mcf_lzma_t *c = mcf_lzma_from_alloc(p);
    uint32_t    top;
    uint32_t    need;

    if (size == 0u || size > (size_t)0xFFFFFFFFu) {
        return NULL;
    }
    need = (uint32_t)size;
    top  = (c->ws_used + 7u) & ~7u;
    if (top > c->ws_size || need > (c->ws_size - top)) {
        return NULL;
    }
    if (c->alloc_count >= MCF_LZMA_MAX_ALLOCS) {
        return NULL;
    }
    c->alloc_mark[c->alloc_count] = top;
    c->alloc_ptr[c->alloc_count]  = c->ws + top;
    c->alloc_count++;
    c->ws_used = top + need;
    return c->ws + top;
}

static void mcf_lzma_free_cb(ISzAllocPtr p, void *address)
{
    mcf_lzma_t *c = mcf_lzma_from_alloc(p);
    uint32_t    i;

    if (address == NULL || c->alloc_count == 0u) {
        return;
    }
    /* The SDK frees in reverse order; only the most recent allocation can be
     * rolled back. A free of anything else leaves the cursor where it is -
     * the memory stays "used" until the workspace is released, which is
     * harmless because a session never reuses a workspace it has destroyed. */
    i = c->alloc_count - 1u;
    if (c->alloc_ptr[i] == address) {
        c->ws_used    = c->alloc_mark[i];
        c->alloc_count = i;
    }
}

/* ---------------------------------------------------------------------- *
 * Properties. Layout is documented in mcf_lzma.h (9 bytes, little-endian).
 * ---------------------------------------------------------------------- */

static int mcf_lzma_props(const uint8_t *props, uint32_t props_len,
                          uint32_t *lc, uint32_t *lp, uint32_t *pb,
                          uint32_t *dict_size, uint32_t *content_size)
{
    uint32_t v;

    if (props == NULL || props_len < MCF_LZMA_PROPS_LEN) {
        return -1;
    }
    v = props[0];
    if (v >= (9u * 5u * 5u)) {
        return -1;
    }
    *lc = v % 9u;
    *lp = (v / 9u) % 5u;
    *pb = v / 45u;

    *dict_size = mcf_lzma_rd32(&props[1]);
    if (*dict_size < 4096u) {
        *dict_size = 4096u; /* the SDK's LZMA_DIC_MIN clamp */
    }
    *content_size = mcf_lzma_rd32(&props[5]);
    if (*content_size == 0u) {
        return -1;
    }
    return 0;
}

/* The SDK's dictionary rounding (LzmaDec_Allocate). Mirrored so the figure
 * reported here is never smaller than what the SDK will request. */
static uint64_t mcf_lzma_dic_buf_size(uint32_t dict_size)
{
    uint64_t size = (uint64_t)dict_size;
    uint64_t mask = ((uint64_t)1u << 12) - 1u;

    if (dict_size >= (1u << 30)) {
        mask = ((uint64_t)1u << 22) - 1u;
    } else if (dict_size >= (1u << 22)) {
        mask = ((uint64_t)1u << 20) - 1u;
    }
    size = (size + mask) & ~mask;
    if (size < (uint64_t)dict_size) {
        size = (uint64_t)dict_size;
    }
    return size;
}

uint32_t mcf_lzma_workspace(const uint8_t *props, uint32_t props_len)
{
    uint32_t lc, lp, pb, dict_size, content_size;
    uint64_t probs_entries;
    uint64_t probs_bytes;
    uint64_t total;

    if (mcf_lzma_props(props, props_len, &lc, &lp, &pb, &dict_size,
                       &content_size) != 0) {
        return 0u;
    }
    (void)pb;
    (void)content_size;

    probs_entries = (uint64_t)MCF_LZMA_NUM_BASE_PROBS +
                    ((uint64_t)MCF_LZMA_LIT_SIZE << (lc + lp));
    probs_bytes = probs_entries * 2u;

    total = ((uint64_t)MCF_LZMA_STATE_BYTES + probs_bytes + 7u) &
            ~(uint64_t)7u;
    total += mcf_lzma_dic_buf_size(dict_size);
    if (total > 0xFFFFFFFFu) {
        return 0u;
    }
    return (uint32_t)total;
}

/* ---------------------------------------------------------------------- *
 * Codec vtable
 * ---------------------------------------------------------------------- */

static int32_t mcf_lzma_map(SRes res)
{
    switch (res) {
    case SZ_OK:
        return (int32_t)MCF_OK;
    case SZ_ERROR_MEM:
        return (int32_t)MCF_E_NOMEM;
    case SZ_ERROR_UNSUPPORTED:
        return (int32_t)MCF_E_UNSUPPORTED;
    case SZ_ERROR_INPUT_EOF:
        return (int32_t)MCF_E_TRUNCATED;
    case SZ_ERROR_DATA:
    case SZ_ERROR_FAIL:
    default:
        return (int32_t)MCF_E_CORRUPT;
    }
}

int32_t mcf_lzma_init(mcf_codec_t **out, const uint8_t *props, uint32_t props_len,
                      uint8_t *workspace)
{
    mcf_lzma_t *c;
    uint32_t    lc, lp, pb, dict_size, content_size;
    SRes        res;

    if (out == NULL || workspace == NULL || props == NULL) {
        return (int32_t)MCF_E_PARAM;
    }
    if (mcf_lzma_props(props, props_len, &lc, &lp, &pb, &dict_size,
                       &content_size) != 0) {
        return (int32_t)MCF_E_FORMAT;
    }
    (void)pb;

    c = (mcf_lzma_t *)(void *)workspace;
    memset(c, 0, sizeof(*c));
    c->ws      = workspace;
    c->ws_size = mcf_lzma_workspace(props, props_len);
    if (c->ws_size == 0u) {
        return (int32_t)MCF_E_FORMAT;
    }
    c->ws_used = MCF_LZMA_STATE_BYTES;
    c->content_size = content_size;
    c->alloc.Alloc  = mcf_lzma_alloc_cb;
    c->alloc.Free   = mcf_lzma_free_cb;

    LzmaDec_Construct(&c->sdk);
    res = LzmaDec_Allocate(&c->sdk, props, MCF_LZMA_PROPS_LEN, &c->alloc);
    if (res != SZ_OK) {
        /* Allocate frees what it took before failing; release anything a
         * partial path may have left, then report the mapped status. */
        LzmaDec_Free(&c->sdk, &c->alloc);
        return mcf_lzma_map(res);
    }
    LzmaDec_Init(&c->sdk);

    *out = (mcf_codec_t *)(void *)c;
    return (int32_t)MCF_OK;
}

int32_t mcf_lzma_decode(mcf_codec_t *codec,
                        uint8_t *out, uint32_t cap, uint32_t *produced,
                        const uint8_t *in, uint32_t in_avail, uint32_t *consumed)
{
    mcf_lzma_t *c = (mcf_lzma_t *)(void *)codec;
    uint32_t    in_at_entry;
    uint32_t    total = 0u;

    if (c == NULL || out == NULL || produced == NULL || consumed == NULL) {
        return (int32_t)MCF_E_PARAM;
    }
    *produced = 0u;
    *consumed = 0u;

    /* Input ownership: the session hands a sliding window whose base moves as
     * it advances. The range coder keeps its own cursor, so the stream base
     * and total length are captured on the first call and used from then on;
     * see mcf_lzma.h. */
    if (c->started == 0u) {
        c->started = 1u;
        c->in      = in;
        c->in_size = in_avail;
    }
    if (c->input_exhausted != 0u || c->done != 0u || cap == 0u) {
        return (int32_t)MCF_OK;
    }
    in_at_entry = c->in_pos;

    /* Loop until some output is produced or the input is genuinely spent.
     * A single SDK call may consume bytes (range-coder init) without producing
     * output; reporting that as (produced == 0) would make the session treat
     * it as end-of-stream, so it must not escape this function. */
    for (;;) {
        SizeT       dest_len = (SizeT)(cap - total);
        SizeT       src_len  = (SizeT)(c->in_size - c->in_pos);
        ELzmaStatus status;
        SRes        res;

        if (dest_len == 0u) {
            break;
        }
        res = LzmaDec_DecodeToBuf(&c->sdk, &out[total], &dest_len,
                                  c->in + c->in_pos, &src_len,
                                  LZMA_FINISH_ANY, &status);
        if (res != SZ_OK) {
            return mcf_lzma_map(res);
        }
        c->in_pos += (uint32_t)src_len;
        c->produced += (uint32_t)dest_len;
        total += (uint32_t)dest_len;

        if (dest_len > 0u) {
            break;
        }
        if (src_len == 0u) {
            c->input_exhausted = 1u;
            break;
        }
    }

    if (c->produced >= c->content_size) {
        c->done = 1u;
    }
    *produced = total;
    *consumed = c->in_pos - in_at_entry;
    return (int32_t)MCF_OK;
}

int32_t mcf_lzma_finish(mcf_codec_t *codec)
{
    mcf_lzma_t *c = (mcf_lzma_t *)(void *)codec;

    if (c == NULL) {
        return (int32_t)MCF_E_PARAM;
    }
    /* The exact-length check is the truncation guard: a stream cut short
     * produces fewer bytes than the properties declare, and one padded out
     * produces more. */
    if (c->produced != c->content_size) {
        return (int32_t)MCF_E_TRUNCATED;
    }
    return (int32_t)MCF_OK;
}

void mcf_lzma_destroy(mcf_codec_t *codec)
{
    mcf_lzma_t *c = (mcf_lzma_t *)(void *)codec;

    if (c == NULL) {
        return;
    }
    LzmaDec_Free(&c->sdk, &c->alloc);
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
