/* SPDX-License-Identifier: MIT */
#include "microfoam_v2.h"
#include "mcf_internal.h"
#include <string.h>
#include <stdint.h>

static int v2_ranges_overlap(const void *a, uint32_t an, const void *b, uint32_t bn)
{
    uintptr_t ap, bp;
    if (an == 0u || bn == 0u) return 0;
    ap = (uintptr_t)a;
    bp = (uintptr_t)b;
    return (ap < bp) ? (bp - ap < (uintptr_t)an)
                      : (ap - bp < (uintptr_t)bn);
}

static int v2_add_u32(uint32_t a, uint32_t b, uint32_t *out)
{
    if (b > UINT32_MAX - a) return 0;
    *out = a + b;
    return 1;
}

static void v2_wipe(void *p, uint32_t n)
{
    volatile uint8_t *q = (volatile uint8_t *)p;
    while (n-- != 0u) *q++ = 0u;
}
static void v2_wr32(uint8_t *p, uint32_t x)
{
    p[0]=(uint8_t)x; p[1]=(uint8_t)(x>>8); p[2]=(uint8_t)(x>>16); p[3]=(uint8_t)(x>>24);
}
static mcf_status_t v2_fail(mcf_v2_session_t *s, mcf_status_t st)
{
    s->status = st; s->state = MCF_ST_FAILED;
    if (s->inner != NULL) mcf_session_close(s->inner);
    v2_wipe(s->key, (uint32_t)sizeof(s->key));
    if (s->scratch != NULL) v2_wipe(s->scratch, s->scratch_len);
    s->scratch = NULL; s->scratch_len = 0u;
    if (s->win != NULL) v2_wipe(s->win, s->win_cap);
    s->win = NULL; s->win_len = 0u;
    return st;
}

/* ---------------------------------------------------------------------- *
 * Resume support (MFP2). See docs/format-v2-design.md section 8.
 *
 * Policy: the session halts the inner engine exactly on erase-block
 * boundaries, captures the engine's complete position there, and writes one
 * journal record. A resume re-feeds the codec from the record that contains
 * that position, drops the already-consumed prefix, and restores the exact
 * phase - no work is repeated beyond one record's plaintext, and nothing
 * below the block boundary is rewritten.
 * ---------------------------------------------------------------------- */

/* Decoded (delta) length of one record's plaintext: the sum of its complete
 * LZ4 blocks' output lengths. The plaintext is authenticated; a malformed
 * stream here is treated as corrupt. */
static mcf_status_t v2_record_dlen(const uint8_t *plain, uint32_t len, uint32_t *out)
{
    uint32_t pos = 0u;
    uint32_t total = 0u;
    while (pos < len) {
        uint32_t blen, ip, end, produced = 0u;
        if (len - pos < 4u) return MCF_E_CORRUPT;
        blen = mcf_rd32(&plain[pos]); pos += 4u;
        if (blen == 0u) {
            if (pos != len) return MCF_E_CORRUPT;
            break;
        }
        if (blen > len - pos) return MCF_E_CORRUPT;
        ip = pos; end = pos + blen;
        while (ip < end) {
            uint32_t lit, match, off; uint8_t token, x;
            token = plain[ip++]; lit = (uint32_t)(token >> 4);
            if (lit == 15u) { do { if (ip >= end) return MCF_E_CORRUPT; x = plain[ip++]; lit += (uint32_t)x; } while (x == 255u); }
            if (lit > end - ip) return MCF_E_CORRUPT;
            ip += lit; produced += lit;
            if (ip == end) break;
            if (end - ip < 2u) return MCF_E_CORRUPT;
            off = mcf_rd16(&plain[ip]); ip += 2u;
            if (off == 0u || off > produced) return MCF_E_CORRUPT;
            match = (uint32_t)(token & 15u);
            if (match == 15u) { do { if (ip >= end) return MCF_E_CORRUPT; x = plain[ip++]; match += (uint32_t)x; } while (x == 255u); }
            match += 4u;
            if (UINT32_MAX - produced < match) return MCF_E_CORRUPT;
            produced += match;
        }
        if (UINT32_MAX - total < produced) return MCF_E_CORRUPT;
        total += produced; pos = end;
    }
    *out = total;
    return MCF_OK;
}

/* ---------------------------------------------------------------------- *
 * Streaming feed. See docs/mfp2-streaming-decryption-design.md.
 *
 * The framed LZ4 stream is never wholly resident. Records are decrypted into a
 * sliding window as the engine asks for bytes; each record is wiped as the
 * window compacts past it. The stream is terminated by the four-byte zero
 * marker the LZ4 framing requires, produced once the records are exhausted.
 *
 * One record's plaintext may be arbitrary bytes - the producer only guarantees
 * a record *boundary* falls on a frame boundary - so a frame may straddle a
 * record boundary and the consumer may need bytes from both. The window is
 * therefore two maximum-size records plus the marker, and the feed always
 * tries to materialise a complete frame before reporting.
 * ---------------------------------------------------------------------- */

/* Decrypt record `s->cur_record` into the window at its current end and
 * advance. The window always holds whole records from the stream start, so
 * appending is safe while win_len + (1<<record_log2) fits. */
static mcf_status_t v2_feed_pull_record(mcf_v2_session_t *s)
{
    const mcf_v2_config_t *c = s->cfg;
    const mcf_v2_view_t *v = &s->view;
    uint32_t off, len;
    int32_t i;
    uint8_t *ad = s->ad;

    /* The framing cursor advances one record at a time, so decrypting the
     * whole stream is linear rather than a re-walk from record zero. */
    if (s->cur_record >= v->record_count) return MCF_E_FORMAT;
    off = s->feed_off;
    if (v->payload_size - off < 4u) return MCF_E_FORMAT;
    len = mcf_rd32(&c->patch[v->header_len + off]);
    if (len == 0u || len > (1u << v->record_log2) ||
        len > v->payload_size - off - 4u ||
        v->payload_size - off - 4u - len < MCF_V2_RECORD_TAG_SIZE) return MCF_E_FORMAT;
    if (s->win_len + len > s->win_cap) return MCF_E_CORRUPT;

    /* AAD = "MCF2REC\0" || header(sig and payload-CRC zeroed) || LE32(i) || LE32(len).
     * The header body is copied once in begin(); only the two trailing words
     * change per record. */
    v2_wr32(&ad[8u + s->hdr_len], s->cur_record);
    v2_wr32(&ad[12u + s->hdr_len], len);
    { uint32_t k; for (k = 0u; k < 4u; k++) s->nonce_pre[16u + k] = (uint8_t)(s->cur_record >> (8u * k)); }
    s->nonce_pre[20u] = 0u; s->nonce_pre[21u] = 0u;
    s->nonce_pre[22u] = 0u; s->nonce_pre[23u] = 0u; /* LE64(i): high half zero */

    i = c->aead(c->aead_ctx, s->key, s->nonce_pre,
                &c->patch[s->view.header_len + off + 4u], len,
                &c->patch[s->view.header_len + off + 4u + len], MCF_V2_RECORD_TAG_SIZE,
                ad, 16u + s->hdr_len, &s->win[s->win_len]);
    if (i != MCF_OK) return (i < 0) ? (mcf_status_t)i : MCF_E_AUTH;

    /* Remember where this record's plaintext sits in decoded coordinates, so
     * the checkpoint can name a record whose plaintext is no longer resident.
     * A small ring suffices: the engine trails the feed by at most one window. */
    {
        uint32_t dlen, k;
        mcf_status_t ds = v2_record_dlen(&s->win[s->win_len], len, &dlen);
        if (ds != MCF_OK) return ds;
        for (k = 0u; k + 1u < 4u; k++) s->ring[k] = s->ring[k + 1u];
        s->ring[3].index  = s->cur_record;
        s->ring[3].base_d = s->d_base;
        s->ring[3].dlen   = dlen;
        s->d_base += dlen;
    }

    s->cur_record++;
    s->feed_off += 4u + len + MCF_V2_RECORD_TAG_SIZE;
    s->win_len += len;
    return MCF_OK;
}

/* Length of the largest prefix of win[] that is a whole number of complete
 * framed blocks (ending with the terminal zero marker, when present). The
 * codec must never be handed a partial block, so this is what the feed
 * reports. */
static uint32_t v2_feed_avail(const mcf_v2_session_t *s)
{
    uint32_t off = 0u;
    for (;;) {
        uint32_t blen, need;
        if (s->win_len - off < 4u) break;
        blen = mcf_rd32(&s->win[off]);
        if (blen == 0u) { off += 4u; break; }
        need = 4u + blen;
        if (s->win_len - off < need) break;
        off += need;
    }
    return off;
}

/* Answer the session's request for the run of framed stream starting at `pos`,
 * which is always a framed block boundary (the codec consumes whole blocks). */
static int32_t v2_feed_run(void *ctx, uint32_t pos, const uint8_t **src, uint32_t *avail)
{
    mcf_v2_session_t *s = (mcf_v2_session_t *)ctx;
    uint32_t rlog = 1u << s->view.record_log2;

    *src = NULL;
    *avail = 0u;
    if (pos < s->win_base) return (int32_t)MCF_E_PARAM;

    /* Drop bytes the codec has passed, wiping them as they go. */
    if (pos > s->win_base) {
        uint32_t drop = pos - s->win_base;
        if (drop > s->win_len) return (int32_t)MCF_E_PARAM;
        v2_wipe(s->win, drop);
        if (drop < s->win_len) memmove(s->win, &s->win[drop], s->win_len - drop);
        s->win_len -= drop;
        s->win_base  = pos;
    }

    /* Pull records until at least one complete block is resident, then keep
     * pulling while there is room and more records to come. */
    for (;;) {
        if (v2_feed_avail(s) > 0u) {
            if (s->cur_record >= s->view.record_count) break;   /* no more records */
            if (s->win_len + rlog > s->win_cap) break;          /* window nearly full */
        } else if (s->cur_record >= s->view.record_count) {
            break;                                              /* nothing left to pull */
        }
        {
            mcf_status_t st = v2_feed_pull_record(s);
            if (st != MCF_OK) return (int32_t)st;
        }
    }

    /* Terminate the framing once every record is in the window. The producer's
     * framing ends with a zero block marker; the last record's plaintext may
     * not carry it, so it is synthesised here. */
    if (s->cur_record >= s->view.record_count && !s->win_end) {
        s->win_end = 1u;
        if (s->win_len + 4u <= s->win_cap) {
            v2_wr32(&s->win[s->win_len], 0u);
            s->win_len += 4u;
        }
    }

    /* Report only complete blocks. A partial block at the tail is left for the
     * next call, once more records have been pulled. */
    *src   = s->win;
    *avail = v2_feed_avail(s);
    return 0;
}

static uint32_t v2_journal_crc(const mcf_v2_journal_t *j)
{
    mcf_v2_journal_t t = *j;
    t.record_crc = 0u;
    return mcf_crc32((const uint8_t *)&t, (uint32_t)sizeof(t));
}

mcf_status_t mcf_v2_session_open(mcf_v2_session_t *s, const mcf_v2_config_t *cfg)
{
    uint32_t blk;
    if (s==NULL || cfg==NULL) return MCF_E_PARAM;
    memset(s,0,sizeof(*s)); s->cfg=cfg; s->status=MCF_OK; s->state=MCF_ST_IDLE;
    if (cfg->hal==NULL || cfg->patch==NULL || cfg->patch_size==0u ||
        (cfg->old==NULL && cfg->old_read==NULL) || cfg->key_provider==NULL ||
        cfg->verify==NULL || cfg->aead==NULL || cfg->workspace==NULL ||
        cfg->workspace_size < 124u || cfg->ram_budget == 0u) return MCF_E_PARAM;
    if (v2_ranges_overlap(cfg->patch, cfg->patch_size,
                          cfg->workspace, cfg->workspace_size)) return MCF_E_PARAM;
    if (cfg->old != NULL && v2_ranges_overlap(cfg->old, cfg->old_size,
                                               cfg->workspace, cfg->workspace_size)) return MCF_E_PARAM;

    /* The view is parsed here so the resume paths can reason about the record
     * framing without re-deriving it. A parse failure is NOT reported here:
     * begin() owns the patch-validation contract and produces the precise
     * status; the view is simply left zeroed, which makes a later resume probe
     * reject with MCF_E_NOT_FOUND. */
    (void)mcf_v2_parse(cfg->patch, cfg->patch_size, &s->view);

    /* Resume configuration, when present. The journal region must sit on an
     * erase boundary and outside the destination image, or a checkpoint would
     * erase the very bytes it is journaling about. The overlap check needs a
     * valid view; a malformed patch skips it and fails in begin() anyway. */
    if (cfg->journal_addr != 0u) {
        uint32_t dst_end;
        if (cfg->hal->flash_block_size == NULL) return MCF_E_PARAM;
        blk = cfg->hal->flash_block_size(cfg->hal->ctx);
        if (blk == 0u || (blk & (blk - 1u)) != 0u) return MCF_E_PARAM;
        if ((cfg->journal_addr & (blk - 1u)) != 0u) return MCF_E_PARAM;
        if (!v2_add_u32(cfg->journal_addr, (uint32_t)sizeof(mcf_v2_journal_t),
                        &dst_end)) return MCF_E_PARAM;
        if (s->view.record_count != 0u &&
            v2_add_u32(cfg->dst_addr, s->view.new_size, &dst_end)) {
            if (cfg->journal_addr < dst_end && dst_end > cfg->dst_addr &&
                cfg->journal_addr + (uint32_t)sizeof(mcf_v2_journal_t) > cfg->dst_addr) {
                return MCF_E_PARAM;
            }
        }
        s->flash_block = blk;
        s->journal_interval = (cfg->journal_interval != 0u)
                                  ? cfg->journal_interval
                                  : 32u;
    }
    /* The session id ties a journal record to this exact patch. It is the CRC
     * of the header, computed on every path so a cold run can checkpoint. */
    s->session_id = mcf_crc32(cfg->patch, MCF_V2_HEADER_MIN);
    return MCF_OK;
}

mcf_status_t mcf_v2_resume_clear(mcf_v2_session_t *s)
{
    mcf_v2_journal_t j;

    if (s == NULL || s->cfg == NULL) return MCF_E_PARAM;
    if (s->cfg->journal_addr == 0u) return MCF_OK;
    memset(&j, 0, sizeof(j));
    if (mcf_nvm_record_write(s->cfg->hal, s->cfg->journal_addr,
                             (const uint8_t *)&j, (uint32_t)sizeof(j)) != MCF_OK) {
        return MCF_E_IO;
    }
    return MCF_OK;
}

mcf_status_t mcf_v2_resume_probe(mcf_v2_session_t *s)
{
    mcf_v2_journal_t j;
    uint32_t crc;
    int32_t r;

    if (s == NULL || s->cfg == NULL) return MCF_E_PARAM;
    s->resume_positioned = 0;
    if (s->cfg->journal_addr == 0u) return MCF_E_NOT_FOUND;

    r = mcf_nvm_record_read(s->cfg->hal, s->cfg->journal_addr,
                            (uint8_t *)&j, (uint32_t)sizeof(j));
    if (r != MCF_OK) return MCF_E_NOT_FOUND;

    /* Every rejection below means "start clean", not "fail": a stale or
     * damaged resume point is an ordinary condition after a power cut. */
    if (j.magic != MCF_V2_JOURNAL_MAGIC || j.record_crc != v2_journal_crc(&j)) {
        return MCF_E_NOT_FOUND;
    }
    if (j.session_id != s->session_id) return MCF_E_NOT_FOUND;
    if (j.out_off == 0u || j.out_off >= s->view.new_size) return MCF_E_NOT_FOUND;
    if ((j.out_off & (s->flash_block - 1u)) != 0u) return MCF_E_NOT_FOUND;
    if (j.record_index >= s->view.record_count) return MCF_E_NOT_FOUND;
    if (j.phase > (uint32_t)MCF_EP_EXTRA) return MCF_E_NOT_FOUND;
    if (j.record_base_d > j.d_off) return MCF_E_NOT_FOUND;
    /* The delta stream decodes to exactly new_size bytes (every output byte
     * consumes one delta byte), so neither offset can exceed it. */
    if (j.d_off > s->view.new_size) return MCF_E_NOT_FOUND;

    /* The prefix on flash must match what the journal claims. This is the
     * check that makes resume a feature rather than a hazard. */
    r = mcf_dst_prefix_crc(s->cfg->hal, s->cfg->dst_addr, j.out_off, &crc);
    if (r != MCF_OK) return MCF_E_NOT_FOUND;
    if (crc != j.prefix_crc32) return MCF_E_NOT_FOUND;

    s->resume_positioned    = 1;
    s->resume_out_off       = j.out_off;
    s->resume_old_off       = (int32_t)j.old_off;
    s->resume_d_off         = j.d_off;
    s->resume_record        = j.record_index;
    s->resume_record_base_d = j.record_base_d;
    s->resume_phase         = j.phase;
    s->resume_diff_remaining  = (int32_t)j.diff_remaining;
    s->resume_extra_remaining = (int32_t)j.extra_remaining;
    return MCF_OK;
}

/* Write a checkpoint if the engine has halted on the armed boundary. Failures
 * degrade to "not resumable" - the update itself continues. */
static void v2_checkpoint(mcf_v2_session_t *s)
{
    mcf_resume_point_t pt;
    mcf_v2_journal_t j;
    uint32_t step, rec_index = 0u, rec_base = 0u;
    uint32_t i, found = 0u;
    int32_t r;

    if (s->journal_interval == 0u) return;
    if (mcf_session_snapshot(s->inner, &pt) == 0) return;
    if (pt.out_off != s->next_ckpt_out) return; /* still mid-block */

    /* Name the record whose plaintext contains pt.d_off. The plaintext is not
     * resident - the feed has moved past it - so the mapping comes from the
     * ring of recently decrypted records. The engine only consumes bytes the
     * feed has already produced and trails it by at most one window, so the
     * containing record is always among the newest entries; if it is not, this
     * is not a resumable point and the update simply continues unresumable. */
    for (i = 0u; i < 4u; i++) {
        if (s->ring[i].index != 0xFFFFFFFFu &&
            pt.d_off >= s->ring[i].base_d &&
            pt.d_off < s->ring[i].base_d + s->ring[i].dlen) {
            rec_index = s->ring[i].index;
            rec_base  = s->ring[i].base_d;
            found = 1u;
            break;
        }
    }
    if (!found) {
        goto degrade;
    }

    memset(&j, 0, sizeof(j));
    j.magic           = MCF_V2_JOURNAL_MAGIC;
    j.session_id      = s->session_id;
    j.out_off         = pt.out_off;
    j.old_off         = (uint32_t)pt.old_off;
    j.d_off           = pt.d_off;
    j.record_index    = rec_index;
    j.record_base_d   = rec_base;
    j.phase           = pt.phase;
    j.diff_remaining  = (uint32_t)pt.diff_remaining;
    j.extra_remaining = (uint32_t)pt.extra_remaining;
    r = mcf_dst_prefix_crc(s->cfg->hal, s->cfg->dst_addr, pt.out_off, &j.prefix_crc32);
    if (r != MCF_OK) goto degrade;
    j.record_crc = v2_journal_crc(&j);
    r = mcf_nvm_record_write(s->cfg->hal, s->cfg->journal_addr,
                             (const uint8_t *)&j, (uint32_t)sizeof(j));
    if (r != MCF_OK) goto degrade;

    /* Arm the next checkpoint. */
    step = s->flash_block * s->journal_interval;
    if (step < s->flash_block || pt.out_off > UINT32_MAX - step) {
        goto degrade;
    }
    s->next_ckpt_out = pt.out_off + step;
    mcf_session_set_stop(s->inner, s->next_ckpt_out);
    return;

degrade:
    /* A checkpoint that cannot be written is not a reason to abandon the
     * update; the restore simply will not be resumable. */
    s->journal_interval = 0u;
    s->flags |= MCF_V2_SESSION_FLAG_RESUME_DEGRADED;
}

mcf_status_t mcf_v2_session_begin(mcf_v2_session_t *s)
{
    const mcf_v2_config_t *c; mcf_v2_view_t v; uint8_t *buf; uint8_t *hdr;
    uint32_t pos=0u, i, start=0u, delta_size, need, win, ad, start_off=0u;
    uint32_t crc, framed_total, rec_dlen; int32_t r;
    mcf_resume_point_t pt;
    mcf_hdr_view_t hv;
    if (s==NULL || s->cfg==NULL) return MCF_E_PARAM;
    if (s->state!=MCF_ST_IDLE) return v2_fail(s,MCF_E_STATE);
    c=s->cfg;
    r=(int32_t)mcf_v2_parse(c->patch,c->patch_size,&v); if (r!=MCF_OK) return v2_fail(s,(mcf_status_t)r);
    if (c->hal->get_product_id==NULL || c->hal->get_fw_version==NULL ||
        v.product_id!=c->hal->get_product_id(c->hal->ctx)) return v2_fail(s,MCF_E_PRODUCT);
    if (v.fw_version<=c->hal->get_fw_version(c->hal->ctx)) return v2_fail(s,MCF_E_ROLLBACK);
    if (v.old_version!=c->hal->get_fw_version(c->hal->ctx) || v.old_size!=c->old_size) return v2_fail(s,MCF_E_MISMATCH);
    crc=mcf_crc32(&c->patch[v.header_len],v.payload_size);
    if (crc!=mcf_rd32(&c->patch[MCF_V2_OFF_PAYLOAD_CRC])) return v2_fail(s,MCF_E_CORRUPT);

    /* Streaming workspace:
     *   [0, 124)                        synthetic MFP1 header
     *   [124, 124+win)                  record window (two records + marker)
     *   [124+win, 124+win+ad)           AAD scratch: "MCF2REC\0" + header + 8
     *   [124+win+ad, ...)               inner session workspace
     * The decrypted payload is never wholly resident; the whole-delta size is
     * computed below by decrypting record by record through this window. */
    ad  = 8u + (uint32_t)v.header_len + 8u;
    win = (2u * ((uint32_t)1u << v.record_log2)) + 4u;
    if (!v2_add_u32(124u, win, &need) || !v2_add_u32(need, ad, &need) ||
        need > c->workspace_size || need > c->ram_budget) return v2_fail(s,MCF_E_DICT_TOO_LARGE);
    if (v.workspace_req == 0u || v.workspace_req > c->ram_budget) return v2_fail(s,MCF_E_DICT_TOO_LARGE);
    buf=(uint8_t *)c->workspace;
    s->scratch = buf; s->scratch_len = need;
    s->win = &buf[124u]; s->win_cap = win;
    s->ad  = &buf[124u + win]; s->ad_len = ad;
    if (v2_ranges_overlap(c->patch, c->patch_size, buf, need) ||
        (c->old != NULL && v2_ranges_overlap(c->old, c->old_size, buf, need))) return v2_fail(s,MCF_E_PARAM);
    hdr=buf; memcpy(hdr,c->patch,v.header_len); memset(&hdr[MCF_V2_OFF_SIGNATURE],0,MCF_SIG_SIZE);
    /* The signature covers the ciphertext record area, which is always
     * resident in the patch, so it is verified here in full before any
     * decryption. The streaming feed later re-authenticates each record. */
    r=c->verify(c->verify_ctx,&c->patch[MCF_V2_OFF_SIGNATURE],MCF_SIG_SIZE,
                (const uint8_t *)MCF_V2_SIGNATURE_DOMAIN,8u,hdr,v.header_len,
                &c->patch[v.header_len],v.payload_size);
    if (r!=MCF_OK) return v2_fail(s,(r<0 && r!=MCF_E_SIGNATURE)?(mcf_status_t)r:MCF_E_SIGNATURE);
    r=(int32_t)c->key_provider(c->key_ctx,&c->patch[MCF_V2_OFF_KEY_ID],s->key);
    if (r!=MCF_OK) return v2_fail(s,(r<0)?(mcf_status_t)r:MCF_E_IO);

    /* A resume feeds the codec from the record the journal names; earlier
     * records were already authenticated and their output programmed. */
    if (s->resume_positioned) {
        if (s->resume_record >= v.record_count) return v2_fail(s, MCF_E_PARAM);
        start = s->resume_record;
    }

    /* Walk the feed from `start`, decrypting one record at a time into the
     * window, to obtain the exact decoded delta size the synthetic MFP1 header
     * must declare. CPU cost only: no flash is touched and each record is
     * overwritten by the next. */
    framed_total = 0u; delta_size = 0u;
    s->hdr_len = v.header_len;
    for (i=0u;i<start;i++) {
        uint32_t len;
        if(v.payload_size-pos<4u) return v2_fail(s,MCF_E_FORMAT);
        len=mcf_rd32(&c->patch[v.header_len+pos]); pos+=4u;
        if(len==0u || len>(1u<<v.record_log2) || len>v.payload_size-pos || v.payload_size-pos-len<16u) return v2_fail(s,MCF_E_FORMAT);
        pos+=len+16u;
    }
    start_off = pos;   /* framing offset of record `start`'s length field */
    /* AAD body, built once: "MCF2REC\0" || header (signature and payload-CRC
     * fields zeroed). The per-record index and length are written into the
     * trailing 8 bytes by the feed before each AEAD call. */
    memcpy(s->ad, MCF_V2_AEAD_AD_PREFIX, 8u);
    memcpy(&s->ad[8u], hdr, v.header_len);
    memset(&s->ad[8u + MCF_V2_OFF_SIGNATURE], 0, MCF_SIG_SIZE);
    memset(&s->ad[8u + MCF_V2_OFF_PAYLOAD_CRC], 0, 4u);
    memcpy(s->nonce_pre, &c->patch[MCF_V2_OFF_NONCE_PREFIX], 16u);
    {
        uint32_t rlog = 1u << v.record_log2;
        for (i=start;i<v.record_count;i++) {
            uint32_t len, off;
            if(v.payload_size-pos<4u) return v2_fail(s,MCF_E_FORMAT);
            len=mcf_rd32(&c->patch[v.header_len+pos]); pos+=4u;
            if(len==0u || len>rlog || len>v.payload_size-pos || v.payload_size-pos-len<16u) return v2_fail(s,MCF_E_FORMAT);
            off = pos;
            { uint32_t k; for(k=0u;k<4u;k++) s->nonce_pre[16u+k]=(uint8_t)(i>>(8u*k)); }
            s->nonce_pre[20u]=0u; s->nonce_pre[21u]=0u; s->nonce_pre[22u]=0u; s->nonce_pre[23u]=0u;
            v2_wr32(&s->ad[8u+v.header_len],i); v2_wr32(&s->ad[12u+v.header_len],len);
            r=c->aead(c->aead_ctx,s->key,s->nonce_pre,&c->patch[v.header_len+off],len,
                      &c->patch[v.header_len+off+len],16u,s->ad,s->ad_len,s->win);
            if(r!=MCF_OK) return v2_fail(s,(r<0 && r!=MCF_E_AUTH)?(mcf_status_t)r:MCF_E_AUTH);
            r=(int32_t)v2_record_dlen(s->win,len,&rec_dlen);
            if(r!=MCF_OK) return v2_fail(s,MCF_E_CORRUPT);
            if (delta_size > UINT32_MAX-rec_dlen) return v2_fail(s,MCF_E_CORRUPT);
            delta_size += rec_dlen;
            if (framed_total > UINT32_MAX-len) return v2_fail(s,MCF_E_CORRUPT);
            framed_total += len;
            pos+=len+16u;
        }
    }
    if(pos!=v.payload_size) return v2_fail(s,MCF_E_FORMAT);
    if(delta_size==0u) return v2_fail(s,MCF_E_CORRUPT);
    /* The walk used win[] as scratch; the feed starts clean at the stream
     * head and re-decrypts as the engine asks. */
    v2_wipe(s->win, win);
    s->win_len = 0u; s->win_base = 0u; s->win_end = 0u;
    s->cur_record = start;
    s->feed_off   = start_off;
    /* On a resume the feed begins at the journal's record, whose decoded base
     * is not zero: the ring records absolute decoded offsets, so seed it. */
    s->d_base     = s->resume_positioned ? s->resume_record_base_d : 0u;
    for (i = 0u; i < 4u; i++) s->ring[i].index = 0xFFFFFFFFu;
    /* The decrypted records are wiped inside the walk; the whole scratch area
     * (header + window) is wiped again on close. */

    v2_wr32(&buf[0],MCF_HDR_MAGIC); buf[4]=120u;buf[5]=0u;buf[6]=0u;buf[7]=1u;
    v2_wr32(&buf[8],MCF_FLAG_CODEC_LZ4); memcpy(&buf[12],&c->patch[12],4u); memcpy(&buf[16],&c->patch[16],4u);
    memcpy(&buf[20],&c->patch[20],4u);memcpy(&buf[24],&c->patch[24],4u);v2_wr32(&buf[28],framed_total+4u);
    memcpy(&buf[32],&c->patch[32],4u);memcpy(&buf[36],&c->patch[36],4u);
    /* The synthetic header must declare what the inner session will actually
     * consume from ITS workspace slice: two decode/apply blocks plus the LZ4
     * state. Declaring the caller's whole budget here makes the inner session's
     * own budget check (block_size > (budget - workspace_req)/2) reject. */
    {
        uint32_t log2, inner_ws;
        log2 = v.record_log2;
        inner_ws = 2u * ((uint32_t)1u << log2) + 16u; /* 2 blocks + LZ4 state */
        v2_wr32(&buf[44], inner_ws);
        if (need > c->workspace_size) return v2_fail(s, MCF_E_DICT_TOO_LARGE);
        need = c->workspace_size - need;              /* remainder for the inner session */
        if (need < inner_ws) return v2_fail(s, MCF_E_DICT_TOO_LARGE);
        buf[52] = (uint8_t)MCF_CODEC_LZ4;
        buf[53] = (uint8_t)log2;
        buf[54] = 0u; buf[55] = 0u;
        memset(&buf[56], 0, 64u);
    }
    v2_wr32(&buf[120],delta_size);
    v2_wr32(&buf[40],0u); /* streaming: the inner CRC walk is suppressed */

    /* Hand the inner session a validated, authenticated view and a callback
     * that feeds the framed stream record by record. */
    memset(&hv,0,sizeof(hv));
    hv.hdr_len = 120u; hv.hdr_ver = 1u; hv.flags = MCF_FLAG_CODEC_LZ4;
    hv.product_id = v.product_id; hv.fw_version = v.fw_version;
    hv.old_size = v.old_size; hv.new_size = v.new_size;
    hv.payload_size = framed_total + 4u; hv.old_crc32 = mcf_rd32(&c->patch[32]);
    hv.new_crc32 = mcf_rd32(&c->patch[36]); hv.payload_crc32 = 0u;
    hv.workspace_req = 2u*((uint32_t)1u<<v.record_log2)+16u; hv.old_version = v.old_version;
    hv.codec_id = (uint8_t)MCF_CODEC_LZ4; hv.block_log2 = v.record_log2;
    hv.props = &buf[120]; hv.props_len = 4u;
    /* The payload pointer is deliberately NULL: the stream is not resident and
     * only the feed may produce it. */
    hv.payload = NULL; hv.payload_stream_len = framed_total;

    memset(&s->inner_cfg,0,sizeof(s->inner_cfg)); s->inner_cfg.hal=c->hal;s->inner_cfg.patch=buf;s->inner_cfg.patch_size=124u;
    s->inner_cfg.old=c->old;s->inner_cfg.old_read=c->old_read;s->inner_cfg.old_ctx=c->old_ctx;s->inner_cfg.old_size=c->old_size;s->inner_cfg.dst_addr=c->dst_addr;
    s->inner_cfg.codec=MCF_CODEC_LZ4;s->inner_cfg.block_size=(uint32_t)1u<<v.record_log2;s->inner_cfg.ram_budget=need;
    s->inner_cfg.workspace=&buf[124u+ad+win];s->inner_cfg.workspace_size=need;s->inner_cfg.progress=c->progress;s->inner_cfg.progress_ctx=c->progress_ctx;s->inner_cfg.commit=c->commit;s->inner_cfg.commit_ctx=c->commit_ctx;
    s->inner=(mcf_session_t *)(void *)&s->inner_storage; r=mcf_session_open(s->inner,&s->inner_cfg); if(r!=MCF_OK) return v2_fail(s,(mcf_status_t)r);
    mcf_session_set_streamed(s->inner, &hv, v2_feed_run, (void *)s);
    if (s->resume_positioned) {
        memset(&pt, 0, sizeof(pt));
        pt.d_off           = s->resume_d_off;
        pt.out_off         = s->resume_out_off;
        pt.old_off         = s->resume_old_off;
        pt.feed_D          = s->resume_record_base_d;
        pt.phase           = s->resume_phase;
        pt.diff_remaining  = s->resume_diff_remaining;
        pt.extra_remaining = s->resume_extra_remaining;
        mcf_session_restore(s->inner, &pt);
    }
    r=mcf_session_begin(s->inner); if(r!=MCF_OK) return v2_fail(s,(mcf_status_t)r);

    /* Checkpoint cursor and the first armed boundary. The record ring starts
     * empty and is filled as the feed decrypts. */
    s->d_base = s->resume_positioned ? s->resume_record_base_d : 0u;
    s->next_ckpt_out = 0u;
    if (s->journal_interval != 0u) {
        uint32_t step = s->flash_block * s->journal_interval;
        uint32_t base = s->resume_positioned ? s->resume_out_off : 0u;
        if (step < s->flash_block || base > UINT32_MAX - step) {
            s->journal_interval = 0u;
            s->flags |= MCF_V2_SESSION_FLAG_RESUME_DEGRADED;
        } else {
            s->next_ckpt_out = base + step;
            mcf_session_set_stop(s->inner, s->next_ckpt_out);
        }
    }
    s->state=MCF_ST_HEADER; s->status=MCF_OK; return MCF_OK;
}

mcf_status_t mcf_v2_session_step(mcf_v2_session_t *s)
{
    mcf_status_t st;
    if(s==NULL)return MCF_E_PARAM;
    if(s->state==MCF_ST_FAILED)return s->status;
    if(s->state==MCF_ST_DONE)return MCF_OK;
    if(s->inner==NULL)return MCF_E_STATE;
    st=mcf_session_step(s->inner);
    if(st!=MCF_OK)return v2_fail(s,st);
    if(mcf_session_state(s->inner)!=MCF_ST_VERIFY) v2_checkpoint(s);
    return MCF_OK;
}

mcf_status_t mcf_v2_session_finish(mcf_v2_session_t *s)
{
    mcf_status_t st;
    if(s==NULL)return MCF_E_PARAM;
    if(s->state==MCF_ST_FAILED)return s->status;
    if(s->inner==NULL)return MCF_E_STATE;
    st=mcf_session_finish(s->inner);
    if(st!=MCF_OK)return v2_fail(s,st);
    /* The key was needed for every record the feed decrypted, so it is wiped
     * only here, at the end of the last step, and on close(). */
    v2_wipe(s->key,(uint32_t)sizeof(s->key));
    if (s->win != NULL) { v2_wipe(s->win, s->win_cap); s->win_len = 0u; }
    s->state=MCF_ST_DONE;s->status=MCF_OK;
    /* A finished update must not leave a resume point behind. */
    (void)mcf_v2_resume_clear(s);
    return MCF_OK;
}

mcf_status_t mcf_v2_session_run(mcf_v2_session_t *s)
{ mcf_status_t st; if(s==NULL)return MCF_E_PARAM; st=mcf_v2_session_begin(s);if(st!=MCF_OK)return st;for(;;){st=mcf_v2_session_step(s);if(st!=MCF_OK)return st;if(mcf_session_state(s->inner)==MCF_ST_VERIFY)break;}return mcf_v2_session_finish(s); }
void mcf_v2_session_close(mcf_v2_session_t *s)
{ if(s==NULL)return; if(s->inner!=NULL)mcf_session_close(s->inner);v2_wipe(s->key,(uint32_t)sizeof(s->key));if(s->scratch!=NULL)v2_wipe(s->scratch,s->scratch_len);s->scratch=NULL;s->scratch_len=0u;s->inner=NULL;s->state=MCF_ST_IDLE;s->status=MCF_OK; }
mcf_state_t mcf_v2_session_state(const mcf_v2_session_t *s)
{ return s==NULL?MCF_ST_FAILED:(mcf_state_t)s->state; }
mcf_status_t mcf_v2_session_status(const mcf_v2_session_t *s)
{ return s==NULL?MCF_E_PARAM:s->status; }
uint32_t mcf_v2_session_flags(const mcf_v2_session_t *s)
{ return s==NULL?0u:s->flags; }
uint32_t mcf_v2_session_progress(const mcf_v2_session_t *s)
{ return (s==NULL || s->inner==NULL)?0u:mcf_session_progress(s->inner); }
