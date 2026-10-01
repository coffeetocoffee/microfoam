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
    return st;
}

/* Return the exact decoded delta size of the authenticated LZ4 framing. */
static mcf_status_t v2_lz4_size(const uint8_t *p, uint32_t n, uint32_t *out)
{
    uint32_t pos=0u, total=0u;
    while (pos < n) {
        uint32_t len, ip, end, produced=0u;
        if (n-pos < 4u) return MCF_E_TRUNCATED;
        len=mcf_rd32(&p[pos]); pos+=4u;
        if (len==0u) { if (pos != n) return MCF_E_CORRUPT; *out=total; return total ? MCF_OK : MCF_E_CORRUPT; }
        if (len > n-pos) return MCF_E_TRUNCATED;
        ip=pos; end=pos+len;
        while (ip < end) {
            uint32_t lit, match, off; uint8_t token, x;
            token=p[ip++]; lit=(uint32_t)(token>>4);
            if (lit==15u) { do { if (ip>=end) return MCF_E_CORRUPT; x=p[ip++]; if (lit > UINT32_MAX-(uint32_t)x) return MCF_E_CORRUPT; lit+=(uint32_t)x; } while (x==255u); }
            if (lit > end-ip) return MCF_E_CORRUPT;
            ip+=lit; produced+=lit;
            if (ip==end) break;
            if (end-ip<2u) return MCF_E_CORRUPT;
            off=mcf_rd16(&p[ip]); ip+=2u;
            if (off==0u || off>produced) return MCF_E_CORRUPT;
            match=(uint32_t)(token&15u);
            if (match==15u) { do { if (ip>=end) return MCF_E_CORRUPT; x=p[ip++]; if (match > UINT32_MAX-(uint32_t)x) return MCF_E_CORRUPT; match+=(uint32_t)x; } while (x==255u); }
            if (match > UINT32_MAX-4u) return MCF_E_CORRUPT;
            match+=4u;
            if (UINT32_MAX-produced < match) return MCF_E_CORRUPT;
            produced+=match;
        }
        if (UINT32_MAX-total < produced) return MCF_E_CORRUPT;
        total+=produced; pos=end;
    }
    return MCF_E_TRUNCATED;
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

/* Offset of record `index`'s framing within the record area and its plaintext
 * length (ciphertext length equals plaintext length). The parse that preceded
 * this call already proved the framing; these checks are belt-and-braces for
 * a path that never trusts memory alone. */
static int v2_record_at(const mcf_v2_view_t *v, const uint8_t *patch,
                        uint32_t index, uint32_t *out_off, uint32_t *out_len)
{
    uint32_t pos = 0u;
    uint32_t i;
    const uint8_t *area = &patch[v->header_len];

    if (index >= v->record_count) return 0;
    for (i = 0u; i < index; i++) {
        uint32_t len;
        if (v->payload_size - pos < 4u) return 0;
        len = mcf_rd32(&area[pos]); pos += 4u;
        if (len == 0u || len > (1u << v->record_log2) ||
            len > v->payload_size - pos || v->payload_size - pos - len < MCF_V2_RECORD_TAG_SIZE) return 0;
        pos += len + MCF_V2_RECORD_TAG_SIZE;
    }
    if (v->payload_size - pos < 4u) return 0;
    *out_len = mcf_rd32(&area[pos]);
    *out_off = pos;
    if (*out_len == 0u || *out_len > (1u << v->record_log2) ||
        *out_len > v->payload_size - pos - 4u ||
        v->payload_size - pos - 4u - *out_len < MCF_V2_RECORD_TAG_SIZE) return 0;
    return 1;
}

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
    uint32_t dlen, plen, off, step;
    int32_t r;

    if (s->journal_interval == 0u) return;
    if (mcf_session_snapshot(s->inner, &pt) == 0) return;
    if (pt.out_off != s->next_ckpt_out) return; /* still mid-block */

    /* Advance the walk to the record containing pt.d_off. The decoded length
     * of a record cannot be read from the framing (it is the LZ4 blocks'
     * output length), so the walk re-parses block headers from the plaintext
     * slice in the scratch area. */
    for (;;) {
        if (s->wk_index >= s->view.record_count) return; /* past the end */
        if (!v2_record_at(&s->view, s->cfg->patch, s->wk_index, &off, &plen)) return;
        (void)off;
        if (v2_record_dlen(&s->scratch[124u + s->wk_plain], plen, &dlen) != MCF_OK) {
            goto degrade;
        }
        if (pt.d_off < s->wk_d + dlen || s->wk_index + 1u >= s->view.record_count) {
            break;
        }
        s->wk_d     += dlen;
        s->wk_plain += plen;
        s->wk_index += 1u;
    }

    memset(&j, 0, sizeof(j));
    j.magic           = MCF_V2_JOURNAL_MAGIC;
    j.session_id      = s->session_id;
    j.out_off         = pt.out_off;
    j.old_off         = (uint32_t)pt.old_off;
    j.d_off           = pt.d_off;
    j.record_index    = s->wk_index;
    j.record_base_d   = s->wk_d;
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
    uint8_t nonce[MCF_V2_NONCE_SIZE]; uint8_t ad[8u+MCF_V2_HEADER_MAX+8u];
    uint32_t pos=0u, out=0u, i, start=0u, delta_size, need, total_need;
    uint32_t crc; int32_t r;
    mcf_resume_point_t pt;
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
    if (v.workspace_req == 0u || v.workspace_req > c->ram_budget ||
        v.workspace_req > c->workspace_size ||
        !v2_add_u32(124u, v.payload_size, &total_need) ||
        total_need > c->workspace_size || total_need > c->ram_budget) return v2_fail(s,MCF_E_DICT_TOO_LARGE);
    buf=(uint8_t *)c->workspace;
    s->scratch = buf; s->scratch_len = total_need;
    if (v2_ranges_overlap(c->patch, c->patch_size, buf, total_need) ||
        (c->old != NULL && v2_ranges_overlap(c->old, c->old_size, buf, total_need))) return v2_fail(s,MCF_E_PARAM);
    hdr=buf; memcpy(hdr,c->patch,v.header_len); memset(&hdr[MCF_V2_OFF_SIGNATURE],0,MCF_SIG_SIZE);
    r=c->verify(c->verify_ctx,&c->patch[MCF_V2_OFF_SIGNATURE],MCF_SIG_SIZE,
                (const uint8_t *)MCF_V2_SIGNATURE_DOMAIN,8u,hdr,v.header_len,
                &c->patch[v.header_len],v.payload_size);
    if (r!=MCF_OK) return v2_fail(s,(r<0 && r!=MCF_E_SIGNATURE)?(mcf_status_t)r:MCF_E_SIGNATURE);
    r=(int32_t)c->key_provider(c->key_ctx,&c->patch[MCF_V2_OFF_KEY_ID],s->key);
    if (r!=MCF_OK) return v2_fail(s,(r<0)?(mcf_status_t)r:MCF_E_IO);
    memcpy(nonce,&c->patch[MCF_V2_OFF_NONCE_PREFIX],16u);
    ad[0]='M';ad[1]='C';ad[2]='F';ad[3]='2';ad[4]='R';ad[5]='E';ad[6]='C';ad[7]=0;
    memcpy(&ad[8],hdr,v.header_len);
    /* The payload CRC covers the ciphertext, so the producer could not have
     * had it inside the AAD that produces that ciphertext; both sides carry
     * this field as zero in the AAD. The stored CRC remains signature-covered. */
    memset(&ad[8u + MCF_V2_OFF_PAYLOAD_CRC], 0, 4u);

    /* A resume feeds the codec from the record the journal names; the records
     * before it were already authenticated and their output programmed by the
     * interrupted run, so they are neither re-fed nor re-authenticated. */
    if (s->resume_positioned) {
        if (s->resume_record >= v.record_count) return v2_fail(s, MCF_E_PARAM);
        start = s->resume_record;
    }
    for (i=0u;i<start;i++) {
        uint32_t len;
        if(v.payload_size-pos<4u) return v2_fail(s,MCF_E_FORMAT);
        len=mcf_rd32(&c->patch[v.header_len+pos]); pos+=4u;
        if(len==0u || len>(1u<<v.record_log2) || len>v.payload_size-pos || v.payload_size-pos-len<16u) return v2_fail(s,MCF_E_FORMAT);
        pos+=len+16u;
    }
    for(i=start;i<v.record_count;i++) {
        uint32_t len; const uint8_t *rec;
        if(v.payload_size-pos<4u) return v2_fail(s,MCF_E_FORMAT);
        len=mcf_rd32(&c->patch[v.header_len+pos]); pos+=4u;
        if(len==0u || len>(1u<<v.record_log2) || len>v.payload_size-pos || v.payload_size-pos-len<16u) return v2_fail(s,MCF_E_FORMAT);
        rec=&c->patch[v.header_len+pos];
        v2_wr32(&ad[8u+v.header_len],i); v2_wr32(&ad[12u+v.header_len],len);
        { uint32_t k; for(k=0u;k<4u;k++) nonce[16u+k]=(uint8_t)(i>>(8u*k));
          for(k=4u;k<8u;k++) nonce[16u+k]=0u; } /* LE64(i): high half is zero */
        r=c->aead(c->aead_ctx,s->key,nonce,rec,len,rec+len,16u,ad,16u+v.header_len,&buf[124u+out]);
        if(r!=MCF_OK) return v2_fail(s,(r<0 && r!=MCF_E_AUTH)?(mcf_status_t)r:MCF_E_AUTH);
        if (out > UINT32_MAX-len || pos > UINT32_MAX-len-16u) return v2_fail(s,MCF_E_CORRUPT);
        out+=len; pos+=len+16u;
    }
    if(pos!=v.payload_size) return v2_fail(s,MCF_E_FORMAT);
    s->feed_len = out;
    r=(int32_t)v2_lz4_size(&buf[124u],out,&delta_size); if(r!=MCF_OK) return v2_fail(s,(mcf_status_t)r);
    if(delta_size==0u || out>UINT32_MAX-124u) return v2_fail(s,MCF_E_CORRUPT);
    v2_wr32(&buf[0],MCF_HDR_MAGIC); buf[4]=120u;buf[5]=0u;buf[6]=0u;buf[7]=1u;
    v2_wr32(&buf[8],MCF_FLAG_CODEC_LZ4); memcpy(&buf[12],&c->patch[12],4u); memcpy(&buf[16],&c->patch[16],4u);
    memcpy(&buf[20],&c->patch[20],4u);memcpy(&buf[24],&c->patch[24],4u);v2_wr32(&buf[28],out+4u);
    memcpy(&buf[32],&c->patch[32],4u);memcpy(&buf[36],&c->patch[36],4u);
    /* The synthetic header must declare what the inner session will actually
     * consume from ITS workspace slice: two decode/apply blocks plus the LZ4
     * state. Declaring the caller's whole budget here makes the inner session's
     * own budget check (block_size > (budget - workspace_req)/2) reject. */
    {
        uint32_t log2, inner_ws;
        /* The producer chunks the framed LZ4 stream at (1<<record_log2)-64, so
         * each framed block decodes to at most 1<<record_log2 bytes. The inner
         * decode window must therefore be the MFP2 record size, not the caller's
         * MFP1 block_size and not the ciphertext length. */
        log2 = v.record_log2;
        inner_ws = 2u * ((uint32_t)1u << log2) + 16u; /* 2 blocks + LZ4 state */
        v2_wr32(&buf[44], inner_ws);
        need = c->workspace_size - total_need;
        if (need < inner_ws) return v2_fail(s, MCF_E_DICT_TOO_LARGE);
        /* Codec id and block_log2 must agree with the framed stream. */
        buf[52] = (uint8_t)MCF_CODEC_LZ4;
        buf[53] = (uint8_t)log2;
        buf[54] = 0u; buf[55] = 0u;
        memset(&buf[56], 0, 64u);
    }
    v2_wr32(&buf[120],delta_size);
    v2_wr32(&buf[28],out+4u); /* MFP1 payload_crc32 covers the framed stream only, not the props block */
    if (!v2_add_u32(124u, out, &total_need) || total_need > c->workspace_size ||
        v.workspace_req > c->ram_budget) return v2_fail(s,MCF_E_DICT_TOO_LARGE);
    v2_wr32(&buf[40],mcf_crc32(&buf[124u],out));
    memset(&s->inner_cfg,0,sizeof(s->inner_cfg)); s->inner_cfg.hal=c->hal;s->inner_cfg.patch=buf;s->inner_cfg.patch_size=124u+out;
    s->inner_cfg.old=c->old;s->inner_cfg.old_read=c->old_read;s->inner_cfg.old_ctx=c->old_ctx;s->inner_cfg.old_size=c->old_size;s->inner_cfg.dst_addr=c->dst_addr;
    s->inner_cfg.codec=MCF_CODEC_LZ4;s->inner_cfg.block_size=(uint32_t)1u<<v.record_log2;s->inner_cfg.ram_budget=need;
    s->inner_cfg.workspace=&buf[124u+out];s->inner_cfg.workspace_size=need;s->inner_cfg.progress=c->progress;s->inner_cfg.progress_ctx=c->progress_ctx;s->inner_cfg.commit=c->commit;s->inner_cfg.commit_ctx=c->commit_ctx;
    s->inner=(mcf_session_t *)(void *)&s->inner_storage; r=mcf_session_open(s->inner,&s->inner_cfg); if(r!=MCF_OK) return v2_fail(s,(mcf_status_t)r);
    if (s->resume_positioned) {
        /* Restore the engine exactly where the journal recorded it - phase and
         * outstanding counts included - and let begin() position it. */
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

    /* Checkpoint cursor and the first armed boundary. The walk starts where
     * the feed starts: record `start` at its decoded base. */
    s->wk_index = start;
    s->wk_plain = 0u;
    s->wk_d     = s->resume_positioned ? s->resume_record_base_d : 0u;
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
    v2_wipe(s->key,(uint32_t)sizeof(s->key)); s->state=MCF_ST_HEADER; s->status=MCF_OK; return MCF_OK;
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
