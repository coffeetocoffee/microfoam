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

mcf_status_t mcf_v2_session_open(mcf_v2_session_t *s, const mcf_v2_config_t *cfg)
{
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
    return MCF_OK;
}

mcf_status_t mcf_v2_session_begin(mcf_v2_session_t *s)
{
    const mcf_v2_config_t *c; mcf_v2_view_t v; uint8_t *buf; uint8_t *hdr;
    uint8_t nonce[MCF_V2_NONCE_SIZE]; uint8_t ad[8u+MCF_V2_HEADER_MAX+8u];
    uint32_t pos=0u, out=0u, i, delta_size, need, total_need; uint32_t crc; int32_t r;
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
    for(i=0u;i<v.record_count;i++) {
        uint32_t len; const uint8_t *rec;
        if(v.payload_size-pos<4u) return v2_fail(s,MCF_E_FORMAT);
        len=mcf_rd32(&c->patch[v.header_len+pos]); pos+=4u;
        if(len==0u || len>(1u<<v.record_log2) || len>v.payload_size-pos || v.payload_size-pos-len<16u) return v2_fail(s,MCF_E_FORMAT);
        rec=&c->patch[v.header_len+pos];
        v2_wr32(&ad[8u+v.header_len],i); v2_wr32(&ad[12u+v.header_len],len);
        { uint32_t k; for(k=0u;k<8u;k++) nonce[16u+k]=(uint8_t)(i>>(8u*k)); }
        r=c->aead(c->aead_ctx,s->key,nonce,rec,len,rec+len,16u,ad,16u+v.header_len,&buf[124u+out]);
        if(r!=MCF_OK) return v2_fail(s,(r<0 && r!=MCF_E_AUTH)?(mcf_status_t)r:MCF_E_AUTH);
        if (out > UINT32_MAX-len || pos > UINT32_MAX-len-16u) return v2_fail(s,MCF_E_CORRUPT);
        out+=len; pos+=len+16u;
    }
    if(pos!=v.payload_size) return v2_fail(s,MCF_E_FORMAT);
    r=(int32_t)v2_lz4_size(&buf[124u],out,&delta_size); if(r!=MCF_OK) return v2_fail(s,(mcf_status_t)r);
    if(delta_size==0u || out>UINT32_MAX-124u) return v2_fail(s,MCF_E_CORRUPT);
    v2_wr32(&buf[0],MCF_HDR_MAGIC); buf[4]=120u;buf[5]=0u;buf[6]=0u;buf[7]=1u;
    v2_wr32(&buf[8],MCF_FLAG_CODEC_LZ4); memcpy(&buf[12],&c->patch[12],4u); memcpy(&buf[16],&c->patch[16],4u);
    memcpy(&buf[20],&c->patch[20],4u);memcpy(&buf[24],&c->patch[24],4u);v2_wr32(&buf[28],out+4u);
    memcpy(&buf[32],&c->patch[32],4u);memcpy(&buf[36],&c->patch[36],4u);
    v2_wr32(&buf[44],c->ram_budget);memcpy(&buf[48],&c->patch[48],4u);buf[52]=MCF_CODEC_LZ4;buf[53]=10u;buf[54]=0u;buf[55]=0u;memset(&buf[56],0,64u);
    v2_wr32(&buf[120],delta_size);
    v2_wr32(&buf[28],out+4u); v2_wr32(&buf[40],mcf_crc32(&buf[120],out+4u));
    if (!v2_add_u32(124u, out, &total_need) || total_need > c->workspace_size ||
        v.workspace_req > c->ram_budget || c->ram_budget - v.workspace_req < 124u) return v2_fail(s,MCF_E_DICT_TOO_LARGE);
    need=c->workspace_size-total_need;
    memset(&s->inner_cfg,0,sizeof(s->inner_cfg)); s->inner_cfg.hal=c->hal;s->inner_cfg.patch=buf;s->inner_cfg.patch_size=124u+out;
    s->inner_cfg.old=c->old;s->inner_cfg.old_read=c->old_read;s->inner_cfg.old_ctx=c->old_ctx;s->inner_cfg.old_size=c->old_size;s->inner_cfg.dst_addr=c->dst_addr;
    s->inner_cfg.codec=MCF_CODEC_LZ4;s->inner_cfg.block_size=c->block_size;s->inner_cfg.ram_budget=(need<c->ram_budget)?need:c->ram_budget;
    s->inner_cfg.workspace=(need!=0u)?&buf[124u+out]:NULL;s->inner_cfg.workspace_size=need;s->inner_cfg.progress=c->progress;s->inner_cfg.progress_ctx=c->progress_ctx;s->inner_cfg.commit=c->commit;s->inner_cfg.commit_ctx=c->commit_ctx;
    s->inner=(mcf_session_t *)(void *)&s->inner_storage; r=mcf_session_open(s->inner,&s->inner_cfg); if(r!=MCF_OK) return v2_fail(s,(mcf_status_t)r);
    r=mcf_session_begin(s->inner); if(r!=MCF_OK) return v2_fail(s,(mcf_status_t)r);
    v2_wipe(s->key,(uint32_t)sizeof(s->key)); s->state=MCF_ST_HEADER; s->status=MCF_OK; return MCF_OK;
}

mcf_status_t mcf_v2_session_step(mcf_v2_session_t *s)
{ mcf_status_t st; if(s==NULL)return MCF_E_PARAM; if(s->state==MCF_ST_FAILED)return s->status; if(s->state==MCF_ST_DONE)return MCF_OK; if(s->inner==NULL)return MCF_E_STATE; st=mcf_session_step(s->inner); if(st!=MCF_OK)return v2_fail(s,st); return MCF_OK; }
mcf_status_t mcf_v2_session_finish(mcf_v2_session_t *s)
{ mcf_status_t st; if(s==NULL)return MCF_E_PARAM; if(s->state==MCF_ST_FAILED)return s->status; if(s->inner==NULL)return MCF_E_STATE; st=mcf_session_finish(s->inner); if(st!=MCF_OK)return v2_fail(s,st); s->state=MCF_ST_DONE;s->status=MCF_OK;return MCF_OK; }
mcf_status_t mcf_v2_session_run(mcf_v2_session_t *s)
{ mcf_status_t st; if(s==NULL)return MCF_E_PARAM; st=mcf_v2_session_begin(s);if(st!=MCF_OK)return st;for(;;){st=mcf_v2_session_step(s);if(st!=MCF_OK)return st;if(mcf_session_state(s->inner)==MCF_ST_VERIFY)break;}return mcf_v2_session_finish(s); }
void mcf_v2_session_close(mcf_v2_session_t *s)
{ if(s==NULL)return; if(s->inner!=NULL)mcf_session_close(s->inner);v2_wipe(s->key,(uint32_t)sizeof(s->key));if(s->scratch!=NULL)v2_wipe(s->scratch,s->scratch_len);s->scratch=NULL;s->scratch_len=0u;s->inner=NULL;s->state=MCF_ST_IDLE;s->status=MCF_OK; }
mcf_state_t mcf_v2_session_state(const mcf_v2_session_t *s)
{ return s==NULL?MCF_ST_FAILED:(mcf_state_t)s->state; }
mcf_status_t mcf_v2_session_status(const mcf_v2_session_t *s)
{ return s==NULL?MCF_E_PARAM:s->status; }
