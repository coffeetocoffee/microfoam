/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - codec registry.
 *
 * The registry is write-once at link time and read-only thereafter. It holds
 * configuration, not session state, so it does not violate the rule that no
 * session state lives in mutable globals.
 */

#include "mcf_internal.h"
#include "mcf_codec_lz4.h"
#include "mcf_codec_raw.h"
#ifdef MCF_ENABLE_LZMA
#include "mcf_lzma.h"
#endif

static const mcf_codec_ops_t *const g_builtin[] = {
    &mcf_codec_lz4_ops,
    &mcf_codec_raw_ops,
#ifdef MCF_ENABLE_LZMA
    &mcf_codec_lzma_ops,
#endif
    NULL
};

static int mcf_codec_valid(const mcf_codec_ops_t *ops)
{
    return ops != NULL && ops->name != NULL && ops->id != MCF_CODEC_AUTO &&
           (ops->id < MCF_CODEC_MAX || ops->id >= MCF_CODEC_CUSTOM_MIN) &&
           ops->workspace_size != NULL &&
           ops->init != NULL && ops->decode != NULL && ops->finish != NULL &&
           ops->destroy != NULL;
}

mcf_status_t mcf_codec_validate(const mcf_codec_ops_t *ops)
{
    return mcf_codec_valid(ops) ? MCF_OK : MCF_E_PARAM;
}

mcf_status_t mcf_codec_register(const mcf_codec_ops_t *ops)
{
    return mcf_codec_validate(ops);
}

const mcf_codec_ops_t *mcf_codec_lookup(const mcf_config_t *cfg, mcf_codec_id_t id)
{
    uint32_t i;
    const mcf_codec_ops_t *const *p;

    if (cfg != NULL && cfg->codecs != NULL) {
        for (i = 0u; i < cfg->codec_count; i++) {
            if (mcf_codec_valid(&cfg->codecs[i]) && cfg->codecs[i].id == id) {
                return &cfg->codecs[i];
            }
        }
    }
    for (p = &g_builtin[0]; *p != NULL; p++) {
        if ((*p)->id == id) {
            return *p;
        }
    }
    return NULL;
}

uint32_t mcf_codec_props_len(mcf_codec_id_t id)
{
    switch (id) {
    case MCF_CODEC_LZ4:
        return 4u;  /* u32 le content size            */
    case MCF_CODEC_LZMA:
        return 9u;  /* props byte, u32 dict, u32 size */
    case MCF_CODEC_RAW:
        return 0u;  /* the payload is the delta itself */
    default:
        return 0u;
    }
}

const char *mcf_codec_name(mcf_codec_id_t id)
{
    const mcf_codec_ops_t *ops = mcf_codec_lookup(NULL, id);
    return (ops != NULL) ? ops->name : "?";
}
