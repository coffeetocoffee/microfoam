/* SPDX-License-Identifier: MIT */
#include "microfoam_v2.h"
#include <stdio.h>
#include <string.h>

static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }

int main(void)
{
    uint8_t patch[256];
    uint8_t bad[256];
    mcf_v2_view_t view;
    mcf_v2_record_t rec;
    uint32_t off;
    memset(patch, 0, sizeof(patch));
    wr32(&patch[MCF_V2_OFF_MAGIC], MCF_V2_MAGIC);
    wr16(&patch[MCF_V2_OFF_HEADER_LEN], MCF_V2_HEADER_MIN);
    wr16(&patch[MCF_V2_OFF_VERSION], MCF_V2_VERSION);
    wr32(&patch[MCF_V2_OFF_FLAGS], MCF_V2_FLAG_CODEC_LZ4);
    patch[MCF_V2_OFF_CODEC] = (uint8_t)MCF_CODEC_LZ4;
    patch[MCF_V2_OFF_RECORD_LOG2] = 8u;
    wr32(&patch[MCF_V2_OFF_PAYLOAD_SIZE], 12u);
    wr32(&patch[MCF_V2_OFF_RECORD_COUNT], 2u);
    wr32(&patch[MCF_V2_HEADER_MIN], 2u);
    patch[MCF_V2_HEADER_MIN + 4u] = 0xAAu;
    patch[MCF_V2_HEADER_MIN + 5u] = 0xBBu;
    wr32(&patch[MCF_V2_HEADER_MIN + 6u], 2u);
    patch[MCF_V2_HEADER_MIN + 10u] = 0xCCu;
    patch[MCF_V2_HEADER_MIN + 11u] = 0xDDu;

    if (mcf_v2_parse(patch, sizeof(patch), &view) != MCF_OK) return 1;
    off = 0u;
    if (mcf_v2_next_record(&view, patch, sizeof(patch), &off, &rec) != MCF_OK ||
        rec.index != 0u || rec.data_len != 2u || rec.data[0] != 0xAAu) return 2;
    if (mcf_v2_next_record(&view, patch, sizeof(patch), &off, &rec) != MCF_OK ||
        rec.index != 1u || rec.data[0] != 0xCCu) return 3;
    if (mcf_v2_next_record(&view, patch, sizeof(patch), &off, &rec) != MCF_E_NOT_FOUND) return 4;

    memcpy(bad, patch, sizeof(bad));
    bad[MCF_V2_OFF_FLAGS] = 0x80u;
    if (mcf_v2_parse(bad, sizeof(bad), &view) != MCF_E_FORMAT) return 5;
    memcpy(bad, patch, sizeof(bad));
    wr32(&bad[MCF_V2_OFF_FLAGS], MCF_V2_FLAG_ENCRYPTED | MCF_V2_FLAG_CODEC_LZ4);
    if (mcf_v2_parse(bad, sizeof(bad), &view) != MCF_E_UNSUPPORTED) return 6;
    memcpy(bad, patch, sizeof(bad));
    wr32(&bad[MCF_V2_OFF_RESERVED], 1u);
    if (mcf_v2_parse(bad, sizeof(bad), &view) != MCF_E_FORMAT) return 7;
    puts("v2 structural parser: valid records and malformed headers passed");
    return 0;
}
