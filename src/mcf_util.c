/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - CRC-32, version, diagnostics.
 *
 * Nothing here includes <stdio.h>; the library has no standard-library
 * dependency beyond <string.h> and <stdint.h>.
 */

#include "mcf_internal.h"

/* ---------------------------------------------------------------------- *
 * CRC-32 (IEEE 802.3, reflected, polynomial 0xEDB88320).
 *
 * Nibble-wise with a 16-entry table rather than the customary 256-entry one.
 * A byte-wise table costs 1 KB of RAM, which is a third of the entire
 * Constrained-profile budget, to speed up a check that is not the bottleneck.
 *
 * The table is const, so it lives in flash and the device build has no
 * initialised or zeroed RAM at all. It used to be generated into a static
 * array on first use, which cost 65 bytes of .bss on every target and made
 * the "all tables are const, nothing lands in RAM" claim in the README false;
 * the size gate added for that claim found it. The values are the same either
 * way - this is the published CRC-32 nibble table, and the self-test's
 * published CRC vectors cover it.
 * ---------------------------------------------------------------------- */

static const uint32_t g_crc_nib[16] = {
    0x00000000u, 0x1DB71064u, 0x3B6E20C8u, 0x26D930ACu,
    0x76DC4190u, 0x6B6B51F4u, 0x4DB26158u, 0x5005713Cu,
    0xEDB88320u, 0xF00F9344u, 0xD6D6A3E8u, 0xCB61B38Cu,
    0x9B64C2B0u, 0x86D3D2D4u, 0xA00AE278u, 0xBDBDF21Cu
};

uint32_t mcf_crc32_init(void)
{
    return 0xFFFFFFFFu;
}

uint32_t mcf_crc32_update(uint32_t crc, const uint8_t *buf, uint32_t len)
{
    uint32_t i;

    if (buf == NULL) {
        return crc;
    }
    for (i = 0; i < len; i++) {
        crc ^= (uint32_t)buf[i];
        crc = g_crc_nib[crc & 0x0Fu] ^ (crc >> 4);
        crc = g_crc_nib[crc & 0x0Fu] ^ (crc >> 4);
    }
    return crc;
}

uint32_t mcf_crc32_final(uint32_t crc)
{
    return crc ^ 0xFFFFFFFFu;
}

uint32_t mcf_crc32(const uint8_t *buf, uint32_t len)
{
    return mcf_crc32_final(mcf_crc32_update(mcf_crc32_init(), buf, len));
}

/* ---------------------------------------------------------------------- */

uint32_t mcf_version(void)
{
    return (MCF_VERSION_MAJOR << 16) | (MCF_VERSION_MINOR << 8) | MCF_VERSION_PATCH;
}

const char *mcf_session_strerror(mcf_status_t status)
{
    switch (status) {
    case MCF_OK:               return "ok";
    case MCF_E_PARAM:          return "invalid argument";
    case MCF_E_STATE:          return "invalid state";
    case MCF_E_NOMEM:          return "out of memory";
    case MCF_E_FORMAT:         return "malformed patch";
    case MCF_E_UNSUPPORTED:    return "unsupported feature";
    case MCF_E_DICT_TOO_LARGE: return "patch needs more memory than budgeted";
    case MCF_E_PRODUCT:        return "patch is for a different product";
    case MCF_E_MISMATCH:       return "base image does not match";
    case MCF_E_CORRUPT:        return "corrupt patch";
    case MCF_E_TRUNCATED:      return "patch is truncated";
    case MCF_E_SIGNATURE:      return "signature verification failed";
    case MCF_E_ROLLBACK:       return "refusing downgrade";
    case MCF_E_FLASH:          return "flash write failed";
    case MCF_E_IO:             return "source or sink read failed";
    case MCF_E_ABORTED:        return "aborted by caller";
    case MCF_E_COMMIT:         return "rejected by commit hook";
    case MCF_E_NOT_FOUND:      return "not found";
    case MCF_E_AUTH:           return "authentication failed";
    default:                   return "unknown error";
    }
}

void mcf_log_emit(const mcf_hal_t *hal, int level, uint32_t site, mcf_status_t st)
{
    static const char hex[] = "0123456789ABCDEF";
    char        msg[64];
    size_t      n;
    int         i;
    const char *s;

    if (hal == NULL || hal->log == NULL) {
        return;
    }

    /* Format: "S<site> <status>". Assembled by hand to keep <stdio.h> out. */
    n = 0;
    msg[n++] = 'S';
    for (i = 3; i >= 0; i--) {
        msg[n++] = hex[(site >> (i * 4)) & 0xFu];
    }
    msg[n++] = ' ';
    s = mcf_session_strerror(st);
    while (*s != '\0' && n < (sizeof(msg) - 1u)) {
        msg[n++] = *s++;
    }
    msg[n] = '\0';

    hal->log(hal->ctx, level, msg);
}
