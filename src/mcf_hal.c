/* SPDX-License-Identifier: MIT */
/*
 * Microfoam - HAL registration, workspace allocation, and diagnostics.
 */

#include "mcf_internal.h"

/* HAL descriptions are supplied per session; no process-global device state is
 * retained here. */

mcf_status_t mcf_hal_register(const mcf_hal_t *hal)
{
    if (hal == NULL) {
        return MCF_E_PARAM;
    }
    if (hal->flash_erase == NULL || hal->flash_write == NULL ||
        hal->flash_block_size == NULL || hal->get_product_id == NULL ||
        hal->get_fw_version == NULL) {
        return MCF_E_PARAM;
    }
    return MCF_OK;
}

mcf_status_t mcf_hal_set_static_workspace(const mcf_hal_t *hal, void *bytes, uint32_t size)
{
    if (hal == NULL || bytes == NULL || size == 0u) {
        return MCF_E_PARAM;
    }
    (void)bytes;
    (void)size;
    return MCF_E_UNSUPPORTED; /* workspace is now configured per session */
}

void *mcf_ws_alloc(const mcf_hal_t *hal, uint8_t *static_ws,
                   uint32_t static_ws_size, uint32_t size)
{
    if (size == 0u) {
        return NULL;
    }
    if (hal != NULL && hal->alloc != NULL) {
        if (hal->free == NULL) {
            return NULL;
        }
        return hal->alloc(hal->ctx, size);
    }
    if (static_ws == NULL || size > static_ws_size) {
        return NULL;
    }
    return static_ws;
}

void mcf_ws_free(const mcf_hal_t *hal, void *ptr)
{
    if (ptr == NULL) {
        return;
    }
    if (hal != NULL && hal->free != NULL) {
        hal->free(hal->ctx, ptr);
    }
    /* Caller-owned static workspace is not released by the library. */
}
