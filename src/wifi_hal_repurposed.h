/* SPDX-License-Identifier: Apache-2.0 */
#ifndef WIFI_HAL_REPURPOSED_H
#define WIFI_HAL_REPURPOSED_H

#include "wifi_hal.h"
#include <stdbool.h>
#include <string.h>

/* Physical identity stays unchanged. Never classify every repurposed VAP as private. */
static inline bool wifi_hal_is_private_2g_target(const wifi_vap_info_t *vap)
{
#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT)
    return vap != NULL && vap->vap_mode == wifi_vap_mode_ap &&
        strncmp(vap->vap_name, "hotspot_secure_2g", sizeof(vap->vap_name)) == 0;
#else
    (void)vap;
    return false;
#endif
}

static inline bool wifi_hal_is_repurposed_private_2g(const wifi_vap_info_t *vap)
{
    return wifi_hal_is_private_2g_target(vap) &&
        strncmp(vap->repurposed_vap_name, WIFI_REPURPOSED_PRIVATE_2G_NAME,
            sizeof(vap->repurposed_vap_name)) == 0;
}

/* The dormant target must not save the previous generated profile either. */
static inline bool wifi_hal_is_private_2g_runtime_only(const wifi_vap_info_t *vap)
{
    return wifi_hal_is_repurposed_private_2g(vap) ||
        (wifi_hal_is_private_2g_target(vap) && !vap->u.bss_info.enabled);
}

static inline bool wifi_hal_repurposed_private_2g_valid(const wifi_vap_info_t *vap)
{
    return wifi_hal_is_repurposed_private_2g(vap) && !vap->u.bss_info.wps.enable &&
        !vap->u.bss_info.mld_info.common_info.mld_enable &&
        !vap->u.bss_info.bssTransitionActivated && !vap->u.bss_info.bssHotspot &&
        (!vap->u.bss_info.enabled || vap->bridge_name[0] != '\0');
}

#endif /* WIFI_HAL_REPURPOSED_H */
