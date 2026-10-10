/* SPDX-License-Identifier: Apache-2.0 */
#ifndef WIFI_HAL_REPURPOSED_H
#define WIFI_HAL_REPURPOSED_H

#include "wifi_hal.h"
#include <stdbool.h>
#include <string.h>

/* Every log line of the repurposed private VAP path starts with this tag, in the HAL and in
 * OneWifi, so that one grep follows a request from OneWifi through the HAL to the driver. */
#define WIFI_REPURPOSED_LOG_TAG "SREESH"
#define wifi_hal_repurposed_info(format, ...)                                                 \
    wifi_hal_info_print(WIFI_REPURPOSED_LOG_TAG ": %s:%d: " format, __func__, __LINE__,      \
        ##__VA_ARGS__)
#define wifi_hal_repurposed_error(format, ...)                                                \
    wifi_hal_error_print(WIFI_REPURPOSED_LOG_TAG ": %s:%d: " format, __func__, __LINE__,     \
        ##__VA_ARGS__)

/*
 * The secure 2.4 GHz hotspot VAP that OneWifi can repurpose as a private VAP.
 *
 * With the role it has every setting and capability of the private 2.4 GHz VAP except MLO and
 * steering:
 * - its VAP configuration, derived by OneWifi from the private 2.4 GHz one, goes through the
 *   common path like any VAP (wifi_hal_createVAP(), platform_create_vap()),
 * - the private bridge (nl80211_create_bridge()),
 * - the per BSS driver settings of the private BSS that are not part of a VAP configuration
 *   (platform_set_repurposed_bss_profile()),
 * - the WPS device of the private VAPs (UUID, RF bands) when its WPS is on: hostapd runs it in
 *   their sessions (wifi_hal_wps_init()); NVRAM shows no WPS for it (platform_create_vap()),
 * - no hotspot feature (connected building) and no steering list (re_configure_steering_mac_list()).
 * Its physical identity (index, interface, BSSID) and its index based classification stay
 * unchanged: index based private-only features (MLD membership) never include it.
 */
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

/* The target holds the repurposed private role. Without it, the target is the ordinary
 * hotspot VAP, enabled or not, and every path treats it as before. */
static inline bool wifi_hal_is_repurposed_private_2g(const wifi_vap_info_t *vap)
{
    return wifi_hal_is_private_2g_target(vap) &&
        strncmp(vap->repurposed_vap_name, WIFI_REPURPOSED_PRIVATE_2G_NAME,
            sizeof(vap->repurposed_vap_name)) == 0;
}

/* A role request: the exceptions of the role hold (no MLO, BSS transition steering or hotspot
 * flag) and an enabled BSS has its bridge. */
static inline bool wifi_hal_repurposed_private_2g_valid(const wifi_vap_info_t *vap)
{
    return wifi_hal_is_repurposed_private_2g(vap) &&
        !vap->u.bss_info.mld_info.common_info.mld_enable &&
        !vap->u.bss_info.bssTransitionActivated && !vap->u.bss_info.bssHotspot &&
        (!vap->u.bss_info.enabled || vap->bridge_name[0] != '\0');
}

#endif /* WIFI_HAL_REPURPOSED_H */
