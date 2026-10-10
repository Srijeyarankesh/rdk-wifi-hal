#!/usr/bin/env python3
"""Execute the production wifi_hal_createVAP() for the repurposed private role, with fakes that keep
the rules of the XB10 kernel (cfg80211, 5.15) and of hostapd 2.11 that the role change relies on:
- SET_MAC_ACL is rejected (-EINVAL) until the AP is started (nl80211_set_mac_acl),
- STOP_AP fails (-ENOENT) on an AP that is not running (___cfg80211_stop_ap),
- taking a netdev down stops its AP (cfg80211_leave), START_AP needs the netdev up,
- set_ap is skipped while the interface is in reconfiguration (wifi_drv_set_ap),
- hostapd_setup_bss() refuses a BSS that is already started until deinit_bss() frees it."""
from pathlib import Path
import subprocess
import tempfile
repo = Path(__file__).resolve().parents[2]
halif = repo.parent / "rdkb-halif-wifi/include"


def extract(path, name, result="int"):
    source = (repo / path).read_text()
    start = source.index(result + " " + name + "(")
    # the closing brace at column 0: #if branches can open a brace twice
    end = source.index("\n}\n", start) + 3
    return source[start:end]


prelude = r"""
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "wifi_hal_repurposed.h"
#define TRUE 1
#define FALSE 0
#define NUM_VAPS 24
#define RADIO_INDEX_ASSERT(index) do { if ((int)(index) != 0) return RETURN_ERR; } while (0)
#define NULL_PTR_ASSERT(ptr) do { if ((ptr) == NULL) return RETURN_ERR; } while (0)
#define WPA_DRIVER_FLAGS_BEACON_PROTECTION 0x4000000000000000ULL

static char logbuf[1 << 17];
static void log_line(const char *format, ...) __attribute__((format(printf, 1, 2)));
static void log_line(const char *format, ...)
{
    size_t used = strlen(logbuf);
    va_list ap;

    va_start(ap, format);
    if (used < sizeof(logbuf) - 1) {
        vsnprintf(logbuf + used, sizeof(logbuf) - used, format, ap);
    }
    va_end(ap);
}
#define wifi_hal_dbg_print(...) log_line(__VA_ARGS__)
#define wifi_hal_info_print(...) log_line(__VA_ARGS__)
#define wifi_hal_error_print(...) log_line(__VA_ARGS__)

struct hostapd_wpa_psk { struct hostapd_wpa_psk *next; };
struct hostapd_bss_config { struct { struct hostapd_wpa_psk *wpa_psk; } ssid; };
struct hostapd_iface { int dummy; };
struct hostapd_data { struct hostapd_iface *iface; struct hostapd_bss_config *conf; int started; };
typedef struct { unsigned int count; } hash_map_t;
static unsigned int __attribute__((unused)) hash_map_count(hash_map_t *map) { return map->count; }

typedef struct {
    char name[32];
    mac_address_t mac;
    wifi_vap_info_t vap_info;
    bool vap_initialized, bss_started, in_reconf;
    int beacon_set;
    hash_map_t *acl_map;
    struct {
        struct {
            struct hostapd_data hapd;
            struct { unsigned long long drv_flags; } iface;
            struct { int beacon_prot; } conf;
        } ap;
        struct { int sta_4addr; } sta;
    } u;
    /* kernel and network state of the fake */
    bool netdev_up, ap_started, acl_programmed;
    char bridge[32];
} wifi_interface_info_t;
typedef struct {
    int index;
    bool configured, radio_presence;
    struct { bool enable; } oper_param;
} wifi_radio_info_t;
typedef int (*platform_pre_create_vap_t)(wifi_radio_index_t index, wifi_vap_info_map_t *map);
typedef int (*platform_create_vap_t)(wifi_radio_index_t index, wifi_vap_info_map_t *map);
typedef int (*platform_set_beacon_prot_t)(unsigned int apIndex, bool enabled);

static struct { int nl80211_id; pthread_mutex_t hapd_lock; } g_wifi_hal = {
    .hapd_lock = PTHREAD_MUTEX_INITIALIZER
};
static wifi_interface_info_t interfaces[NUM_VAPS];
static wifi_radio_info_t radio;
static struct hostapd_iface hostapd_iface;
static struct hostapd_bss_config hostapd_conf[NUM_VAPS];
static hash_map_t acl_maps[NUM_VAPS];
static wifi_vap_info_map_t map;
/* fault injection and observations */
static int fail_start_bss, fail_update_params, fail_reload_vap, fail_platform_create;
static int fail_mgmt_power, fail_acl_driver;
static int platform_create_calls, profile_calls, profile_role, reload_vap_calls;
static int steering_calls[NUM_VAPS];

static wifi_interface_info_t *by_name(const char *name)
{
    for (unsigned int i = 0; i < NUM_VAPS; i++) {
        if (interfaces[i].name[0] != '\0' && strcmp(interfaces[i].name, name) == 0) {
            return &interfaces[i];
        }
    }
    return NULL;
}
static wifi_radio_info_t *get_radio_by_rdk_index(wifi_radio_index_t index)
{ return index == 0 ? &radio : NULL; }
static wifi_interface_info_t *get_interface_by_vap_index(unsigned int index)
{ return (index < NUM_VAPS && interfaces[index].name[0] != '\0') ? &interfaces[index] : NULL; }
static bool is_wifi_hal_vap_hotspot_secure_2g(unsigned int index) { return index == 8; }
static int validate_wifi_interface_vap_info_params(wifi_vap_info_t *vap, char *msg, int len)
{ (void)vap; snprintf(msg, len, "ok"); return RETURN_OK; }
static int pre_create(wifi_radio_index_t index, wifi_vap_info_map_t *m)
{ (void)index; (void)m; return RETURN_OK; }
static int post_create(wifi_radio_index_t index, wifi_vap_info_map_t *m)
{ (void)index; (void)m; platform_create_calls++; return fail_platform_create ? RETURN_ERR : RETURN_OK; }
static platform_pre_create_vap_t get_platform_pre_create_vap_fn(void) { return pre_create; }
static platform_create_vap_t get_platform_create_vap_fn(void) { return post_create; }
static platform_set_beacon_prot_t get_platform_set_beacon_prot_fn(void) { return NULL; }
static int nl80211_create_interface(wifi_radio_info_t *r, wifi_vap_info_t *vap,
    wifi_interface_info_t **interface)
{ (void)r; (void)vap; *interface = NULL; return -1; }
static char *wifi_hal_get_interface_name(wifi_interface_info_t *interface) { return interface->name; }
/* cfg80211: a netdev that goes down stops its AP */
static int nl80211_interface_enable(const char *name, bool enable)
{
    wifi_interface_info_t *interface = by_name(name);

    if (interface != NULL) {
        interface->netdev_up = enable;
        if (!enable) {
            interface->ap_started = false;
        }
    }
    return 0;
}
static int nl80211_retry_interface_enable(wifi_interface_info_t *interface, bool enable)
{ return nl80211_interface_enable(interface->name, enable); }
static int nl80211_remove_from_bridge(const char *name)
{ wifi_interface_info_t *i = by_name(name); if (i != NULL) i->bridge[0] = '\0'; return 0; }
static int nl80211_create_bridge(const char *name, const char *bridge)
{
    wifi_interface_info_t *i = by_name(name);
    if (i != NULL) snprintf(i->bridge, sizeof(i->bridge), "%s", bridge);
    return 0;
}
static int nl80211_update_interface(wifi_interface_info_t *interface) { (void)interface; return 0; }
static int update_hostap_interface_params(wifi_interface_info_t *interface)
{ (void)interface; return fail_update_params ? RETURN_ERR : RETURN_OK; }
static int update_hostap_interfaces(wifi_radio_info_t *r) { (void)r; return RETURN_OK; }
/* hostapd_setup_bss(): started is set before anything that can fail, deinit_bss() clears it */
static int start_bss(wifi_interface_info_t *interface)
{
    struct hostapd_data *hapd = &interface->u.ap.hapd;

    if (hapd->started) {
        return -1;
    }
    hapd->started = 1;
    if (fail_start_bss) {
        return -1;
    }
    if (interface->in_reconf) {
        return 0; /* wifi_drv_set_ap() skips START_AP and reports success */
    }
    if (!interface->netdev_up) {
        return -1; /* START_AP: -ENETDOWN */
    }
    interface->ap_started = true;
    return 0;
}
static int hostapd_reload_config(struct hostapd_iface *iface) { (void)iface; return 0; }
static void deinit_bss(struct hostapd_data *hapd) { hapd->started = 0; }
static void hostapd_config_clear_wpa_psk(struct hostapd_wpa_psk **psk) { *psk = NULL; }
/* STOP_AP: -ENOENT on an AP that is not running */
static int nl80211_enable_ap(wifi_interface_info_t *interface, bool enable)
{
    assert(!enable);
    if (!interface->ap_started) {
        return RETURN_ERR;
    }
    interface->ap_started = false;
    return RETURN_OK;
}
static int reload_vap_configuration(wifi_interface_info_t *interface)
{ (void)interface; reload_vap_calls++; return fail_reload_vap ? -1 : 0; }
/* SET_MAC_ACL: -EINVAL until the AP is started */
static int __attribute__((unused)) nl80211_set_acl(wifi_interface_info_t *interface)
{
    if (!interface->ap_started) {
        return -EINVAL;
    }
    if (fail_acl_driver) {
        return -EIO;
    }
    interface->acl_programmed = true;
    return 0;
}
int wifi_setApMacAddressControlMode(int index, int mode)
{ interfaces[index].acl_programmed = mode >= 0; return 0; }
static void re_configure_steering_mac_list(wifi_interface_info_t *interface)
{ steering_calls[interface->vap_info.vap_index]++; }
int wifi_setApManagementFramePowerControl(int index, int power)
{ (void)index; (void)power; return fail_mgmt_power ? RETURN_ERR : RETURN_OK; }
/* the per BSS driver settings are applied while the BSS is down */
static void platform_set_repurposed_bss_profile(wifi_interface_info_t *interface,
    const wifi_vap_info_t *vap)
{
    assert(!interface->netdev_up && !interface->ap_started);
    profile_calls++;
    profile_role = wifi_hal_is_repurposed_private_2g(vap);
}
static wifi_interface_info_t *wifi_hal_get_mbssid_tx_interface(wifi_radio_info_t *r)
{ (void)r; return NULL; }
static void wifi_hal_configure_mbssid(wifi_radio_info_t *r) { (void)r; }
static int get_sta_4addr_status(bool *sta_4addr) { *sta_4addr = false; return 0; }
const char *get_vap_bridge_name(wifi_vap_info_t *vap) { return vap->bridge_name; }
static int wifi_drv_set_operstate(void *priv, int state) { (void)priv; (void)state; return 0; }
"""

tests = r"""
static void setup(unsigned int index, const char *name, const char *vap_name, const char *bridge)
{
    wifi_interface_info_t *i = &interfaces[index];

    snprintf(i->name, sizeof(i->name), "%s", name);
    i->vap_info.vap_index = index;
    i->vap_info.radio_index = 0;
    i->vap_info.vap_mode = wifi_vap_mode_ap;
    snprintf(i->vap_info.vap_name, sizeof(i->vap_info.vap_name), "%s", vap_name);
    snprintf(i->vap_info.bridge_name, sizeof(i->vap_info.bridge_name), "%s", bridge);
    i->vap_info.u.bss_info.enabled = true;
    i->vap_initialized = i->bss_started = true;
    i->u.ap.hapd.started = 1;
    i->u.ap.hapd.iface = &hostapd_iface;
    i->u.ap.hapd.conf = &hostapd_conf[index];
    i->netdev_up = i->ap_started = true;
    snprintf(i->bridge, sizeof(i->bridge), "%s", bridge);
    i->acl_map = &acl_maps[index];
}

static void reset(void)
{
    memset(interfaces, 0, sizeof(interfaces));
    memset(logbuf, 0, sizeof(logbuf));
    radio = (wifi_radio_info_t){ .index = 0, .configured = true, .radio_presence = true,
        .oper_param.enable = true };
    fail_start_bss = fail_update_params = fail_reload_vap = fail_platform_create = 0;
    fail_mgmt_power = fail_acl_driver = 0;
    platform_create_calls = profile_calls = reload_vap_calls = 0;
    profile_role = -1;
    memset(steering_calls, 0, sizeof(steering_calls));
    setup(0, "wl0.1", "private_ssid_2g", "brlan0");
    setup(8, "wl0.5", "hotspot_secure_2g", "brlan4");
}

static wifi_vap_info_t hotspot_vap(bool enabled)
{
    wifi_vap_info_t vap = interfaces[8].vap_info;

    memset(vap.repurposed_vap_name, 0, sizeof(vap.repurposed_vap_name));
    snprintf(vap.bridge_name, sizeof(vap.bridge_name), "brlan4");
    vap.u.bss_info.enabled = enabled;
    return vap;
}

static wifi_vap_info_t role_vap(bool enabled)
{
    wifi_vap_info_t vap = hotspot_vap(enabled);

    snprintf(vap.repurposed_vap_name, sizeof(vap.repurposed_vap_name), "%s",
        WIFI_REPURPOSED_PRIVATE_2G_NAME);
    snprintf(vap.bridge_name, sizeof(vap.bridge_name), "brlan0");
    vap.u.bss_info.security.mode = wifi_security_mode_wpa3_compatibility;
    return vap;
}

static int create(const wifi_vap_info_t *a, const wifi_vap_info_t *b)
{
    memset(&map, 0, sizeof(map));
    map.vap_array[map.num_vaps++] = *a;
    if (b != NULL) {
        map.vap_array[map.num_vaps++] = *b;
    }
    for (unsigned int i = 0; i < NUM_VAPS; i++) {
        interfaces[i].acl_programmed = false;
    }
    return wifi_hal_createVAP(0, &map);
}

static void assert_running(unsigned int index, const char *bridge)
{
    wifi_interface_info_t *i = &interfaces[index];

    assert(i->bss_started && i->u.ap.hapd.started && i->ap_started && i->netdev_up);
    assert(strcmp(i->bridge, bridge) == 0 && !i->in_reconf);
}

static void assert_stopped(unsigned int index)
{
    wifi_interface_info_t *i = &interfaces[index];

    assert(!i->bss_started && !i->u.ap.hapd.started && !i->ap_started && !i->netdev_up);
    assert(i->bridge[0] == '\0' && !i->vap_info.u.bss_info.enabled && !i->in_reconf);
}

static bool logged(const char *text) { return strstr(logbuf, text) != NULL; }

int main(void)
{
    wifi_vap_info_t vap, private_vap;

    /* Enter: the running hotspot BSS moves to the private bridge and starts again; the ACL is
     * set once the AP runs, the BSS profile while it is down, and no steering list. */
    reset();
    vap = role_vap(true);
    assert(create(&vap, NULL) == RETURN_OK);
    assert_running(8, "brlan0");
    assert(interfaces[8].acl_programmed && profile_calls == 1 && profile_role == 1);
    assert(steering_calls[8] == 0 && platform_create_calls == 1);
    assert(wifi_hal_is_repurposed_private_2g(&interfaces[8].vap_info));
    assert(logged(WIFI_REPURPOSED_LOG_TAG ": wifi_hal_createVAP:"));
    assert(logged("takes the repurposed private role") && logged("role change applied"));
    assert(!logged("role change failed"));

    /* Reapply: the role is kept with a new configuration. */
    memset(logbuf, 0, sizeof(logbuf));
    assert(create(&vap, NULL) == RETURN_OK);
    assert_running(8, "brlan0");
    assert(interfaces[8].acl_programmed && logged("keeps the repurposed private role"));

    /* Leave: back to the hotspot bridge and BSS profile, with its steering list. */
    memset(logbuf, 0, sizeof(logbuf));
    vap = hotspot_vap(true);
    assert(create(&vap, NULL) == RETURN_OK);
    assert_running(8, "brlan4");
    assert(interfaces[8].acl_programmed && profile_calls == 3 && profile_role == 0);
    assert(steering_calls[8] == 1 && logged("leaves the repurposed private role"));
    assert(!wifi_hal_is_repurposed_private_2g(&interfaces[8].vap_info));

    /* First create at boot: nothing runs yet. */
    reset();
    interfaces[8].vap_initialized = interfaces[8].bss_started = false;
    interfaces[8].u.ap.hapd.started = 0;
    interfaces[8].ap_started = interfaces[8].netdev_up = false;
    interfaces[8].bridge[0] = '\0';
    vap = role_vap(true);
    assert(create(&vap, NULL) == RETURN_OK);
    assert_running(8, "brlan0");
    assert(interfaces[8].vap_initialized && interfaces[8].acl_programmed);

    /* The role with the private 2.4 GHz VAP disabled: stopped, out of any bridge, no ACL. */
    reset();
    vap = role_vap(false);
    assert(create(&vap, NULL) == RETURN_OK);
    assert(!interfaces[8].bss_started && !interfaces[8].ap_started && !interfaces[8].netdev_up);
    assert(interfaces[8].bridge[0] == '\0' && !interfaces[8].u.ap.hapd.started);
    assert(profile_role == 1);
#ifdef NL80211_ACL
    /* the vendor ACL (no NL80211_ACL) is set whatever the BSS state */
    assert(!interfaces[8].acl_programmed);
#endif

    /* A BSS whose AP already stopped underneath (STOP_AP: -ENOENT) still changes role. */
    reset();
    interfaces[8].ap_started = false;
    vap = role_vap(true);
    assert(create(&vap, NULL) == RETURN_OK);
    assert_running(8, "brlan0");

    /* A failed start fails closed and frees the hostapd BSS, so the next attempt can start it. */
    reset();
    fail_start_bss = 1;
    vap = role_vap(true);
    assert(create(&vap, NULL) == RETURN_ERR);
    assert_stopped(8);
    assert(logged("role change failed (start the BSS)"));
    fail_start_bss = 0;
    assert(create(&vap, NULL) == RETURN_OK);
    assert_running(8, "brlan0");
    /* and the hotspot can come back after a failed role change */
    reset();
    fail_start_bss = 1;
    vap = role_vap(true);
    assert(create(&vap, NULL) == RETURN_ERR);
    fail_start_bss = 0;
    vap = hotspot_vap(true);
    assert(create(&vap, NULL) == RETURN_OK);
    assert_running(8, "brlan4");

#ifdef NL80211_ACL
    /* The driver refuses the ACL of the role: fail closed, never beacon without it. */
    reset();
    fail_acl_driver = 1;
    vap = role_vap(true);
    assert(create(&vap, NULL) == RETURN_ERR);
    assert_stopped(8);
    assert(logged("role change failed (set the ACL)"));
#endif

    /* hostapd parameters rejected: fail closed before anything starts. */
    reset();
    fail_update_params = 1;
    vap = role_vap(true);
    assert(create(&vap, NULL) == RETURN_ERR);
    assert_stopped(8);
    assert(logged("role change failed (update the hostapd parameters)"));

    /* The management frame power is not part of the role: its failure is logged only, as for
     * the private VAP. */
    reset();
    fail_mgmt_power = 1;
    vap = role_vap(true);
    assert(create(&vap, NULL) == RETURN_OK);
    assert_running(8, "brlan0");

    /* The platform hook fails for a role request: the target fails closed. */
    reset();
    fail_platform_create = 1;
    vap = role_vap(true);
    assert(create(&vap, NULL) == RETURN_ERR);
    assert_stopped(8);
    assert(logged("role change failed (platform create)"));

    /* A failure of another VAP of the map does not fail the target, and the platform hook
     * still runs for the radio; the result is the one of the common path. */
    reset();
    fail_reload_vap = 1;
    private_vap = interfaces[0].vap_info;
    vap = role_vap(false);
    assert(create(&private_vap, &vap) == RETURN_ERR);
    assert(reload_vap_calls == 1 && platform_create_calls == 1);
    assert(!logged("role change failed") && profile_role == 1);
    assert(wifi_hal_is_repurposed_private_2g(&interfaces[8].vap_info));

    /* Invalid role requests change nothing. */
    reset();
    vap = role_vap(true);
    vap.u.bss_info.bssTransitionActivated = true;
    assert(create(&vap, NULL) == WIFI_HAL_INVALID_ARGUMENTS);
    vap = role_vap(true);
    vap.u.bss_info.bssHotspot = true;
    assert(create(&vap, NULL) == WIFI_HAL_INVALID_ARGUMENTS);
    vap = role_vap(true);
    vap.u.bss_info.mld_info.common_info.mld_enable = true;
    assert(create(&vap, NULL) == WIFI_HAL_INVALID_ARGUMENTS);
    vap = role_vap(true);
    vap.bridge_name[0] = '\0';
    assert(create(&vap, NULL) == WIFI_HAL_INVALID_ARGUMENTS);
    private_vap = interfaces[0].vap_info;
    snprintf(private_vap.repurposed_vap_name, sizeof(private_vap.repurposed_vap_name), "%s",
        WIFI_REPURPOSED_PRIVATE_2G_NAME);
    assert(create(&private_vap, NULL) == WIFI_HAL_INVALID_ARGUMENTS);
    assert_running(8, "brlan4");
    assert_running(0, "brlan0");
    assert(profile_calls == 0 && platform_create_calls == 0);
    assert(logged("invalid repurposed private VAP request"));

    /* The WPS of the private VAP is part of the role. */
    reset();
    vap = role_vap(true);
    vap.u.bss_info.wps.enable = true;
    vap.u.bss_info.wps.methods = WIFI_ONBOARDINGMETHODS_PUSHBUTTON;
    assert(create(&vap, NULL) == RETURN_OK);
    assert_running(8, "brlan0");
    assert(wifi_hal_is_repurposed_private_2g(&interfaces[8].vap_info));

    /* An ordinary hotspot update takes the common path, as before. */
    reset();
    vap = hotspot_vap(true);
    assert(create(&vap, NULL) == RETURN_OK);
    assert(reload_vap_calls == 1 && profile_calls == 0 && steering_calls[8] == 1);
    assert(!logged(WIFI_REPURPOSED_LOG_TAG));

    puts("repurposed wifi_hal_createVAP tests passed");
    return 0;
}
"""

body = prelude
body += extract("src/wifi_hal_nl80211_utils.c", "reload_interface")
body += extract("src/wifi_hal.c", "wifi_hal_private_2g_apply_failed", "static void")
body += extract("src/wifi_hal.c", "wifi_hal_private_2g_activate", "static int")
body += extract("src/wifi_hal.c", "wifi_hal_createVAP", "INT")
body += tests
variants = [["-DXB10_PORT", "-DNL80211_ACL"], ["-DTCXB8_PORT", "-DNL80211_ACL"], ["-DXB10_PORT"]]
with tempfile.TemporaryDirectory(prefix=".repurposed-create-vap-", dir=repo) as work:
    work = Path(work)
    source, executable = work / "test.c", work / "test"
    source.write_text(body)
    for flags in variants:
        subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-sign-compare",
                        "-Wno-unused-parameter", *flags, "-I" + str(halif), "-I" + str(repo / "src"),
                        str(source), "-o", str(executable)], check=True)
        print(" ".join(flags) + ": ", end="", flush=True)
        subprocess.run([str(executable)], check=True)
