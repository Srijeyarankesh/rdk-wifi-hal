#!/usr/bin/env python3
"""Host tests of the WPS of the repurposed private 2.4 GHz VAP, on the real HAL code:
- wifi_hal_wps_init() with wifi_hal_get_wps_vap_type(), wifi_hal_is_wps_enabled(),
  wifi_hal_band_to_wps_band(), wifi_hal_get_vap_interface_type() and get_private_2g_vap_index():
  the hostapd WPS configuration of a BSS (state, UUID, RF bands, methods, AP PIN),
- the Broadcom platform_create_vap() with wps_enum_to_string() and its NVRAM setters: the WPS
  NVRAM of a BSS.
Hostapd and the driver are fakes. uuid_gen_mac_addr() (a SHA-256 of the MAC in hostapd) is
replaced by the MAC itself, so two UUIDs are equal exactly when they come from the same MAC."""
from pathlib import Path
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[2]
halif = repo.parent / "rdkb-halif-wifi/include"


def extract(path, signature):
    text = (repo / path).read_text()
    begin = text.index(signature)
    brace = text.index("{", begin)
    depth, end = 1, brace + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    if text.startswith("wifi_enum_to_str_map_t", begin):
        end = text.index(";", end) + 1
    return text[begin:end] + "\n"


prelude = r"""
#include <assert.h>
#include <linux/version.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wifi_hal_repurposed.h"
#ifndef RETURN_OK
#define RETURN_OK 0
#endif
#ifndef RETURN_ERR
#define RETURN_ERR -1
#endif
#define TRUE 1
#define FALSE 0
#define NUM_VAPS 24
#define NVRAM_NAME_SIZE 64
#define WPS_METHODS_SIZE 512
#define WPS_PIN_SIZE 9
#define WPS_RF_24GHZ 0x01
#define WPS_RF_50GHZ 0x02
#define WPS_STATE_CONFIGURED 2
#if defined(TCXB7_PORT) || defined(TCXB8_PORT) || defined(XB10_PORT)
#define ROLE 1
#else
#define ROLE 0
#endif
typedef uint8_t u8;
typedef wifi_vap_name_t wifi_vap_type_t;
typedef struct wifi_enum_to_str_map {
    int enum_val;
    const char *str_val;
} wifi_enum_to_str_map_t;

static char logbuf[1 << 16];
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

/* hostapd (src/ap/ap_config.h): the fields wifi_hal_wps_init() sets */
struct hostapd_bss_config {
    char iface[17];
    int ignore_broadcast_ssid;
    int wps_state;
    int wps_independent;
    u8 uuid[16];
    char *config_methods;
    char *ap_pin;
    int wps_cred_processing;
    int pbc_in_m1;
    u8 wps_rf_bands;
};
struct hostapd_config { struct { u8 he_bss_color; u8 he_bss_color_disabled; } he_op; };

typedef struct {
    char name[32];
    unsigned int rdk_radio_index;
    mac_address_t mac;
    wifi_vap_info_t vap_info;
    struct { struct { struct hostapd_bss_config conf; } ap; } u;
    char config_methods[WPS_METHODS_SIZE], ap_pin[WPS_PIN_SIZE]; /* init_radius_config() */
} wifi_interface_info_t;
typedef struct {
    unsigned int index;
    struct { wifi_freq_bands_t band; } oper_param;
    struct hostapd_config iconf;
} wifi_radio_info_t;

static struct { int num_radios; } g_wifi_hal;
static wifi_radio_info_t radios[3];
static wifi_interface_info_t interfaces[NUM_VAPS];

/* The interface map of the Broadcom gateways (XB7, XB8, XB10) */
static wifi_interface_name_idex_map_t interface_index_map[] = {
    { .rdk_radio_index = 0, .interface_name = "wl0.1", .index = 0, .vap_name = "private_ssid_2g" },
    { .rdk_radio_index = 1, .interface_name = "wl1.1", .index = 1, .vap_name = "private_ssid_5g" },
    { .rdk_radio_index = 0, .interface_name = "wl0.2", .index = 2, .vap_name = "iot_ssid_2g" },
    { .rdk_radio_index = 0, .interface_name = "wl0.5", .index = 8, .vap_name = "hotspot_secure_2g" },
    { .rdk_radio_index = 1, .interface_name = "wl1.5", .index = 9, .vap_name = "hotspot_secure_5g" },
    { .rdk_radio_index = 2, .interface_name = "wl2.1", .index = 16, .vap_name = "private_ssid_6g" },
};
static unsigned int get_sizeof_interfaces_index_map(void)
{ return sizeof(interface_index_map) / sizeof(interface_index_map[0]); }

static wifi_radio_info_t *get_radio_by_rdk_index(wifi_radio_index_t index)
{ return (int)index < g_wifi_hal.num_radios ? &radios[index] : NULL; }
static wifi_interface_info_t *get_interface_by_vap_index(unsigned int index)
{ return (index < NUM_VAPS && interfaces[index].name[0] != '\0') ? &interfaces[index] : NULL; }
/* wifi_hal_nl80211_utils.c walks the interface hash map of the radio; these radios have one
 * interface per family */
static wifi_interface_info_t *wifi_hal_get_vap_interface_by_type(wifi_radio_info_t *radio,
    wifi_vap_type_t vap_type)
{
    for (unsigned int i = 0; i < NUM_VAPS; i++) {
        if (interfaces[i].name[0] != '\0' && interfaces[i].rdk_radio_index == radio->index &&
            strncmp(interfaces[i].vap_info.vap_name, vap_type,
                strnlen(vap_type, sizeof(wifi_vap_type_t))) == 0) {
            return &interfaces[i];
        }
    }
    return NULL;
}
static int uuid_gen_mac_addr(const u8 *mac, u8 *uuid)
{ memset(uuid, 0xa5, 16); memcpy(uuid, mac, 6); return 0; }
static int is_nil_uuid(const u8 *uuid)
{ for (int i = 0; i < 16; i++) if (uuid[i]) return 0; return 1; }

/* NVRAM and the platform calls of platform_create_vap() */
static struct { char name[NVRAM_NAME_SIZE]; char value[256]; } nvram[256];
static int nvram_count;
static int nvram_set(const char *name, const char *value)
{
    int i;
    for (i = 0; i < nvram_count && strcmp(nvram[i].name, name) != 0; i++) {
    }
    assert(i < 256);
    snprintf(nvram[i].name, sizeof(nvram[i].name), "%s", name);
    snprintf(nvram[i].value, sizeof(nvram[i].value), "%s", value);
    nvram_count += (i == nvram_count);
    return 0;
}
static const char *nvram_value(const char *name)
{
    for (int i = 0; i < nvram_count; i++) {
        if (strcmp(nvram[i].name, name) == 0) return nvram[i].value;
    }
    return NULL;
}
static int get_interface_name_from_vap_index(unsigned int index, char *name)
{ if (get_interface_by_vap_index(index) == NULL) return RETURN_ERR; strcpy(name, interfaces[index].name); return RETURN_OK; }
static int __attribute__((unused)) get_ccspwifiagent_interface_name_from_vap_index(unsigned int index, char *name)
{ return get_interface_name_from_vap_index(index, name); }
static int get_vap_mode_str_from_int_mode(unsigned char mode, char *str) { (void)mode; strcpy(str, "ap"); return 0; }
static int wl_iovar_getint(char *name, char *key, int *value) { (void)name; (void)key; *value = 12; return 0; }
static int convert_enum_beaconrate_to_int(wifi_bitrate_t rate) { (void)rate; return 6; }
static int nl_set_beacon_rate(int vap_index, int rate) { (void)vap_index; (void)rate; return 0; }
static int get_security_mode_str_from_int(wifi_security_modes_t mode, unsigned int index, char *str)
{ (void)mode; (void)index; strcpy(str, "psk2"); return RETURN_OK; }
static int get_security_encryption_mode_str_from_int(wifi_encryption_method_t encr, unsigned int index, char *str)
{ (void)encr; (void)index; strcpy(str, "aes"); return RETURN_OK; }
INT wifi_setApMaxAssociatedDevices(INT index, UINT number) { (void)index; (void)number; return RETURN_OK; }
INT wifi_setApManagementFramePowerControl(INT index, INT dbm) { (void)index; (void)dbm; return RETURN_OK; }
static int get_security_mode_support_radius(int mode) { return mode == wifi_security_mode_wpa2_enterprise; }
static BOOL is_wifi_hal_vap_hotspot_open(UINT index) { (void)index; return false; }
static int getIpStringFromAdrress(char *str, ip_addr_t *ip) { (void)ip; str[0] = '\0'; return 0; }
static int set_ap_bss_color_value(int index, uint32_t color) { (void)index; (void)color; return 0; }
"""

tests = r"""
static void reset(void)
{
    memset(interfaces, 0, sizeof(interfaces));
    memset(radios, 0, sizeof(radios));
    memset(nvram, 0, sizeof(nvram));
    nvram_count = 0;
    logbuf[0] = '\0';
    g_wifi_hal.num_radios = 3;
    radios[0].oper_param.band = WIFI_FREQUENCY_2_4_BAND;
    radios[1].oper_param.band = WIFI_FREQUENCY_5_BAND;
    radios[2].oper_param.band = WIFI_FREQUENCY_6_BAND;
    for (unsigned int r = 0; r < 3; r++) radios[r].index = r;
    for (unsigned int i = 0; i < get_sizeof_interfaces_index_map(); i++) {
        const wifi_interface_name_idex_map_t *m = &interface_index_map[i];
        wifi_interface_info_t *interface = &interfaces[m->index];

        snprintf(interface->name, sizeof(interface->name), "%s", m->interface_name);
        interface->rdk_radio_index = m->rdk_radio_index;
        interface->mac[0] = 0x02;
        interface->mac[4] = (u8)m->rdk_radio_index;
        interface->mac[5] = (u8)(0x10 + m->index);
        interface->vap_info.vap_index = m->index;
        interface->vap_info.radio_index = m->rdk_radio_index;
        interface->vap_info.vap_mode = wifi_vap_mode_ap;
        interface->vap_info.u.bss_info.showSsid = true;
        snprintf(interface->vap_info.vap_name, sizeof(interface->vap_info.vap_name), "%s", m->vap_name);
        snprintf(interface->u.ap.conf.iface, sizeof(interface->u.ap.conf.iface), "%.16s", m->interface_name);
        interface->u.ap.conf.config_methods = interface->config_methods;
        interface->u.ap.conf.ap_pin = interface->ap_pin;
    }
}

static void set_wps(unsigned int index, bool enable, unsigned int methods, const char *pin)
{
    wifi_wps_t *wps = &interfaces[index].vap_info.u.bss_info.wps;

    wps->enable = enable;
    wps->methods = methods;
    snprintf(wps->pin, sizeof(wps->pin), "%s", pin);
}

static void set_role(bool role)
{
    snprintf(interfaces[8].vap_info.repurposed_vap_name, sizeof(interfaces[8].vap_info.repurposed_vap_name),
        "%s", role ? WIFI_REPURPOSED_PRIVATE_2G_NAME : "");
}

/* update_hostap_bss() */
static struct hostapd_bss_config *apply(unsigned int index)
{
    wifi_interface_info_t *interface = &interfaces[index];

    interface->u.ap.conf.ignore_broadcast_ssid = !interface->vap_info.u.bss_info.showSsid;
    wifi_hal_wps_init(get_radio_by_rdk_index(interface->vap_info.radio_index), &interface->vap_info,
        &interface->u.ap.conf);
    return &interface->u.ap.conf;
}

static bool uuid_of(const struct hostapd_bss_config *conf, unsigned int index)
{
    u8 uuid[16];

    uuid_gen_mac_addr(interfaces[index].mac, uuid);
    return memcmp(conf->uuid, uuid, sizeof(uuid)) == 0;
}

static bool same_wps_config(const struct hostapd_bss_config *a, const struct hostapd_bss_config *b)
{
    return a->wps_state == b->wps_state && memcmp(a->uuid, b->uuid, 16) == 0 &&
        a->wps_rf_bands == b->wps_rf_bands && strcmp(a->config_methods, b->config_methods) == 0 &&
        strcmp(a->ap_pin, b->ap_pin) == 0 && a->wps_cred_processing == b->wps_cred_processing &&
        a->pbc_in_m1 == b->pbc_in_m1;
}

#if defined(BROADCOM_PLATFORM)
static void nvram_wps_is(const char *ifname, const char *mode, const char *pin, const char *methods,
    const char *state)
{
    char name[NVRAM_NAME_SIZE];

    snprintf(name, sizeof(name), "%s_wps_mode", ifname);
    assert(nvram_value(name) != NULL && strcmp(nvram_value(name), mode) == 0);
    snprintf(name, sizeof(name), "%s_wps_device_pin", ifname);
    assert(nvram_value(name) != NULL && strcmp(nvram_value(name), pin) == 0);
    snprintf(name, sizeof(name), "%s_wps_method_enabled", ifname);
    assert(nvram_value(name) != NULL && strcmp(nvram_value(name), methods) == 0);
    snprintf(name, sizeof(name), "%s_wps_config_state", ifname);
    assert(nvram_value(name) != NULL && strcmp(nvram_value(name), state) == 0);
}

static int create(unsigned int count, const unsigned int *indexes)
{
    wifi_vap_info_map_t map;

    memset(&map, 0, sizeof(map));
    map.num_vaps = count;
    for (unsigned int i = 0; i < count; i++) map.vap_array[i] = interfaces[indexes[i]].vap_info;
    return platform_create_vap(0, &map);
}
#endif

static const unsigned int METHODS[] = { WIFI_ONBOARDINGMETHODS_PUSHBUTTON, WIFI_ONBOARDINGMETHODS_PIN,
    WIFI_ONBOARDINGMETHODS_PUSHBUTTON | WIFI_ONBOARDINGMETHODS_PIN };

static void test_wps_init(void)
{
    struct hostapd_bss_config *private_2g, *private_5g, *target;
    wifi_vap_type_t type;
    u8 marker[16];

    /* the private family: one WPS device on 2.4 and 5 GHz (no WPS on 6 GHz) */
    for (unsigned int k = 0; k < 3; k++) {
        reset();
        set_wps(0, true, METHODS[k], "12345670");
        set_wps(1, true, METHODS[k], "12345670");
        private_2g = apply(0);
        private_5g = apply(1);
        assert(private_2g->wps_state == WPS_STATE_CONFIGURED && uuid_of(private_2g, 0));
        assert(private_2g->wps_rf_bands == (WPS_RF_24GHZ | WPS_RF_50GHZ));
        assert(memcmp(private_5g->uuid, private_2g->uuid, 16) == 0);
        assert(strcmp(private_2g->ap_pin, "12345670") == 0);

        /* the role with the same WPS: the same WPS device and configuration as wl0.1 */
        set_role(true);
        set_wps(8, true, METHODS[k], "12345670");
        logbuf[0] = '\0';
        target = apply(8);
#if ROLE
        assert(same_wps_config(target, private_2g));
        assert(strstr(logbuf, "wps_state:2") && strstr(logbuf, "wps device of private_ssid_"));
#else
        /* no role on this platform: the BSS of the hotspot family */
        assert(target->wps_state == WPS_STATE_CONFIGURED && uuid_of(target, 8));
#endif
        assert(strstr(logbuf, "12345670") == NULL); /* the PIN is never logged */
    }

    /* the target over hotspot, role, hotspot, role: the UUID follows the role it has */
    reset();
    set_wps(0, true, WIFI_ONBOARDINGMETHODS_PUSHBUTTON, "12345670");
    private_2g = apply(0);
    for (unsigned int cycle = 0; cycle < 2; cycle++) {
        set_role(false);
        set_wps(8, false, 0, "");
        target = apply(8);
        assert(target->wps_state == 0);
        assert(ROLE ? is_nil_uuid(target->uuid) : (cycle == 0 || uuid_of(target, 8)));
        /* a hotspot BSS with WPS (not used today): the WPS device of the hotspot family */
        set_wps(8, true, WIFI_ONBOARDINGMETHODS_PUSHBUTTON, "");
        target = apply(8);
        assert(target->wps_state == WPS_STATE_CONFIGURED && uuid_of(target, 8));
        assert(target->wps_rf_bands == (WPS_RF_24GHZ | WPS_RF_50GHZ));
        set_role(true);
        set_wps(8, true, WIFI_ONBOARDINGMETHODS_PUSHBUTTON, "12345670");
        target = apply(8);
        assert(target->wps_state == WPS_STATE_CONFIGURED);
        assert(ROLE ? uuid_of(target, 0) : uuid_of(target, 8));
        /* the role with WPS off: no WPS, the UUID of no family */
        set_wps(8, false, WIFI_ONBOARDINGMETHODS_PUSHBUTTON, "12345670");
        target = apply(8);
        assert(target->wps_state == 0 && (!ROLE || is_nil_uuid(target->uuid)));
        set_wps(8, true, WIFI_ONBOARDINGMETHODS_PUSHBUTTON, "12345670");
        assert(apply(8)->wps_state == WPS_STATE_CONFIGURED);
    }
    /* the role with a hidden SSID: no WPS */
    interfaces[8].vap_info.u.bss_info.showSsid = false;
    assert(apply(8)->wps_state == 0);
    interfaces[8].vap_info.u.bss_info.showSsid = true;

    /* every other BSS keeps its UUID: never cleared, never derived again */
    memset(marker, 0x3c, sizeof(marker));
    for (unsigned int index = 0; index < 3; index++) {
        memcpy(interfaces[index].u.ap.conf.uuid, marker, sizeof(marker));
        set_wps(index, true, WIFI_ONBOARDINGMETHODS_PUSHBUTTON, "");
        assert(apply(index)->wps_state == WPS_STATE_CONFIGURED);
        assert(memcmp(interfaces[index].u.ap.conf.uuid, marker, sizeof(marker)) == 0);
        set_wps(index, false, 0, "");
        assert(apply(index)->wps_state == 0);
        assert(memcmp(interfaces[index].u.ap.conf.uuid, marker, sizeof(marker)) == 0);
    }

    /* the WPS family of each BSS */
    reset();
    assert(wifi_hal_get_wps_vap_type(&interfaces[0].vap_info, type) == 0 && strcmp(type, "private_ssid_") == 0);
    assert(wifi_hal_get_wps_vap_type(&interfaces[8].vap_info, type) == 0 && strcmp(type, "hotspot_secure_") == 0);
    set_role(true);
    assert(wifi_hal_get_wps_vap_type(&interfaces[8].vap_info, type) == 0 &&
        strcmp(type, ROLE ? "private_ssid_" : "hotspot_secure_") == 0);

#if ROLE
    /* no private 2.4 GHz interface: no WPS device for the role, WPS stays off */
    set_wps(8, true, WIFI_ONBOARDINGMETHODS_PUSHBUTTON, "12345670");
    interfaces[0].name[0] = '\0';
    assert(wifi_hal_get_wps_vap_type(&interfaces[8].vap_info, type) == -1);
    target = apply(8);
    assert(target->wps_state == 0 && is_nil_uuid(target->uuid) && target->wps_rf_bands == 0);
    assert(strstr(logbuf, "no private 2.4 GHz interface"));
    snprintf(interfaces[0].name, sizeof(interfaces[0].name), "%s", "wl0.1");
    /* the private 2.4 GHz VAP is not in the interface map */
    snprintf(interface_index_map[0].vap_name, sizeof(interface_index_map[0].vap_name), "%s", "private_ssid_x");
    assert(wifi_hal_get_wps_vap_type(&interfaces[8].vap_info, type) == -1);
    assert(apply(8)->wps_state == 0);
    snprintf(interface_index_map[0].vap_name, sizeof(interface_index_map[0].vap_name), "%s", "private_ssid_2g");
    assert(apply(8)->wps_state == WPS_STATE_CONFIGURED && uuid_of(&interfaces[8].u.ap.conf, 0));
#endif
}

#if defined(BROADCOM_PLATFORM)
static void test_nvram(void)
{
    const unsigned int both[] = { 0, 8 }, target[] = { 8 };

    /* wl0.1 and the role in one map, WPS on in both configurations */
    reset();
    set_wps(0, true, WIFI_ONBOARDINGMETHODS_PUSHBUTTON | WIFI_ONBOARDINGMETHODS_PIN, "12345670");
    set_wps(8, true, WIFI_ONBOARDINGMETHODS_PUSHBUTTON | WIFI_ONBOARDINGMETHODS_PIN, "12345670");
    set_role(true);
    assert(create(2, both) == RETURN_OK);
    nvram_wps_is("wl0.1", "enabled", "12345670", "push_button,keypad", "2");
#if ROLE
    nvram_wps_is("wl0.5", "disabled", "", "", "0");
#else
    nvram_wps_is("wl0.5", "enabled", "12345670", "push_button,keypad", "2");
#endif
    assert(nvram_value("wl0.5_ssid") == NULL);

    /* the hotspot: written from its configuration, as before */
    for (unsigned int on = 0; on < 2; on++) {
        reset();
        set_wps(8, on, WIFI_ONBOARDINGMETHODS_PUSHBUTTON, "87654321");
        interfaces[8].vap_info.u.bss_info.security.mode = wifi_security_mode_wpa2_enterprise;
        assert(create(1, target) == RETURN_OK);
        nvram_wps_is("wl0.5", on ? "enabled" : "disabled", "87654321", "push_button", on ? "2" : "0");
    }
    /* wl0.1 with a hidden SSID: as before */
    reset();
    set_wps(0, true, WIFI_ONBOARDINGMETHODS_PUSHBUTTON, "12345670");
    interfaces[0].vap_info.u.bss_info.showSsid = false;
    assert(create(1, both) == RETURN_OK);
    nvram_wps_is("wl0.1", "enabled", "12345670", "push_button", "0");
}
#endif

int main(void)
{
    test_wps_init();
#if defined(BROADCOM_PLATFORM)
    test_nvram();
#endif
    puts("repurposed VAP WPS tests passed");
    return 0;
}
"""

hostapd = "src/wifi_hal_hostapd.c"
body = prelude
body += extract("src/wifi_hal_nl80211_utils.c", "int wifi_hal_get_vap_interface_type(")
body += "static " + extract("src/wifi_hal_nl80211_utils.c", "int get_private_2g_vap_index(")
body += extract(hostapd, "static int wifi_hal_band_to_wps_band(")
body += extract(hostapd, "static bool wifi_hal_is_wps_enabled(")
body += extract(hostapd, "static int wifi_hal_get_wps_vap_type(")
body += extract(hostapd, "static void wifi_hal_wps_init(")
body += "static " + extract(hostapd, "wifi_enum_to_str_map_t wps_config_method_table[] = {")
body += "static " + extract(hostapd, "void wps_enum_to_string(")
platform = "".join("static " + extract("platform/broadcom/platform.c", signature) for signature in (
    "void prepare_param_name(", "void set_decimal_nvram_param(", "void set_string_nvram_param(",
    "int platform_create_vap("))
variants = [["-DXB10_PORT", "-DNEWPLATFORM_PORT", "-DBROADCOM_PLATFORM"],
            ["-DTCXB8_PORT", "-DNEWPLATFORM_PORT", "-DBROADCOM_PLATFORM"],
            ["-DTCXB8_PORT", "-DBROADCOM_PLATFORM"], ["-DTCXB7_PORT", "-DBROADCOM_PLATFORM"],
            ["-DCMXB7_PORT"]]
with tempfile.TemporaryDirectory(prefix=".repurposed-wps-", dir=repo) as work:
    work = Path(work)
    for flags in variants:
        source, executable = work / "test.c", work / "test"
        source.write_text(body + (platform if "-DBROADCOM_PLATFORM" in flags else "") + tests)
        # the HAL is built with WIFI_HAL_VERSION_3 and signed/unsigned char mixing allowed
        subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-sign-compare",
                        "-Wno-unused-parameter", "-Wno-unused-function", "-Wno-pointer-sign",
                        "-DWIFI_HAL_VERSION_3", *flags,
                        "-I" + str(halif), "-I" + str(repo / "src"), str(source), "-o",
                        str(executable)], check=True)
        result = subprocess.run([str(executable)], check=True, capture_output=True, text=True)
        print(" ".join(flags) + ": " + result.stdout.strip())
