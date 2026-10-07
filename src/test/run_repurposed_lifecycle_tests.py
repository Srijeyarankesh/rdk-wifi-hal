#!/usr/bin/env python3
"""Execute production activation, first-create, MLO and VLAN functions with fakes."""
from pathlib import Path
import subprocess
import tempfile
repo = Path(__file__).resolve().parents[2]
halif = repo.parent / "rdkb-halif-wifi/include"
def extract(path, name, result="int"):
    source = (repo / path).read_text()
    start = source.index(result + " " + name + "(")
    brace = source.index("{", start)
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]
prelude = r"""
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "wifi_hal_repurposed.h"
#define RETURN_OK 0
#define RETURN_ERR -1
#define BUFLEN_256 256
#define TRUE 1
#define FALSE 0
#define NL80211_CMD_NEW_INTERFACE 1
#define NL80211_ATTR_WIPHY 2
#define NL80211_ATTR_IFNAME 3
#define NL80211_ATTR_IFTYPE 4
#define NL80211_ATTR_MAC 5
#define NL80211_IFTYPE_STATION 6
#define NL80211_IFTYPE_AP 7
#define ETH_ALEN 6
static void log_fake(const char *format, ...) { (void)format; }
#define wifi_hal_dbg_print(...) log_fake(__VA_ARGS__)
#define wifi_hal_info_print(...) log_fake(__VA_ARGS__)
#define wifi_hal_error_print(...) log_fake(__VA_ARGS__)
typedef struct { char name[32]; wifi_vap_info_t vap_info; bool in_reconf, bss_started; } wifi_interface_info_t;
typedef struct { int index; bool configured; struct { bool enable; } oper_param; } wifi_radio_info_t;
static wifi_interface_info_t target;
static struct { int nl80211_id; } g_wifi_hal;
static int ups, acl_calls, acl_error, sequence, acl_sequence, up_sequence, driver_reads, driver_sets;
static bool acl_programmed;
static int _vap_enable[32], _vap_mld_unit[32];
static int mld_vapidx[MLD_UNIT_COUNT][MAX_NUM_RADIOS];
static wifi_interface_name_idex_map_t interface_index_map[2] = {
    { .index = 0, .vap_name = "private_ssid_2g", .interface_name = "wl0.1", .vlan_id = 100 },
    { .index = 8, .vap_name = "hotspot_secure_2g", .interface_name = "wl0.5", .vlan_id = 104 }
};
static unsigned int get_sizeof_interfaces_index_map(void) { return 2; }
static wifi_vap_info_t *get_wifi_vap_info_from_interfacename(const char *name)
{ return strcmp(name, "wl0.5") == 0 ? &target.vap_info : NULL; }
static wifi_interface_info_t *get_interface_by_vap_index(unsigned int index)
{ (void)index; return &target; }
static int get_interface_name_from_vap_index(unsigned int index, char *name)
{ (void)index; strcpy(name, "wl0.5"); return 0; }
static void get_ifname(int index, char *name) { (void)index; strcpy(name, "legacy"); }
static int nl80211_interface_enable(const char *name, bool enable)
{
    (void)name;
    if (enable) {
        if (wifi_hal_is_repurposed_private_2g(&target.vap_info)) assert(acl_programmed);
        ups++; up_sequence = ++sequence;
    }
    return 0;
}
static int nl80211_set_acl(wifi_interface_info_t *interface)
{
    (void)interface;
    acl_calls++; acl_sequence = ++sequence;
    acl_programmed = !acl_error;
    return acl_error ? -1 : 0;
}
struct nl_msg { int dummy; };
static struct nl_msg message;
static struct nl_msg *nl80211_drv_cmd_msg(int id, void *interface, int flags, int cmd)
{ (void)id; (void)interface; (void)flags; (void)cmd; return &message; }
static void nlmsg_free(struct nl_msg *msg) { (void)msg; }
static int nla_put_u32(struct nl_msg *msg, int attr, unsigned int value)
{ (void)msg; (void)attr; (void)value; return 0; }
static int nla_put_string(struct nl_msg *msg, int attr, const char *value)
{ (void)msg; (void)attr; (void)value; return 0; }
static int nla_put(struct nl_msg *msg, int attr, int size, const void *value)
{ (void)msg; (void)attr; (void)size; (void)value; return 0; }
static bool is_wifi_hal_vap_mesh_sta(unsigned int index) { (void)index; return false; }
#define interface_info_handler NULL
static int nl80211_send_and_recv(struct nl_msg *msg, void *handler, void *data, void *a, void *b)
{ (void)msg; (void)handler; (void)data; (void)a; (void)b; return 0; }
static int wl_iovar_getint(char *name, char *key, int *value)
{
    (void)key;
    if (wifi_hal_is_private_2g_runtime_only(&target.vap_info)) assert(strcmp(name, "wl0.5") == 0);
    *value = 5; driver_reads++; return 0;
}
static int wl_iovar_getbuf(char *name, char *key, void *input, int len, void *output, int size)
{ (void)name; (void)key; (void)input; (void)len; (void)size; *(int *)output = 0; return 0; }
static int wl_iovar_set(char *name, char *key, void *value, int size)
{ (void)name; (void)key; (void)value; (void)size; driver_sets++; return 0; }
static int fake_system(const char *command) { (void)command; assert(0); return -1; }
#define system fake_system
"""
tests = r"""
static void reset(void)
{
    memset(&target, 0, sizeof(target));
    strcpy(target.name, "wl0.5");
    target.vap_info.vap_mode = wifi_vap_mode_ap;
    target.vap_info.vap_index = 8;
    target.vap_info.u.bss_info.enabled = true;
    strcpy(target.vap_info.vap_name, "hotspot_secure_2g");
    strcpy(target.vap_info.repurposed_vap_name, WIFI_REPURPOSED_PRIVATE_2G_NAME);
    strcpy(target.vap_info.bridge_name, "brlan0");
    ups = acl_calls = acl_error = sequence = driver_reads = driver_sets = 0;
    acl_programmed = false;
    memset(_vap_enable, 0, sizeof(_vap_enable));
    memset(_vap_mld_unit, -1, sizeof(_vap_mld_unit));
    memset(mld_vapidx, -1, sizeof(mld_vapidx));
}
int main(void)
{
    wifi_radio_info_t radio = { .configured = true, .oper_param.enable = true };
    wifi_interface_info_t *created = NULL;
    wifi_vap_info_t request;
    reset();
    target.vap_info.u.bss_info.nbrReportActivated = true;
    target.vap_info.u.bss_info.security.mode = wifi_security_mode_wpa3_compatibility;
    target.vap_info.u.bss_info.security.encr = wifi_encryption_aes_gcmp256;
    assert(wifi_hal_repurposed_private_2g_valid(&target.vap_info));
    target.vap_info.u.bss_info.bssTransitionActivated = true;
    assert(!wifi_hal_repurposed_private_2g_valid(&target.vap_info));
    target.vap_info.u.bss_info.bssTransitionActivated = false;
    request = target.vap_info;
    assert(nl80211_create_interface(&radio, &request, &created) == 0);
    assert(created == &target && ups == 0);
    assert(wifi_hal_private_2g_activate(&target, &radio) == 0);
    assert(acl_calls == 1 && ups == 1 && acl_sequence < up_sequence);
    reset();
    acl_error = 1;
    assert(wifi_hal_private_2g_activate(&target, &radio) != 0);
    assert(ups == 0);
    reset();
    target.vap_info.repurposed_vap_name[0] = '\0';
    target.vap_info.u.bss_info.enabled = false;
    request = target.vap_info;
    assert(nl80211_create_interface(&radio, &request, &created) == 0 && ups == 0);
    assert(wifi_hal_private_2g_activate(&target, &radio) == 0 && ups == 0);
    reset();
    strcpy(target.vap_info.vap_name, "private_ssid_2g");
    target.vap_info.repurposed_vap_name[0] = '\0';
    request = target.vap_info;
    assert(nl80211_create_interface(&radio, &request, &created) == 0 && ups == 1);
    reset();
    _vap_enable[8] = 1;
    target.vap_info.u.bss_info.enabled = false;
    target.bss_started = true;
    assert(platform_bss_up(8, true) == 0);
    assert(_vap_enable[8] == 0 && driver_reads == 0 && driver_sets == 0);
    reset();
    _vap_enable[8] = 1;
    assert(platform_bss_up(8, true) == 0);
    assert(_vap_enable[8] == 0 && driver_reads == 0);
    reset();
    target.bss_started = true;
    assert(platform_bss_up(8, true) == 0 && driver_reads == 1 && driver_sets == 1);
    mld_vapidx[0][0] = 8; _vap_mld_unit[8] = 0;
    platform_mld_update(&target.vap_info);
    assert(mld_vapidx[0][0] == -1 && _vap_mld_unit[8] == -1);
    assert(get_ap_vlan_id("wl0.5") == 100);
    assert(interface_index_map[1].vlan_id == 104);
    target.vap_info.repurposed_vap_name[0] = '\0';
    assert(get_ap_vlan_id("wl0.5") == 104);
    assert(get_ap_vlan_id("wl0.1") == 100);
    puts("repurposed first-create/ACL/stale-enable/MLO/VLAN tests passed");
    return 0;
}
"""
body = prelude + extract("src/wifi_hal_nl80211.c", "nl80211_create_interface")
body += extract("src/wifi_hal.c", "wifi_hal_private_2g_activate")
body += extract("platform/broadcom/platform.c", "platform_bss_up")
body += extract("platform/broadcom/platform.c", "platform_mld_update", "void")
body += extract("src/wifi_hal_nl80211_utils.c", "get_ap_vlan_id") + tests
with tempfile.TemporaryDirectory(prefix=".repurposed-lifecycle-", dir=repo) as work:
    work = Path(work)
    source, executable = work / "test.c", work / "test"
    source.write_text(body)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-sign-compare", "-DTCXB8_PORT",
                    "-DNL80211_ACL", "-I" + str(halif), "-I" + str(repo / "src"),
                    str(source), "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
