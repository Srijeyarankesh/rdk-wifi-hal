#!/usr/bin/env python3
"""Host tests of the real role predicates and Broadcom runtime preparation.

Compiles against the adjacent halif checkout; hardware calls are fakes. The exact
platform function is extracted so tests exercise production code without linking
the complete vendor HAL/hostap libraries.
"""
import pathlib
import subprocess
import tempfile

repo = pathlib.Path(__file__).resolve().parents[2]
halif = repo.parent / "rdkb-halif-wifi" / "include"
source = (repo / "platform/broadcom/platform.c").read_text()
start = source.index("int platform_prepare_repurposed_private_vap(")
opening = source.index("{", start)
depth = 1
end = opening + 1
while depth:
    depth += (source[end] == "{") - (source[end] == "}")
    end += 1
function = source[start:end]
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
typedef struct { char name[32]; } wifi_interface_info_t;
static int calls, fail_at;
static char keys[8][32];
static int values[8];
static int wl_iovar_set(char *ifname, char *key, void *value, int size)
{
    assert(strcmp(ifname, "wl0.5") == 0);
    assert(size == sizeof(int));
    strcpy(keys[calls], key);
    values[calls] = *(int *)value;
    return ++calls == fail_at ? -1 : 0;
}
static int convert_enum_beaconrate_to_int(wifi_bitrate_t rate)
{
    (void)rate;
    return 6;
}
static int nl_set_beacon_rate(int vap_index, int rate)
{
    assert(vap_index == 8 && rate == 6);
    strcpy(keys[calls], "beacon_rate");
    return ++calls == fail_at ? -1 : 0;
}
"""
tests = r"""
int main(void)
{
    wifi_vap_info_t vap = {0};
    wifi_interface_info_t interface = {"wl0.5"};
    int i;
    vap.vap_mode = wifi_vap_mode_ap;
    vap.vap_index = 8;
    strcpy(vap.vap_name, "hotspot_secure_2g");
    assert(!wifi_hal_is_repurposed_private_2g(NULL));
    assert(!wifi_hal_is_repurposed_private_2g(&vap));
    assert(wifi_hal_is_private_2g_runtime_only(&vap));
    vap.u.bss_info.enabled = true;
    assert(!wifi_hal_is_private_2g_runtime_only(&vap));
    strcpy(vap.repurposed_vap_name, WIFI_REPURPOSED_PRIVATE_2G_NAME);
    assert(wifi_hal_is_repurposed_private_2g(&vap));
    vap.u.bss_info.bssMaxSta = 75;
    vap.u.bss_info.isolation = false;
    vap.u.bss_info.hostap_mgt_frame_ctrl = true;
    assert(platform_prepare_repurposed_private_vap(NULL, &vap) == RETURN_ERR);
    assert(platform_prepare_repurposed_private_vap(&interface, &vap) == RETURN_OK);
    assert(calls == 6);
    assert(strcmp(keys[0], "ap_isolate") == 0 && values[0] == 0);
    assert(strcmp(keys[1], "bss_maxassoc") == 0 && values[1] == 75);
    assert(strcmp(keys[2], "usr_beacon") == 0 && values[2] == 1);
    assert(strcmp(keys[3], "usr_probresp") == 0 && values[3] == 1);
    assert(strcmp(keys[4], "usr_auth") == 0 && values[4] == 1);
    /* Every driver failure must stop preparation and reach the caller. */
    for (i = 1; i <= 6; i++) {
        calls = 0;
        fail_at = i;
        assert(platform_prepare_repurposed_private_vap(&interface, &vap) == RETURN_ERR);
        assert(calls == i);
    }
    fail_at = 0;
    calls = 0;
    vap.u.bss_info.enabled = false;
    vap.repurposed_vap_name[0] = '\0';
    assert(wifi_hal_is_private_2g_runtime_only(&vap));
    assert(platform_prepare_repurposed_private_vap(&interface, &vap) == RETURN_OK);
    assert(calls == 0);
    strcpy(vap.repurposed_vap_name, "private_ssid_2g_compat_extra");
    assert(!wifi_hal_is_repurposed_private_2g(&vap));
    strcpy(vap.repurposed_vap_name, WIFI_REPURPOSED_PRIVATE_2G_NAME);
    strcpy(vap.vap_name, "hotspot_secure_5g");
    assert(!wifi_hal_is_repurposed_private_2g(&vap));
    assert(!wifi_hal_is_private_2g_runtime_only(&vap));
    assert(platform_prepare_repurposed_private_vap(&interface, &vap) == RETURN_OK);
    assert(calls == 0);
    puts("repurposed VAP runtime tests passed");
    return 0;
}
"""
with tempfile.TemporaryDirectory(prefix=".repurposed-test-", dir=repo) as work:
    work = pathlib.Path(work)
    unit = work / "test.c"
    unit.write_text(prelude + function + tests)
    for target in ("TCXB7_PORT", "TCXB8_PORT", "XB10_PORT"):
        executable = work / target
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-D" + target, "-I" + str(halif), "-I" + str(repo / "src"),
                        str(unit), "-o", str(executable)], check=True)
        subprocess.run([str(executable)], check=True)

# Exercise production bridge routing/removal with fake netlink and OVS backends.
netlink = (repo / "src/wifi_hal_nl80211.c").read_text()
def extract(name):
    begin = netlink.index("int " + name + "(")
    brace = netlink.index("{", begin)
    count, finish = 1, brace + 1
    while count:
        count += (netlink[finish] == "{") - (netlink[finish] == "}")
        finish += 1
    return netlink[begin:finish]

bridge_prelude = r"""
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "wifi_hal_repurposed.h"
#define IFNAMSIZ 16
#define OVS_MODULE "ovs"
#define F_OK 0
#define NETLINK_ROUTE 0
#define AF_UNSPEC 0
static void fake_log(const char *format, ...) { (void)format; }
#define wifi_hal_error_print(...) fake_log(__VA_ARGS__)
#define wifi_hal_info_print(...) fake_log(__VA_ARGS__)
#define wifi_hal_dbg_print(...) fake_log(__VA_ARGS__)
#define access fake_access
struct nl_sock { int dummy; };
struct nl_cache { int dummy; };
struct rtnl_link { int master; };
static struct nl_sock sock;
static struct nl_cache cache;
static struct rtnl_link bridge, device;
static wifi_vap_info_t config;
static int ovs_on, ovs_port, ovs_bridge, create_error, add_error, release_error;
static int adds, deletes, attaches, releases;
static int fake_access(const char *path, int mode)
{ (void)path; (void)mode; return ovs_on ? 0 : -1; }
static int ovs_if_get_br(char *name, const char *ifname)
{ (void)ifname; if (!ovs_port) return -1; strcpy(name, "oldbr"); return 0; }
static int ovs_br_del_if(const char *name, const char *ifname)
{ (void)name; (void)ifname; deletes++; ovs_port = 0; return 0; }
static int ovs_br_add_if(const char *name, const char *ifname)
{ (void)name; (void)ifname; adds++; return add_error ? -1 : 0; }
static int ovs_br_exists(const char *name)
{ (void)name; return ovs_bridge ? 0 : -1; }
static int ovs_add_br(const char *name)
{ (void)name; return create_error ? -1 : 0; }
static bool is_wifi_hal_vap_hotspot_from_interfacename(const char *name)
{ (void)name; return true; }
static wifi_vap_info_t *get_wifi_vap_info_from_interfacename(const char *name)
{ (void)name; return &config; }
static bool is_wifi_hal_vap_lnf_psk(unsigned int index)
{ (void)index; return false; }
static struct nl_sock *nl_socket_alloc(void) { return &sock; }
static void nl_socket_free(struct nl_sock *s) { (void)s; }
static int nl_connect(struct nl_sock *s, int protocol)
{ (void)s; (void)protocol; return 0; }
static int rtnl_link_alloc_cache(struct nl_sock *s, int family, struct nl_cache **c)
{ (void)s; (void)family; *c = &cache; return 0; }
static void nl_cache_refill(struct nl_sock *s, struct nl_cache *c) { (void)s; (void)c; }
static void nl_cache_free(struct nl_cache *c) { (void)c; }
static struct rtnl_link *rtnl_link_get_by_name(struct nl_cache *c, const char *name)
{ (void)c; return strcmp(name, "wl0.5") == 0 ? &device : &bridge; }
static int rtnl_link_get_master(struct rtnl_link *d) { return d->master; }
static int rtnl_link_release(struct nl_sock *s, struct rtnl_link *d)
{ (void)s; releases++; d->master = 0; return release_error ? -1 : 0; }
static void rtnl_link_put(struct rtnl_link *d) { (void)d; }
static int rtnl_link_bridge_add(struct nl_sock *s, const char *name)
{ (void)s; (void)name; return 0; }
static int rtnl_link_enslave(struct nl_sock *s, struct rtnl_link *b, struct rtnl_link *d)
{ (void)s; (void)b; (void)d; attaches++; return 0; }
"""
bridge_tests = r"""
static void reset(void)
{
    memset(&config, 0, sizeof(config));
    config.vap_mode = wifi_vap_mode_ap;
    config.u.bss_info.enabled = true;
    strcpy(config.vap_name, "hotspot_secure_2g");
    ovs_on = ovs_bridge = 1;
    ovs_port = create_error = add_error = release_error = 0;
    adds = deletes = attaches = releases = device.master = 0;
}
int main(void)
{
    reset();
    assert(nl80211_create_bridge("wl0.5", "brlan4") == 0);
    assert(attaches == 1 && adds == 0); /* Ordinary hotspot unchanged. */
    reset();
    strcpy(config.repurposed_vap_name, WIFI_REPURPOSED_PRIVATE_2G_NAME);
    assert(nl80211_create_bridge("wl0.5", "brlan0") == 0);
    assert(adds == 1 && attaches == 0);
    reset();
    strcpy(config.repurposed_vap_name, WIFI_REPURPOSED_PRIVATE_2G_NAME);
    ovs_on = 0;
    assert(nl80211_create_bridge("wl0.5", "brlan0") == 0);
    assert(attaches == 1 && adds == 0);
    reset();
    strcpy(config.repurposed_vap_name, WIFI_REPURPOSED_PRIVATE_2G_NAME);
    ovs_bridge = 0; create_error = 1;
    assert(nl80211_create_bridge("wl0.5", "brlan0") != 0);
    assert(adds == 0);
    reset();
    strcpy(config.repurposed_vap_name, WIFI_REPURPOSED_PRIVATE_2G_NAME);
    add_error = 1;
    assert(nl80211_create_bridge("wl0.5", "brlan0") != 0);
    reset();
    ovs_port = 1;
    assert(nl80211_remove_from_bridge("wl0.5") == 0);
    assert(deletes == 1 && releases == 0);
    reset();
    device.master = 42;
    assert(nl80211_remove_from_bridge("wl0.5") == 0);
    assert(releases == 1 && deletes == 0);
    assert(nl80211_remove_from_bridge("wl0.5") == 0);
    assert(releases == 1); /* Repeated removal is idempotent. */
    reset();
    device.master = 42; release_error = 1;
    assert(nl80211_remove_from_bridge("wl0.5") != 0);
    puts("repurposed VAP bridge tests passed");
    return 0;
}
"""
with tempfile.TemporaryDirectory(prefix=".repurposed-bridge-test-", dir=repo) as work:
    work = pathlib.Path(work)
    unit = work / "bridge.c"
    unit.write_text(bridge_prelude + extract("nl80211_remove_from_bridge") +
                    extract("nl80211_create_bridge") + bridge_tests)
    executable = work / "bridge"
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-DTCXB8_PORT",
                    "-I" + str(halif), "-I" + str(repo / "src"), str(unit),
                    "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
