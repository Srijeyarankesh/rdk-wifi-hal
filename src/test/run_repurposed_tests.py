#!/usr/bin/env python3
"""Host tests of the real role predicates, Broadcom per BSS role profile and bridge routing.

Compiles against the adjacent halif checkout; hardware calls are fakes. The exact
platform functions are extracted so tests exercise production code without linking
the complete vendor HAL/hostap libraries.
"""
import pathlib
import subprocess
import tempfile

repo = pathlib.Path(__file__).resolve().parents[2]
halif = repo.parent / "rdkb-halif-wifi" / "include"
source = (repo / "platform/broadcom/platform.c").read_text()


def extract_from(text, signature):
    begin = text.index(signature)
    brace = text.index("{", begin)
    count, finish = 1, brace + 1
    while count:
        count += (text[finish] == "{") - (text[finish] == "}")
        finish += 1
    return text[begin:finish]


table_start = source.index("typedef struct wl_runtime_params {")
table = source[table_start:source.index("};", source.index("g_wl_runtime_params[] = {")) + 2]
function = (table + "\n" + extract_from(source, "static char *platform_bss_nvram_get(") + "\n" +
            extract_from(source, "static int platform_set_mbo_ap_enable(") + "\n" +
            extract_from(source, "void platform_set_repurposed_bss_profile("))
prelude = r"""
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wifi_hal_repurposed.h"
#define RETURN_OK 0
#define RETURN_ERR -1
#define NVRAM_NAME_SIZE 64
static void log_fake(const char *format, ...) { (void)format; }
#define wifi_hal_info_print(...) log_fake(__VA_ARGS__)
#define wifi_hal_error_print(...) log_fake(__VA_ARGS__)
typedef struct { char name[32]; } wifi_interface_info_t;
/* NVRAM: the boot profile of the platform scripts. No setter exists, so the function under
 * test cannot change NVRAM (it would not link). */
static const char *nvram[16][2];
static int nvram_reads;
static char *nvram_get(const char *name)
{
    int i;
    nvram_reads++;
    for (i = 0; i < 16 && nvram[i][0] != NULL; i++) {
        if (strcmp(nvram[i][0], name) == 0) return (char *)nvram[i][1];
    }
    return NULL;
}
static void set_nvram(int slot, const char *name, const char *value)
{ nvram[slot][0] = name; nvram[slot][1] = value; nvram[slot + 1][0] = NULL; }
/* The XB8/XB10 interface map: wl0.1 private_ssid_2g, wl0.5 hotspot_secure_2g. */
static int name_error;
static int get_interface_name_from_vap_index(unsigned int index, char *name)
{ strcpy(name, index == 0 ? "wl0.1" : index == 8 ? "wl0.5" : "wlX"); return name_error ? RETURN_ERR : RETURN_OK; }
static int private_index = 0;
static int get_private_2g_vap_index(void) { return private_index; }
/* The Broadcom definitions the function uses (wlioctl.h, wlioctl_defs.h, bcmiov.h, bcmtlv.h). */
#define WLC_SET_PROTECTION_CONTROL 179
#define WL_MBO_IOV_VERSION ((1 << 8) | 1)
#define WL_MBO_CMD_AP_ENAB 13
#define WL_MBO_XTLV_AP_ENAB 0xC
#define BCM_XTLV_HDR_SIZE 4
typedef struct { uint16_t version; uint16_t len; uint16_t id; uint16_t data[1]; } bcm_iov_buf_t;
typedef struct { uint16_t id; uint16_t len; uint8_t data[1]; } bcm_xtlv_t;
/* The driver: every setting is logged as the wl command that does the same. */
static char commands[8][96];
static int command_count, command_error, txbf_value, txbf_calls, txbf_error;
static int wl_ioctl(char *ifname, int cmd, void *buf, int len)
{
    assert(strcmp(ifname, "wl0.5") == 0 && cmd == WLC_SET_PROTECTION_CONTROL && len == sizeof(int));
    snprintf(commands[command_count++], sizeof(commands[0]), "wl -i %s protection_control %d",
        ifname, *(int *)buf);
    return command_error ? -1 : 0;
}
static int wl_iovar_set(char *ifname, char *key, void *value, int size)
{
    assert(strcmp(ifname, "wl0.5") == 0);
    if (strcmp(key, "txbf_bfe_cap") == 0) {
        assert(size == sizeof(int));
        txbf_value = *(int *)value;
        txbf_calls++;
        return txbf_error ? -1 : 0;
    }
    if (strcmp(key, "mbo") == 0) {
        /* wl mbo ap_enable: one 32 bit aligned XTLV, as wluc_mbo.c packs it */
        bcm_iov_buf_t *iov = value;
        bcm_xtlv_t *xtlv = (bcm_xtlv_t *)iov->data;
        int32_t enable;
        assert(iov->version == WL_MBO_IOV_VERSION && iov->id == WL_MBO_CMD_AP_ENAB);
        assert(iov->len == BCM_XTLV_HDR_SIZE + sizeof(int32_t));
        assert(size == (int)(sizeof(bcm_iov_buf_t) + iov->len));
        assert(xtlv->id == WL_MBO_XTLV_AP_ENAB && xtlv->len == sizeof(int32_t));
        memcpy(&enable, xtlv->data, sizeof(enable));
        snprintf(commands[command_count++], sizeof(commands[0]), "wl -i %s mbo ap_enable %d",
            ifname, enable);
        return command_error ? -1 : 0;
    }
    assert(size == sizeof(int));
    snprintf(commands[command_count++], sizeof(commands[0]), "wl -i %s %s %d", ifname, key,
        *(int *)value);
    return command_error ? -1 : 0;
}
"""
tests = r"""
/* wlconf names the NVRAM of a BSS after its interface, whatever NVRAM names the HAL build uses. */
#define PRIVATE_NV "wl0.1_"
#define TARGET_NV "wl0.5_"
/* The private 11g/11n protection settings of set_wl_runtime_configs() are per BSS: private
 * values with the role, the driver defaults of a BSS without it; radio wide ones are left.
 * protection_control and gmode_protection_control are the same ioctl. */
static void check_protection(bool role)
{
    assert(command_count == 4);
    assert(strcmp(commands[1], role ? "wl -i wl0.5 nmode_protection_override 0" :
                                      "wl -i wl0.5 nmode_protection_override -1") == 0);
    assert(strcmp(commands[2], role ? "wl -i wl0.5 protection_control 0" :
                                      "wl -i wl0.5 protection_control 2") == 0);
    assert(strcmp(commands[3], commands[2]) == 0);
}
static void reset(void)
{
    nvram[0][0] = NULL;
    command_count = command_error = txbf_value = txbf_calls = txbf_error = nvram_reads = name_error = 0;
    private_index = 0;
    memset(commands, 0, sizeof(commands));
}
int main(void)
{
    wifi_vap_info_t vap = {0};
    wifi_interface_info_t interface = {"wl0.5"};
    vap.vap_mode = wifi_vap_mode_ap;
    vap.vap_index = 8;
    vap.radio_index = 0;
    strcpy(vap.vap_name, "hotspot_secure_2g");

    /* Role predicates: only the role name counts, a disabled hotspot is an ordinary hotspot. */
    assert(!wifi_hal_is_repurposed_private_2g(NULL));
    assert(wifi_hal_is_private_2g_target(&vap));
    assert(!wifi_hal_is_repurposed_private_2g(&vap));
    vap.u.bss_info.enabled = false;
    assert(!wifi_hal_is_repurposed_private_2g(&vap));
    strcpy(vap.repurposed_vap_name, "private_ssid_2g_compat_extra");
    assert(!wifi_hal_is_repurposed_private_2g(&vap));
    strcpy(vap.repurposed_vap_name, WIFI_REPURPOSED_PRIVATE_2G_NAME);
    assert(wifi_hal_is_repurposed_private_2g(&vap));
    assert(wifi_hal_repurposed_private_2g_valid(&vap)); /* disabled: no bridge needed */
    vap.u.bss_info.enabled = true;
    assert(!wifi_hal_repurposed_private_2g_valid(&vap)); /* enabled: needs the bridge */
    strcpy(vap.bridge_name, "brlan0");
    assert(wifi_hal_repurposed_private_2g_valid(&vap));
    vap.u.bss_info.wps.enable = true;
    assert(wifi_hal_repurposed_private_2g_valid(&vap)); /* the WPS of the private VAP */
    vap.u.bss_info.bssTransitionActivated = true;
    assert(!wifi_hal_repurposed_private_2g_valid(&vap)); /* no steering */
    vap.u.bss_info.bssTransitionActivated = false;
    vap.u.bss_info.bssHotspot = true;
    assert(!wifi_hal_repurposed_private_2g_valid(&vap)); /* no hotspot feature */
    vap.u.bss_info.bssHotspot = false;
    vap.u.bss_info.mld_info.common_info.mld_enable = true;
    assert(!wifi_hal_repurposed_private_2g_valid(&vap)); /* no MLO for the repurposed VAP */
    vap.u.bss_info.mld_info.common_info.mld_enable = false;
    vap.u.bss_info.wps.enable = false;

    /* Taking the role on XB10: the private 2.4 GHz boot profile (wl0.1 mbo 0, txbf_bfe_cap 111). */
    reset();
    set_nvram(0, PRIVATE_NV "mbo_enable", "0");
    set_nvram(1, PRIVATE_NV "txbf_bfe_cap", "111");
    set_nvram(2, TARGET_NV "txbf_bfe_cap", "7");
    platform_set_repurposed_bss_profile(&interface, &vap);
    assert(strcmp(commands[0], "wl -i wl0.5 mbo ap_enable 0") == 0);
    assert(txbf_calls == 1 && txbf_value == 111);
    check_protection(true);

    /* The legacy CCSP NVRAM names (wl0 for private 2.4 GHz, wl0.4 for index 8) are not read. */
    reset();
    set_nvram(0, "wl0_mbo_enable", "0");
    set_nvram(1, "wl0_txbf_bfe_cap", "15");
    platform_set_repurposed_bss_profile(&interface, &vap);
    assert(strcmp(commands[0], "wl -i wl0.5 mbo ap_enable 1") == 0 && txbf_value == -1);

    /* Without the interface name: the wlconf defaults. */
    reset();
    set_nvram(0, PRIVATE_NV "mbo_enable", "0");
    name_error = 1;
    platform_set_repurposed_bss_profile(&interface, &vap);
    assert(strcmp(commands[0], "wl -i wl0.5 mbo ap_enable 1") == 0 && txbf_value == -1);

    /* XB8 boot profile (txbf_bfe_cap 15). */
    reset();
    set_nvram(0, PRIVATE_NV "mbo_enable", "0");
    set_nvram(1, PRIVATE_NV "txbf_bfe_cap", "15");
    platform_set_repurposed_bss_profile(&interface, &vap);
    assert(strcmp(commands[0], "wl -i wl0.5 mbo ap_enable 0") == 0 && txbf_value == 15);

    /* No private NVRAM: the wlconf defaults (MBO on, beamformee AUTO); 2 is the CMS default. */
    reset();
    set_nvram(0, PRIVATE_NV "txbf_bfe_cap", "2");
    platform_set_repurposed_bss_profile(&interface, &vap);
    assert(strcmp(commands[0], "wl -i wl0.5 mbo ap_enable 1") == 0 && txbf_value == -1);

    /* Leaving the role: the target gets its own boot profile back (none for the hotspot BSS). */
    vap.repurposed_vap_name[0] = '\0';
    reset();
    set_nvram(0, PRIVATE_NV "mbo_enable", "0");
    set_nvram(1, PRIVATE_NV "txbf_bfe_cap", "111");
    platform_set_repurposed_bss_profile(&interface, &vap);
    assert(strcmp(commands[0], "wl -i wl0.5 mbo ap_enable 1") == 0 && txbf_value == -1);
    check_protection(false);
    reset();
    set_nvram(0, TARGET_NV "mbo_enable", "0");
    set_nvram(1, TARGET_NV "txbf_bfe_cap", "7");
    platform_set_repurposed_bss_profile(&interface, &vap);
    assert(strcmp(commands[0], "wl -i wl0.5 mbo ap_enable 0") == 0 && txbf_value == 7);
    strcpy(vap.repurposed_vap_name, WIFI_REPURPOSED_PRIVATE_2G_NAME);

    /* Driver failures are logged; both settings are still attempted. */
    reset();
    command_error = 1;
    txbf_error = 1;
    platform_set_repurposed_bss_profile(&interface, &vap);
    assert(command_count == 4 && txbf_calls == 1);

    /* Nothing is touched without an interface, a private 2.4 GHz VAP or on other VAPs. */
    reset();
    platform_set_repurposed_bss_profile(NULL, &vap);
    private_index = -1;
    platform_set_repurposed_bss_profile(&interface, &vap);
    private_index = 0;
    strcpy(vap.vap_name, "hotspot_secure_5g");
    platform_set_repurposed_bss_profile(&interface, &vap);
    strcpy(vap.vap_name, "private_ssid_2g");
    platform_set_repurposed_bss_profile(&interface, &vap);
    assert(command_count == 0 && txbf_calls == 0 && nvram_reads == 0);
    puts("repurposed VAP BSS profile tests passed");
    return 0;
}
"""
with tempfile.TemporaryDirectory(prefix=".repurposed-test-", dir=repo) as work:
    work = pathlib.Path(work)
    unit = work / "test.c"
    unit.write_text(prelude + function + tests)
    for target in ("TCXB7_PORT", "TCXB8_PORT", "XB10_PORT", "SCXER10_PORT", "SCXF10_PORT",
                   "XER2_PORT"):
        for naming in ([], ["-DNEWPLATFORM_PORT"]):
            executable = work / (target + "".join(naming))
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-D" + target, *naming, "-I" + str(halif), "-I" + str(repo / "src"),
                            str(unit), "-o", str(executable)], check=True)
            subprocess.run([str(executable)], check=True)

# Exercise production bridge routing/removal with fake netlink and OVS backends.
netlink = (repo / "src/wifi_hal_nl80211.c").read_text()
def extract(name):
    return extract_from(netlink, "int " + name + "(")

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

# Exercise the production MLD bookkeeping of the Broadcom platform: the MLD step of
# platform_create_vap() and the bring-up of platform_vap_enable_update().
mld_begin = source.rindex("\n", 0, source.index("/* The repurposed VAP is never an MLD link")) + 1
mld_step = source[mld_begin:source.index("#endif /* MLO_ENAB */", mld_begin)]
mld_prelude = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "wifi_hal_repurposed.h"
#define RETURN_OK 0
#define RETURN_ERR -1
#define MAX_MLO_RADIOS (4)
static void fake_log(const char *format, ...) { (void)format; }
#define wifi_hal_error_print(...) fake_log(__VA_ARGS__)
#define wifi_hal_info_print(...) fake_log(__VA_ARGS__)
typedef struct { wifi_vap_info_t vap_info; bool bss_started; } wifi_interface_info_t;
static int mld_vapidx[MLD_UNIT_COUNT][MAX_MLO_RADIOS];
static int _mld_enable[MLD_UNIT_COUNT] = { 0 };
static int _vap_enable[MAX_VAP] = { 0 };
static int _vap_mld_unit[MAX_VAP];
static wifi_interface_info_t interfaces[MAX_VAP];
static int bss_up[MAX_VAP], mld_up[MLD_UNIT_COUNT];
static wifi_interface_info_t *get_interface_by_vap_index(int vap_index)
{ return interfaces[vap_index].bss_started ? &interfaces[vap_index] : NULL; }
static bool platform_is_vap_enabled(const wifi_vap_info_t *vap_info)
{ return vap_info->u.bss_info.enabled; }
static bool platform_is_radio_enabled(int radio_index) { (void)radio_index; return true; }
static int platform_bss_up(int vap_index, bool up) { bss_up[vap_index] += up; return RETURN_OK; }
static void platform_mld_up(int mld_unit, bool up) { mld_up[mld_unit] += up; }
"""
mld_tests = r"""
static void create_vap_mld_step(wifi_vap_info_map_t *map, unsigned int index)
{
""" + mld_step + r"""
}
/* One VAP per map, as OneWifi creates the repurposed VAP. */
static wifi_vap_info_map_t vap_map(unsigned int vap_index, unsigned int radio_index,
    const char *name, const char *role, bool mld, unsigned int mld_id, unsigned int link_id)
{
    wifi_vap_info_map_t map;
    wifi_vap_info_t *vap = &map.vap_array[0];

    memset(&map, 0, sizeof(map));
    map.num_vaps = 1;
    vap->vap_index = vap_index;
    vap->radio_index = radio_index;
    vap->vap_mode = wifi_vap_mode_ap;
    vap->u.bss_info.enabled = true;
    strcpy(vap->vap_name, name);
    strcpy(vap->repurposed_vap_name, role);
    vap->u.bss_info.mld_info.common_info.mld_enable = mld;
    vap->u.bss_info.mld_info.common_info.mld_id = mld_id;
    vap->u.bss_info.mld_info.common_info.mld_link_id = link_id;
    interfaces[vap_index].vap_info = *vap;
    interfaces[vap_index].bss_started = true;
    return map;
}
static void create(wifi_vap_info_map_t map)
{
    create_vap_mld_step(&map, 0);
    memset(bss_up, 0, sizeof(bss_up));
    memset(mld_up, 0, sizeof(mld_up));
    assert(platform_vap_enable_update(&map, 1, -1, NULL) == RETURN_OK);
}
static void reset(void)
{
    memset(mld_vapidx, 0xff, sizeof(mld_vapidx));
    memset(_vap_mld_unit, 0xff, sizeof(_vap_mld_unit));
    memset(_mld_enable, 0, sizeof(_mld_enable));
    memset(_vap_enable, 0, sizeof(_vap_enable));
    memset(interfaces, 0, sizeof(interfaces));
}
int main(void)
{
    /* hotspot_secure_2g (8) and hotspot_secure_5g (9), links of the hotspot MLD unit 1 */
    reset();
    create(vap_map(9, 1, "hotspot_secure_5g", "", true, 1, 1));
    create(vap_map(8, 0, "hotspot_secure_2g", "", true, 1, 2));
    assert(_vap_mld_unit[8] == 1 && mld_vapidx[1][0] == 8 && mld_vapidx[1][1] == 9);
    assert(bss_up[8] == 0 && mld_up[1] == 1); /* Up as a link of the MLD. */
    /* Repurposed: out of the MLD, up as a BSS of its own; the MLD keeps its other link. */
    create(vap_map(8, 0, "hotspot_secure_2g", WIFI_REPURPOSED_PRIVATE_2G_NAME, false, 255, 255));
    assert(_vap_mld_unit[8] == -1 && mld_vapidx[1][0] == -1 && mld_vapidx[1][1] == 9);
    assert(_vap_mld_unit[9] == 1 && _mld_enable[1]);
    assert(bss_up[8] == 1);
    /* A hotspot again: back in the MLD. */
    create(vap_map(8, 0, "hotspot_secure_2g", "", true, 1, 2));
    assert(_vap_mld_unit[8] == 1 && mld_vapidx[1][0] == 8 && bss_up[8] == 0 && mld_up[1] == 1);
    /* Never an MLD link: the update changes nothing of the other MLDs. */
    reset();
    create(vap_map(0, 0, "private_ssid_2g", "", true, 0, 2));
    create(vap_map(8, 0, "hotspot_secure_2g", WIFI_REPURPOSED_PRIVATE_2G_NAME, false, 255, 255));
    assert(_vap_mld_unit[0] == 0 && mld_vapidx[0][0] == 0 && _vap_mld_unit[8] == -1);
    assert(bss_up[8] == 1 && bss_up[0] == 0 && mld_up[0] == 1);
    puts("repurposed VAP MLD tests passed");
    return 0;
}
"""
with tempfile.TemporaryDirectory(prefix=".repurposed-mld-test-", dir=repo) as work:
    work = pathlib.Path(work)
    unit = work / "mld.c"
    unit.write_text(mld_prelude + extract_from(source, "void platform_mld_update(") + "\n" +
                    extract_from(source, "static void update_mld_enable(") + "\n" +
                    extract_from(source, "static bool vap_maps_contain(") + "\n" +
                    extract_from(source, "static int platform_vap_enable_update(") + mld_tests)
    executable = work / "mld"
    # The bring-up code compares signed and unsigned indices.
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-sign-compare",
                    "-DXB10_PORT", "-I" + str(halif), "-I" + str(repo / "src"), str(unit),
                    "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
