#include "iface.h"
#include "log.h"
#include "utils.h"
#include "../io/vnic.h"

#include <string.h>

#define MODULE "IFACE"

static iface_config_t g_ifaces[IFACE_MAX];
static int g_iface_count = 0;

int iface_init(void) {
    memset(g_ifaces, 0, sizeof(g_ifaces));
    g_iface_count = 0;
    LOG_INF(MODULE, "Interface manager initialized");
    return 0;
}

int iface_add(const char *name, uint8_t mac[IRON_MAC_LEN],
              uint32_t ip, uint8_t prefix_len) {
    if (g_iface_count >= IFACE_MAX) {
        LOG_ERR(MODULE, "Max interfaces reached");
        return -1;
    }

    iface_config_t *ifc = &g_ifaces[g_iface_count];
    strncpy(ifc->name, name, IRON_MAX_NAME - 1);
    memcpy(ifc->mac, mac, IRON_MAC_LEN);
    ifc->ip = ip;
    ifc->prefix_len = prefix_len;
    ifc->up = true;
    ifc->configured = true;

    /* Create the TAP interface */
    int vnic_idx = vnic_create(name, mac);
    ifc->vnic_idx = vnic_idx;

    char ip_buf[16];
    LOG_INF(MODULE, "Interface %s added: %s/%d (vnic=%d)",
            name, iron_ip_to_str(ip, ip_buf, sizeof(ip_buf)), prefix_len, vnic_idx);

    int idx = g_iface_count;
    g_iface_count++;
    return idx;
}

iface_config_t *iface_get(int idx) {
    if (idx < 0 || idx >= g_iface_count) return NULL;
    return &g_ifaces[idx];
}

iface_config_t *iface_find_by_ip(uint32_t ip) {
    for (int i = 0; i < g_iface_count; i++) {
        if (g_ifaces[i].configured && g_ifaces[i].ip == ip)
            return &g_ifaces[i];
    }
    return NULL;
}

iface_config_t *iface_find_by_name(const char *name) {
    for (int i = 0; i < g_iface_count; i++) {
        if (g_ifaces[i].configured && strcmp(g_ifaces[i].name, name) == 0)
            return &g_ifaces[i];
    }
    return NULL;
}

int iface_get_count(void) {
    return g_iface_count;
}

bool iface_is_local_ip(uint32_t ip) {
    return iface_find_by_ip(ip) != NULL;
}
