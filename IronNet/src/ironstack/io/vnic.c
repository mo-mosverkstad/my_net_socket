#include "vnic.h"
#include "log.h"
#include "stats.h"

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#define MODULE "VNIC"

static vnic_t g_vnics[VNIC_MAX_INTERFACES];
static int g_vnic_count = 0;

static int tun_alloc(const char *name) {
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        LOG_ERR(MODULE, "Failed to open /dev/net/tun");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        LOG_ERR(MODULE, "ioctl TUNSETIFF failed for %s", name);
        close(fd);
        return -1;
    }

    LOG_INF(MODULE, "Created TAP interface: %s (fd=%d)", ifr.ifr_name, fd);
    return fd;
}

int vnic_init(void) {
    memset(g_vnics, 0, sizeof(g_vnics));
    g_vnic_count = 0;
    LOG_INF(MODULE, "VNIC subsystem initialized");
    return 0;
}

void vnic_shutdown(void) {
    for (int i = 0; i < g_vnic_count; i++) {
        if (g_vnics[i].active && g_vnics[i].fd >= 0) {
            close(g_vnics[i].fd);
            g_vnics[i].active = false;
            LOG_INF(MODULE, "Closed interface: %s", g_vnics[i].name);
        }
    }
    LOG_INF(MODULE, "VNIC subsystem shutdown");
}

int vnic_create(const char *name, uint8_t mac[IRON_MAC_LEN]) {
    if (g_vnic_count >= VNIC_MAX_INTERFACES) {
        LOG_ERR(MODULE, "Max interfaces reached");
        return -1;
    }

    int fd = tun_alloc(name);
    if (fd < 0) return -1;

    vnic_t *v = &g_vnics[g_vnic_count];
    strncpy(v->name, name, IRON_MAX_NAME - 1);
    memcpy(v->mac, mac, IRON_MAC_LEN);
    v->fd = fd;
    v->active = true;
    v->rx_packets = 0;
    v->tx_packets = 0;
    v->rx_drops = 0;

    int idx = g_vnic_count;
    g_vnic_count++;
    LOG_INF(MODULE, "Interface %s registered (idx=%d)", name, idx);
    return idx;
}

int vnic_read(int iface_idx, uint8_t *buf, int buf_len) {
    if (iface_idx < 0 || iface_idx >= g_vnic_count) return -1;
    vnic_t *v = &g_vnics[iface_idx];
    if (!v->active) return -1;

    int n = read(v->fd, buf, buf_len);
    if (n > 0) {
        v->rx_packets++;
        iron_stats_increment(STAT_L2_RX_FRAMES);
    }
    return n;
}

int vnic_write(int iface_idx, const uint8_t *buf, int len) {
    if (iface_idx < 0 || iface_idx >= g_vnic_count) return -1;
    vnic_t *v = &g_vnics[iface_idx];
    if (!v->active) return -1;

    int n = write(v->fd, buf, len);
    if (n > 0) {
        v->tx_packets++;
        iron_stats_increment(STAT_L2_TX_FRAMES);
    }
    return n;
}

int vnic_inject(int iface_idx, const uint8_t *buf, int len) {
    return vnic_write(iface_idx, buf, len);
}

int vnic_get_count(void) {
    return g_vnic_count;
}

vnic_t *vnic_get(int iface_idx) {
    if (iface_idx < 0 || iface_idx >= g_vnic_count) return NULL;
    return &g_vnics[iface_idx];
}
