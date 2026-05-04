#include "bridge.h"
#include "eth.h"
#include "vlan.h"
#include "log.h"
#include "stats.h"
#include "utils.h"
#include "../io/vnic.h"

#include <string.h>
#include <time.h>

#define MODULE "BRIDGE"

static bridge_t g_bridges[BRIDGE_MAX];
static int g_bridge_count = 0;

static uint64_t bridge_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec;
}

int bridge_init(void) {
    memset(g_bridges, 0, sizeof(g_bridges));
    g_bridge_count = 0;
    LOG_INF(MODULE, "Bridge initialized");
    return 0;
}

int bridge_create(const char *name) {
    if (g_bridge_count >= BRIDGE_MAX) {
        LOG_ERR(MODULE, "Max bridges reached");
        return -1;
    }

    bridge_t *br = &g_bridges[g_bridge_count];
    strncpy(br->name, name, IRON_MAX_NAME - 1);
    br->port_count = 0;
    br->active = true;
    br->frames_forwarded = 0;
    br->frames_flooded = 0;
    br->frames_dropped = 0;

    int idx = g_bridge_count;
    g_bridge_count++;
    LOG_INF(MODULE, "Bridge '%s' created (idx=%d)", name, idx);
    return idx;
}

int bridge_add_port(int bridge_idx, int port_idx) {
    if (bridge_idx < 0 || bridge_idx >= g_bridge_count) return -1;
    bridge_t *br = &g_bridges[bridge_idx];
    if (!br->active) return -1;
    if (br->port_count >= BRIDGE_MAX_PORTS) return -1;

    br->ports[br->port_count] = port_idx;
    br->port_count++;
    LOG_INF(MODULE, "Port %d added to bridge '%s'", port_idx, br->name);
    return 0;
}

static bool port_in_bridge(bridge_t *br, int port_idx) {
    for (int i = 0; i < br->port_count; i++) {
        if (br->ports[i] == port_idx) return true;
    }
    return false;
}

static bridge_t *find_bridge_for_port(int port_idx) {
    for (int i = 0; i < g_bridge_count; i++) {
        if (g_bridges[i].active && port_in_bridge(&g_bridges[i], port_idx))
            return &g_bridges[i];
    }
    return NULL;
}

static bridge_mac_entry_t *mac_lookup(bridge_t *br, const uint8_t *mac, uint16_t vlan_id) {
    for (int i = 0; i < BRIDGE_MAC_TABLE_SIZE; i++) {
        if (br->mac_table[i].valid &&
            br->mac_table[i].vlan_id == vlan_id &&
            memcmp(br->mac_table[i].mac, mac, IRON_MAC_LEN) == 0) {
            return &br->mac_table[i];
        }
    }
    return NULL;
}

static void mac_learn(bridge_t *br, const uint8_t *mac, int port_idx, uint16_t vlan_id) {
    /* Update existing */
    bridge_mac_entry_t *entry = mac_lookup(br, mac, vlan_id);
    if (entry) {
        entry->port_idx = port_idx;
        entry->timestamp = bridge_now();
        return;
    }

    /* Find free slot */
    for (int i = 0; i < BRIDGE_MAC_TABLE_SIZE; i++) {
        if (!br->mac_table[i].valid) {
            entry = &br->mac_table[i];
            break;
        }
    }

    /* Table full — overwrite oldest */
    if (!entry) {
        entry = &br->mac_table[0];
        for (int i = 1; i < BRIDGE_MAC_TABLE_SIZE; i++) {
            if (br->mac_table[i].timestamp < entry->timestamp)
                entry = &br->mac_table[i];
        }
    }

    memcpy(entry->mac, mac, IRON_MAC_LEN);
    entry->port_idx = port_idx;
    entry->vlan_id = vlan_id;
    entry->timestamp = bridge_now();
    entry->valid = true;

    LOG_DBG(MODULE, "Learned %02X:%02X:%02X:%02X:%02X:%02X on port %d vlan %u",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], port_idx, vlan_id);
}

static bool is_broadcast(const uint8_t *mac) {
    return mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF &&
           mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF;
}

static bool is_multicast(const uint8_t *mac) {
    return (mac[0] & 0x01) != 0;
}

static void bridge_send_frame(int port_idx, uint8_t *frame, int frame_len, uint16_t vlan_id) {
    uint8_t out_buf[ETH_MAX_FRAME + VLAN_TAG_LEN];
    int out_len = vlan_egress(frame, frame_len, port_idx, vlan_id, out_buf, sizeof(out_buf));
    if (out_len > 0) {
        vnic_write(port_idx, out_buf, out_len);
    }
}

int bridge_input(uint8_t *frame, int frame_len, int port_idx, uint16_t vlan_id) {
    bridge_t *br = find_bridge_for_port(port_idx);
    if (!br) return -1;

    if (frame_len < ETH_HEADER_LEN) {
        br->frames_dropped++;
        return -1;
    }

    eth_header_t *hdr = (eth_header_t *)frame;

    /* Learn source MAC */
    mac_learn(br, hdr->src_mac, port_idx, vlan_id);

    /* Forwarding decision */
    if (is_broadcast(hdr->dst_mac) || is_multicast(hdr->dst_mac)) {
        /* Flood to all ports in same VLAN except ingress */
        for (int i = 0; i < br->port_count; i++) {
            if (br->ports[i] == port_idx) continue;

            /* Check VLAN membership */
            vlan_port_t *vp = vlan_port_get(br->ports[i]);
            if (vp) {
                if (vp->mode == VLAN_PORT_ACCESS && vp->access_vlan != vlan_id) continue;
                /* Trunk: vlan_egress will check allowed list */
            }

            bridge_send_frame(br->ports[i], frame, frame_len, vlan_id);
        }
        br->frames_flooded++;
        return 0;
    }

    /* Unicast: lookup destination MAC */
    bridge_mac_entry_t *dst_entry = mac_lookup(br, hdr->dst_mac, vlan_id);
    if (dst_entry) {
        /* Known unicast — forward to learned port */
        if (dst_entry->port_idx == port_idx) {
            /* Same port — drop (no need to send back) */
            br->frames_dropped++;
            return 0;
        }
        bridge_send_frame(dst_entry->port_idx, frame, frame_len, vlan_id);
        br->frames_forwarded++;
        return 0;
    }

    /* Unknown unicast — flood */
    for (int i = 0; i < br->port_count; i++) {
        if (br->ports[i] == port_idx) continue;

        vlan_port_t *vp = vlan_port_get(br->ports[i]);
        if (vp) {
            if (vp->mode == VLAN_PORT_ACCESS && vp->access_vlan != vlan_id) continue;
        }

        bridge_send_frame(br->ports[i], frame, frame_len, vlan_id);
    }
    br->frames_flooded++;
    return 0;
}

void bridge_timer_tick(void) {
    uint64_t now = bridge_now();
    for (int b = 0; b < g_bridge_count; b++) {
        bridge_t *br = &g_bridges[b];
        if (!br->active) continue;
        for (int i = 0; i < BRIDGE_MAC_TABLE_SIZE; i++) {
            if (br->mac_table[i].valid &&
                (now - br->mac_table[i].timestamp) >= BRIDGE_MAC_AGING_SEC) {
                br->mac_table[i].valid = false;
            }
        }
    }
}

void bridge_dump(void) {
    for (int b = 0; b < g_bridge_count; b++) {
        bridge_t *br = &g_bridges[b];
        if (!br->active) continue;
        LOG_INF(MODULE, "--- Bridge '%s' (%d ports) ---", br->name, br->port_count);
        LOG_INF(MODULE, "  forwarded=%lu flooded=%lu dropped=%lu",
                br->frames_forwarded, br->frames_flooded, br->frames_dropped);
        LOG_INF(MODULE, "  MAC table:");
        for (int i = 0; i < BRIDGE_MAC_TABLE_SIZE; i++) {
            if (!br->mac_table[i].valid) continue;
            bridge_mac_entry_t *e = &br->mac_table[i];
            LOG_INF(MODULE, "    %02X:%02X:%02X:%02X:%02X:%02X -> port %d vlan %u",
                    e->mac[0], e->mac[1], e->mac[2], e->mac[3], e->mac[4], e->mac[5],
                    e->port_idx, e->vlan_id);
        }
    }
}
