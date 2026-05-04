#include "arp.h"
#include "eth.h"
#include "log.h"
#include "stats.h"
#include "utils.h"
#include "../core/iface.h"
#include "../io/vnic.h"

#include <string.h>
#include <time.h>

#define MODULE "ARP"

static arp_entry_t g_arp_table[ARP_TABLE_MAX];
static int g_arp_count = 0;

static uint64_t arp_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec;
}

int arp_init(void) {
    memset(g_arp_table, 0, sizeof(g_arp_table));
    g_arp_count = 0;
    LOG_INF(MODULE, "ARP initialized");
    return 0;
}

void arp_add_entry(uint32_t ip, const uint8_t *mac) {
    /* Update existing entry */
    for (int i = 0; i < g_arp_count; i++) {
        if (g_arp_table[i].valid && g_arp_table[i].ip == ip) {
            memcpy(g_arp_table[i].mac, mac, 6);
            g_arp_table[i].timestamp = arp_now();
            return;
        }
    }

    /* Add new entry */
    if (g_arp_count >= ARP_TABLE_MAX) {
        /* Overwrite oldest */
        int oldest = 0;
        for (int i = 1; i < ARP_TABLE_MAX; i++) {
            if (g_arp_table[i].timestamp < g_arp_table[oldest].timestamp)
                oldest = i;
        }
        g_arp_table[oldest].ip = ip;
        memcpy(g_arp_table[oldest].mac, mac, 6);
        g_arp_table[oldest].timestamp = arp_now();
        g_arp_table[oldest].valid = true;
        return;
    }

    arp_entry_t *e = &g_arp_table[g_arp_count];
    e->ip = ip;
    memcpy(e->mac, mac, 6);
    e->timestamp = arp_now();
    e->valid = true;
    g_arp_count++;

    char ip_buf[16];
    LOG_DBG(MODULE, "Learned %s -> %02X:%02X:%02X:%02X:%02X:%02X",
            iron_ip_to_str(ip, ip_buf, sizeof(ip_buf)),
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int arp_resolve(uint32_t ip, int iface_idx, uint8_t *mac_out) {
    /* Check table */
    for (int i = 0; i < g_arp_count; i++) {
        if (g_arp_table[i].valid && g_arp_table[i].ip == ip) {
            memcpy(mac_out, g_arp_table[i].mac, 6);
            return 0;
        }
    }

    /* Not found — send ARP request */
    iface_config_t *ifc = iface_get(iface_idx);
    if (!ifc) return -1;

    uint8_t frame[64];
    uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    arp_packet_t arp;
    arp.hw_type = iron_htons(ARP_HW_ETHERNET);
    arp.proto_type = iron_htons(ARP_PROTO_IPV4);
    arp.hw_len = 6;
    arp.proto_len = 4;
    arp.opcode = iron_htons(ARP_OP_REQUEST);
    memcpy(arp.sender_mac, ifc->mac, 6);
    arp.sender_ip = ifc->ip;
    memset(arp.target_mac, 0, 6);
    arp.target_ip = ip;

    int frame_len = eth_build(bcast, ifc->mac, ETHERTYPE_ARP,
                              (uint8_t *)&arp, sizeof(arp), frame, sizeof(frame));
    if (frame_len > 0) {
        vnic_write(ifc->vnic_idx, frame, frame_len);
        LOG_DBG(MODULE, "ARP request sent for %08X on %s", ip, ifc->name);
    }

    return -1; /* Not resolved yet */
}

int arp_input(uint8_t *data, int len, int iface_idx) {
    if (len < (int)sizeof(arp_packet_t)) {
        LOG_DBG(MODULE, "ARP packet too short: %d", len);
        return -1;
    }

    arp_packet_t *arp = (arp_packet_t *)data;
    uint16_t opcode = iron_ntohs(arp->opcode);

    /* Learn sender's MAC regardless of opcode */
    arp_add_entry(arp->sender_ip, arp->sender_mac);

    if (opcode == ARP_OP_REQUEST) {
        /* Is the target IP ours? */
        if (!iface_is_local_ip(arp->target_ip)) return 0;

        iface_config_t *ifc = iface_get(iface_idx);
        if (!ifc) return -1;

        /* Send ARP reply */
        arp_packet_t reply;
        reply.hw_type = iron_htons(ARP_HW_ETHERNET);
        reply.proto_type = iron_htons(ARP_PROTO_IPV4);
        reply.hw_len = 6;
        reply.proto_len = 4;
        reply.opcode = iron_htons(ARP_OP_REPLY);
        memcpy(reply.sender_mac, ifc->mac, 6);
        reply.sender_ip = ifc->ip;
        memcpy(reply.target_mac, arp->sender_mac, 6);
        reply.target_ip = arp->sender_ip;

        uint8_t frame[64];
        int frame_len = eth_build(arp->sender_mac, ifc->mac, ETHERTYPE_ARP,
                                  (uint8_t *)&reply, sizeof(reply), frame, sizeof(frame));
        if (frame_len > 0) {
            vnic_write(ifc->vnic_idx, frame, frame_len);
            LOG_DBG(MODULE, "ARP reply sent on %s", ifc->name);
        }
    }

    return 0;
}

void arp_timer_tick(void) {
    uint64_t now = arp_now();
    for (int i = 0; i < g_arp_count; i++) {
        if (g_arp_table[i].valid &&
            (now - g_arp_table[i].timestamp) >= ARP_TIMEOUT_SEC) {
            g_arp_table[i].valid = false;
        }
    }
}

void arp_dump(void) {
    char ip_buf[16];
    LOG_INF(MODULE, "--- ARP Table ---");
    for (int i = 0; i < g_arp_count; i++) {
        if (!g_arp_table[i].valid) continue;
        LOG_INF(MODULE, "  %s -> %02X:%02X:%02X:%02X:%02X:%02X",
                iron_ip_to_str(g_arp_table[i].ip, ip_buf, sizeof(ip_buf)),
                g_arp_table[i].mac[0], g_arp_table[i].mac[1],
                g_arp_table[i].mac[2], g_arp_table[i].mac[3],
                g_arp_table[i].mac[4], g_arp_table[i].mac[5]);
    }
}
