#include "arp.h"
#include "eth.h"
#include "log.h"
#include "stats.h"
#include "utils.h"
#include "../core/iface.h"
#include "../io/vnic.h"
#include "../security/defense.h"
#include "../ironmon/audit.h"

#include <string.h>
#include <time.h>

#define MODULE "ARP"

static arp_entry_t g_arp_table[ARP_TABLE_MAX];
static int g_arp_count = 0;

/* --- ARP Inspection: trusted IP-MAC bindings --- */
#define ARP_TRUST_MAX 32
typedef struct { uint32_t ip; uint8_t mac[6]; bool valid; } arp_trust_t;
static arp_trust_t g_arp_trust[ARP_TRUST_MAX];
static int g_arp_trust_count = 0;

void arp_trust_add(uint32_t ip, const uint8_t *mac) {
    if (g_arp_trust_count >= ARP_TRUST_MAX) return;
    g_arp_trust[g_arp_trust_count].ip = ip;
    memcpy(g_arp_trust[g_arp_trust_count].mac, mac, 6);
    g_arp_trust[g_arp_trust_count].valid = true;
    g_arp_trust_count++;
}

static bool arp_inspect_ok(uint32_t ip, const uint8_t *mac) {
    for (int i = 0; i < g_arp_trust_count; i++) {
        if (g_arp_trust[i].valid && g_arp_trust[i].ip == ip)
            return memcmp(g_arp_trust[i].mac, mac, 6) == 0;
    }
    return true; /* No binding for this IP, allow */
}

static uint64_t arp_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec;
}

int arp_init(void) {
    memset(g_arp_table, 0, sizeof(g_arp_table));
    memset(g_arp_trust, 0, sizeof(g_arp_trust));
    g_arp_count = 0;
    g_arp_trust_count = 0;
    LOG_INF(MODULE, "ARP initialized");
    return 0;
}

void arp_add_entry(uint32_t ip, const uint8_t *mac) {
    /* Update existing entry */
    for (int i = 0; i < g_arp_count; i++) {
        if (g_arp_table[i].valid && g_arp_table[i].ip == ip) {
            /* MITM detection: MAC changed for same IP */
            if (defense_is_enabled("mitm-detect") &&
                memcmp(g_arp_table[i].mac, mac, 6) != 0) {
                char ip_buf[16];
                LOG_WRN(MODULE, "MITM DETECT: MAC flap for %s "
                        "(%02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X)",
                        iron_ip_to_str(ip, ip_buf, sizeof(ip_buf)),
                        g_arp_table[i].mac[0], g_arp_table[i].mac[1],
                        g_arp_table[i].mac[2], g_arp_table[i].mac[3],
                        g_arp_table[i].mac[4], g_arp_table[i].mac[5],
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                audit_log_event(AUDIT_ARP_ANOMALY, ip, 0, 0, 0, 0, "MAC flap - possible MITM");
            }
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

    /* ARP inspection defense */
    if (defense_is_enabled("arp-inspection")) {
        if (!arp_inspect_ok(arp->sender_ip, arp->sender_mac)) {
            char ip_buf[16];
            LOG_WRN(MODULE, "ARP inspection BLOCKED: %s untrusted MAC %02X:%02X:%02X:%02X:%02X:%02X",
                    iron_ip_to_str(arp->sender_ip, ip_buf, sizeof(ip_buf)),
                    arp->sender_mac[0], arp->sender_mac[1], arp->sender_mac[2],
                    arp->sender_mac[3], arp->sender_mac[4], arp->sender_mac[5]);
            audit_log_event(AUDIT_ARP_ANOMALY, arp->sender_ip, 0, 0, 0, 0, "inspection failed");
            return -1;
        }
    }
    /* Learn sender's MAC */
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

void arp_flush(void) {
    memset(g_arp_table, 0, sizeof(g_arp_table));
    g_arp_count = 0;
    LOG_INF(MODULE, "ARP table flushed");
}
