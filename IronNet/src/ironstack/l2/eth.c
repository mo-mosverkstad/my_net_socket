#include "eth.h"
#include "arp.h"
#include "log.h"
#include "stats.h"
#include "utils.h"
#include "../l3/ip.h"
#include "../security/defense.h"
#include "../ironmon/audit.h"

#include <string.h>

#define MODULE "L2"

int eth_parse(const uint8_t *raw, int len, int iface_idx, eth_frame_t *frame) {
    if (len < ETH_HEADER_LEN) {
        LOG_DBG(MODULE, "Frame too short: %d bytes", len);
        iron_stats_increment(STAT_L2_RX_DROPS);
        return -1;
    }

    /* VLAN strict mode: reject tagged frames (double-tag / VLAN hop defense) */
    if (defense_is_enabled("vlan-strict")) {
        if (len >= 14 && raw[12] == 0x81 && raw[13] == 0x00) {
            LOG_WRN(MODULE, "VLAN strict: tagged frame dropped (TPID 0x8100)");
            audit_log_event(AUDIT_VLAN_MISMATCH, 0, 0, 0, 0, 0, "tagged frame on access port");
            iron_stats_increment(STAT_L2_RX_DROPS);
            return -1;
        }
    }

    frame->header = (eth_header_t *)raw;
    frame->payload = (uint8_t *)(raw + ETH_HEADER_LEN);
    frame->payload_len = len - ETH_HEADER_LEN;
    frame->iface_idx = iface_idx;

    uint16_t ethertype = iron_ntohs(frame->header->ethertype);

    if (ethertype != ETHERTYPE_IPV4 && ethertype != ETHERTYPE_ARP) {
        LOG_DBG(MODULE, "Unknown ethertype: 0x%04x, dropping", ethertype);
        iron_stats_increment(STAT_L2_RX_DROPS);
        return -1;
    }

    return 0;
}

int eth_build(const uint8_t *dst_mac, const uint8_t *src_mac,
              uint16_t ethertype, const uint8_t *payload, int payload_len,
              uint8_t *out_buf, int out_buf_len) {
    int total = ETH_HEADER_LEN + payload_len;
    if (total > out_buf_len || total > ETH_MAX_FRAME) return -1;

    eth_header_t *hdr = (eth_header_t *)out_buf;
    memcpy(hdr->dst_mac, dst_mac, IRON_MAC_LEN);
    memcpy(hdr->src_mac, src_mac, IRON_MAC_LEN);
    hdr->ethertype = iron_htons(ethertype);

    memcpy(out_buf + ETH_HEADER_LEN, payload, payload_len);
    return total;
}

void eth_dispatch(eth_frame_t *frame) {
    uint16_t ethertype = iron_ntohs(frame->header->ethertype);

    switch (ethertype) {
    case ETHERTYPE_IPV4:
        LOG_DBG(MODULE, "Dispatching IPv4 packet (%d bytes)", frame->payload_len);
        ip_input(frame->payload, frame->payload_len, frame->iface_idx);
        break;
    case ETHERTYPE_ARP:
        LOG_DBG(MODULE, "ARP frame received (%d bytes)", frame->payload_len);
        arp_input(frame->payload, frame->payload_len, frame->iface_idx);
        break;
    default:
        iron_stats_increment(STAT_L2_RX_DROPS);
        break;
    }
}
