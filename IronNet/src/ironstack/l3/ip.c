#include "ip.h"
#include "route.h"
#include "acl.h"
#include "pbr.h"
#include "icmp.h"
#include "ip_frag.h"
#include "../l4/udp.h"
#include "../l4/tcp.h"
#include "../core/iface.h"
#include "../l2/arp.h"
#include "log.h"
#include "stats.h"
#include "utils.h"
#include "../io/vnic.h"
#include "../l2/eth.h"

#include <string.h>

#define MODULE "IP"

int ip_input(uint8_t *data, int len, int iface_idx) {
    iron_stats_increment(STAT_L3_RX_PACKETS);

    if (len < IP_HEADER_MIN_LEN) {
        LOG_DBG(MODULE, "Packet too short: %d", len);
        iron_stats_increment(STAT_L3_DROPS_INVALID);
        return -1;
    }

    ip_header_t *hdr = (ip_header_t *)data;

    /* Validate version */
    if (ip_get_version(hdr) != IP_VERSION_4) {
        LOG_DBG(MODULE, "Not IPv4: version=%d", ip_get_version(hdr));
        iron_stats_increment(STAT_L3_DROPS_INVALID);
        return -1;
    }

    /* Validate IHL */
    int hdr_len = ip_get_header_len(hdr);
    if (hdr_len < IP_HEADER_MIN_LEN || hdr_len > len) {
        LOG_DBG(MODULE, "Invalid IHL: hdr_len=%d, pkt_len=%d", hdr_len, len);
        iron_stats_increment(STAT_L3_DROPS_INVALID);
        return -1;
    }

    /* Validate checksum */
    if (iron_checksum(data, hdr_len) != 0) {
        LOG_DBG(MODULE, "IP checksum invalid");
        iron_stats_increment(STAT_L3_DROPS_INVALID);
        return -1;
    }

    /* TTL check */
    if (hdr->ttl == 0) {
        LOG_DBG(MODULE, "TTL expired");
        iron_stats_increment(STAT_L3_DROPS_TTL);
        return -1;
    }

    uint8_t *payload = data + hdr_len;
    int payload_len = iron_ntohs(hdr->total_len) - hdr_len;

    /* Extract ports for ACL (needed for both local and forward paths) */
    uint16_t sport = 0, dport = 0;
    if ((hdr->protocol == PROTO_TCP || hdr->protocol == PROTO_UDP) && payload_len >= 4) {
        sport = (payload[0] << 8) | payload[1];
        dport = (payload[2] << 8) | payload[3];
    }

    /* ACL check (applied to ALL traffic — local and forwarded) */
    acl_action_t acl_result = acl_evaluate(hdr->src_ip, hdr->dst_ip,
                                           hdr->protocol, sport, dport);
    if (acl_result == ACL_DENY) {
        return -1;
    }

    /* Local delivery? */
    if (iface_is_local_ip(hdr->dst_ip)) {
        iron_stats_increment(STAT_L3_LOCAL_DELIVER);

        switch (hdr->protocol) {
        case PROTO_ICMP:
            return icmp_input(hdr->src_ip, hdr->dst_ip, payload, payload_len, iface_idx);
        case PROTO_TCP:
            return tcp_input(hdr->src_ip, hdr->dst_ip, payload, payload_len, iface_idx);
        case PROTO_UDP:
            return udp_input(hdr->src_ip, hdr->dst_ip, payload, payload_len, iface_idx);
        default:
            LOG_DBG(MODULE, "Unknown protocol %d", hdr->protocol);
            break;
        }
        return 0;
    }

    /* Forward: decrement TTL */
    hdr->ttl--;
    if (hdr->ttl == 0) {
        LOG_DBG(MODULE, "TTL expired after decrement");
        iron_stats_increment(STAT_L3_DROPS_TTL);
        return -1;
    }

    /* Recompute checksum after TTL change */
    hdr->checksum = 0;
    hdr->checksum = iron_checksum(data, hdr_len);

    /* Step 1: PBR lookup (highest priority) */
    pkt_context_t ctx;
    pkt_context_init(&ctx);
    ctx.acl_checked = true;

    uint32_t next_hop;
    int out_iface;
    int pbr_rc = pbr_lookup(hdr->src_ip, hdr->dst_ip, hdr->protocol,
                            &ctx, &next_hop, &out_iface);

    if (pbr_rc == -2) {
        /* PBR loop detected */
        iron_stats_increment(STAT_L3_DROPS_NO_ROUTE);
        return -1;
    }

    if (pbr_rc != 0) {
        /* No PBR match, fall through to FIB (static routing) */
        if (route_lookup(hdr->dst_ip, &next_hop, &out_iface) != 0) {
            LOG_DBG(MODULE, "No route to host");
            iron_stats_increment(STAT_L3_DROPS_NO_ROUTE);
            return -1;
        }
    }

    /* Forward via L2 — resolve MAC via ARP */
    vnic_t *out = vnic_get(out_iface);
    if (!out) {
        iron_stats_increment(STAT_L3_DROPS_NO_ROUTE);
        return -1;
    }

    uint8_t dst_mac[6];
    if (arp_resolve(next_hop ? next_hop : hdr->dst_ip, out_iface, dst_mac) != 0) {
        /* ARP not resolved yet — use broadcast as fallback */
        memset(dst_mac, 0xFF, 6);
    }

    uint8_t frame_buf[ETH_MAX_FRAME];
    int total_ip_len = iron_ntohs(hdr->total_len);

    int frame_len = eth_build(dst_mac, out->mac, ETHERTYPE_IPV4,
                              data, total_ip_len, frame_buf, sizeof(frame_buf));
    if (frame_len < 0) return -1;

    vnic_write(out_iface, frame_buf, frame_len);
    iron_stats_increment(STAT_L3_FORWARDED);

    return 0;
}

int ip_output(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol,
              const uint8_t *payload, int payload_len) {
    uint8_t pkt[ETH_MAX_FRAME];
    ip_header_t *hdr = (ip_header_t *)pkt;

    hdr->version_ihl = (IP_VERSION_4 << 4) | 5;
    hdr->tos = 0;
    hdr->total_len = iron_htons(IP_HEADER_MIN_LEN + payload_len);
    hdr->id = 0;
    hdr->flags_frag = 0;
    hdr->ttl = IP_DEFAULT_TTL;
    hdr->protocol = protocol;
    hdr->checksum = 0;
    hdr->src_ip = src_ip;
    hdr->dst_ip = dst_ip;

    memcpy(pkt + IP_HEADER_MIN_LEN, payload, payload_len);

    hdr->checksum = iron_checksum(pkt, IP_HEADER_MIN_LEN);

    /* Route lookup for output */
    uint32_t next_hop;
    int out_iface;
    if (route_lookup(dst_ip, &next_hop, &out_iface) != 0) {
        LOG_DBG(MODULE, "ip_output: no route to dst");
        iron_stats_increment(STAT_L3_DROPS_NO_ROUTE);
        return -1;
    }

    vnic_t *out = vnic_get(out_iface);
    if (!out) return -1;

    uint8_t frame_buf[ETH_MAX_FRAME];
    uint8_t bcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    int ip_total = IP_HEADER_MIN_LEN + payload_len;

    int frame_len = eth_build(bcast_mac, out->mac, ETHERTYPE_IPV4,
                              pkt, ip_total, frame_buf, sizeof(frame_buf));
    if (frame_len < 0) return -1;

    vnic_write(out_iface, frame_buf, frame_len);
    iron_stats_increment(STAT_L3_TX_PACKETS);

    return 0;
}
