#include "udp.h"
#include "log.h"
#include "stats.h"
#include "utils.h"
#include "../ironapps/app_socket.h"

#include <string.h>

#define MODULE "UDP"

int udp_input(uint32_t src_ip, uint32_t dst_ip,
              uint8_t *data, int len, int iface_idx) {
    (void)iface_idx;

    if (len < UDP_HEADER_LEN) {
        LOG_DBG(MODULE, "UDP packet too short: %d", len);
        return -1;
    }

    udp_header_t *hdr = (udp_header_t *)data;
    uint16_t sport = iron_ntohs(hdr->src_port);
    uint16_t dport = iron_ntohs(hdr->dst_port);
    int payload_len = iron_ntohs(hdr->length) - UDP_HEADER_LEN;

    if (payload_len < 0 || payload_len > len - UDP_HEADER_LEN) {
        LOG_DBG(MODULE, "UDP invalid length field");
        return -1;
    }

    iron_stats_increment(STAT_UDP_RX);

    char src_buf[16], dst_buf[16];
    LOG_DBG(MODULE, "UDP %s:%u -> %s:%u (%d bytes payload)",
            iron_ip_to_str(src_ip, src_buf, sizeof(src_buf)), sport,
            iron_ip_to_str(dst_ip, dst_buf, sizeof(dst_buf)), dport,
            payload_len);

    /* Dispatch to registered app */
    app_listener_t *listener = app_find_listener(PROTO_UDP, dport);
    if (listener && listener->on_data) {
        listener->on_data(0, src_ip, sport, data + UDP_HEADER_LEN, payload_len);
    }

    return 0;
}
