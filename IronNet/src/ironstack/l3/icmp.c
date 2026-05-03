#include "icmp.h"
#include "ip.h"
#include "log.h"
#include "stats.h"
#include "utils.h"

#include <string.h>

#define MODULE "ICMP"

int icmp_input(uint32_t src_ip, uint32_t dst_ip,
               uint8_t *data, int len, int iface_idx) {
    (void)iface_idx;

    if (len < (int)sizeof(icmp_header_t)) {
        LOG_DBG(MODULE, "ICMP packet too short: %d", len);
        return -1;
    }

    icmp_header_t *hdr = (icmp_header_t *)data;

    if (iron_checksum(data, len) != 0) {
        LOG_DBG(MODULE, "ICMP checksum invalid");
        return -1;
    }

    switch (hdr->type) {
    case ICMP_TYPE_ECHO_REQUEST:
        LOG_DBG(MODULE, "Echo request from %08X, id=%u seq=%u",
                src_ip, iron_ntohs(hdr->id), iron_ntohs(hdr->seq));

        /* Build echo reply: swap src/dst, change type to reply, recompute checksum */
        hdr->type = ICMP_TYPE_ECHO_REPLY;
        hdr->checksum = 0;
        hdr->checksum = iron_checksum(data, len);

        ip_output(dst_ip, src_ip, PROTO_ICMP, data, len);
        break;

    case ICMP_TYPE_ECHO_REPLY:
        LOG_DBG(MODULE, "Echo reply from %08X", src_ip);
        break;

    default:
        LOG_DBG(MODULE, "ICMP type %d not handled", hdr->type);
        break;
    }

    return 0;
}
