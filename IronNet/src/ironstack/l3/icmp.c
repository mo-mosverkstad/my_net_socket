#include "icmp.h"
#include "ip.h"
#include "route.h"
#include "log.h"
#include "stats.h"
#include "utils.h"
#include "../security/defense.h"
#include "../security/covert_detect.h"
#include "../ironmon/audit.h"

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

        /* Covert channel detection: check ICMP payload entropy + timing */
        if (defense_is_enabled("covert-detect")) {
            covert_detect_icmp(data, len, src_ip, dst_ip);
            covert_detect_timing(src_ip, dst_ip);
        }

        /* Build echo reply: swap src/dst, change type to reply, recompute checksum */
        hdr->type = ICMP_TYPE_ECHO_REPLY;
        hdr->checksum = 0;
        hdr->checksum = iron_checksum(data, len);

        ip_output(dst_ip, src_ip, PROTO_ICMP, data, len);
        break;

    case ICMP_TYPE_ECHO_REPLY:
        LOG_DBG(MODULE, "Echo reply from %08X", src_ip);
        break;

    case ICMP_TYPE_REDIRECT: {
        /* ICMP Redirect: attacker tells us to use a different gateway */
        if (defense_is_enabled("icmp-redirect-disable")) {
            LOG_WRN(MODULE, "ICMP redirect ignored (defense enabled) from %08X", src_ip);
            audit_log_event(AUDIT_ACL_DENY, src_ip, dst_ip, PROTO_ICMP, 0, 0,
                            "ICMP redirect ignored");
            break;
        }
        /* Without defense: extract new gateway from redirect message */
        if (len >= 28) {
            uint32_t new_gw;
            memcpy(&new_gw, data + 4, 4); /* Gateway IP at ICMP offset 4 */
            uint32_t redir_dst;
            memcpy(&redir_dst, data + 8 + 16, 4); /* Dst IP in embedded IP header (offset 16) */
            char gw_buf[16], dst_buf[16];
            LOG_WRN(MODULE, "ICMP redirect: use gateway %s for dest %s",
                    iron_ip_to_str(new_gw, gw_buf, sizeof(gw_buf)),
                    iron_ip_to_str(redir_dst, dst_buf, sizeof(dst_buf)));
            ip_prefix_t pfx = { redir_dst, 32 };
            route_add(pfx, new_gw, 0);
        }
        break;
    }
    }

    return 0;
}
