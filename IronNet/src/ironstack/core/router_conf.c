#include "router_conf.h"
#include "iface.h"
#include "log.h"
#include "utils.h"
#include "../l3/route.h"
#include "../l3/acl.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MODULE "CONF"
#define MAX_LINE 256

static int parse_mac(const char *str, uint8_t mac[6]) {
    return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6 ? 0 : -1;
}

static int parse_prefix(const char *str, uint32_t *ip, uint8_t *prefix_len) {
    char ip_str[16];
    int plen;
    if (sscanf(str, "%15[^/]/%d", ip_str, &plen) != 2) return -1;
    *ip = iron_str_to_ip(ip_str);
    *prefix_len = (uint8_t)plen;
    return 0;
}

static void handle_interface(char *line) {
    /* interface iron0 mac 02:00:00:00:00:01 ip 10.0.1.1/24 */
    char name[32], mac_str[20], ip_str[20];
    if (sscanf(line, "interface %31s mac %19s ip %19s", name, mac_str, ip_str) != 3) {
        LOG_ERR(MODULE, "Invalid interface line: %s", line);
        return;
    }

    uint8_t mac[6];
    if (parse_mac(mac_str, mac) != 0) {
        LOG_ERR(MODULE, "Invalid MAC: %s", mac_str);
        return;
    }

    uint32_t ip; uint8_t prefix_len;
    if (parse_prefix(ip_str, &ip, &prefix_len) != 0) {
        LOG_ERR(MODULE, "Invalid IP/prefix: %s", ip_str);
        return;
    }

    iface_add(name, mac, ip, prefix_len);
}

static void handle_route(char *line) {
    /* route 10.0.1.0/24 dev iron0 */
    /* route 0.0.0.0/0 via 10.0.1.254 dev iron0 */
    char prefix_str[20], keyword[8], val[32], dev_kw[4], dev_name[32];
    uint32_t net_ip; uint8_t prefix_len;
    uint32_t next_hop = 0;

    /* Try "via" format first */
    if (sscanf(line, "route %19s via %31s dev %31s", prefix_str, val, dev_name) == 3) {
        if (parse_prefix(prefix_str, &net_ip, &prefix_len) != 0) return;
        next_hop = iron_str_to_ip(val);
    } else if (sscanf(line, "route %19s dev %31s", prefix_str, dev_name) == 2) {
        if (parse_prefix(prefix_str, &net_ip, &prefix_len) != 0) return;
        /* Connected route: next_hop = 0 (direct) */
    } else {
        LOG_ERR(MODULE, "Invalid route line: %s", line);
        return;
    }

    /* Find interface index */
    iface_config_t *ifc = iface_find_by_name(dev_name);
    int out_iface = ifc ? ifc->vnic_idx : 0;

    ip_prefix_t prefix = { net_ip, prefix_len };
    route_add(prefix, next_hop, out_iface);
}

static void handle_acl(char *line) {
    /* acl permit tcp any any port 80 */
    /* acl deny tcp any any port 22 */
    char action_str[8], proto_str[8], port_str[8];
    int port = 0;

    if (sscanf(line, "acl %7s %7s any any port %d", action_str, proto_str, &port) != 3) {
        LOG_ERR(MODULE, "Invalid ACL line: %s", line);
        return;
    }

    acl_action_t action = (strcmp(action_str, "permit") == 0) ? ACL_PERMIT : ACL_DENY;
    ip_protocol_t proto = PROTO_ANY;
    if (strcmp(proto_str, "tcp") == 0) proto = PROTO_TCP;
    else if (strcmp(proto_str, "udp") == 0) proto = PROTO_UDP;
    else if (strcmp(proto_str, "icmp") == 0) proto = PROTO_ICMP;

    static uint32_t acl_id = 1;
    acl_match_t m = {0};
    m.protocol = proto;
    m.dst_port = (port_range_t){port, port};
    acl_add_rule(acl_id++, &m, action);
}

int router_conf_load(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        LOG_WRN(MODULE, "Config file not found: %s (using defaults)", filename);
        return 0;
    }

    LOG_INF(MODULE, "Loading config: %s", filename);

    char line[MAX_LINE];
    int line_num = 0;

    while (fgets(line, sizeof(line), f)) {
        line_num++;
        /* Strip newline */
        line[strcspn(line, "\r\n")] = 0;
        /* Skip empty lines and comments */
        if (line[0] == '\0' || line[0] == '#') continue;

        if (strncmp(line, "interface ", 10) == 0) {
            handle_interface(line);
        } else if (strncmp(line, "route ", 6) == 0) {
            handle_route(line);
        } else if (strncmp(line, "acl ", 4) == 0) {
            handle_acl(line);
        } else {
            LOG_WRN(MODULE, "Unknown config line %d: %s", line_num, line);
        }
    }

    fclose(f);
    LOG_INF(MODULE, "Config loaded (%d lines)", line_num);
    return 0;
}
