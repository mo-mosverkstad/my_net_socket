#include "route.h"
#include "log.h"
#include "utils.h"

#include <string.h>

#define MODULE "ROUTE"

static route_entry_t g_routes[ROUTE_MAX_ENTRIES];
static int g_route_count = 0;

int route_init(void) {
    memset(g_routes, 0, sizeof(g_routes));
    g_route_count = 0;
    LOG_INF(MODULE, "Routing table initialized");
    return 0;
}

int route_add(ip_prefix_t prefix, uint32_t next_hop, int out_iface) {
    if (g_route_count >= ROUTE_MAX_ENTRIES) {
        LOG_ERR(MODULE, "Routing table full");
        return -1;
    }

    route_entry_t *r = &g_routes[g_route_count];
    r->prefix = prefix;
    r->next_hop = next_hop;
    r->out_iface = out_iface;
    r->active = true;
    r->hit_count = 0;
    g_route_count++;

    char buf[16];
    LOG_INF(MODULE, "Route added: %s/%d via %s iface %d",
            iron_ip_to_str(prefix.addr, buf, sizeof(buf)),
            prefix.prefix_len,
            iron_ip_to_str(next_hop, buf, sizeof(buf)),
            out_iface);
    return 0;
}

int route_delete(ip_prefix_t prefix) {
    for (int i = 0; i < g_route_count; i++) {
        if (g_routes[i].active &&
            g_routes[i].prefix.addr == prefix.addr &&
            g_routes[i].prefix.prefix_len == prefix.prefix_len) {
            g_routes[i].active = false;
            return 0;
        }
    }
    return -1;
}

int route_lookup(uint32_t dst_ip, uint32_t *next_hop, int *out_iface) {
    int best_idx = -1;
    uint8_t best_prefix_len = 0;

    for (int i = 0; i < g_route_count; i++) {
        if (!g_routes[i].active) continue;

        if (iron_ip_matches(dst_ip, g_routes[i].prefix.addr, g_routes[i].prefix.prefix_len)) {
            if (g_routes[i].prefix.prefix_len >= best_prefix_len) {
                best_prefix_len = g_routes[i].prefix.prefix_len;
                best_idx = i;
            }
        }
    }

    if (best_idx < 0) return -1;

    g_routes[best_idx].hit_count++;
    *next_hop = g_routes[best_idx].next_hop;
    *out_iface = g_routes[best_idx].out_iface;
    return 0;
}

void route_dump(void) {
    char dst_buf[16], nh_buf[16];
    LOG_INF(MODULE, "--- Routing Table ---");
    for (int i = 0; i < g_route_count; i++) {
        if (!g_routes[i].active) continue;
        LOG_INF(MODULE, "  %s/%d via %s iface %d (hits: %lu)",
                iron_ip_to_str(g_routes[i].prefix.addr, dst_buf, sizeof(dst_buf)),
                g_routes[i].prefix.prefix_len,
                iron_ip_to_str(g_routes[i].next_hop, nh_buf, sizeof(nh_buf)),
                g_routes[i].out_iface,
                g_routes[i].hit_count);
    }
}
