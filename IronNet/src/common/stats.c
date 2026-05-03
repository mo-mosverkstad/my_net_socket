#include "stats.h"
#include "log.h"

iron_stats_t g_stats;

static const char *stat_names[STAT_COUNT] = {
    [STAT_ASSERT_FAILURES]   = "assert_failures",
    [STAT_L2_RX_FRAMES]      = "l2.rx_frames",
    [STAT_L2_TX_FRAMES]      = "l2.tx_frames",
    [STAT_L2_RX_DROPS]       = "l2.rx_drops",
    [STAT_L3_RX_PACKETS]     = "l3.rx_packets",
    [STAT_L3_TX_PACKETS]     = "l3.tx_packets",
    [STAT_L3_FORWARDED]      = "l3.forwarded",
    [STAT_L3_LOCAL_DELIVER]   = "l3.local_deliver",
    [STAT_L3_DROPS_ACL]      = "l3.drops.acl",
    [STAT_L3_DROPS_NO_ROUTE] = "l3.drops.no_route",
    [STAT_L3_DROPS_TTL]      = "l3.drops.ttl",
    [STAT_L3_DROPS_INVALID]  = "l3.drops.invalid",
    [STAT_TCP_CONN_CREATED]  = "tcp.conn_created",
    [STAT_TCP_CONN_CLOSED]   = "tcp.conn_closed",
    [STAT_TCP_HALF_OPEN]     = "tcp.half_open",
    [STAT_TCP_RETRANSMISSIONS] = "tcp.retransmissions",
    [STAT_TCP_INVALID_FLAGS] = "tcp.invalid_flags",
    [STAT_TCP_DROPS_RESOURCE] = "tcp.drops.resource",
    [STAT_UDP_RX]            = "udp.rx",
    [STAT_UDP_TX]            = "udp.tx",
};

const char *iron_stats_name(stat_id_t id) {
    if (id >= STAT_COUNT) return "unknown";
    return stat_names[id];
}

void iron_stats_dump(void) {
    LOG_INF("STATS", "--- IronNet Statistics ---");
    for (int i = 0; i < STAT_COUNT; i++) {
        if (g_stats.counters[i] > 0) {
            LOG_INF("STATS", "  %-30s %lu", stat_names[i], g_stats.counters[i]);
        }
    }
    LOG_INF("STATS", "--- End ---");
}
