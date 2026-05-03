#ifndef IRON_STATS_H
#define IRON_STATS_H

#include <stdint.h>
#include <string.h>

typedef enum {
    /* Global */
    STAT_ASSERT_FAILURES = 0,

    /* L2 */
    STAT_L2_RX_FRAMES,
    STAT_L2_TX_FRAMES,
    STAT_L2_RX_DROPS,

    /* L3 */
    STAT_L3_RX_PACKETS,
    STAT_L3_TX_PACKETS,
    STAT_L3_FORWARDED,
    STAT_L3_LOCAL_DELIVER,
    STAT_L3_DROPS_ACL,
    STAT_L3_DROPS_NO_ROUTE,
    STAT_L3_DROPS_TTL,
    STAT_L3_DROPS_INVALID,

    /* L4 TCP */
    STAT_TCP_CONN_CREATED,
    STAT_TCP_CONN_CLOSED,
    STAT_TCP_HALF_OPEN,
    STAT_TCP_RETRANSMISSIONS,
    STAT_TCP_INVALID_FLAGS,
    STAT_TCP_DROPS_RESOURCE,

    /* L4 UDP */
    STAT_UDP_RX,
    STAT_UDP_TX,

    STAT_COUNT
} stat_id_t;

typedef struct {
    uint64_t counters[STAT_COUNT];
} iron_stats_t;

/* Global stats instance */
extern iron_stats_t g_stats;

static inline void iron_stats_init(void) {
    memset(&g_stats, 0, sizeof(g_stats));
}

static inline void iron_stats_increment(stat_id_t id) {
    g_stats.counters[id]++;
}

static inline void iron_stats_add(stat_id_t id, uint64_t val) {
    g_stats.counters[id] += val;
}

static inline uint64_t iron_stats_get(stat_id_t id) {
    return g_stats.counters[id];
}

static inline void iron_stats_decrement(stat_id_t id) {
    if (g_stats.counters[id] > 0)
        g_stats.counters[id]--;
}

const char *iron_stats_name(stat_id_t id);
void iron_stats_dump(void);

#endif /* IRON_STATS_H */
