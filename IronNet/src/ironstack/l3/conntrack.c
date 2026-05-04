#include "conntrack.h"
#include "log.h"
#include "stats.h"
#include "utils.h"
#include "../l4/tcp.h"

#include <string.h>
#include <time.h>

#define MODULE "CONNTRACK"

static ct_entry_t g_ct_table[CONNTRACK_MAX_ENTRIES];
static int g_ct_count = 0;

static uint64_t ct_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec;
}

int conntrack_init(void) {
    memset(g_ct_table, 0, sizeof(g_ct_table));
    g_ct_count = 0;
    LOG_INF(MODULE, "Connection tracking initialized (max: %d)", CONNTRACK_MAX_ENTRIES);
    return 0;
}

/* Match in original direction */
static ct_entry_t *ct_find_orig(uint32_t src_ip, uint32_t dst_ip,
                                uint8_t protocol, uint16_t src_port, uint16_t dst_port) {
    for (int i = 0; i < CONNTRACK_MAX_ENTRIES; i++) {
        ct_entry_t *e = &g_ct_table[i];
        if (!e->active) continue;
        if (e->src_ip == src_ip && e->dst_ip == dst_ip &&
            e->protocol == protocol &&
            e->src_port == src_port && e->dst_port == dst_port)
            return e;
    }
    return NULL;
}

/* Match in reply direction (swapped src/dst) */
static ct_entry_t *ct_find_reply(uint32_t src_ip, uint32_t dst_ip,
                                 uint8_t protocol, uint16_t src_port, uint16_t dst_port) {
    for (int i = 0; i < CONNTRACK_MAX_ENTRIES; i++) {
        ct_entry_t *e = &g_ct_table[i];
        if (!e->active) continue;
        if (e->dst_ip == src_ip && e->src_ip == dst_ip &&
            e->protocol == protocol &&
            e->dst_port == src_port && e->src_port == dst_port)
            return e;
    }
    return NULL;
}

ct_entry_t *conntrack_lookup(uint32_t src_ip, uint32_t dst_ip,
                             uint8_t protocol, uint16_t src_port, uint16_t dst_port) {
    ct_entry_t *e = ct_find_orig(src_ip, dst_ip, protocol, src_port, dst_port);
    if (e) return e;
    return ct_find_reply(src_ip, dst_ip, protocol, src_port, dst_port);
}

ct_state_t conntrack_get_state(uint32_t src_ip, uint32_t dst_ip,
                               uint8_t protocol, uint16_t src_port, uint16_t dst_port) {
    ct_entry_t *e = conntrack_lookup(src_ip, dst_ip, protocol, src_port, dst_port);
    if (!e) return CT_STATE_INVALID;
    return e->state;
}

static ct_entry_t *ct_alloc(void) {
    /* Find free slot */
    for (int i = 0; i < CONNTRACK_MAX_ENTRIES; i++) {
        if (!g_ct_table[i].active) {
            g_ct_count++;
            return &g_ct_table[i];
        }
    }
    /* Table full — evict oldest */
    ct_entry_t *oldest = &g_ct_table[0];
    for (int i = 1; i < CONNTRACK_MAX_ENTRIES; i++) {
        if (g_ct_table[i].last_seen < oldest->last_seen)
            oldest = &g_ct_table[i];
    }
    return oldest;
}

int conntrack_update(uint32_t src_ip, uint32_t dst_ip,
                     uint8_t protocol, uint16_t src_port, uint16_t dst_port,
                     uint8_t tcp_flags) {
    uint64_t now = ct_now();

    /* Check original direction */
    ct_entry_t *e = ct_find_orig(src_ip, dst_ip, protocol, src_port, dst_port);
    if (e) {
        e->last_seen = now;
        e->packets_orig++;

        /* TCP state transitions in original direction */
        if (protocol == PROTO_TCP) {
            if ((tcp_flags & TCP_FLAG_FIN) || (tcp_flags & TCP_FLAG_RST)) {
                /* Connection closing */
                e->state = CT_STATE_NEW; /* Will timeout quickly */
            }
        }
        return 0;
    }

    /* Check reply direction */
    e = ct_find_reply(src_ip, dst_ip, protocol, src_port, dst_port);
    if (e) {
        e->last_seen = now;
        e->packets_reply++;

        /* Reply seen → connection is ESTABLISHED */
        if (e->state == CT_STATE_NEW) {
            e->state = CT_STATE_ESTABLISHED;
            LOG_DBG(MODULE, "Connection ESTABLISHED: proto=%d %08X:%u -> %08X:%u",
                    protocol, e->src_ip, e->src_port, e->dst_ip, e->dst_port);
        }
        return 0;
    }

    /* New connection */
    e = ct_alloc();
    memset(e, 0, sizeof(*e));
    e->src_ip = src_ip;
    e->dst_ip = dst_ip;
    e->protocol = protocol;
    e->src_port = src_port;
    e->dst_port = dst_port;
    e->state = CT_STATE_NEW;
    e->last_seen = now;
    e->packets_orig = 1;
    e->packets_reply = 0;
    e->active = true;

    LOG_DBG(MODULE, "New connection: proto=%d %08X:%u -> %08X:%u",
            protocol, src_ip, src_port, dst_ip, dst_port);
    return 0;
}

static uint64_t ct_get_timeout(ct_entry_t *e) {
    switch (e->protocol) {
    case PROTO_TCP:
        return (e->state == CT_STATE_ESTABLISHED) ?
               CONNTRACK_TCP_EST_SEC : CONNTRACK_TCP_OTHER_SEC;
    case PROTO_UDP:
        return CONNTRACK_UDP_SEC;
    case PROTO_ICMP:
        return CONNTRACK_ICMP_SEC;
    default:
        return CONNTRACK_UDP_SEC;
    }
}

void conntrack_timer_tick(void) {
    uint64_t now = ct_now();
    for (int i = 0; i < CONNTRACK_MAX_ENTRIES; i++) {
        ct_entry_t *e = &g_ct_table[i];
        if (!e->active) continue;

        uint64_t timeout = ct_get_timeout(e);
        if ((now - e->last_seen) >= timeout) {
            e->active = false;
            g_ct_count--;
            LOG_DBG(MODULE, "Entry expired: proto=%d %08X:%u -> %08X:%u",
                    e->protocol, e->src_ip, e->src_port, e->dst_ip, e->dst_port);
        }
    }
}

int conntrack_get_count(void) {
    return g_ct_count;
}

void conntrack_dump(void) {
    char src_buf[16], dst_buf[16];
    const char *state_names[] = {"NEW", "ESTABLISHED", "RELATED", "INVALID"};
    LOG_INF(MODULE, "--- Connection Tracking (%d entries) ---", g_ct_count);
    for (int i = 0; i < CONNTRACK_MAX_ENTRIES; i++) {
        ct_entry_t *e = &g_ct_table[i];
        if (!e->active) continue;
        LOG_INF(MODULE, "  proto=%d %s:%u -> %s:%u state=%s pkts=%lu/%lu",
                e->protocol,
                iron_ip_to_str(e->src_ip, src_buf, sizeof(src_buf)), e->src_port,
                iron_ip_to_str(e->dst_ip, dst_buf, sizeof(dst_buf)), e->dst_port,
                state_names[e->state], e->packets_orig, e->packets_reply);
    }
}
