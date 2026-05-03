#include "tcp.h"
#include "log.h"
#include "stats.h"
#include "utils.h"

#include <string.h>
#include <time.h>

#define MODULE "TCP"

static tcp_conn_t g_tcp_conns[TCP_MAX_CONNECTIONS];
static int g_tcp_conn_count = 0;

int tcp_init(void) {
    memset(g_tcp_conns, 0, sizeof(g_tcp_conns));
    g_tcp_conn_count = 0;
    LOG_INF(MODULE, "TCP initialized (max connections: %d)", TCP_MAX_CONNECTIONS);
    return 0;
}

static uint64_t tcp_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec;
}

static tcp_conn_t *tcp_alloc_conn(void) {
    if (g_tcp_conn_count >= TCP_MAX_CONNECTIONS) {
        LOG_WRN(MODULE, "Connection table full (%d)", TCP_MAX_CONNECTIONS);
        iron_stats_increment(STAT_TCP_DROPS_RESOURCE);
        return NULL;
    }
    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        if (!g_tcp_conns[i].active) {
            g_tcp_conn_count++;
            return &g_tcp_conns[i];
        }
    }
    return NULL;
}

static void tcp_free_conn(tcp_conn_t *conn) {
    conn->active = false;
    conn->state = TCP_CLOSED;
    if (g_tcp_conn_count > 0) g_tcp_conn_count--;
}

tcp_conn_t *tcp_find_conn(uint32_t src_ip, uint32_t dst_ip,
                          uint16_t src_port, uint16_t dst_port) {
    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        tcp_conn_t *c = &g_tcp_conns[i];
        if (!c->active) continue;
        if (c->src_ip == src_ip && c->dst_ip == dst_ip &&
            c->src_port == src_port && c->dst_port == dst_port)
            return c;
        /* Also check reverse direction */
        if (c->src_ip == dst_ip && c->dst_ip == src_ip &&
            c->src_port == dst_port && c->dst_port == src_port)
            return c;
    }
    return NULL;
}

int tcp_get_connection_count(void) {
    return g_tcp_conn_count;
}

static bool tcp_is_valid_flags(uint8_t flags) {
    /* Invalid: SYN+FIN or SYN+RST */
    if ((flags & TCP_FLAG_SYN) && (flags & TCP_FLAG_FIN)) return false;
    if ((flags & TCP_FLAG_SYN) && (flags & TCP_FLAG_RST)) return false;
    return true;
}

static const char *tcp_state_name(tcp_state_t state) {
    switch (state) {
    case TCP_CLOSED:      return "CLOSED";
    case TCP_SYN_RECV:    return "SYN_RECV";
    case TCP_ESTABLISHED: return "ESTABLISHED";
    case TCP_FIN_WAIT_1:  return "FIN_WAIT_1";
    case TCP_FIN_WAIT_2:  return "FIN_WAIT_2";
    case TCP_TIME_WAIT:   return "TIME_WAIT";
    default:              return "UNKNOWN";
    }
}

int tcp_input(uint32_t src_ip, uint32_t dst_ip,
              uint8_t *data, int len, int iface_idx) {
    (void)iface_idx;

    if (len < TCP_HEADER_MIN_LEN) {
        LOG_DBG(MODULE, "TCP packet too short: %d", len);
        return -1;
    }

    tcp_header_t *hdr = (tcp_header_t *)data;
    uint16_t sport = iron_ntohs(hdr->src_port);
    uint16_t dport = iron_ntohs(hdr->dst_port);
    uint32_t seq = iron_ntohl(hdr->seq);
    uint32_t ack = iron_ntohl(hdr->ack);
    uint8_t flags = hdr->flags;

    /* Validate flags */
    if (!tcp_is_valid_flags(flags)) {
        LOG_DBG(MODULE, "Invalid TCP flags: 0x%02X", flags);
        iron_stats_increment(STAT_TCP_INVALID_FLAGS);
        return -1;
    }

    /* Find existing connection */
    tcp_conn_t *conn = tcp_find_conn(src_ip, dst_ip, sport, dport);

    /* RST handling */
    if (flags & TCP_FLAG_RST) {
        if (conn) {
            LOG_DBG(MODULE, "RST received, closing connection");
            tcp_free_conn(conn);
            iron_stats_increment(STAT_TCP_CONN_CLOSED);
        }
        return 0;
    }

    /* New connection: SYN without existing state */
    if ((flags & TCP_FLAG_SYN) && !(flags & TCP_FLAG_ACK) && !conn) {
        conn = tcp_alloc_conn();
        if (!conn) return -1; /* Table full */

        conn->src_ip = src_ip;
        conn->dst_ip = dst_ip;
        conn->src_port = sport;
        conn->dst_port = dport;
        conn->state = TCP_SYN_RECV;
        conn->rcv_nxt = seq + 1;
        conn->snd_nxt = 1000; /* Initial sequence number */
        conn->last_activity = tcp_now();
        conn->active = true;

        iron_stats_increment(STAT_TCP_CONN_CREATED);
        iron_stats_increment(STAT_TCP_HALF_OPEN);
        LOG_DBG(MODULE, "New connection: SYN_RECV (port %u -> %u)", sport, dport);
        return 0;
    }

    if (!conn) {
        LOG_DBG(MODULE, "No connection for packet (port %u -> %u)", sport, dport);
        return -1;
    }

    conn->last_activity = tcp_now();

    /* State machine */
    switch (conn->state) {
    case TCP_SYN_RECV:
        if (flags & TCP_FLAG_ACK) {
            conn->state = TCP_ESTABLISHED;
            conn->rcv_nxt = seq;
            iron_stats_decrement(STAT_TCP_HALF_OPEN);
            LOG_DBG(MODULE, "Connection ESTABLISHED (port %u -> %u)", sport, dport);
        }
        break;

    case TCP_ESTABLISHED:
        if (flags & TCP_FLAG_FIN) {
            conn->state = TCP_FIN_WAIT_1;
            conn->rcv_nxt = seq + 1;
            LOG_DBG(MODULE, "FIN received, FIN_WAIT_1");
        } else {
            /* Data transfer: advance rcv_nxt */
            int hdr_len = tcp_get_header_len(hdr);
            int payload_len = len - hdr_len;
            if (payload_len > 0) {
                conn->rcv_nxt = seq + payload_len;
            }
        }
        break;

    case TCP_FIN_WAIT_1:
        if (flags & TCP_FLAG_ACK) {
            conn->state = TCP_FIN_WAIT_2;
            LOG_DBG(MODULE, "ACK received, FIN_WAIT_2");
        }
        break;

    case TCP_FIN_WAIT_2:
        if (flags & TCP_FLAG_FIN) {
            conn->state = TCP_TIME_WAIT;
            conn->last_activity = tcp_now();
            LOG_DBG(MODULE, "FIN received, TIME_WAIT");
        }
        break;

    case TCP_TIME_WAIT:
        /* Ignore packets in TIME_WAIT */
        break;

    case TCP_CLOSED:
        break;
    }

    return 0;
}

void tcp_timer_tick(void) {
    uint64_t now = tcp_now();

    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        tcp_conn_t *c = &g_tcp_conns[i];
        if (!c->active) continue;

        if (c->state == TCP_TIME_WAIT &&
            (now - c->last_activity) >= TCP_TIME_WAIT_TIMEOUT) {
            LOG_DBG(MODULE, "TIME_WAIT expired, closing");
            tcp_free_conn(c);
            iron_stats_increment(STAT_TCP_CONN_CLOSED);
        }
    }
}

void tcp_dump(void) {
    LOG_INF(MODULE, "--- TCP Connections (%d active) ---", g_tcp_conn_count);
    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        tcp_conn_t *c = &g_tcp_conns[i];
        if (!c->active) continue;
        char src_buf[16], dst_buf[16];
        LOG_INF(MODULE, "  %s:%u -> %s:%u  state=%s",
                iron_ip_to_str(c->src_ip, src_buf, sizeof(src_buf)), c->src_port,
                iron_ip_to_str(c->dst_ip, dst_buf, sizeof(dst_buf)), c->dst_port,
                tcp_state_name(c->state));
    }
}
