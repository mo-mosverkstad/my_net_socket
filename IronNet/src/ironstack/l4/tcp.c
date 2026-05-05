#include "tcp.h"
#include "log.h"
#include "stats.h"
#include "utils.h"
#include "../ironapps/app_socket.h"
#include "../l3/ip.h"
#include "../security/defense.h"

#include <string.h>
#include <time.h>

#define MODULE "TCP"

static tcp_conn_t g_tcp_conns[TCP_MAX_CONNECTIONS];
static int g_tcp_conn_count = 0;
static int g_conn_timeout_sec = 30; /* default idle timeout */

void tcp_set_idle_timeout(int seconds) {
    g_conn_timeout_sec = seconds;
}

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

void tcp_flush(void) {
    memset(g_tcp_conns, 0, sizeof(g_tcp_conns));
    g_tcp_conn_count = 0;
    LOG_INF(MODULE, "TCP connections flushed");
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

static int tcp_send_segment(uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            uint32_t seq, uint32_t ack_num, uint8_t flags) {
    uint8_t seg[TCP_HEADER_MIN_LEN];
    memset(seg, 0, TCP_HEADER_MIN_LEN);
    seg[0] = (src_port >> 8) & 0xFF;
    seg[1] = src_port & 0xFF;
    seg[2] = (dst_port >> 8) & 0xFF;
    seg[3] = dst_port & 0xFF;
    uint32_t seq_n = iron_htonl(seq);
    memcpy(seg + 4, &seq_n, 4);
    uint32_t ack_n = iron_htonl(ack_num);
    memcpy(seg + 8, &ack_n, 4);
    seg[12] = (5 << 4); /* data offset = 20 bytes */
    seg[13] = flags;
    seg[14] = 0xFF; seg[15] = 0xFF; /* window = 65535 */
    /* checksum at seg[16..17] = 0 for now, compute below */

    /* Compute TCP checksum with pseudo-header */
    uint32_t sum = 0;
    /* Pseudo-header: src_ip, dst_ip, zero, protocol, tcp_length */
    uint8_t *sip = (uint8_t *)&src_ip;
    uint8_t *dip = (uint8_t *)&dst_ip;
    sum += (sip[0] << 8) | sip[1];
    sum += (sip[2] << 8) | sip[3];
    sum += (dip[0] << 8) | dip[1];
    sum += (dip[2] << 8) | dip[3];
    sum += PROTO_TCP;
    sum += TCP_HEADER_MIN_LEN;
    /* TCP header */
    for (int i = 0; i < TCP_HEADER_MIN_LEN; i += 2) {
        sum += (seg[i] << 8) | seg[i + 1];
    }
    while (sum >> 16) sum = (sum >> 16) + (sum & 0xFFFF);
    uint16_t cksum = ~sum & 0xFFFF;
    seg[16] = (cksum >> 8) & 0xFF;
    seg[17] = cksum & 0xFF;

    return ip_output(src_ip, dst_ip, PROTO_TCP, seg, TCP_HEADER_MIN_LEN);
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
            /* RST validation defense: only accept if seq matches expected */
            if (defense_is_enabled("rst-validation")) {
                if (seq != conn->rcv_nxt) {
                    LOG_DBG(MODULE, "RST validation: rejected (seq=%u, expected=%u)", seq, conn->rcv_nxt);
                    return 0; /* Silently drop forged RST */
                }
            }
            LOG_DBG(MODULE, "RST received, closing connection");
            tcp_free_conn(conn);
            iron_stats_increment(STAT_TCP_CONN_CLOSED);
        }
        return 0;
    }

    /* New connection: SYN without existing state */
    if ((flags & TCP_FLAG_SYN) && !(flags & TCP_FLAG_ACK) && !conn) {
        /* Rate limiting defense */
        if (defense_is_enabled("rate-limit")) {
            if (!rate_limit_check(src_ip)) {
                LOG_DBG(MODULE, "Rate limit: SYN dropped from %08X", src_ip);
                iron_stats_increment(STAT_TCP_DROPS_RESOURCE);
                return -1;
            }
        }

        /* SYN cookies defense: don't allocate state, send cookie in seq */
        if (defense_is_enabled("syn-cookies")) {
            app_listener_t *listener = app_find_listener(PROTO_TCP, dport);
            if (listener) {
                uint32_t cookie = syncookie_generate(src_ip, dst_ip, sport, dport, seq);
                tcp_send_segment(dst_ip, src_ip, dport, sport,
                                 cookie, seq + 1,
                                 TCP_FLAG_SYN | TCP_FLAG_ACK);
                LOG_DBG(MODULE, "SYN cookie sent (port %u -> %u)", sport, dport);
            }
            return 0; /* No state allocated */
        }

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

        /* If an app is listening on this port, send SYN+ACK */
        app_listener_t *listener = app_find_listener(PROTO_TCP, dport);
        if (listener) {
            tcp_send_segment(dst_ip, src_ip, dport, sport,
                             conn->snd_nxt, conn->rcv_nxt,
                             TCP_FLAG_SYN | TCP_FLAG_ACK);
            conn->snd_nxt++;
        }
        return 0;
    }

    /* SYN cookie validation: ACK arrives but no connection exists */
    if ((flags & TCP_FLAG_ACK) && !conn && defense_is_enabled("syn-cookies")) {
        if (syncookie_validate(src_ip, dst_ip, sport, dport, 0, ack)) {
            conn = tcp_alloc_conn();
            if (!conn) return -1;
            conn->src_ip = src_ip;
            conn->dst_ip = dst_ip;
            conn->src_port = sport;
            conn->dst_port = dport;
            conn->state = TCP_ESTABLISHED;
            conn->rcv_nxt = seq;
            conn->snd_nxt = ack;
            conn->last_activity = tcp_now();
            conn->active = true;
            iron_stats_increment(STAT_TCP_CONN_CREATED);
            LOG_DBG(MODULE, "SYN cookie validated, ESTABLISHED (port %u -> %u)", sport, dport);
            app_listener_t *listener = app_find_listener(PROTO_TCP, dport);
            if (listener && listener->on_accept)
                listener->on_accept(0, src_ip, sport);
            return 0;
        }
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

            /* Notify app */
            app_listener_t *listener = app_find_listener(PROTO_TCP, dport);
            if (listener && listener->on_accept) {
                listener->on_accept(0, src_ip, sport);
            }
        }
        break;

    case TCP_ESTABLISHED:
        if (flags & TCP_FLAG_FIN) {
            conn->state = TCP_FIN_WAIT_1;
            conn->rcv_nxt = seq + 1;
            LOG_DBG(MODULE, "FIN received, FIN_WAIT_1");
        } else {
            /* Data transfer: advance rcv_nxt and deliver to app */
            int hdr_len_tcp = tcp_get_header_len(hdr);
            int payload_len_tcp = len - hdr_len_tcp;
            if (payload_len_tcp > 0) {
                conn->rcv_nxt = seq + payload_len_tcp;

                /* Send ACK */
                tcp_send_segment(dst_ip, src_ip, dport, sport,
                                 conn->snd_nxt, conn->rcv_nxt, TCP_FLAG_ACK);

                /* Deliver to app */
                app_listener_t *listener = app_find_listener(PROTO_TCP, dport);
                if (listener && listener->on_data) {
                    listener->on_data(0, src_ip, sport,
                                      data + hdr_len_tcp, payload_len_tcp);
                }
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

        /* Connection idle timeout defense */
        if (defense_is_enabled("conn-timeout") &&
            c->state == TCP_ESTABLISHED &&
            (now - c->last_activity) >= g_conn_timeout_sec) {
            LOG_INF(MODULE, "Idle timeout: closing connection (port %u -> %u)",
                    c->src_port, c->dst_port);
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
