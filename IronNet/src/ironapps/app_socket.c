#include "app_socket.h"
#include "log.h"
#include "utils.h"
#include "../ironstack/l3/ip.h"
#include "../ironstack/l4/tcp.h"

#include <string.h>

#define MODULE "APP"

static app_listener_t g_listeners[APP_MAX_LISTENERS];
static int g_listener_count = 0;

int app_socket_init(void) {
    memset(g_listeners, 0, sizeof(g_listeners));
    g_listener_count = 0;
    LOG_INF(MODULE, "Application socket API initialized");
    return 0;
}

int app_socket_listen(uint8_t protocol, uint16_t port,
                      app_data_cb_t on_data,
                      app_accept_cb_t on_accept,
                      app_close_cb_t on_close) {
    if (g_listener_count >= APP_MAX_LISTENERS) {
        LOG_ERR(MODULE, "Max listeners reached");
        return -1;
    }

    app_listener_t *l = &g_listeners[g_listener_count];
    l->protocol = protocol;
    l->port = port;
    l->on_data = on_data;
    l->on_accept = on_accept;
    l->on_close = on_close;
    l->active = true;
    g_listener_count++;

    LOG_INF(MODULE, "Listening on %s port %u",
            protocol == PROTO_TCP ? "TCP" : "UDP", port);
    return g_listener_count - 1;
}

app_listener_t *app_find_listener(uint8_t protocol, uint16_t port) {
    for (int i = 0; i < g_listener_count; i++) {
        if (g_listeners[i].active &&
            g_listeners[i].protocol == protocol &&
            g_listeners[i].port == port)
            return &g_listeners[i];
    }
    return NULL;
}

int app_socket_send(uint32_t dst_ip, uint16_t dst_port,
                    uint32_t src_ip, uint16_t src_port,
                    uint8_t protocol,
                    const uint8_t *data, int data_len) {
    if (protocol == PROTO_UDP) {
        /* Build UDP packet and send via ip_output */
        uint8_t udp_pkt[APP_MAX_RECV_BUF + 8];
        if (data_len + 8 > (int)sizeof(udp_pkt)) return -1;

        /* UDP header */
        udp_pkt[0] = (src_port >> 8) & 0xFF;
        udp_pkt[1] = src_port & 0xFF;
        udp_pkt[2] = (dst_port >> 8) & 0xFF;
        udp_pkt[3] = dst_port & 0xFF;
        uint16_t udp_len = 8 + data_len;
        udp_pkt[4] = (udp_len >> 8) & 0xFF;
        udp_pkt[5] = udp_len & 0xFF;
        udp_pkt[6] = 0; udp_pkt[7] = 0; /* checksum = 0 */
        memcpy(udp_pkt + 8, data, data_len);

        return ip_output(src_ip, dst_ip, PROTO_UDP, udp_pkt, udp_len);
    }

    if (protocol == PROTO_TCP) {
        /* Build TCP data segment and send via ip_output */
        tcp_conn_t *conn = tcp_find_conn(dst_ip, src_ip, dst_port, src_port);
        if (!conn) return -1;

        uint8_t tcp_pkt[APP_MAX_RECV_BUF + TCP_HEADER_MIN_LEN];
        if (data_len + TCP_HEADER_MIN_LEN > (int)sizeof(tcp_pkt)) return -1;

        int tcp_total = TCP_HEADER_MIN_LEN + data_len;

        /* TCP header */
        memset(tcp_pkt, 0, TCP_HEADER_MIN_LEN);
        tcp_pkt[0] = (src_port >> 8) & 0xFF;
        tcp_pkt[1] = src_port & 0xFF;
        tcp_pkt[2] = (dst_port >> 8) & 0xFF;
        tcp_pkt[3] = dst_port & 0xFF;
        /* seq */
        uint32_t seq = iron_htonl(conn->snd_nxt);
        memcpy(tcp_pkt + 4, &seq, 4);
        /* ack */
        uint32_t ack = iron_htonl(conn->rcv_nxt);
        memcpy(tcp_pkt + 8, &ack, 4);
        /* data offset = 5 (20 bytes), flags = ACK + PSH */
        tcp_pkt[12] = (5 << 4);
        tcp_pkt[13] = TCP_FLAG_ACK | TCP_FLAG_PSH;
        /* window */
        tcp_pkt[14] = 0xFF; tcp_pkt[15] = 0xFF;
        /* checksum at [16..17] = 0 for now */

        memcpy(tcp_pkt + TCP_HEADER_MIN_LEN, data, data_len);

        /* Compute TCP checksum with pseudo-header */
        uint32_t sum = 0;
        uint8_t *sip = (uint8_t *)&src_ip;
        uint8_t *dip = (uint8_t *)&dst_ip;
        sum += (sip[0] << 8) | sip[1];
        sum += (sip[2] << 8) | sip[3];
        sum += (dip[0] << 8) | dip[1];
        sum += (dip[2] << 8) | dip[3];
        sum += PROTO_TCP;
        sum += tcp_total;
        for (int i = 0; i < tcp_total; i += 2) {
            uint16_t word = (tcp_pkt[i] << 8);
            if (i + 1 < tcp_total) word |= tcp_pkt[i + 1];
            sum += word;
        }
        while (sum >> 16) sum = (sum >> 16) + (sum & 0xFFFF);
        uint16_t cksum = ~sum & 0xFFFF;
        tcp_pkt[16] = (cksum >> 8) & 0xFF;
        tcp_pkt[17] = cksum & 0xFF;

        conn->snd_nxt += data_len;

        return ip_output(src_ip, dst_ip, PROTO_TCP, tcp_pkt, tcp_total);
    }

    return -1;
}

int app_socket_close_conn(uint32_t dst_ip, uint16_t dst_port,
                          uint32_t src_ip, uint16_t src_port) {
    tcp_conn_t *conn = tcp_find_conn(dst_ip, src_ip, dst_port, src_port);
    if (!conn) return -1;

    /* Send FIN */
    uint8_t tcp_pkt[TCP_HEADER_MIN_LEN];
    memset(tcp_pkt, 0, TCP_HEADER_MIN_LEN);
    tcp_pkt[0] = (src_port >> 8) & 0xFF;
    tcp_pkt[1] = src_port & 0xFF;
    tcp_pkt[2] = (dst_port >> 8) & 0xFF;
    tcp_pkt[3] = dst_port & 0xFF;
    uint32_t seq = iron_htonl(conn->snd_nxt);
    memcpy(tcp_pkt + 4, &seq, 4);
    uint32_t ack = iron_htonl(conn->rcv_nxt);
    memcpy(tcp_pkt + 8, &ack, 4);
    tcp_pkt[12] = (5 << 4);
    tcp_pkt[13] = TCP_FLAG_ACK | TCP_FLAG_FIN;
    tcp_pkt[14] = 0xFF; tcp_pkt[15] = 0xFF;

    return ip_output(src_ip, dst_ip, PROTO_TCP, tcp_pkt, TCP_HEADER_MIN_LEN);
}
