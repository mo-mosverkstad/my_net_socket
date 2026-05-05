#ifndef IRON_TCP_H
#define IRON_TCP_H

#include "types.h"

#define TCP_HEADER_MIN_LEN 20
#define TCP_MAX_CONNECTIONS 256
#define TCP_TIME_WAIT_TIMEOUT 60  /* seconds */

/* TCP flags */
#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20

typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset; /* upper 4 bits = offset in 32-bit words */
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} tcp_header_t;

typedef enum {
    TCP_CLOSED = 0,
    TCP_SYN_RECV,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_TIME_WAIT
} tcp_state_t;

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    tcp_state_t state;

    uint32_t snd_nxt;
    uint32_t rcv_nxt;

    uint64_t last_activity; /* timestamp in seconds */
    bool active;
} tcp_conn_t;

static inline uint8_t tcp_get_data_offset(const tcp_header_t *h) {
    return (h->data_offset >> 4) & 0xF;
}

static inline int tcp_get_header_len(const tcp_header_t *h) {
    return tcp_get_data_offset(h) * 4;
}

int tcp_init(void);
int tcp_input(uint32_t src_ip, uint32_t dst_ip,
              uint8_t *data, int len, int iface_idx);
void tcp_timer_tick(void);
void tcp_dump(void);

/* For testing */
int tcp_get_connection_count(void);
tcp_conn_t *tcp_find_conn(uint32_t src_ip, uint32_t dst_ip,
                          uint16_t src_port, uint16_t dst_port);
void tcp_flush(void);

#endif /* IRON_TCP_H */
