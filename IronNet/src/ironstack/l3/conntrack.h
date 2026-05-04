#ifndef IRON_CONNTRACK_H
#define IRON_CONNTRACK_H

#include "types.h"

#define CONNTRACK_MAX_ENTRIES   1024
#define CONNTRACK_TCP_EST_SEC   300   /* TCP established timeout */
#define CONNTRACK_TCP_OTHER_SEC 60    /* TCP non-established timeout */
#define CONNTRACK_UDP_SEC       30    /* UDP timeout */
#define CONNTRACK_ICMP_SEC      10    /* ICMP timeout */

typedef enum {
    CT_STATE_NEW,
    CT_STATE_ESTABLISHED,
    CT_STATE_RELATED,
    CT_STATE_INVALID
} ct_state_t;

typedef struct {
    /* Original direction (initiator) */
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;

    ct_state_t state;
    uint64_t last_seen;
    uint64_t packets_orig;   /* Original direction */
    uint64_t packets_reply;  /* Reply direction */
    bool active;
} ct_entry_t;

int conntrack_init(void);
ct_entry_t *conntrack_lookup(uint32_t src_ip, uint32_t dst_ip,
                             uint8_t protocol, uint16_t src_port, uint16_t dst_port);
ct_state_t conntrack_get_state(uint32_t src_ip, uint32_t dst_ip,
                               uint8_t protocol, uint16_t src_port, uint16_t dst_port);
int conntrack_update(uint32_t src_ip, uint32_t dst_ip,
                     uint8_t protocol, uint16_t src_port, uint16_t dst_port,
                     uint8_t tcp_flags);
void conntrack_timer_tick(void);
int conntrack_get_count(void);
void conntrack_dump(void);

#endif /* IRON_CONNTRACK_H */
