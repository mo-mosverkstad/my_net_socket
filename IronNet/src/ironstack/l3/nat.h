#ifndef IRON_NAT_H
#define IRON_NAT_H

#include "types.h"

#define NAT_MAX_RULES      64
#define NAT_MAX_MAPPINGS   1024
#define NAT_PORT_MIN       10000
#define NAT_PORT_MAX       65000

typedef enum {
    NAT_SNAT,   /* Source NAT (masquerade) */
    NAT_DNAT    /* Destination NAT (port forwarding) */
} nat_type_t;

typedef struct {
    nat_type_t type;
    ip_prefix_t match_prefix;   /* SNAT: match src, DNAT: match dst */
    uint16_t match_port;        /* DNAT: match dst port (0=any) */
    uint32_t translate_ip;      /* New IP to use */
    uint16_t translate_port;    /* DNAT: new dst port (0=same) */
    bool active;
    uint64_t hit_count;
} nat_rule_t;

typedef struct {
    uint32_t orig_src_ip;
    uint32_t orig_dst_ip;
    uint16_t orig_src_port;
    uint16_t orig_dst_port;
    uint8_t  protocol;

    uint32_t trans_src_ip;
    uint32_t trans_dst_ip;
    uint16_t trans_src_port;
    uint16_t trans_dst_port;

    nat_type_t type;
    uint64_t last_seen;
    bool active;
} nat_mapping_t;

int nat_init(void);
int nat_add_snat(ip_prefix_t src_prefix, uint32_t translate_ip);
int nat_add_dnat(uint32_t match_dst_ip, uint16_t match_port,
                 uint32_t translate_ip, uint16_t translate_port);

/* Apply NAT. Returns 0 if translated, -1 if dropped, 1 if no rule matched (pass-through). */
int nat_translate_outbound(uint32_t *src_ip, uint32_t *dst_ip,
                           uint16_t *src_port, uint16_t *dst_port,
                           uint8_t protocol);
int nat_translate_inbound(uint32_t *src_ip, uint32_t *dst_ip,
                          uint16_t *src_port, uint16_t *dst_port,
                          uint8_t protocol);

void nat_timer_tick(void);
int nat_get_mapping_count(void);
void nat_dump(void);

#endif /* IRON_NAT_H */
