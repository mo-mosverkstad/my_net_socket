#ifndef IRON_IPSEC_H
#define IRON_IPSEC_H

#include "types.h"

#define IPSEC_MAX_SA      64
#define IPSEC_MAX_POLICY  64
#define IPSEC_SA_LIFETIME 3600  /* seconds */

/* Dummy transform: XOR with a key byte (not real crypto, just exercises control flow) */
#define IPSEC_TRANSFORM_NONE  0
#define IPSEC_TRANSFORM_XOR   1

typedef enum {
    IPSEC_DIR_INBOUND,
    IPSEC_DIR_OUTBOUND
} ipsec_direction_t;

typedef enum {
    IPSEC_ACTION_PROTECT,
    IPSEC_ACTION_BYPASS,
    IPSEC_ACTION_DISCARD
} ipsec_policy_action_t;

typedef struct {
    uint32_t spi;           /* Security Parameter Index */
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t  transform;     /* IPSEC_TRANSFORM_XOR etc. */
    uint8_t  key;           /* Single byte key for XOR dummy */
    ipsec_direction_t direction;
    bool active;
    uint64_t created_at;    /* timestamp */
    uint64_t bytes_processed;
    uint64_t packets_processed;
} ipsec_sa_t;

typedef struct {
    ip_prefix_t src_prefix;
    ip_prefix_t dst_prefix;
    ip_protocol_t protocol;
    ipsec_direction_t direction;
    ipsec_policy_action_t action;
    uint32_t sa_spi;        /* Which SA to use (if action == PROTECT) */
    bool active;
    uint64_t hit_count;
} ipsec_policy_t;

int ipsec_init(void);
int ipsec_sa_add(uint32_t spi, uint32_t src_ip, uint32_t dst_ip,
                 ipsec_direction_t dir, uint8_t transform, uint8_t key);
int ipsec_sa_delete(uint32_t spi);
ipsec_sa_t *ipsec_sa_find(uint32_t spi);

int ipsec_policy_add(ip_prefix_t src, ip_prefix_t dst, ip_protocol_t proto,
                     ipsec_direction_t dir, ipsec_policy_action_t action, uint32_t sa_spi);

/* Returns 0=pass, -1=discard. Modifies payload in-place for PROTECT. */
int ipsec_outbound(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol,
                   uint8_t *payload, int payload_len);
int ipsec_inbound(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol,
                  uint8_t *payload, int payload_len);

void ipsec_timer_tick(void);
void ipsec_dump(void);

#endif /* IRON_IPSEC_H */
