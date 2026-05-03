#ifndef IRON_PBR_H
#define IRON_PBR_H

#include "types.h"

#define PBR_MAX_RULES 64
#define PBR_MAX_HOP_HISTORY 16

typedef struct {
    ip_prefix_t src_ip;
    ip_prefix_t dst_ip;
    ip_protocol_t protocol;
} pbr_match_t;

typedef struct {
    uint32_t next_hop;
    int out_iface;
} pbr_action_t;

typedef struct {
    uint32_t rule_id;
    pbr_match_t match;
    pbr_action_t action;
    bool active;
    uint64_t hit_count;
} pbr_rule_t;

/* Packet context tracks ACL and PBR state for invariant checking */
typedef struct {
    bool acl_checked;
    uint32_t hop_history[PBR_MAX_HOP_HISTORY];
    int hop_count;
} pkt_context_t;

int pbr_init(void);
int pbr_add_rule(uint32_t rule_id, pbr_match_t *match, pbr_action_t *action);
int pbr_delete_rule(uint32_t rule_id);
int pbr_lookup(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol,
               pkt_context_t *ctx, uint32_t *next_hop, int *out_iface);
void pbr_dump(void);

/* Context helpers */
void pkt_context_init(pkt_context_t *ctx);
bool route_seen_hop(pkt_context_t *ctx, uint32_t hop);

#endif /* IRON_PBR_H */
