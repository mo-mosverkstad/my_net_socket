#ifndef IRON_ACL_H
#define IRON_ACL_H

#include "types.h"

#define ACL_MAX_RULES 128

typedef enum {
    ACL_PERMIT,
    ACL_DENY
} acl_action_t;

typedef struct {
    ip_prefix_t src_ip;
    ip_prefix_t dst_ip;
    port_range_t src_port;
    port_range_t dst_port;
    ip_protocol_t protocol;
} acl_match_t;

typedef struct {
    uint32_t rule_id;
    acl_match_t match;
    acl_action_t action;
    bool active;
    uint64_t hit_count;
} acl_rule_t;

typedef enum {
    ACL_DEFAULT_PERMIT,
    ACL_DEFAULT_DENY
} acl_default_policy_t;

int acl_init(acl_default_policy_t default_policy);
int acl_add_rule(uint32_t rule_id, acl_match_t *match, acl_action_t action);
int acl_delete_rule(uint32_t rule_id);
acl_action_t acl_evaluate(uint32_t src_ip, uint32_t dst_ip,
                          uint8_t protocol, uint16_t src_port, uint16_t dst_port);
void acl_dump(void);

#endif /* IRON_ACL_H */
