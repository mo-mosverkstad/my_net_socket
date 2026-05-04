#include "acl.h"
#include "log.h"
#include "stats.h"
#include "utils.h"

#include <string.h>

#define MODULE "ACL"

static acl_rule_t g_acl_rules[ACL_MAX_RULES];
static int g_acl_count = 0;
static acl_default_policy_t g_default_policy = ACL_DEFAULT_DENY;

int acl_init(acl_default_policy_t default_policy) {
    memset(g_acl_rules, 0, sizeof(g_acl_rules));
    g_acl_count = 0;
    g_default_policy = default_policy;
    LOG_INF(MODULE, "ACL initialized (default: %s)",
            default_policy == ACL_DEFAULT_PERMIT ? "PERMIT" : "DENY");
    return 0;
}

int acl_add_rule(uint32_t rule_id, acl_match_t *match, acl_action_t action) {
    if (g_acl_count >= ACL_MAX_RULES) {
        LOG_ERR(MODULE, "ACL table full");
        return -1;
    }

    acl_rule_t *r = &g_acl_rules[g_acl_count];
    r->rule_id = rule_id;
    r->match = *match;
    r->action = action;
    r->active = true;
    r->hit_count = 0;
    g_acl_count++;

    LOG_INF(MODULE, "Rule %u added (%s)", rule_id,
            action == ACL_PERMIT ? "PERMIT" : "DENY");
    return 0;
}

int acl_delete_rule(uint32_t rule_id) {
    for (int i = 0; i < g_acl_count; i++) {
        if (g_acl_rules[i].active && g_acl_rules[i].rule_id == rule_id) {
            g_acl_rules[i].active = false;
            LOG_INF(MODULE, "Rule %u deleted", rule_id);
            return 0;
        }
    }
    return -1;
}

static bool port_matches(uint16_t port, port_range_t *range) {
    if (range->min == 0 && range->max == 0) return true; /* any */
    return port >= range->min && port <= range->max;
}

static bool rule_matches(acl_rule_t *rule, uint32_t src_ip, uint32_t dst_ip,
                         uint8_t protocol, uint16_t src_port, uint16_t dst_port) {
    if (rule->match.protocol != PROTO_ANY && rule->match.protocol != protocol)
        return false;
    if (!iron_ip_matches(src_ip, rule->match.src_ip.addr, rule->match.src_ip.prefix_len))
        return false;
    if (!iron_ip_matches(dst_ip, rule->match.dst_ip.addr, rule->match.dst_ip.prefix_len))
        return false;
    if (!port_matches(src_port, &rule->match.src_port))
        return false;
    if (!port_matches(dst_port, &rule->match.dst_port))
        return false;
    return true;
}

acl_action_t acl_evaluate(uint32_t src_ip, uint32_t dst_ip,
                          uint8_t protocol, uint16_t src_port, uint16_t dst_port) {
    /* First-match, top-down evaluation */
    for (int i = 0; i < g_acl_count; i++) {
        if (!g_acl_rules[i].active) continue;

        if (rule_matches(&g_acl_rules[i], src_ip, dst_ip, protocol, src_port, dst_port)) {
            g_acl_rules[i].hit_count++;

            if (g_acl_rules[i].action == ACL_DENY) {
                iron_stats_increment(STAT_L3_DROPS_ACL);
                char src_buf[16], dst_buf[16];
                LOG_INF(MODULE, "DENY rule %u: %s -> %s proto=%d sport=%d dport=%d",
                        g_acl_rules[i].rule_id,
                        iron_ip_to_str(src_ip, src_buf, sizeof(src_buf)),
                        iron_ip_to_str(dst_ip, dst_buf, sizeof(dst_buf)),
                        protocol, src_port, dst_port);
            }
            return g_acl_rules[i].action;
        }
    }

    /* Default policy */
    if (g_default_policy == ACL_DEFAULT_DENY) {
        iron_stats_increment(STAT_L3_DROPS_ACL);
        LOG_DBG(MODULE, "Packet denied by default policy");
        return ACL_DENY;
    }
    return ACL_PERMIT;
}

void acl_dump(void) {
    LOG_INF(MODULE, "--- ACL Rules ---");
    for (int i = 0; i < g_acl_count; i++) {
        if (!g_acl_rules[i].active) continue;
        LOG_INF(MODULE, "  Rule %u: %s (hits: %lu)",
                g_acl_rules[i].rule_id,
                g_acl_rules[i].action == ACL_PERMIT ? "PERMIT" : "DENY",
                g_acl_rules[i].hit_count);
    }
    LOG_INF(MODULE, "  Default: %s",
            g_default_policy == ACL_DEFAULT_PERMIT ? "PERMIT" : "DENY");
}
