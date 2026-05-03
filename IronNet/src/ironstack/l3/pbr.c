#include "pbr.h"
#include "log.h"
#include "stats.h"
#include "utils.h"

#include <string.h>

#define MODULE "PBR"

static pbr_rule_t g_pbr_rules[PBR_MAX_RULES];
static int g_pbr_count = 0;

int pbr_init(void) {
    memset(g_pbr_rules, 0, sizeof(g_pbr_rules));
    g_pbr_count = 0;
    LOG_INF(MODULE, "PBR initialized");
    return 0;
}

int pbr_add_rule(uint32_t rule_id, pbr_match_t *match, pbr_action_t *action) {
    if (g_pbr_count >= PBR_MAX_RULES) {
        LOG_ERR(MODULE, "PBR table full");
        return -1;
    }

    pbr_rule_t *r = &g_pbr_rules[g_pbr_count];
    r->rule_id = rule_id;
    r->match = *match;
    r->action = *action;
    r->active = true;
    r->hit_count = 0;
    g_pbr_count++;

    LOG_INF(MODULE, "PBR rule %u added", rule_id);
    return 0;
}

int pbr_delete_rule(uint32_t rule_id) {
    for (int i = 0; i < g_pbr_count; i++) {
        if (g_pbr_rules[i].active && g_pbr_rules[i].rule_id == rule_id) {
            g_pbr_rules[i].active = false;
            LOG_INF(MODULE, "PBR rule %u deleted", rule_id);
            return 0;
        }
    }
    return -1;
}

static bool pbr_rule_matches(pbr_rule_t *rule, uint32_t src_ip, uint32_t dst_ip, uint8_t protocol) {
    if (rule->match.protocol != PROTO_ANY && rule->match.protocol != protocol)
        return false;
    if (!iron_ip_matches(src_ip, rule->match.src_ip.addr, rule->match.src_ip.prefix_len))
        return false;
    if (!iron_ip_matches(dst_ip, rule->match.dst_ip.addr, rule->match.dst_ip.prefix_len))
        return false;
    return true;
}

void pkt_context_init(pkt_context_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
}

bool route_seen_hop(pkt_context_t *ctx, uint32_t hop) {
    for (int i = 0; i < ctx->hop_count; i++) {
        if (ctx->hop_history[i] == hop) return true;
    }
    return false;
}

static void context_add_hop(pkt_context_t *ctx, uint32_t hop) {
    if (ctx->hop_count < PBR_MAX_HOP_HISTORY) {
        ctx->hop_history[ctx->hop_count++] = hop;
    }
}

int pbr_lookup(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol,
               pkt_context_t *ctx, uint32_t *next_hop, int *out_iface) {
    /* Invariant: ACL must be checked before PBR */
    if (!ctx->acl_checked) {
        LOG_ERR(MODULE, "INVARIANT VIOLATION: PBR evaluated before ACL");
        return -1;
    }

    for (int i = 0; i < g_pbr_count; i++) {
        if (!g_pbr_rules[i].active) continue;

        if (pbr_rule_matches(&g_pbr_rules[i], src_ip, dst_ip, protocol)) {
            uint32_t hop = g_pbr_rules[i].action.next_hop;

            /* Loop detection */
            if (route_seen_hop(ctx, hop)) {
                LOG_WRN(MODULE, "Loop detected at hop %08X, rule %u",
                        hop, g_pbr_rules[i].rule_id);
                return -2; /* Loop */
            }

            context_add_hop(ctx, hop);
            g_pbr_rules[i].hit_count++;

            *next_hop = hop;
            *out_iface = g_pbr_rules[i].action.out_iface;

            LOG_DBG(MODULE, "PBR rule %u matched, next_hop=%08X iface=%d",
                    g_pbr_rules[i].rule_id, hop, *out_iface);
            return 0;
        }
    }

    return -1; /* No PBR match, fall through to FIB */
}

void pbr_dump(void) {
    LOG_INF(MODULE, "--- PBR Rules ---");
    for (int i = 0; i < g_pbr_count; i++) {
        if (!g_pbr_rules[i].active) continue;
        char nh_buf[16];
        LOG_INF(MODULE, "  Rule %u: next_hop=%s iface=%d (hits: %lu)",
                g_pbr_rules[i].rule_id,
                iron_ip_to_str(g_pbr_rules[i].action.next_hop, nh_buf, sizeof(nh_buf)),
                g_pbr_rules[i].action.out_iface,
                g_pbr_rules[i].hit_count);
    }
}
