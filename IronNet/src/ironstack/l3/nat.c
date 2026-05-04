#include "nat.h"
#include "log.h"
#include "stats.h"
#include "utils.h"

#include <string.h>
#include <time.h>

#define MODULE "NAT"
#define NAT_MAPPING_TIMEOUT 300  /* 5 minutes */

static nat_rule_t g_nat_rules[NAT_MAX_RULES];
static int g_nat_rule_count = 0;

static nat_mapping_t g_nat_mappings[NAT_MAX_MAPPINGS];
static int g_nat_mapping_count = 0;

static uint16_t g_next_port = NAT_PORT_MIN;

static uint64_t nat_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec;
}

int nat_init(void) {
    memset(g_nat_rules, 0, sizeof(g_nat_rules));
    memset(g_nat_mappings, 0, sizeof(g_nat_mappings));
    g_nat_rule_count = 0;
    g_nat_mapping_count = 0;
    g_next_port = NAT_PORT_MIN;
    LOG_INF(MODULE, "NAT initialized");
    return 0;
}

int nat_add_snat(ip_prefix_t src_prefix, uint32_t translate_ip) {
    if (g_nat_rule_count >= NAT_MAX_RULES) return -1;

    nat_rule_t *r = &g_nat_rules[g_nat_rule_count];
    r->type = NAT_SNAT;
    r->match_prefix = src_prefix;
    r->match_port = 0;
    r->translate_ip = translate_ip;
    r->translate_port = 0;
    r->active = true;
    r->hit_count = 0;
    g_nat_rule_count++;

    char ip_buf[16], tr_buf[16];
    LOG_INF(MODULE, "SNAT added: src %s/%d -> %s",
            iron_ip_to_str(src_prefix.addr, ip_buf, sizeof(ip_buf)),
            src_prefix.prefix_len,
            iron_ip_to_str(translate_ip, tr_buf, sizeof(tr_buf)));
    return 0;
}

int nat_add_dnat(uint32_t match_dst_ip, uint16_t match_port,
                 uint32_t translate_ip, uint16_t translate_port) {
    if (g_nat_rule_count >= NAT_MAX_RULES) return -1;

    nat_rule_t *r = &g_nat_rules[g_nat_rule_count];
    r->type = NAT_DNAT;
    r->match_prefix = (ip_prefix_t){match_dst_ip, 32};
    r->match_port = match_port;
    r->translate_ip = translate_ip;
    r->translate_port = translate_port;
    r->active = true;
    r->hit_count = 0;
    g_nat_rule_count++;

    char ip_buf[16], tr_buf[16];
    LOG_INF(MODULE, "DNAT added: dst %s:%u -> %s:%u",
            iron_ip_to_str(match_dst_ip, ip_buf, sizeof(ip_buf)), match_port,
            iron_ip_to_str(translate_ip, tr_buf, sizeof(tr_buf)), translate_port);
    return 0;
}

static uint16_t nat_alloc_port(void) {
    uint16_t port = g_next_port;
    g_next_port++;
    if (g_next_port > NAT_PORT_MAX) g_next_port = NAT_PORT_MIN;
    return port;
}

static nat_mapping_t *nat_find_mapping_orig(uint32_t src_ip, uint32_t dst_ip,
                                            uint8_t protocol, uint16_t src_port, uint16_t dst_port) {
    for (int i = 0; i < NAT_MAX_MAPPINGS; i++) {
        nat_mapping_t *m = &g_nat_mappings[i];
        if (!m->active) continue;
        if (m->orig_src_ip == src_ip && m->orig_dst_ip == dst_ip &&
            m->protocol == protocol &&
            m->orig_src_port == src_port && m->orig_dst_port == dst_port)
            return m;
    }
    return NULL;
}

static nat_mapping_t *nat_find_mapping_trans(uint32_t src_ip, uint32_t dst_ip,
                                             uint8_t protocol, uint16_t src_port, uint16_t dst_port,
                                             nat_type_t type) {
    for (int i = 0; i < NAT_MAX_MAPPINGS; i++) {
        nat_mapping_t *m = &g_nat_mappings[i];
        if (!m->active || m->type != type) continue;

        if (type == NAT_SNAT) {
            /* Return traffic: dst matches translated src */
            if (m->trans_src_ip == dst_ip && m->trans_src_port == dst_port &&
                m->orig_dst_ip == src_ip && m->orig_dst_port == src_port &&
                m->protocol == protocol)
                return m;
        } else {
            /* Return traffic from DNAT target */
            if (m->trans_dst_ip == src_ip && m->trans_dst_port == src_port &&
                m->orig_src_ip == dst_ip && m->orig_src_port == dst_port &&
                m->protocol == protocol)
                return m;
        }
    }
    return NULL;
}

static nat_mapping_t *nat_alloc_mapping(void) {
    for (int i = 0; i < NAT_MAX_MAPPINGS; i++) {
        if (!g_nat_mappings[i].active) {
            g_nat_mapping_count++;
            return &g_nat_mappings[i];
        }
    }
    /* Full — evict oldest */
    nat_mapping_t *oldest = &g_nat_mappings[0];
    for (int i = 1; i < NAT_MAX_MAPPINGS; i++) {
        if (g_nat_mappings[i].last_seen < oldest->last_seen)
            oldest = &g_nat_mappings[i];
    }
    return oldest;
}

int nat_translate_outbound(uint32_t *src_ip, uint32_t *dst_ip,
                           uint16_t *src_port, uint16_t *dst_port,
                           uint8_t protocol) {
    /* Check existing mapping first */
    nat_mapping_t *m = nat_find_mapping_orig(*src_ip, *dst_ip, protocol, *src_port, *dst_port);
    if (m) {
        m->last_seen = nat_now();
        *src_ip = m->trans_src_ip;
        *src_port = m->trans_src_port;
        return 0;
    }

    /* Find matching SNAT rule */
    for (int i = 0; i < g_nat_rule_count; i++) {
        nat_rule_t *r = &g_nat_rules[i];
        if (!r->active || r->type != NAT_SNAT) continue;

        if (iron_ip_matches(*src_ip, r->match_prefix.addr, r->match_prefix.prefix_len)) {
            r->hit_count++;

            /* Create mapping */
            m = nat_alloc_mapping();
            memset(m, 0, sizeof(*m));
            m->orig_src_ip = *src_ip;
            m->orig_dst_ip = *dst_ip;
            m->orig_src_port = *src_port;
            m->orig_dst_port = *dst_port;
            m->protocol = protocol;
            m->trans_src_ip = r->translate_ip;
            m->trans_src_port = nat_alloc_port();
            m->trans_dst_ip = *dst_ip;
            m->trans_dst_port = *dst_port;
            m->type = NAT_SNAT;
            m->last_seen = nat_now();
            m->active = true;

            LOG_DBG(MODULE, "SNAT: %08X:%u -> %08X:%u",
                    *src_ip, *src_port, m->trans_src_ip, m->trans_src_port);

            *src_ip = m->trans_src_ip;
            *src_port = m->trans_src_port;
            return 0;
        }
    }

    return 1; /* No rule matched */
}

int nat_translate_inbound(uint32_t *src_ip, uint32_t *dst_ip,
                          uint16_t *src_port, uint16_t *dst_port,
                          uint8_t protocol) {
    /* Check for SNAT return traffic */
    nat_mapping_t *m = nat_find_mapping_trans(*src_ip, *dst_ip, protocol,
                                              *src_port, *dst_port, NAT_SNAT);
    if (m) {
        m->last_seen = nat_now();
        /* Reverse translate: restore original dst (which was the original src) */
        *dst_ip = m->orig_src_ip;
        *dst_port = m->orig_src_port;
        return 0;
    }

    /* Check for DNAT rules */
    for (int i = 0; i < g_nat_rule_count; i++) {
        nat_rule_t *r = &g_nat_rules[i];
        if (!r->active || r->type != NAT_DNAT) continue;

        if (*dst_ip == r->match_prefix.addr &&
            (r->match_port == 0 || *dst_port == r->match_port)) {
            r->hit_count++;

            /* Check existing DNAT mapping */
            m = nat_find_mapping_orig(*src_ip, *dst_ip, protocol, *src_port, *dst_port);
            if (!m) {
                m = nat_alloc_mapping();
                memset(m, 0, sizeof(*m));
                m->orig_src_ip = *src_ip;
                m->orig_dst_ip = *dst_ip;
                m->orig_src_port = *src_port;
                m->orig_dst_port = *dst_port;
                m->protocol = protocol;
                m->trans_src_ip = *src_ip;
                m->trans_src_port = *src_port;
                m->trans_dst_ip = r->translate_ip;
                m->trans_dst_port = r->translate_port ? r->translate_port : *dst_port;
                m->type = NAT_DNAT;
                m->last_seen = nat_now();
                m->active = true;
            }

            LOG_DBG(MODULE, "DNAT: dst %08X:%u -> %08X:%u",
                    *dst_ip, *dst_port, m->trans_dst_ip, m->trans_dst_port);

            *dst_ip = m->trans_dst_ip;
            *dst_port = m->trans_dst_port;
            return 0;
        }
    }

    return 1; /* No rule matched */
}

void nat_timer_tick(void) {
    uint64_t now = nat_now();
    for (int i = 0; i < NAT_MAX_MAPPINGS; i++) {
        nat_mapping_t *m = &g_nat_mappings[i];
        if (!m->active) continue;
        if ((now - m->last_seen) >= NAT_MAPPING_TIMEOUT) {
            m->active = false;
            g_nat_mapping_count--;
        }
    }
}

int nat_get_mapping_count(void) {
    return g_nat_mapping_count;
}

void nat_dump(void) {
    char s1[16], s2[16], d1[16], d2[16];
    LOG_INF(MODULE, "--- NAT Mappings (%d active) ---", g_nat_mapping_count);
    for (int i = 0; i < NAT_MAX_MAPPINGS; i++) {
        nat_mapping_t *m = &g_nat_mappings[i];
        if (!m->active) continue;
        LOG_INF(MODULE, "  %s %s:%u->%s:%u => %s:%u->%s:%u",
                m->type == NAT_SNAT ? "SNAT" : "DNAT",
                iron_ip_to_str(m->orig_src_ip, s1, sizeof(s1)), m->orig_src_port,
                iron_ip_to_str(m->orig_dst_ip, d1, sizeof(d1)), m->orig_dst_port,
                iron_ip_to_str(m->trans_src_ip, s2, sizeof(s2)), m->trans_src_port,
                iron_ip_to_str(m->trans_dst_ip, d2, sizeof(d2)), m->trans_dst_port);
    }
}
