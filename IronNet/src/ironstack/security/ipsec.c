#include "ipsec.h"
#include "log.h"
#include "stats.h"
#include "utils.h"

#include <string.h>
#include <time.h>

#define MODULE "IPSEC"

static ipsec_sa_t g_sa_db[IPSEC_MAX_SA];
static int g_sa_count = 0;

static ipsec_policy_t g_policies[IPSEC_MAX_POLICY];
static int g_policy_count = 0;

static uint64_t ipsec_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec;
}

int ipsec_init(void) {
    memset(g_sa_db, 0, sizeof(g_sa_db));
    memset(g_policies, 0, sizeof(g_policies));
    g_sa_count = 0;
    g_policy_count = 0;
    LOG_INF(MODULE, "IPsec initialized");
    return 0;
}

int ipsec_sa_add(uint32_t spi, uint32_t src_ip, uint32_t dst_ip,
                 ipsec_direction_t dir, uint8_t transform, uint8_t key) {
    if (g_sa_count >= IPSEC_MAX_SA) {
        LOG_ERR(MODULE, "SA database full");
        return -1;
    }

    ipsec_sa_t *sa = &g_sa_db[g_sa_count];
    sa->spi = spi;
    sa->src_ip = src_ip;
    sa->dst_ip = dst_ip;
    sa->direction = dir;
    sa->transform = transform;
    sa->key = key;
    sa->active = true;
    sa->created_at = ipsec_now();
    sa->bytes_processed = 0;
    sa->packets_processed = 0;
    g_sa_count++;

    LOG_INF(MODULE, "SA added: SPI=0x%08X transform=%d dir=%s",
            spi, transform, dir == IPSEC_DIR_OUTBOUND ? "OUT" : "IN");
    return 0;
}

int ipsec_sa_delete(uint32_t spi) {
    for (int i = 0; i < g_sa_count; i++) {
        if (g_sa_db[i].active && g_sa_db[i].spi == spi) {
            g_sa_db[i].active = false;
            LOG_INF(MODULE, "SA deleted: SPI=0x%08X", spi);
            return 0;
        }
    }
    return -1;
}

ipsec_sa_t *ipsec_sa_find(uint32_t spi) {
    for (int i = 0; i < g_sa_count; i++) {
        if (g_sa_db[i].active && g_sa_db[i].spi == spi)
            return &g_sa_db[i];
    }
    return NULL;
}

int ipsec_policy_add(ip_prefix_t src, ip_prefix_t dst, ip_protocol_t proto,
                     ipsec_direction_t dir, ipsec_policy_action_t action, uint32_t sa_spi) {
    if (g_policy_count >= IPSEC_MAX_POLICY) {
        LOG_ERR(MODULE, "Policy database full");
        return -1;
    }

    ipsec_policy_t *p = &g_policies[g_policy_count];
    p->src_prefix = src;
    p->dst_prefix = dst;
    p->protocol = proto;
    p->direction = dir;
    p->action = action;
    p->sa_spi = sa_spi;
    p->active = true;
    p->hit_count = 0;
    g_policy_count++;

    LOG_INF(MODULE, "Policy added: action=%s dir=%s SPI=0x%08X",
            action == IPSEC_ACTION_PROTECT ? "PROTECT" :
            action == IPSEC_ACTION_BYPASS ? "BYPASS" : "DISCARD",
            dir == IPSEC_DIR_OUTBOUND ? "OUT" : "IN", sa_spi);
    return 0;
}

static ipsec_policy_t *ipsec_policy_lookup(uint32_t src_ip, uint32_t dst_ip,
                                           uint8_t protocol, ipsec_direction_t dir) {
    for (int i = 0; i < g_policy_count; i++) {
        ipsec_policy_t *p = &g_policies[i];
        if (!p->active) continue;
        if (p->direction != dir) continue;
        if (p->protocol != PROTO_ANY && p->protocol != protocol) continue;
        if (!iron_ip_matches(src_ip, p->src_prefix.addr, p->src_prefix.prefix_len)) continue;
        if (!iron_ip_matches(dst_ip, p->dst_prefix.addr, p->dst_prefix.prefix_len)) continue;
        return p;
    }
    return NULL;
}

static void ipsec_apply_transform(ipsec_sa_t *sa, uint8_t *payload, int len) {
    if (sa->transform == IPSEC_TRANSFORM_XOR) {
        for (int i = 0; i < len; i++) {
            payload[i] ^= sa->key;
        }
    }
    /* IPSEC_TRANSFORM_NONE: no modification */
    sa->bytes_processed += len;
    sa->packets_processed++;
}

int ipsec_outbound(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol,
                   uint8_t *payload, int payload_len) {
    ipsec_policy_t *pol = ipsec_policy_lookup(src_ip, dst_ip, protocol, IPSEC_DIR_OUTBOUND);

    if (!pol) return 0; /* No policy = implicit bypass */

    pol->hit_count++;

    switch (pol->action) {
    case IPSEC_ACTION_BYPASS:
        LOG_DBG(MODULE, "Outbound: BYPASS");
        return 0;

    case IPSEC_ACTION_DISCARD:
        LOG_DBG(MODULE, "Outbound: DISCARD");
        return -1;

    case IPSEC_ACTION_PROTECT: {
        ipsec_sa_t *sa = ipsec_sa_find(pol->sa_spi);
        if (!sa) {
            LOG_WRN(MODULE, "Outbound: no SA for SPI=0x%08X (fail closed)", pol->sa_spi);
            return -1; /* Fail closed: no SA = drop */
        }
        LOG_DBG(MODULE, "Outbound: PROTECT with SPI=0x%08X", sa->spi);
        ipsec_apply_transform(sa, payload, payload_len);
        return 0;
    }
    }

    return 0;
}

int ipsec_inbound(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol,
                  uint8_t *payload, int payload_len) {
    ipsec_policy_t *pol = ipsec_policy_lookup(src_ip, dst_ip, protocol, IPSEC_DIR_INBOUND);

    if (!pol) return 0; /* No policy = implicit bypass */

    pol->hit_count++;

    switch (pol->action) {
    case IPSEC_ACTION_BYPASS:
        LOG_DBG(MODULE, "Inbound: BYPASS");
        return 0;

    case IPSEC_ACTION_DISCARD:
        LOG_DBG(MODULE, "Inbound: DISCARD");
        return -1;

    case IPSEC_ACTION_PROTECT: {
        ipsec_sa_t *sa = ipsec_sa_find(pol->sa_spi);
        if (!sa) {
            LOG_WRN(MODULE, "Inbound: no SA for SPI=0x%08X (fail closed)", pol->sa_spi);
            return -1; /* Fail closed */
        }
        LOG_DBG(MODULE, "Inbound: decrypt with SPI=0x%08X", sa->spi);
        ipsec_apply_transform(sa, payload, payload_len); /* XOR is its own inverse */
        return 0;
    }
    }

    return 0;
}

void ipsec_timer_tick(void) {
    uint64_t now = ipsec_now();

    for (int i = 0; i < g_sa_count; i++) {
        ipsec_sa_t *sa = &g_sa_db[i];
        if (!sa->active) continue;

        if ((now - sa->created_at) >= IPSEC_SA_LIFETIME) {
            LOG_INF(MODULE, "SA expired: SPI=0x%08X (processed %lu packets, %lu bytes)",
                    sa->spi, sa->packets_processed, sa->bytes_processed);
            sa->active = false;
        }
    }
}

void ipsec_dump(void) {
    LOG_INF(MODULE, "--- IPsec SA Database ---");
    for (int i = 0; i < g_sa_count; i++) {
        ipsec_sa_t *sa = &g_sa_db[i];
        if (!sa->active) continue;
        LOG_INF(MODULE, "  SPI=0x%08X dir=%s transform=%d pkts=%lu bytes=%lu",
                sa->spi,
                sa->direction == IPSEC_DIR_OUTBOUND ? "OUT" : "IN",
                sa->transform, sa->packets_processed, sa->bytes_processed);
    }
    LOG_INF(MODULE, "--- IPsec Policies ---");
    for (int i = 0; i < g_policy_count; i++) {
        ipsec_policy_t *p = &g_policies[i];
        if (!p->active) continue;
        LOG_INF(MODULE, "  dir=%s action=%s SPI=0x%08X hits=%lu",
                p->direction == IPSEC_DIR_OUTBOUND ? "OUT" : "IN",
                p->action == IPSEC_ACTION_PROTECT ? "PROTECT" :
                p->action == IPSEC_ACTION_BYPASS ? "BYPASS" : "DISCARD",
                p->sa_spi, p->hit_count);
    }
}
