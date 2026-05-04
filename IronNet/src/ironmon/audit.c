#include "audit.h"
#include "log.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#define MODULE "AUDIT"

static audit_event_t g_ring[AUDIT_RING_SIZE];
static int g_ring_head = 0;
static int g_ring_count = 0;
static FILE *g_audit_file = NULL;
static bool g_enabled = true;

static const char *event_type_name(audit_event_type_t type) {
    switch (type) {
    case AUDIT_ACL_DENY:           return "ACL_DENY";
    case AUDIT_IPSEC_DROP:         return "IPSEC_DROP";
    case AUDIT_TCP_INVALID_FLAGS:  return "TCP_INVALID_FLAGS";
    case AUDIT_TCP_TABLE_FULL:     return "TCP_TABLE_FULL";
    case AUDIT_ARP_ANOMALY:        return "ARP_ANOMALY";
    case AUDIT_NAT_EXHAUSTION:     return "NAT_EXHAUSTION";
    case AUDIT_CONNTRACK_INVALID:  return "CONNTRACK_INVALID";
    case AUDIT_FRAGMENT_DROP:      return "FRAGMENT_DROP";
    case AUDIT_VLAN_MISMATCH:      return "VLAN_MISMATCH";
    case AUDIT_TTL_EXPIRED:        return "TTL_EXPIRED";
    default:                       return "UNKNOWN";
    }
}

static uint64_t audit_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec;
}

int audit_init(const char *log_file) {
    memset(g_ring, 0, sizeof(g_ring));
    g_ring_head = 0;
    g_ring_count = 0;
    g_enabled = true;

    if (log_file) {
        g_audit_file = fopen(log_file, "a");
        if (!g_audit_file) {
            LOG_WRN(MODULE, "Cannot open audit log: %s", log_file);
        } else {
            LOG_INF(MODULE, "Audit log: %s", log_file);
        }
    }

    LOG_INF(MODULE, "Audit logging initialized (enabled=%s)", g_enabled ? "true" : "false");
    return 0;
}

void audit_shutdown(void) {
    if (g_audit_file) {
        fclose(g_audit_file);
        g_audit_file = NULL;
    }
}

void audit_enable(void) {
    g_enabled = true;
    LOG_INF(MODULE, "Audit logging enabled");
}

void audit_disable(void) {
    g_enabled = false;
    LOG_INF(MODULE, "Audit logging disabled");
}

void audit_log_event(audit_event_type_t type,
                     uint32_t src_ip, uint32_t dst_ip,
                     uint8_t protocol, uint16_t src_port, uint16_t dst_port,
                     const char *detail) {
    if (!g_enabled) return;

    uint64_t now = audit_now();

    /* Add to ring buffer */
    audit_event_t *e = &g_ring[g_ring_head];
    e->timestamp = now;
    e->type = type;
    e->src_ip = src_ip;
    e->dst_ip = dst_ip;
    e->protocol = protocol;
    e->src_port = src_port;
    e->dst_port = dst_port;
    if (detail)
        strncpy(e->detail, detail, sizeof(e->detail) - 1);
    else
        e->detail[0] = 0;

    g_ring_head = (g_ring_head + 1) % AUDIT_RING_SIZE;
    if (g_ring_count < AUDIT_RING_SIZE) g_ring_count++;

    /* Write to file */
    if (g_audit_file) {
        char src_buf[16], dst_buf[16];
        fprintf(g_audit_file, "%lu|%s|%s|%s|%u|%u|%u|%s\n",
                now, event_type_name(type),
                iron_ip_to_str(src_ip, src_buf, sizeof(src_buf)),
                iron_ip_to_str(dst_ip, dst_buf, sizeof(dst_buf)),
                protocol, src_port, dst_port,
                detail ? detail : "");
        fflush(g_audit_file);
    }
}

int audit_get_recent(audit_event_t *out, int max_count) {
    int count = (max_count < g_ring_count) ? max_count : g_ring_count;
    int start = (g_ring_head - count + AUDIT_RING_SIZE) % AUDIT_RING_SIZE;

    for (int i = 0; i < count; i++) {
        int idx = (start + i) % AUDIT_RING_SIZE;
        out[i] = g_ring[idx];
    }
    return count;
}

void audit_dump(void) {
    char src_buf[16], dst_buf[16];
    printf("--- Audit Log (last %d events) ---\n", g_ring_count);
    int start = (g_ring_head - g_ring_count + AUDIT_RING_SIZE) % AUDIT_RING_SIZE;
    for (int i = 0; i < g_ring_count; i++) {
        int idx = (start + i) % AUDIT_RING_SIZE;
        audit_event_t *e = &g_ring[idx];
        printf("  [%lu] %-20s %s:%u -> %s:%u proto=%u %s\n",
               e->timestamp, event_type_name(e->type),
               iron_ip_to_str(e->src_ip, src_buf, sizeof(src_buf)), e->src_port,
               iron_ip_to_str(e->dst_ip, dst_buf, sizeof(dst_buf)), e->dst_port,
               e->protocol, e->detail);
    }
}

void audit_dump_json(void) {
    char src_buf[16], dst_buf[16];
    printf("[\n");
    int start = (g_ring_head - g_ring_count + AUDIT_RING_SIZE) % AUDIT_RING_SIZE;
    for (int i = 0; i < g_ring_count; i++) {
        int idx = (start + i) % AUDIT_RING_SIZE;
        audit_event_t *e = &g_ring[idx];
        printf("  {\"ts\":%lu,\"type\":\"%s\",\"src\":\"%s\",\"dst\":\"%s\","
               "\"proto\":%u,\"sport\":%u,\"dport\":%u,\"detail\":\"%s\"}%s\n",
               e->timestamp, event_type_name(e->type),
               iron_ip_to_str(e->src_ip, src_buf, sizeof(src_buf)),
               iron_ip_to_str(e->dst_ip, dst_buf, sizeof(dst_buf)),
               e->protocol, e->src_port, e->dst_port, e->detail,
               (i < g_ring_count - 1) ? "," : "");
    }
    printf("]\n");
}
