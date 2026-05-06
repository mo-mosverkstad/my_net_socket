#include "defense.h"
#include "log.h"

#include <string.h>
#include <stdio.h>
#include <time.h>

#define MODULE "DEFENSE"

static defense_entry_t g_defenses[DEFENSE_MAX];
static int g_defense_count = 0;

/* Rate limit state */
typedef struct {
    uint32_t src_ip;
    int count;
} rate_bucket_t;

static rate_bucket_t g_rate_buckets[RATE_LIMIT_BUCKETS];
static int g_rate_max = RATE_LIMIT_DEFAULT;

static int defense_find_or_create(const char *name) {
    for (int i = 0; i < g_defense_count; i++) {
        if (strcmp(g_defenses[i].name, name) == 0) return i;
    }
    if (g_defense_count >= DEFENSE_MAX) return -1;
    int idx = g_defense_count++;
    strncpy(g_defenses[idx].name, name, DEFENSE_NAME_LEN - 1);
    g_defenses[idx].enabled = false;
    return idx;
}

int defense_init(void) {
    memset(g_defenses, 0, sizeof(g_defenses));
    memset(g_rate_buckets, 0, sizeof(g_rate_buckets));
    g_defense_count = 0;
    /* Pre-register known defenses */
    defense_find_or_create("syn-cookies");
    defense_find_or_create("rate-limit");
    defense_find_or_create("arp-inspection");
    defense_find_or_create("vlan-strict");
    defense_find_or_create("rst-validation");
    defense_find_or_create("urpf");
    defense_find_or_create("conn-timeout");
    defense_find_or_create("frag-strict");
    defense_find_or_create("icmp-redirect-disable");
    defense_find_or_create("mitm-detect");
    defense_find_or_create("dns-validate");
    defense_find_or_create("covert-detect");
    LOG_INF(MODULE, "Defense module initialized (%d defenses registered)", g_defense_count);
    return 0;
}

int defense_enable(const char *name) {
    int idx = defense_find_or_create(name);
    if (idx < 0) return -1;
    g_defenses[idx].enabled = true;
    LOG_INF(MODULE, "Defense '%s' ENABLED", name);
    return 0;
}

int defense_disable(const char *name) {
    for (int i = 0; i < g_defense_count; i++) {
        if (strcmp(g_defenses[i].name, name) == 0) {
            g_defenses[i].enabled = false;
            LOG_INF(MODULE, "Defense '%s' DISABLED", name);
            return 0;
        }
    }
    return -1;
}

bool defense_is_enabled(const char *name) {
    for (int i = 0; i < g_defense_count; i++) {
        if (strcmp(g_defenses[i].name, name) == 0)
            return g_defenses[i].enabled;
    }
    return false;
}

void defense_dump(void) {
    printf("=== Defense Status ===\n");
    for (int i = 0; i < g_defense_count; i++) {
        printf("  %-20s %s\n", g_defenses[i].name,
               g_defenses[i].enabled ? "ENABLED" : "disabled");
    }
    printf("\n");
}

/* --- SYN Cookies --- */

static uint32_t cookie_hash(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    /* Simple hash for cookie generation (not cryptographic) */
    uint32_t h = a ^ (b << 7) ^ (c << 13) ^ (d << 19);
    h ^= h >> 16;
    h *= 0x45d9f3b;
    h ^= h >> 16;
    return h;
}

uint32_t syncookie_generate(uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port, uint32_t seq) {
    (void)seq;
    uint32_t cookie = cookie_hash(src_ip, dst_ip,
                                  ((uint32_t)src_port << 16) | dst_port,
                                  0xDEADBEEF);
    return cookie;
}

bool syncookie_validate(uint32_t src_ip, uint32_t dst_ip,
                        uint16_t src_port, uint16_t dst_port,
                        uint32_t cookie, uint32_t ack) {
    uint32_t expected = syncookie_generate(src_ip, dst_ip, src_port, dst_port, 0) + 1;
    return (ack == expected);
}

/* --- Rate Limiting --- */

void rate_limit_set(int max_per_sec) {
    g_rate_max = max_per_sec;
    LOG_INF(MODULE, "Rate limit set to %d/s per source", max_per_sec);
}

bool rate_limit_check(uint32_t src_ip) {
    /* Find existing bucket or use empty one */
    int empty = -1;
    for (int i = 0; i < RATE_LIMIT_BUCKETS; i++) {
        if (g_rate_buckets[i].src_ip == src_ip) {
            g_rate_buckets[i].count++;
            return g_rate_buckets[i].count <= g_rate_max;
        }
        if (g_rate_buckets[i].src_ip == 0 && empty < 0) empty = i;
    }
    /* New source */
    if (empty >= 0) {
        g_rate_buckets[empty].src_ip = src_ip;
        g_rate_buckets[empty].count = 1;
        return true;
    }
    return true; /* No bucket available, allow */
}

void rate_limit_tick(void) {
    memset(g_rate_buckets, 0, sizeof(g_rate_buckets));
}
