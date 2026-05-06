#include "dns_server.h"
#include "app_socket.h"
#include "log.h"
#include "utils.h"
#include "../ironstack/core/iface.h"

#include <string.h>

#define MODULE "DNS"
#define DNS_PORT 53
#define DNS_MAX_ZONES 16
#define DNS_MAX_NAME  64
#define DNS_MAX_RESPONSE 512

/* DNS header (12 bytes) */
typedef struct __attribute__((packed)) {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

/* Static zone entries */
typedef struct {
    char name[DNS_MAX_NAME];
    uint32_t ip;
    bool active;
} dns_zone_entry_t;

static dns_zone_entry_t g_zones[DNS_MAX_ZONES];
static int g_zone_count = 0;

/* --- DNS Cache --- */
#define DNS_CACHE_MAX 32

typedef struct {
    char name[DNS_MAX_NAME];
    uint32_t ip;
    uint64_t expire_time; /* monotonic seconds when entry expires */
    bool active;
} dns_cache_entry_t;

static dns_cache_entry_t g_dns_cache[DNS_CACHE_MAX];
static int g_dns_cache_count = 0;

static uint64_t dns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec;
}

static dns_cache_entry_t *dns_cache_find(const char *name) {
    uint64_t now = dns_now();
    for (int i = 0; i < g_dns_cache_count; i++) {
        if (g_dns_cache[i].active && strcmp(g_dns_cache[i].name, name) == 0) {
            if (now >= g_dns_cache[i].expire_time) {
                g_dns_cache[i].active = false; /* expired */
                return NULL;
            }
            return &g_dns_cache[i];
        }
    }
    return NULL;
}

void dns_cache_add(const char *name, uint32_t ip, int ttl_sec) {
    /* Overwrite existing */
    for (int i = 0; i < g_dns_cache_count; i++) {
        if (g_dns_cache[i].active && strcmp(g_dns_cache[i].name, name) == 0) {
            g_dns_cache[i].ip = ip;
            g_dns_cache[i].expire_time = dns_now() + ttl_sec;
            return;
        }
    }
    /* Add new */
    if (g_dns_cache_count < DNS_CACHE_MAX) {
        dns_cache_entry_t *e = &g_dns_cache[g_dns_cache_count];
        strncpy(e->name, name, DNS_MAX_NAME - 1);
        e->ip = ip;
        e->expire_time = dns_now() + ttl_sec;
        e->active = true;
        g_dns_cache_count++;
    }
}

void dns_cache_flush(void) {
    memset(g_dns_cache, 0, sizeof(g_dns_cache));
    g_dns_cache_count = 0;
}

void dns_cache_dump(void) {
    uint64_t now = dns_now();
    printf("=== DNS Cache ===\n");
    int active = 0;
    for (int i = 0; i < g_dns_cache_count; i++) {
        dns_cache_entry_t *e = &g_dns_cache[i];
        if (!e->active) continue;
        if (now >= e->expire_time) { e->active = false; continue; }
        char ip_buf[16];
        printf("  %s -> %s (TTL: %lus)\n", e->name,
               iron_ip_to_str(e->ip, ip_buf, sizeof(ip_buf)),
               (unsigned long)(e->expire_time - now));
        active++;
    }
    if (active == 0) printf("  (empty)\n");
    printf("\n");
}

static void dns_add_zone(const char *name, const char *ip_str) {
    if (g_zone_count >= DNS_MAX_ZONES) return;
    dns_zone_entry_t *z = &g_zones[g_zone_count];
    strncpy(z->name, name, DNS_MAX_NAME - 1);
    z->ip = iron_str_to_ip(ip_str);
    z->active = true;
    g_zone_count++;
}

/* Parse DNS name from query (handles length-prefixed labels) */
static int dns_parse_name(const uint8_t *data, int offset, int max_len, char *out, int out_len) {
    int pos = offset;
    int out_pos = 0;

    while (pos < max_len) {
        uint8_t label_len = data[pos];
        if (label_len == 0) { pos++; break; }
        if (label_len > 63) return -1; /* Compression not supported */

        if (out_pos > 0 && out_pos < out_len - 1) out[out_pos++] = '.';

        pos++;
        for (int i = 0; i < label_len && pos < max_len && out_pos < out_len - 1; i++) {
            out[out_pos++] = data[pos++];
        }
    }
    out[out_pos] = 0;
    return pos;
}

/* Find zone entry by name (checks cache first) */
static dns_zone_entry_t *dns_lookup(const char *name) {
    /* Check cache first */
    dns_cache_entry_t *cached = dns_cache_find(name);
    if (cached) {
        /* Return from cache via a static zone entry (reuse pattern) */
        static dns_zone_entry_t cache_result;
        strncpy(cache_result.name, cached->name, DNS_MAX_NAME - 1);
        cache_result.ip = cached->ip;
        cache_result.active = true;
        return &cache_result;
    }

    /* Fall through to zone table */
    for (int i = 0; i < g_zone_count; i++) {
        if (g_zones[i].active && strcmp(g_zones[i].name, name) == 0) {
            /* Add to cache with default TTL of 60s */
            dns_cache_add(name, g_zones[i].ip, 60);
            return &g_zones[i];
        }
    }
    return NULL;
}

/* Public lookup for testing */
uint32_t dns_zone_lookup(const char *name) {
    dns_zone_entry_t *z = dns_lookup(name);
    return z ? z->ip : 0;
}

/* Public add/overwrite for testing (DNS poisoning simulation) */
void dns_zone_add(const char *name, uint32_t ip) {
    /* Check if exists — overwrite */
    for (int i = 0; i < g_zone_count; i++) {
        if (g_zones[i].active && strcmp(g_zones[i].name, name) == 0) {
            g_zones[i].ip = ip;
            return;
        }
    }
    /* Add new */
    if (g_zone_count < DNS_MAX_ZONES) {
        dns_zone_entry_t *z = &g_zones[g_zone_count];
        strncpy(z->name, name, sizeof(z->name) - 1);
        z->ip = ip;
        z->active = true;
        g_zone_count++;
    }
}

/* Build DNS response */
static int dns_build_response(const uint8_t *query, int query_len,
                              uint32_t answer_ip, uint8_t *resp, int resp_max) {
    if (query_len < 12 || resp_max < DNS_MAX_RESPONSE) return -1;

    /* Copy query as base for response */
    int resp_len = query_len;
    if (resp_len > resp_max) return -1;
    memcpy(resp, query, resp_len);

    dns_header_t *hdr = (dns_header_t *)resp;
    /* Set response flags: QR=1, AA=1, RCODE=0 */
    hdr->flags = iron_htons(0x8400);
    hdr->ancount = iron_htons(1);

    /* Append answer: name pointer + type A + class IN + TTL + rdlength + IP */
    uint8_t answer[] = {
        0xC0, 0x0C,             /* Name pointer to offset 12 (question name) */
        0x00, 0x01,             /* Type A */
        0x00, 0x01,             /* Class IN */
        0x00, 0x00, 0x00, 0x3C, /* TTL = 60 seconds */
        0x00, 0x04,             /* RDLENGTH = 4 */
        0, 0, 0, 0             /* IP address (filled below) */
    };
    memcpy(answer + 12, &answer_ip, 4);

    if (resp_len + (int)sizeof(answer) > resp_max) return -1;
    memcpy(resp + resp_len, answer, sizeof(answer));
    resp_len += sizeof(answer);

    return resp_len;
}

/* Build NXDOMAIN response */
static int dns_build_nxdomain(const uint8_t *query, int query_len,
                              uint8_t *resp, int resp_max) {
    if (query_len < 12 || query_len > resp_max) return -1;
    memcpy(resp, query, query_len);

    dns_header_t *hdr = (dns_header_t *)resp;
    /* QR=1, AA=1, RCODE=3 (NXDOMAIN) */
    hdr->flags = iron_htons(0x8403);
    hdr->ancount = 0;

    return query_len;
}

static void dns_on_query(int sock_id, uint32_t src_ip, uint16_t src_port,
                         const uint8_t *data, int data_len) {
    (void)sock_id;

    if (data_len < 12) return; /* Too short for DNS header */

    dns_header_t *qhdr = (dns_header_t *)data;
    uint16_t qdcount = iron_ntohs(qhdr->qdcount);
    if (qdcount == 0) return;

    /* Parse question name */
    char qname[DNS_MAX_NAME];
    int pos = dns_parse_name(data, 12, data_len, qname, sizeof(qname));
    if (pos < 0) return;

    LOG_INF(MODULE, "Query: %s from port %u", qname, src_port);

    /* Lookup */
    dns_zone_entry_t *zone = dns_lookup(qname);

    uint8_t resp[DNS_MAX_RESPONSE];
    int resp_len;

    if (zone) {
        resp_len = dns_build_response(data, data_len, zone->ip, resp, sizeof(resp));
        char ip_buf[16];
        LOG_INF(MODULE, "Response: %s -> %s", qname,
                iron_ip_to_str(zone->ip, ip_buf, sizeof(ip_buf)));
    } else {
        resp_len = dns_build_nxdomain(data, data_len, resp, sizeof(resp));
        LOG_INF(MODULE, "NXDOMAIN: %s", qname);
    }

    if (resp_len <= 0) return;

    /* Send response */
    iface_config_t *ifc = iface_get(0);
    uint32_t local_ip = ifc ? ifc->ip : 0;

    app_socket_send(src_ip, src_port, local_ip, DNS_PORT,
                    PROTO_UDP, resp, resp_len);
}

int dns_server_start(void) {
    /* Load static zone */
    dns_add_zone("example.com", "93.184.216.34");
    dns_add_zone("ironnet.local", "10.0.1.1");
    dns_add_zone("server.ironnet.local", "10.0.2.1");
    dns_add_zone("www.ironnet.local", "10.0.1.100");

    app_socket_listen(PROTO_UDP, DNS_PORT, dns_on_query, NULL, NULL);
    LOG_INF(MODULE, "DNS server started on UDP port %d (%d zones)", DNS_PORT, g_zone_count);
    return 0;
}
