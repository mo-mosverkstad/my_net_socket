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
    /* DNS security: if dns-validate is enabled, reject external cache additions */
    /* (Only internal zone lookups are allowed to populate cache) */
    /* This is checked by the caller — see dns_cache_add_validated() below */

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

/* Secure cache add — checks dns-validate defense */
#include "../ironstack/security/defense.h"
#include "../ironstack/security/covert_detect.h"
#include "../ironmon/audit.h"

int dns_cache_add_secure(const char *name, uint32_t ip, int ttl_sec) {
    if (defense_is_enabled("dns-validate")) {
        /* Only allow if IP matches zone table (trusted source) */
        uint32_t real_ip = 0;
        for (int i = 0; i < g_zone_count; i++) {
            if (g_zones[i].active && strcmp(g_zones[i].name, name) == 0) {
                real_ip = g_zones[i].ip;
                break;
            }
        }
        if (real_ip != 0 && real_ip != ip) {
            char ip_buf[16], real_buf[16];
            printf("[DNS SECURITY] Cache poison BLOCKED: %s -> %s (real: %s)\n",
                   name,
                   iron_ip_to_str(ip, ip_buf, sizeof(ip_buf)),
                   iron_ip_to_str(real_ip, real_buf, sizeof(real_buf)));
            audit_log_event(AUDIT_ACL_DENY, ip, real_ip, 17, 0, 53, "DNS cache poison blocked");
            return -1;
        }
    }
    dns_cache_add(name, ip, ttl_sec);
    return 0;
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

    /* Parse past the question section to find its end */
    /* We only copy header + question, ignoring any additional records (EDNS0 OPT) */
    int pos = 12; /* skip DNS header */
    dns_header_t *qhdr = (dns_header_t *)query;
    uint16_t qdcount = iron_ntohs(qhdr->qdcount);

    for (int q = 0; q < qdcount && pos < query_len; q++) {
        /* Skip QNAME (labels) */
        while (pos < query_len) {
            uint8_t label_len = query[pos];
            if (label_len == 0) { pos++; break; }
            if (label_len >= 0xC0) { pos += 2; break; } /* pointer */
            pos += 1 + label_len;
        }
        pos += 4; /* QTYPE(2) + QCLASS(2) */
    }

    /* Copy only header + question section */
    int resp_len = pos;
    if (resp_len > resp_max) return -1;
    memcpy(resp, query, resp_len);

    dns_header_t *hdr = (dns_header_t *)resp;
    /* Set response flags: QR=1, AA=1, RD=1, RA=1, RCODE=0 */
    hdr->flags = iron_htons(0x8580);
    hdr->ancount = iron_htons(1);
    hdr->nscount = 0;
    hdr->arcount = 0;

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
    if (query_len < 12 || resp_max < DNS_MAX_RESPONSE) return -1;

    /* Parse past question section only */
    int pos = 12;
    dns_header_t *qhdr = (dns_header_t *)query;
    uint16_t qdcount = iron_ntohs(qhdr->qdcount);

    for (int q = 0; q < qdcount && pos < query_len; q++) {
        while (pos < query_len) {
            uint8_t label_len = query[pos];
            if (label_len == 0) { pos++; break; }
            if (label_len >= 0xC0) { pos += 2; break; }
            pos += 1 + label_len;
        }
        pos += 4;
    }

    int resp_len = pos;
    if (resp_len > resp_max) return -1;
    memcpy(resp, query, resp_len);

    dns_header_t *hdr = (dns_header_t *)resp;
    /* QR=1, AA=1, RD=1, RA=1, RCODE=3 (NXDOMAIN) */
    hdr->flags = iron_htons(0x8583);
    hdr->ancount = 0;
    hdr->nscount = 0;
    hdr->arcount = 0;

    return resp_len;
}

/* Parse answer section to extract IP from A record */
static uint32_t dns_parse_answer_ip(const uint8_t *data, int data_len, int ans_offset) {
    int pos = ans_offset;
    /* Skip name (pointer or labels) */
    if (pos >= data_len) return 0;
    if (data[pos] >= 0xC0) pos += 2; /* pointer */
    else {
        while (pos < data_len && data[pos] != 0) pos += 1 + data[pos];
        pos++; /* skip null terminator */
    }
    /* TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA */
    if (pos + 10 > data_len) return 0;
    uint16_t rtype = (data[pos] << 8) | data[pos + 1];
    uint16_t rdlen = (data[pos + 8] << 8) | data[pos + 9];
    pos += 10;
    if (rtype == 1 && rdlen == 4 && pos + 4 <= data_len) { /* Type A */
        uint32_t ip;
        memcpy(&ip, data + pos, 4);
        return ip;
    }
    return 0;
}

static void dns_on_query(int sock_id, uint32_t src_ip, uint16_t src_port,
                         const uint8_t *data, int data_len) {
    (void)sock_id;

    if (data_len < 12) return; /* Too short for DNS header */

    dns_header_t *qhdr = (dns_header_t *)data;
    uint16_t flags = iron_ntohs(qhdr->flags);
    uint16_t qdcount = iron_ntohs(qhdr->qdcount);

    /* Check if this is a RESPONSE (QR=1) — treat as cache update */
    if (flags & 0x8000) {
        /* This is a DNS response arriving on port 53 (simulates recursive resolver
         * accepting upstream responses). Extract answer and cache it. */
        uint16_t ancount = iron_ntohs(qhdr->ancount);
        if (qdcount == 0 || ancount == 0) return;

        char qname[DNS_MAX_NAME];
        int pos = dns_parse_name(data, 12, data_len, qname, sizeof(qname));
        if (pos < 0) return;
        pos += 4; /* skip QTYPE + QCLASS */

        uint32_t answer_ip = dns_parse_answer_ip(data, data_len, pos);
        if (answer_ip == 0) return;

        char ip_buf[16];
        LOG_INF(MODULE, "Received DNS response: %s -> %s (caching)",
                qname, iron_ip_to_str(answer_ip, ip_buf, sizeof(ip_buf)));

        /* Use secure add — dns-validate defense can block this */
        dns_cache_add_secure(qname, answer_ip, 300);
        return;
    }

    /* Normal query (QR=0) */
    if (qdcount == 0) return;

    /* Parse question name */
    char qname[DNS_MAX_NAME];
    int pos = dns_parse_name(data, 12, data_len, qname, sizeof(qname));
    if (pos < 0) return;

    /* Covert channel detection: check DNS label entropy */
    if (defense_is_enabled("covert-detect")) {
        covert_detect_dns(qname, src_ip, iface_get(0) ? iface_get(0)->ip : 0);
    }

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
