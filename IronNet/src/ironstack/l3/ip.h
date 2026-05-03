#ifndef IRON_IP_H
#define IRON_IP_H

#include "types.h"
#include <stddef.h>

#define IP_HEADER_MIN_LEN 20
#define IP_VERSION_4      4
#define IP_DEFAULT_TTL    64

typedef struct __attribute__((packed)) {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} ip_header_t;

typedef struct {
    ip_header_t *header;
    uint8_t *payload;
    int payload_len;
    int iface_idx;
} ip_packet_t;

static inline uint8_t ip_get_version(const ip_header_t *h) {
    return (h->version_ihl >> 4) & 0xF;
}

static inline uint8_t ip_get_ihl(const ip_header_t *h) {
    return h->version_ihl & 0xF;
}

static inline int ip_get_header_len(const ip_header_t *h) {
    return ip_get_ihl(h) * 4;
}

int ip_input(uint8_t *data, int len, int iface_idx);
int ip_output(uint32_t src_ip, uint32_t dst_ip, uint8_t protocol,
              const uint8_t *payload, int payload_len);

#endif /* IRON_IP_H */
