#ifndef IRON_UTILS_H
#define IRON_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <string.h>

/* Byte-order helpers (network = big-endian) */
static inline uint16_t iron_htons(uint16_t h) { return htons(h); }
static inline uint16_t iron_ntohs(uint16_t n) { return ntohs(n); }
static inline uint32_t iron_htonl(uint32_t h) { return htonl(h); }
static inline uint32_t iron_ntohl(uint32_t n) { return ntohl(n); }

/* IP address string conversion */
static inline const char *iron_ip_to_str(uint32_t ip, char *buf, size_t len) {
    uint8_t *b = (uint8_t *)&ip;
    snprintf(buf, len, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return buf;
}

static inline uint32_t iron_str_to_ip(const char *str) {
    struct in_addr addr;
    inet_pton(AF_INET, str, &addr);
    return addr.s_addr;
}

/* Checksum (RFC 1071) */
static inline uint16_t iron_checksum(const void *data, size_t len) {
    const uint16_t *ptr = (const uint16_t *)data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(const uint8_t *)ptr;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

/* Safe memory zero */
static inline void iron_memzero(void *ptr, size_t len) {
    memset(ptr, 0, len);
}

/* Prefix mask from prefix length */
static inline uint32_t iron_prefix_mask(uint8_t prefix_len) {
    if (prefix_len == 0) return 0;
    return htonl(0xFFFFFFFF << (32 - prefix_len));
}

/* Check if IP matches a prefix */
static inline bool iron_ip_matches(uint32_t ip, uint32_t prefix_addr, uint8_t prefix_len) {
    if (prefix_len == 0) return true;
    uint32_t mask = iron_prefix_mask(prefix_len);
    return (ip & mask) == (prefix_addr & mask);
}

#endif /* IRON_UTILS_H */
