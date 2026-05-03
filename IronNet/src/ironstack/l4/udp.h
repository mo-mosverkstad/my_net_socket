#ifndef IRON_UDP_H
#define IRON_UDP_H

#include "types.h"

#define UDP_HEADER_LEN 8

typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_header_t;

int udp_input(uint32_t src_ip, uint32_t dst_ip,
              uint8_t *data, int len, int iface_idx);

#endif /* IRON_UDP_H */
