#ifndef IRON_ICMP_H
#define IRON_ICMP_H

#include "types.h"

#define ICMP_TYPE_ECHO_REPLY   0
#define ICMP_TYPE_DEST_UNREACH 3
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_TIME_EXCEED  11

typedef struct __attribute__((packed)) {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
} icmp_header_t;

int icmp_input(uint32_t src_ip, uint32_t dst_ip,
               uint8_t *data, int len, int iface_idx);

#endif /* IRON_ICMP_H */
