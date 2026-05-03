#ifndef IRON_ETH_H
#define IRON_ETH_H

#include "types.h"
#include <stddef.h>

#define ETH_HEADER_LEN   14
#define ETH_MIN_FRAME    60
#define ETH_MAX_FRAME    1514

#define ETHERTYPE_IPV4   0x0800
#define ETHERTYPE_ARP    0x0806

typedef struct __attribute__((packed)) {
    uint8_t  dst_mac[IRON_MAC_LEN];
    uint8_t  src_mac[IRON_MAC_LEN];
    uint16_t ethertype;
} eth_header_t;

typedef struct {
    eth_header_t *header;
    uint8_t *payload;
    int payload_len;
    int iface_idx;
} eth_frame_t;

int eth_parse(const uint8_t *raw, int len, int iface_idx, eth_frame_t *frame);
int eth_build(const uint8_t *dst_mac, const uint8_t *src_mac,
              uint16_t ethertype, const uint8_t *payload, int payload_len,
              uint8_t *out_buf, int out_buf_len);
void eth_dispatch(eth_frame_t *frame);

#endif /* IRON_ETH_H */
