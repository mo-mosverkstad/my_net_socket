#ifndef IRON_ARP_H
#define IRON_ARP_H

#include "types.h"

#define ARP_TABLE_MAX    128
#define ARP_TIMEOUT_SEC  300  /* 5 minutes */

#define ARP_OP_REQUEST   1
#define ARP_OP_REPLY     2

#define ARP_HW_ETHERNET  1
#define ARP_PROTO_IPV4   0x0800

typedef struct __attribute__((packed)) {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t  hw_len;
    uint8_t  proto_len;
    uint16_t opcode;
    uint8_t  sender_mac[6];
    uint32_t sender_ip;
    uint8_t  target_mac[6];
    uint32_t target_ip;
} arp_packet_t;

typedef struct {
    uint32_t ip;
    uint8_t mac[6];
    uint64_t timestamp;
    bool valid;
} arp_entry_t;

int arp_init(void);
int arp_input(uint8_t *data, int len, int iface_idx);
int arp_resolve(uint32_t ip, int iface_idx, uint8_t *mac_out);
void arp_add_entry(uint32_t ip, const uint8_t *mac);
void arp_trust_add(uint32_t ip, const uint8_t *mac);
void arp_timer_tick(void);
void arp_dump(void);
void arp_flush(void);
void arp_set_port_security_max(int max);

#endif /* IRON_ARP_H */
