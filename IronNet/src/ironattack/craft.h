#ifndef IRON_CRAFT_H
#define IRON_CRAFT_H

#include <stdint.h>

#define ETH_HLEN    14
#define IP_HLEN     20
#define TCP_HLEN    20
#define ARP_PKTLEN  28

/* Build a complete TCP SYN frame (Ethernet + IP + TCP) */
int craft_tcp_syn(uint8_t *buf, int buf_len,
                  const uint8_t *src_mac, const uint8_t *dst_mac,
                  uint32_t src_ip, uint32_t dst_ip,
                  uint16_t src_port, uint16_t dst_port,
                  uint32_t seq);

/* Build an ARP reply frame */
int craft_arp_reply(uint8_t *buf, int buf_len,
                    const uint8_t *src_mac, const uint8_t *dst_mac,
                    uint32_t sender_ip, const uint8_t *sender_mac,
                    uint32_t target_ip, const uint8_t *target_mac);

/* Build a double-tagged (Q-in-Q) VLAN hopping frame with ICMP ping inside */
int craft_double_tagged(uint8_t *buf, int buf_len,
                        const uint8_t *src_mac, const uint8_t *dst_mac,
                        uint16_t outer_vlan, uint16_t inner_vlan,
                        uint32_t src_ip, uint32_t dst_ip);

/* Open interface for raw packet sending (AF_PACKET) */
int tap_open(const char *name);

/* Write a raw frame */
int tap_write(int fd, const uint8_t *buf, int len);

#endif /* IRON_CRAFT_H */
