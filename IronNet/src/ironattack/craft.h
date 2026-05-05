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

/* Build a TCP RST frame */
int craft_tcp_rst(uint8_t *buf, int buf_len,
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

/* Build a TCP ACK frame (for slowloris — partial data) */
int craft_tcp_ack(uint8_t *buf, int buf_len,
                  const uint8_t *src_mac, const uint8_t *dst_mac,
                  uint32_t src_ip, uint32_t dst_ip,
                  uint16_t src_port, uint16_t dst_port,
                  uint32_t seq, uint32_t ack_num,
                  const uint8_t *payload, int payload_len);

/* Build an IP fragment (for fragmentation attacks) */
int craft_ip_fragment(uint8_t *buf, int buf_len,
                      const uint8_t *src_mac, const uint8_t *dst_mac,
                      uint32_t src_ip, uint32_t dst_ip,
                      uint16_t id, uint16_t frag_offset, int more_frags,
                      const uint8_t *payload, int payload_len);

/* Build an ICMP redirect frame */
int craft_icmp_redirect(uint8_t *buf, int buf_len,
                        const uint8_t *src_mac, const uint8_t *dst_mac,
                        uint32_t src_ip, uint32_t dst_ip,
                        uint32_t new_gw, uint32_t orig_dst);

/* Open interface for raw packet sending (AF_PACKET) */
int tap_open(const char *name);

/* Write a raw frame */
int tap_write(int fd, const uint8_t *buf, int len);

#endif /* IRON_CRAFT_H */
