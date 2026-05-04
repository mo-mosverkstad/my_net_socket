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

/* Open a TAP device by name (returns fd or -1) */
int tap_open(const char *name);

/* Write a raw frame to TAP fd */
int tap_write(int fd, const uint8_t *buf, int len);

#endif /* IRON_CRAFT_H */
