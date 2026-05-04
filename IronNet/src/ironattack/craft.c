#include "craft.h"

#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

static uint16_t ip_checksum(const uint8_t *data, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len - 1; i += 2)
        sum += (data[i] << 8) | data[i + 1];
    if (len & 1) sum += data[len - 1] << 8;
    while (sum >> 16) sum = (sum >> 16) + (sum & 0xFFFF);
    return ~sum & 0xFFFF;
}

static uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip,
                             const uint8_t *tcp, int tcp_len) {
    uint32_t sum = 0;
    uint8_t *s = (uint8_t *)&src_ip;
    uint8_t *d = (uint8_t *)&dst_ip;
    sum += (s[0] << 8) | s[1]; sum += (s[2] << 8) | s[3];
    sum += (d[0] << 8) | d[1]; sum += (d[2] << 8) | d[3];
    sum += 6; /* PROTO_TCP */
    sum += tcp_len;
    for (int i = 0; i < tcp_len - 1; i += 2)
        sum += (tcp[i] << 8) | tcp[i + 1];
    if (tcp_len & 1) sum += tcp[tcp_len - 1] << 8;
    while (sum >> 16) sum = (sum >> 16) + (sum & 0xFFFF);
    return ~sum & 0xFFFF;
}

int craft_tcp_syn(uint8_t *buf, int buf_len,
                  const uint8_t *src_mac, const uint8_t *dst_mac,
                  uint32_t src_ip, uint32_t dst_ip,
                  uint16_t src_port, uint16_t dst_port,
                  uint32_t seq) {
    int total = ETH_HLEN + IP_HLEN + TCP_HLEN;
    if (buf_len < total) return -1;
    memset(buf, 0, total);

    /* Ethernet */
    memcpy(buf, dst_mac, 6);
    memcpy(buf + 6, src_mac, 6);
    buf[12] = 0x08; buf[13] = 0x00; /* IPv4 */

    /* IP header */
    uint8_t *ip = buf + ETH_HLEN;
    ip[0] = 0x45; /* version=4, IHL=5 */
    uint16_t ip_total = IP_HLEN + TCP_HLEN;
    ip[2] = (ip_total >> 8) & 0xFF; ip[3] = ip_total & 0xFF;
    ip[8] = 64; /* TTL */
    ip[9] = 6;  /* TCP */
    memcpy(ip + 12, &src_ip, 4);
    memcpy(ip + 16, &dst_ip, 4);
    uint16_t ck = ip_checksum(ip, IP_HLEN);
    ip[10] = (ck >> 8) & 0xFF; ip[11] = ck & 0xFF;

    /* TCP header */
    uint8_t *tcp = buf + ETH_HLEN + IP_HLEN;
    tcp[0] = (src_port >> 8) & 0xFF; tcp[1] = src_port & 0xFF;
    tcp[2] = (dst_port >> 8) & 0xFF; tcp[3] = dst_port & 0xFF;
    tcp[4] = (seq >> 24) & 0xFF; tcp[5] = (seq >> 16) & 0xFF;
    tcp[6] = (seq >> 8) & 0xFF;  tcp[7] = seq & 0xFF;
    tcp[12] = (5 << 4); /* data offset */
    tcp[13] = 0x02;     /* SYN */
    tcp[14] = 0xFF; tcp[15] = 0xFF; /* window */
    uint16_t tck = tcp_checksum(src_ip, dst_ip, tcp, TCP_HLEN);
    tcp[16] = (tck >> 8) & 0xFF; tcp[17] = tck & 0xFF;

    return total;
}

int tap_open(const char *name) {
    /* Use AF_PACKET raw socket to send frames on existing interface */
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) return -1;

    /* Bind to the named interface */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

int tap_write(int fd, const uint8_t *buf, int len) {
    return send(fd, buf, len, 0);
}
