#include "craft.h"

#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
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

int craft_tcp_rst(uint8_t *buf, int buf_len,
                  const uint8_t *src_mac, const uint8_t *dst_mac,
                  uint32_t src_ip, uint32_t dst_ip,
                  uint16_t src_port, uint16_t dst_port,
                  uint32_t seq) {
    int total = ETH_HLEN + IP_HLEN + TCP_HLEN;
    if (buf_len < total) return -1;
    memset(buf, 0, total);

    memcpy(buf, dst_mac, 6);
    memcpy(buf + 6, src_mac, 6);
    buf[12] = 0x08; buf[13] = 0x00;

    uint8_t *ip = buf + ETH_HLEN;
    ip[0] = 0x45;
    uint16_t ip_total = IP_HLEN + TCP_HLEN;
    ip[2] = (ip_total >> 8) & 0xFF; ip[3] = ip_total & 0xFF;
    ip[8] = 64; ip[9] = 6;
    memcpy(ip + 12, &src_ip, 4);
    memcpy(ip + 16, &dst_ip, 4);
    uint16_t ck = ip_checksum(ip, IP_HLEN);
    ip[10] = (ck >> 8) & 0xFF; ip[11] = ck & 0xFF;

    uint8_t *tcp = buf + ETH_HLEN + IP_HLEN;
    tcp[0] = (src_port >> 8) & 0xFF; tcp[1] = src_port & 0xFF;
    tcp[2] = (dst_port >> 8) & 0xFF; tcp[3] = dst_port & 0xFF;
    tcp[4] = (seq >> 24) & 0xFF; tcp[5] = (seq >> 16) & 0xFF;
    tcp[6] = (seq >> 8) & 0xFF;  tcp[7] = seq & 0xFF;
    tcp[12] = (5 << 4);
    tcp[13] = 0x04; /* RST */
    tcp[14] = 0xFF; tcp[15] = 0xFF;
    uint16_t tck = tcp_checksum(src_ip, dst_ip, tcp, TCP_HLEN);
    tcp[16] = (tck >> 8) & 0xFF; tcp[17] = tck & 0xFF;

    return total;
}

int craft_arp_reply(uint8_t *buf, int buf_len,
                    const uint8_t *src_mac, const uint8_t *dst_mac,
                    uint32_t sender_ip, const uint8_t *sender_mac,
                    uint32_t target_ip, const uint8_t *target_mac) {
    int total = ETH_HLEN + ARP_PKTLEN;
    if (buf_len < total) return -1;
    memset(buf, 0, total);

    memcpy(buf, dst_mac, 6);
    memcpy(buf + 6, src_mac, 6);
    buf[12] = 0x08; buf[13] = 0x06;

    uint8_t *arp = buf + ETH_HLEN;
    arp[0] = 0x00; arp[1] = 0x01;
    arp[2] = 0x08; arp[3] = 0x00;
    arp[4] = 6; arp[5] = 4;
    arp[6] = 0x00; arp[7] = 0x02;
    memcpy(arp + 8, sender_mac, 6);
    memcpy(arp + 14, &sender_ip, 4);
    memcpy(arp + 18, target_mac, 6);
    memcpy(arp + 24, &target_ip, 4);

    return total;
}

int craft_double_tagged(uint8_t *buf, int buf_len,
                        const uint8_t *src_mac, const uint8_t *dst_mac,
                        uint16_t outer_vlan, uint16_t inner_vlan,
                        uint32_t src_ip, uint32_t dst_ip) {
    int total = 14 + 4 + 4 + 20 + 8; /* eth + 2 tags + ip + icmp */
    if (buf_len < total) return -1;
    memset(buf, 0, total);

    memcpy(buf, dst_mac, 6);
    memcpy(buf + 6, src_mac, 6);
    buf[12] = 0x81; buf[13] = 0x00;
    buf[14] = (outer_vlan >> 8) & 0x0F; buf[15] = outer_vlan & 0xFF;
    buf[16] = 0x81; buf[17] = 0x00;
    buf[18] = (inner_vlan >> 8) & 0x0F; buf[19] = inner_vlan & 0xFF;
    buf[20] = 0x08; buf[21] = 0x00;

    uint8_t *ip = buf + 22;
    ip[0] = 0x45;
    uint16_t ip_total = 28;
    ip[2] = (ip_total >> 8) & 0xFF; ip[3] = ip_total & 0xFF;
    ip[8] = 64; ip[9] = 1;
    memcpy(ip + 12, &src_ip, 4);
    memcpy(ip + 16, &dst_ip, 4);
    uint16_t ck = ip_checksum(ip, 20);
    ip[10] = (ck >> 8) & 0xFF; ip[11] = ck & 0xFF;

    uint8_t *icmp = ip + 20;
    icmp[0] = 8; icmp[4] = 0x00; icmp[5] = 0x01; icmp[6] = 0x00; icmp[7] = 0x01;
    uint16_t icmp_ck = ip_checksum(icmp, 8);
    icmp[2] = (icmp_ck >> 8) & 0xFF; icmp[3] = icmp_ck & 0xFF;

    return total;
}

int craft_tcp_ack(uint8_t *buf, int buf_len,
                  const uint8_t *src_mac, const uint8_t *dst_mac,
                  uint32_t src_ip, uint32_t dst_ip,
                  uint16_t src_port, uint16_t dst_port,
                  uint32_t seq, uint32_t ack_num,
                  const uint8_t *payload, int payload_len) {
    int total = ETH_HLEN + IP_HLEN + TCP_HLEN + payload_len;
    if (buf_len < total) return -1;
    memset(buf, 0, ETH_HLEN + IP_HLEN + TCP_HLEN);

    memcpy(buf, dst_mac, 6);
    memcpy(buf + 6, src_mac, 6);
    buf[12] = 0x08; buf[13] = 0x00;

    uint8_t *ip = buf + ETH_HLEN;
    ip[0] = 0x45;
    uint16_t ip_total = IP_HLEN + TCP_HLEN + payload_len;
    ip[2] = (ip_total >> 8) & 0xFF; ip[3] = ip_total & 0xFF;
    ip[8] = 64; ip[9] = 6;
    memcpy(ip + 12, &src_ip, 4);
    memcpy(ip + 16, &dst_ip, 4);
    uint16_t ck = ip_checksum(ip, IP_HLEN);
    ip[10] = (ck >> 8) & 0xFF; ip[11] = ck & 0xFF;

    uint8_t *tcp = buf + ETH_HLEN + IP_HLEN;
    tcp[0] = (src_port >> 8) & 0xFF; tcp[1] = src_port & 0xFF;
    tcp[2] = (dst_port >> 8) & 0xFF; tcp[3] = dst_port & 0xFF;
    tcp[4] = (seq >> 24) & 0xFF; tcp[5] = (seq >> 16) & 0xFF;
    tcp[6] = (seq >> 8) & 0xFF;  tcp[7] = seq & 0xFF;
    uint32_t ack_n = ack_num;
    tcp[8] = (ack_n >> 24) & 0xFF; tcp[9] = (ack_n >> 16) & 0xFF;
    tcp[10] = (ack_n >> 8) & 0xFF; tcp[11] = ack_n & 0xFF;
    tcp[12] = (5 << 4);
    tcp[13] = 0x18; /* ACK + PSH */
    tcp[14] = 0xFF; tcp[15] = 0xFF;
    if (payload_len > 0)
        memcpy(buf + ETH_HLEN + IP_HLEN + TCP_HLEN, payload, payload_len);
    uint16_t tck = tcp_checksum(src_ip, dst_ip, tcp, TCP_HLEN + payload_len);
    tcp[16] = (tck >> 8) & 0xFF; tcp[17] = tck & 0xFF;

    return total;
}

int craft_ip_fragment(uint8_t *buf, int buf_len,
                      const uint8_t *src_mac, const uint8_t *dst_mac,
                      uint32_t src_ip, uint32_t dst_ip,
                      uint16_t id, uint16_t frag_offset, int more_frags,
                      const uint8_t *payload, int payload_len) {
    int total = ETH_HLEN + IP_HLEN + payload_len;
    if (buf_len < total) return -1;
    memset(buf, 0, ETH_HLEN + IP_HLEN);

    memcpy(buf, dst_mac, 6);
    memcpy(buf + 6, src_mac, 6);
    buf[12] = 0x08; buf[13] = 0x00;

    uint8_t *ip = buf + ETH_HLEN;
    ip[0] = 0x45;
    uint16_t ip_total = IP_HLEN + payload_len;
    ip[2] = (ip_total >> 8) & 0xFF; ip[3] = ip_total & 0xFF;
    ip[4] = (id >> 8) & 0xFF; ip[5] = id & 0xFF;
    uint16_t flags_frag = (frag_offset / 8) & 0x1FFF;
    if (more_frags) flags_frag |= 0x2000;
    ip[6] = (flags_frag >> 8) & 0xFF; ip[7] = flags_frag & 0xFF;
    ip[8] = 64; ip[9] = 6; /* TCP */
    memcpy(ip + 12, &src_ip, 4);
    memcpy(ip + 16, &dst_ip, 4);
    uint16_t ck = ip_checksum(ip, IP_HLEN);
    ip[10] = (ck >> 8) & 0xFF; ip[11] = ck & 0xFF;

    memcpy(buf + ETH_HLEN + IP_HLEN, payload, payload_len);
    return total;
}

int craft_icmp_redirect(uint8_t *buf, int buf_len,
                        const uint8_t *src_mac, const uint8_t *dst_mac,
                        uint32_t src_ip, uint32_t dst_ip,
                        uint32_t new_gw, uint32_t orig_dst) {
    /* Eth(14) + IP(20) + ICMP redirect(8) + embedded IP hdr(20) = 62 */
    int total = ETH_HLEN + IP_HLEN + 8 + IP_HLEN;
    if (buf_len < total) return -1;
    memset(buf, 0, total);

    memcpy(buf, dst_mac, 6);
    memcpy(buf + 6, src_mac, 6);
    buf[12] = 0x08; buf[13] = 0x00;

    uint8_t *ip = buf + ETH_HLEN;
    ip[0] = 0x45;
    uint16_t ip_total = IP_HLEN + 8 + IP_HLEN;
    ip[2] = (ip_total >> 8) & 0xFF; ip[3] = ip_total & 0xFF;
    ip[8] = 64; ip[9] = 1; /* ICMP */
    memcpy(ip + 12, &src_ip, 4);
    memcpy(ip + 16, &dst_ip, 4);
    uint16_t ck = ip_checksum(ip, IP_HLEN);
    ip[10] = (ck >> 8) & 0xFF; ip[11] = ck & 0xFF;

    /* ICMP redirect: type=5, code=1 (host redirect) */
    uint8_t *icmp = ip + IP_HLEN;
    icmp[0] = 5; icmp[1] = 1; /* type=5 redirect, code=1 host */
    memcpy(icmp + 4, &new_gw, 4); /* new gateway */
    /* Embedded original IP header pointing to orig_dst */
    uint8_t *emb = icmp + 8;
    emb[0] = 0x45; emb[8] = 64; emb[9] = 6;
    uint16_t emb_total = 40; /* IP + TCP header */
    emb[2] = (emb_total >> 8) & 0xFF; emb[3] = emb_total & 0xFF;
    memcpy(emb + 12, &src_ip, 4);   /* src = original sender (router) */
    memcpy(emb + 16, &orig_dst, 4); /* dst = original destination */
    uint16_t eck = ip_checksum(emb, IP_HLEN);
    emb[10] = (eck >> 8) & 0xFF; emb[11] = eck & 0xFF;
    /* ICMP checksum over redirect header + embedded IP */
    uint16_t ick = ip_checksum(icmp, 8 + IP_HLEN);
    icmp[2] = (ick >> 8) & 0xFF; icmp[3] = ick & 0xFF;

    return total;
}

int tap_open(const char *name) {
    /* Try raw IP socket first (packets go through kernel routing to TAP) */
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd >= 0) {
        int one = 1;
        setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        /* Bind to interface */
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
        return fd;
    }
    return -1;
}

int tap_write(int fd, const uint8_t *buf, int len) {
    /* Skip Ethernet header (14 bytes) — raw IP socket sends IP packets */
    if (len <= ETH_HLEN) return -1;
    const uint8_t *ip_pkt = buf + ETH_HLEN;
    int ip_len = len - ETH_HLEN;

    /* Extract destination IP from IP header for sendto */
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    memcpy(&dst.sin_addr.s_addr, ip_pkt + 16, 4); /* dst IP at offset 16 */

    return sendto(fd, ip_pkt, ip_len, 0, (struct sockaddr *)&dst, sizeof(dst));
}
