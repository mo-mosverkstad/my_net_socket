/*
 * stealth_scan.c — Stealth port scanning (Phase 21a)
 *
 * Implements FIN, XMAS, and NULL scans that evade stateless firewalls:
 *   - FIN scan: send TCP packet with only FIN flag
 *   - XMAS scan: send TCP packet with FIN+PSH+URG flags ("Christmas tree")
 *   - NULL scan: send TCP packet with no flags
 *
 * Interpretation (RFC 793):
 *   - RST received → port is CLOSED
 *   - No response (timeout) → port is OPEN or FILTERED
 *
 * Usage:
 *   sudo ./ironattack stealth-scan --target <ip> --ports <range> --mode fin|xmas|null [--iface <name>]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <poll.h>

#define SCAN_TIMEOUT_MS 500  /* wait 500ms for RST response */

static uint16_t checksum(const void *data, int len) {
    const uint8_t *p = data;
    uint32_t sum = 0;
    for (int i = 0; i < len - 1; i += 2)
        sum += (p[i] << 8) | p[i + 1];
    if (len & 1) sum += p[len - 1] << 8;
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
    sum += 6; /* TCP protocol */
    sum += tcp_len;
    for (int i = 0; i < tcp_len - 1; i += 2)
        sum += (tcp[i] << 8) | tcp[i + 1];
    if (tcp_len & 1) sum += tcp[tcp_len - 1] << 8;
    while (sum >> 16) sum = (sum >> 16) + (sum & 0xFFFF);
    return ~sum & 0xFFFF;
}

/* Send a TCP packet with specified flags and listen for RST response */
static int probe_port(int send_fd, int recv_fd, uint32_t src_ip, uint32_t dst_ip,
                      uint16_t dst_port, uint8_t flags, const char *iface) {
    (void)iface;
    uint8_t pkt[64];
    memset(pkt, 0, sizeof(pkt));
    int ip_total = 40; /* IP(20) + TCP(20) */

    /* IP header */
    pkt[0] = 0x45;
    pkt[2] = 0; pkt[3] = 40;
    pkt[4] = (dst_port >> 8) & 0xFF; pkt[5] = dst_port & 0xFF; /* ID = port */
    pkt[8] = 64; pkt[9] = 6; /* TCP */
    memcpy(pkt + 12, &src_ip, 4);
    memcpy(pkt + 16, &dst_ip, 4);
    uint16_t ip_ck = checksum(pkt, 20);
    pkt[10] = (ip_ck >> 8) & 0xFF; pkt[11] = ip_ck & 0xFF;

    /* TCP header */
    uint8_t *tcp = pkt + 20;
    uint16_t sport = 50000 + (rand() % 10000);
    tcp[0] = (sport >> 8) & 0xFF; tcp[1] = sport & 0xFF;
    tcp[2] = (dst_port >> 8) & 0xFF; tcp[3] = dst_port & 0xFF;
    tcp[4] = 0; tcp[5] = 0; tcp[6] = 0; tcp[7] = 1; /* seq = 1 */
    tcp[12] = (5 << 4); /* data offset = 5 */
    tcp[13] = flags;    /* FIN=0x01, PSH=0x08, URG=0x20, NULL=0x00 */
    tcp[14] = 0x04; tcp[15] = 0x00; /* window = 1024 */
    /* TCP checksum */
    uint16_t tck = tcp_checksum(src_ip, dst_ip, tcp, 20);
    tcp[16] = (tck >> 8) & 0xFF; tcp[17] = tck & 0xFF;

    /* Send */
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = dst_ip;
    sendto(send_fd, pkt, ip_total, 0, (struct sockaddr *)&dst, sizeof(dst));

    /* Wait for RST response */
    struct pollfd pfd = {.fd = recv_fd, .events = POLLIN};
    int ret = poll(&pfd, 1, SCAN_TIMEOUT_MS);

    if (ret > 0) {
        uint8_t buf[128];
        int n = recv(recv_fd, buf, sizeof(buf), 0);
        if (n >= 40) {
            /* Check if it's a TCP RST from the target for our port */
            uint8_t *ip_hdr = buf;
            if (ip_hdr[9] == 6) { /* TCP */
                uint8_t *tcp_resp = ip_hdr + 20;
                uint8_t resp_flags = tcp_resp[13];
                uint16_t resp_sport = (tcp_resp[0] << 8) | tcp_resp[1];
                if ((resp_flags & 0x04) && resp_sport == dst_port) {
                    return 0; /* RST received → CLOSED */
                }
            }
        }
    }

    return 1; /* No RST → OPEN|FILTERED */
}

int cmd_stealth_scan(int argc, char **argv) {
    const char *target_str = NULL;
    const char *ports_str = "7,22,53,80,443,6379,8080,9000,9999";
    const char *mode = "fin";
    const char *iface = "iron0";

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target_str = argv[++i];
        else if (strcmp(argv[i], "--ports") == 0 && i + 1 < argc) ports_str = argv[++i];
        else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) mode = argv[++i];
        else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) iface = argv[++i];
    }

    if (!target_str) {
        fprintf(stderr, "Error: --target required\n");
        fprintf(stderr, "Usage: ironattack stealth-scan --target <ip> [--ports <list>] [--mode fin|xmas|null] [--iface <name>]\n");
        return 1;
    }

    /* Determine flags based on mode */
    uint8_t flags;
    const char *mode_desc;
    if (strcmp(mode, "fin") == 0) {
        flags = 0x01; /* FIN */
        mode_desc = "FIN scan (FIN flag only)";
    } else if (strcmp(mode, "xmas") == 0) {
        flags = 0x29; /* FIN + PSH + URG */
        mode_desc = "XMAS scan (FIN+PSH+URG)";
    } else if (strcmp(mode, "null") == 0) {
        flags = 0x00; /* no flags */
        mode_desc = "NULL scan (no flags)";
    } else {
        fprintf(stderr, "Unknown mode: %s (use fin|xmas|null)\n", mode);
        return 1;
    }

    struct in_addr target_addr;
    if (inet_pton(AF_INET, target_str, &target_addr) != 1) {
        fprintf(stderr, "Error: invalid target IP\n");
        return 1;
    }

    /* Open send socket (raw IP) */
    int send_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (send_fd < 0) {
        fprintf(stderr, "Error: cannot open raw socket (run with sudo)\n");
        return 1;
    }
    int one = 1;
    setsockopt(send_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    setsockopt(send_fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));

    /* Open receive socket (to catch RST responses) */
    int recv_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (recv_fd < 0) {
        close(send_fd);
        fprintf(stderr, "Error: cannot open TCP raw socket\n");
        return 1;
    }
    setsockopt(recv_fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));

    uint32_t src_ip = inet_addr("10.0.1.2");

    printf("=== Stealth Port Scan (Phase 21a) ===\n");
    printf("  Target: %s\n", target_str);
    printf("  Mode:   %s\n", mode_desc);
    printf("  Flags:  0x%02X\n", flags);
    printf("  Iface:  %s\n", iface);
    printf("  Logic:  RST = CLOSED, silence = OPEN|FILTERED\n\n");

    srand(time(NULL));

    /* Parse port list (comma-separated or range) */
    int open_count = 0, closed_count = 0;
    char ports_buf[256];
    strncpy(ports_buf, ports_str, sizeof(ports_buf) - 1);

    printf("  %-8s %-12s\n", "PORT", "STATE");
    printf("  %-8s %-12s\n", "----", "-----");

    char *token = strtok(ports_buf, ",");
    while (token) {
        int port_start, port_end;
        if (strchr(token, '-')) {
            sscanf(token, "%d-%d", &port_start, &port_end);
        } else {
            port_start = port_end = atoi(token);
        }

        for (int port = port_start; port <= port_end && port <= 65535; port++) {
            int result = probe_port(send_fd, recv_fd, src_ip, target_addr.s_addr,
                                    (uint16_t)port, flags, iface);
            if (result == 0) {
                printf("  %-8d CLOSED (RST)\n", port);
                closed_count++;
            } else {
                printf("  %-8d OPEN|FILTERED\n", port);
                open_count++;
            }
        }
        token = strtok(NULL, ",");
    }

    printf("\n  Results: %d open|filtered, %d closed\n", open_count, closed_count);
    printf("\n  Comparison with SYN scan:\n");
    printf("    SYN scan:     SYN+ACK = open,  RST = closed\n");
    printf("    Stealth scan: silence = open,   RST = closed (inverse logic)\n");
    printf("\n  Why stealth: FIN/XMAS/NULL packets don't trigger connection logs\n");
    printf("  in stateless firewalls (only SYN packets are typically logged).\n");

    close(send_fd);
    close(recv_fd);
    return 0;
}
