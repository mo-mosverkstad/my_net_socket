/*
 * decoy_scan.c — Decoy scanning (Phase 21b)
 *
 * Sends SYN scan packets from the real IP AND multiple decoy IPs.
 * The target sees probes from many sources and can't identify the real attacker.
 *
 * Usage:
 *   sudo ./ironattack decoy-scan --target <ip> --ports <list> \
 *       --decoys <ip1,ip2,ip3> [--iface <name>]
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

#define MAX_DECOYS 8

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
    sum += 6; sum += tcp_len;
    for (int i = 0; i < tcp_len - 1; i += 2)
        sum += (tcp[i] << 8) | tcp[i + 1];
    if (tcp_len & 1) sum += tcp[tcp_len - 1] << 8;
    while (sum >> 16) sum = (sum >> 16) + (sum & 0xFFFF);
    return ~sum & 0xFFFF;
}

static void send_syn(int fd, uint32_t src_ip, uint32_t dst_ip,
                     uint16_t dst_port, const char *iface) {
    (void)iface;
    uint8_t pkt[64];
    memset(pkt, 0, sizeof(pkt));
    int ip_total = 40;

    /* IP header */
    pkt[0] = 0x45;
    pkt[2] = 0; pkt[3] = 40;
    pkt[8] = 64; pkt[9] = 6;
    memcpy(pkt + 12, &src_ip, 4);
    memcpy(pkt + 16, &dst_ip, 4);
    uint16_t ip_ck = checksum(pkt, 20);
    pkt[10] = (ip_ck >> 8) & 0xFF; pkt[11] = ip_ck & 0xFF;

    /* TCP SYN */
    uint8_t *tcp = pkt + 20;
    uint16_t sport = 40000 + (rand() % 20000);
    tcp[0] = (sport >> 8) & 0xFF; tcp[1] = sport & 0xFF;
    tcp[2] = (dst_port >> 8) & 0xFF; tcp[3] = dst_port & 0xFF;
    uint32_t seq = rand();
    tcp[4] = (seq >> 24) & 0xFF; tcp[5] = (seq >> 16) & 0xFF;
    tcp[6] = (seq >> 8) & 0xFF; tcp[7] = seq & 0xFF;
    tcp[12] = (5 << 4);
    tcp[13] = 0x02; /* SYN */
    tcp[14] = 0xFF; tcp[15] = 0xFF;
    uint16_t tck = tcp_checksum(src_ip, dst_ip, tcp, 20);
    tcp[16] = (tck >> 8) & 0xFF; tcp[17] = tck & 0xFF;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = dst_ip;
    sendto(fd, pkt, ip_total, 0, (struct sockaddr *)&dst, sizeof(dst));
}

int cmd_decoy_scan(int argc, char **argv) {
    const char *target_str = NULL;
    const char *ports_str = "7,22,80,9999";
    const char *decoys_str = NULL;
    const char *iface = "iron0";

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target_str = argv[++i];
        else if (strcmp(argv[i], "--ports") == 0 && i + 1 < argc) ports_str = argv[++i];
        else if (strcmp(argv[i], "--decoys") == 0 && i + 1 < argc) decoys_str = argv[++i];
        else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) iface = argv[++i];
    }

    if (!target_str || !decoys_str) {
        fprintf(stderr, "Error: --target and --decoys required\n");
        fprintf(stderr, "Usage: ironattack decoy-scan --target <ip> --decoys <ip1,ip2,...> [--ports <list>] [--iface <name>]\n");
        return 1;
    }

    struct in_addr target_addr;
    if (inet_pton(AF_INET, target_str, &target_addr) != 1) {
        fprintf(stderr, "Error: invalid target IP\n");
        return 1;
    }

    /* Parse decoy IPs */
    uint32_t decoy_ips[MAX_DECOYS];
    int decoy_count = 0;
    char decoys_buf[256];
    strncpy(decoys_buf, decoys_str, sizeof(decoys_buf) - 1);
    char *tok = strtok(decoys_buf, ",");
    while (tok && decoy_count < MAX_DECOYS) {
        struct in_addr a;
        if (inet_pton(AF_INET, tok, &a) == 1) {
            decoy_ips[decoy_count++] = a.s_addr;
        }
        tok = strtok(NULL, ",");
    }

    if (decoy_count == 0) {
        fprintf(stderr, "Error: no valid decoy IPs parsed\n");
        return 1;
    }

    /* Real scanner IP */
    uint32_t real_ip = inet_addr("10.0.1.2");

    /* Open raw socket */
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

    printf("=== Decoy Scanning (Phase 21b) ===\n");
    printf("  Target:   %s\n", target_str);
    printf("  Real IP:  10.0.1.2\n");
    printf("  Decoys:   ");
    for (int i = 0; i < decoy_count; i++) {
        char buf[16];
        struct in_addr a = {.s_addr = decoy_ips[i]};
        inet_ntop(AF_INET, &a, buf, sizeof(buf));
        printf("%s%s", buf, i < decoy_count - 1 ? ", " : "");
    }
    printf("\n  Iface:    %s\n", iface);
    printf("  Strategy: For each port, send SYN from real IP + all decoys (random order)\n");
    printf("            Target sees %d source IPs per port — can't identify the real scanner\n\n", decoy_count + 1);

    srand(time(NULL));

    /* Build array of all source IPs (real + decoys) */
    uint32_t all_ips[MAX_DECOYS + 1];
    int total_ips = decoy_count + 1;
    all_ips[0] = real_ip;
    memcpy(all_ips + 1, decoy_ips, decoy_count * sizeof(uint32_t));

    /* Parse ports and scan */
    char ports_buf[256];
    strncpy(ports_buf, ports_str, sizeof(ports_buf) - 1);

    int total_sent = 0;
    tok = strtok(ports_buf, ",");
    while (tok) {
        int port = atoi(tok);
        if (port <= 0 || port > 65535) { tok = strtok(NULL, ","); continue; }

        /* Shuffle the IP order for this port */
        for (int i = total_ips - 1; i > 0; i--) {
            int j = rand() % (i + 1);
            uint32_t tmp = all_ips[i];
            all_ips[i] = all_ips[j];
            all_ips[j] = tmp;
        }

        printf("  Port %d: SYN from ", port);
        for (int i = 0; i < total_ips; i++) {
            char buf[16];
            struct in_addr a = {.s_addr = all_ips[i]};
            inet_ntop(AF_INET, &a, buf, sizeof(buf));
            int is_real = (all_ips[i] == real_ip);
            printf("%s%s%s", buf, is_real ? "*" : "", i < total_ips - 1 ? ", " : "");
            send_syn(fd, all_ips[i], target_addr.s_addr, (uint16_t)port, iface);
            total_sent++;
            usleep(5000); /* 5ms between packets */
        }
        printf("\n");

        tok = strtok(NULL, ",");
    }

    printf("\n  Total SYN packets sent: %d\n", total_sent);
    printf("  (* = real scanner IP mixed among decoys)\n\n");
    printf("  Target's audit log will show SYN from %d different IPs per port.\n", total_ips);
    printf("  Without additional analysis, defender cannot identify the real scanner.\n");
    printf("\n  To verify: ironctl> show audit-log\n");
    printf("  You'll see connection attempts from all %d IPs.\n", total_ips);

    close(fd);
    return 0;
}
