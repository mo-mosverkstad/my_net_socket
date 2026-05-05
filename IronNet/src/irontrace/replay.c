/*
 * irontrace-replay — Replay pcap captures into the network
 *
 * Usage: sudo ./irontrace-replay --file <pcap> [--iface <name>] [--fast]
 *
 * Modes:
 *   --fast    Inject as fast as possible (no timing)
 *   default   Preserve original inter-packet timing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define PCAP_MAGIC       0xA1B2C3D4
#define PCAP_MAGIC_SWAP  0xD4C3B2A1
#define MAX_PACKET       65535

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
} pcap_global_header_t;

typedef struct __attribute__((packed)) {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_packet_header_t;

static void usage(void) {
    fprintf(stderr, "Usage: irontrace-replay --file <pcap> [--iface <name>] [--fast]\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --file <path>   pcap file to replay\n");
    fprintf(stderr, "  --iface <name>  Interface to inject on (default: iron0)\n");
    fprintf(stderr, "  --fast          Replay at max speed (ignore timing)\n");
    fprintf(stderr, "  --help          Show this help\n");
}

static int open_inject_socket(const char *iface) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    /* Bind to interface so packets go out this specific device */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
    return fd;
}

int main(int argc, char **argv) {
    const char *file = NULL;
    const char *iface = "iron0";
    int fast = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) file = argv[++i];
        else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) iface = argv[++i];
        else if (strcmp(argv[i], "--fast") == 0) fast = 1;
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(); return 0;
        }
    }

    if (!file) { fprintf(stderr, "Error: --file required\n"); usage(); return 1; }

    /* Open pcap file */
    FILE *fp = fopen(file, "rb");
    if (!fp) { fprintf(stderr, "Error: cannot open %s\n", file); return 1; }

    /* Read and validate global header */
    pcap_global_header_t ghdr;
    if (fread(&ghdr, sizeof(ghdr), 1, fp) != 1) {
        fprintf(stderr, "Error: cannot read pcap header\n");
        fclose(fp); return 1;
    }

    if (ghdr.magic != PCAP_MAGIC && ghdr.magic != PCAP_MAGIC_SWAP) {
        fprintf(stderr, "Error: not a valid pcap file (magic=0x%08X)\n", ghdr.magic);
        fclose(fp); return 1;
    }

    printf("╔══════════════════════════════════════════╗\n");
    printf("║     irontrace-replay — Packet Replay     ║\n");
    printf("╚══════════════════════════════════════════╝\n\n");
    printf("  File:      %s\n", file);
    printf("  Interface: %s\n", iface);
    printf("  Mode:      %s\n", fast ? "fast (max speed)" : "timed (original delays)");
    printf("  Linktype:  %u\n\n", ghdr.linktype);

    /* Open socket for injection */
    int fd = open_inject_socket(iface);
    if (fd < 0) {
        fprintf(stderr, "Error: cannot open socket (run with sudo)\n");
        fclose(fp); return 1;
    }

    /* Replay packets */
    uint8_t pkt_buf[MAX_PACKET];
    pcap_packet_header_t phdr;
    int pkt_count = 0;
    int pkt_sent = 0;
    int pkt_errors = 0;
    uint32_t prev_sec = 0, prev_usec = 0;

    struct timespec start_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    while (fread(&phdr, sizeof(phdr), 1, fp) == 1) {
        if (phdr.incl_len > MAX_PACKET) {
            fprintf(stderr, "  Warning: packet %d too large (%u bytes), skipping\n",
                    pkt_count, phdr.incl_len);
            fseek(fp, phdr.incl_len, SEEK_CUR);
            pkt_count++;
            continue;
        }

        if (fread(pkt_buf, 1, phdr.incl_len, fp) != phdr.incl_len) break;
        pkt_count++;

        /* Apply timing delay (if not fast mode) */
        if (!fast && prev_sec != 0) {
            int64_t delay_us = (int64_t)(phdr.ts_sec - prev_sec) * 1000000 +
                               (int64_t)(phdr.ts_usec - prev_usec);
            if (delay_us > 0 && delay_us < 10000000) /* cap at 10s */
                usleep((useconds_t)delay_us);
        }
        prev_sec = phdr.ts_sec;
        prev_usec = phdr.ts_usec;

        /* Inject packet — strip Ethernet header, send IP via raw socket */
        int eth_hlen = 14;
        if ((int)phdr.incl_len <= eth_hlen) { pkt_errors++; continue; }

        /* Check ethertype — only replay IPv4 packets */
        uint16_t ethertype = (pkt_buf[12] << 8) | pkt_buf[13];
        if (ethertype != 0x0800) { pkt_sent++; continue; } /* skip ARP etc */

        const uint8_t *ip_pkt = pkt_buf + eth_hlen;
        int ip_len = phdr.incl_len - eth_hlen;

        struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        if (ip_len >= 20)
            memcpy(&dst.sin_addr.s_addr, ip_pkt + 16, 4);

        int rc = sendto(fd, ip_pkt, ip_len, 0,
                        (struct sockaddr *)&dst, sizeof(dst));
        if (rc > 0)
            pkt_sent++;
        else
            pkt_errors++;
    }

    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double elapsed = (end_time.tv_sec - start_time.tv_sec) +
                     (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

    printf("  Replay complete:\n");
    printf("    Packets read:   %d\n", pkt_count);
    printf("    Packets sent:   %d\n", pkt_sent);
    printf("    Errors:         %d\n", pkt_errors);
    printf("    Elapsed:        %.2f s\n", elapsed);
    if (elapsed > 0)
        printf("    Rate:           %.0f pps\n", pkt_sent / elapsed);
    printf("\n");

    close(fd);
    fclose(fp);
    return 0;
}
