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
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define SCAN_TIMEOUT_MS  200
#define MAX_PORTS        65535

/* ---- Packet crafting ---- */

static uint16_t checksum(const uint8_t *data, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len - 1; i += 2)
        sum += (data[i] << 8) | data[i + 1];
    if (len & 1) sum += data[len - 1] << 8;
    while (sum >> 16) sum = (sum >> 16) + (sum & 0xFFFF);
    return ~sum & 0xFFFF;
}

static uint16_t tcp_cksum(uint32_t src, uint32_t dst,
                           const uint8_t *tcp, int tcp_len) {
    uint32_t sum = 0;
    uint8_t *s = (uint8_t *)&src, *d = (uint8_t *)&dst;
    sum += (s[0]<<8)|s[1]; sum += (s[2]<<8)|s[3];
    sum += (d[0]<<8)|d[1]; sum += (d[2]<<8)|d[3];
    sum += 6; sum += tcp_len;
    for (int i = 0; i < tcp_len - 1; i += 2)
        sum += (tcp[i] << 8) | tcp[i + 1];
    if (tcp_len & 1) sum += tcp[tcp_len - 1] << 8;
    while (sum >> 16) sum = (sum >> 16) + (sum & 0xFFFF);
    return ~sum & 0xFFFF;
}

/* ---- Port state ---- */

typedef enum { PORT_OPEN, PORT_FILTERED, PORT_CLOSED } port_state_t;

static const char *state_name(port_state_t s) {
    switch (s) {
    case PORT_OPEN:     return "OPEN";
    case PORT_FILTERED: return "FILTERED";
    default:            return "CLOSED";
    }
}

static const char *fingerprint(uint16_t port) {
    switch (port) {
    case 7:    return "echo";
    case 22:   return "ssh";
    case 53:   return "dns";
    case 80:   return "http";
    case 443:  return "https";
    case 6379: return "kv-store";
    case 8080: return "http-alt";
    case 9000: return "rpc";
    default:   return "";
    }
}

/* ---- Scanner ---- */

static void usage(void) {
    fprintf(stderr, "Usage: ironprobe-ext --target <ip> --ports <start>-<end> [--iface <name>]\n");
    fprintf(stderr, "       ironprobe-ext --target <ip> --ports <p1,p2,...> [--iface <name>]\n");
    fprintf(stderr, "\nRequires sudo (raw socket access).\n");
}

int main(int argc, char **argv) {
    const char *target_str = NULL;
    const char *ports_str  = NULL;
    const char *iface      = "iron0";
    uint16_t port_start = 1, port_end = 1024;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) target_str = argv[++i];
        else if (strcmp(argv[i], "--ports") == 0 && i + 1 < argc) ports_str = argv[++i];
        else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) iface = argv[++i];
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(); return 0;
        }
    }

    if (!target_str) { usage(); return 1; }

    struct in_addr dst_addr;
    if (inet_pton(AF_INET, target_str, &dst_addr) != 1) {
        fprintf(stderr, "Invalid target IP: %s\n", target_str); return 1;
    }
    uint32_t dst_ip = dst_addr.s_addr;

    /* Parse port range */
    if (ports_str) {
        char *dash = strchr(ports_str, '-');
        if (dash) {
            port_start = atoi(ports_str);
            port_end   = atoi(dash + 1);
        } else {
            port_start = port_end = atoi(ports_str);
        }
    }
    if (port_end > MAX_PORTS) port_end = MAX_PORTS;

    /* Open raw socket */
    int send_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (send_fd < 0) { perror("socket (need sudo)"); return 1; }
    int one = 1;
    setsockopt(send_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    /* Bind to interface */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    setsockopt(send_fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));

    /* Get our source IP from the interface */
    if (ioctl(send_fd, SIOCGIFADDR, &ifr) < 0) {
        fprintf(stderr, "Cannot get IP for %s (is it up?)\n", iface);
        close(send_fd); return 1;
    }
    uint32_t src_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    char src_str[16];
    inet_ntop(AF_INET, &src_ip, src_str, sizeof(src_str));

    /* Receive socket to catch SYN+ACK responses */
    int recv_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (recv_fd < 0) { perror("recv socket"); close(send_fd); return 1; }
    struct timeval tv = { 0, SCAN_TIMEOUT_MS * 1000 };
    setsockopt(recv_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int total_ports = port_end - port_start + 1;
    port_state_t *results = calloc(total_ports, sizeof(port_state_t));
    for (int i = 0; i < total_ports; i++) results[i] = PORT_FILTERED;

    printf("=== ironprobe-ext: Scanning %s ports %u-%u ===\n\n",
           target_str, port_start, port_end);

    srand(time(NULL));
    uint16_t base_sport = 40000 + (rand() % 10000);

    /* Send SYN packets */
    for (uint16_t port = port_start; port <= port_end; port++) {
        uint8_t pkt[40];
        memset(pkt, 0, sizeof(pkt));

        /* IP header */
        pkt[0] = 0x45; pkt[8] = 64; pkt[9] = 6;
        uint16_t ip_total = 40;
        pkt[2] = (ip_total >> 8) & 0xFF; pkt[3] = ip_total & 0xFF;
        memcpy(pkt + 12, &src_ip, 4);
        memcpy(pkt + 16, &dst_ip, 4);
        uint16_t ck = checksum(pkt, 20);
        pkt[10] = (ck >> 8) & 0xFF; pkt[11] = ck & 0xFF;

        /* TCP header */
        uint8_t *tcp = pkt + 20;
        uint16_t sport = base_sport + (port - port_start);
        tcp[0] = (sport >> 8) & 0xFF; tcp[1] = sport & 0xFF;
        tcp[2] = (port >> 8) & 0xFF;  tcp[3] = port & 0xFF;
        tcp[4] = 0; tcp[5] = 0; tcp[6] = 0; tcp[7] = 1; /* seq=1 */
        tcp[12] = (5 << 4); tcp[13] = 0x02; /* SYN */
        tcp[14] = 0xFF; tcp[15] = 0xFF;
        uint16_t tck = tcp_cksum(src_ip, dst_ip, tcp, 20);
        tcp[16] = (tck >> 8) & 0xFF; tcp[17] = tck & 0xFF;

        struct sockaddr_in dst = { .sin_family = AF_INET, .sin_addr.s_addr = dst_ip };
        sendto(send_fd, pkt, 40, 0, (struct sockaddr *)&dst, sizeof(dst));
        usleep(500);
    }

    /* Collect responses */
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += 1;

    uint8_t rbuf[4096];
    while (1) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec > deadline.tv_sec) break;

        int n = recv(recv_fd, rbuf, sizeof(rbuf), 0);
        if (n < 40) continue;

        uint8_t *rip  = rbuf;
        uint8_t *rtcp = rbuf + 20;
        uint32_t resp_src;
        memcpy(&resp_src, rip + 12, 4);
        if (resp_src != dst_ip) continue;

        uint16_t dport = (rtcp[2] << 8) | rtcp[3];
        uint8_t  flags = rtcp[13];

        if (dport < port_start || dport > port_end) continue;
        int idx = dport - port_start;

        if ((flags & 0x12) == 0x12) /* SYN+ACK */
            results[idx] = PORT_OPEN;
        else if (flags & 0x04) /* RST */
            results[idx] = PORT_CLOSED;
    }

    /* Print results */
    int open = 0, filtered = 0, closed = 0;
    for (int i = 0; i < total_ports; i++) {
        switch (results[i]) {
        case PORT_OPEN:     open++;     break;
        case PORT_FILTERED: filtered++; break;
        case PORT_CLOSED:   closed++;   break;
        }
    }

    printf("  Open: %d  Filtered: %d  Closed: %d\n\n", open, filtered, closed);
    for (int i = 0; i < total_ports; i++) {
        if (results[i] == PORT_OPEN || results[i] == PORT_FILTERED) {
            uint16_t port = port_start + i;
            printf("  %-6u %-10s %s\n", port, state_name(results[i]), fingerprint(port));
        }
    }
    printf("\n");

    free(results);
    close(send_fd);
    close(recv_fd);
    return 0;
}
