/*
 * ironsim-test — Traffic Generator & Report for ironsim topologies
 *
 * Runs ping and TCP tests against nodes in a running ironsim topology.
 * Produces a formatted report with latency, loss, and throughput metrics.
 *
 * Usage: sudo ./ironsim-test [options]
 *   --target <ip>     Target node IP to test
 *   --all             Test all common IPs (10.0.1.1, 10.0.1.254, 10.0.2.254, 10.0.2.1)
 *   --count <n>       Number of pings (default: 10)
 *   --tcp <port>      Also test TCP connectivity to port
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>

#define MAX_TARGETS  8
#define PING_TIMEOUT_MS 1000

typedef struct {
    char ip[32];
    int  sent;
    int  received;
    double rtt_min;
    double rtt_max;
    double rtt_sum;
    int  tcp_open;   /* -1=not tested, 0=closed, 1=open */
    int  tcp_port;
} test_result_t;

static test_result_t g_results[MAX_TARGETS];
static int g_result_count = 0;

/* ---- Ping using system ping command (simplest, works without raw socket) ---- */

static void run_ping_test(test_result_t *r, int count) {
    char cmd[256];
    char line[256];

    /* Use system ping with parseable output */
    snprintf(cmd, sizeof(cmd),
             "ping -c %d -W 1 -q %s 2>/dev/null", count, r->ip);

    FILE *p = popen(cmd, "r");
    if (!p) { r->sent = count; r->received = 0; return; }

    r->sent = count;
    r->received = 0;
    r->rtt_min = r->rtt_max = r->rtt_sum = 0;

    while (fgets(line, sizeof(line), p)) {
        /* Parse: "X packets transmitted, Y received, Z% packet loss" */
        int tx, rx;
        if (sscanf(line, "%d packets transmitted, %d received", &tx, &rx) == 2) {
            r->sent = tx;
            r->received = rx;
        }
        /* Parse: "rtt min/avg/max/mdev = 5.1/6.2/7.3/0.5 ms" */
        double mn, avg, mx;
        if (sscanf(line, "rtt min/avg/max/mdev = %lf/%lf/%lf", &mn, &avg, &mx) == 3) {
            r->rtt_min = mn;
            r->rtt_max = mx;
            r->rtt_sum = avg * r->received;
        }
    }
    pclose(p);
}

/* ---- TCP connectivity test ---- */

static int test_tcp_connect(const char *ip, int port, int timeout_ms) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;

    /* Non-blocking connect with timeout */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0) { close(fd); return 1; }
    if (errno != EINPROGRESS) { close(fd); return 0; }

    /* Wait for connection */
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };

    rc = select(fd + 1, NULL, &wfds, NULL, &tv);
    if (rc > 0) {
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
        close(fd);
        return (err == 0) ? 1 : 0;
    }

    close(fd);
    return 0;
}

/* ---- Report ---- */

static void print_report(int tcp_port) {
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║            ironsim-test — Topology Test Report               ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    printf("  %-16s %5s %5s %6s %8s %8s %8s",
           "Target", "Sent", "Recv", "Loss%", "Min(ms)", "Avg(ms)", "Max(ms)");
    if (tcp_port > 0) printf("  TCP/%d", tcp_port);
    printf("\n");

    printf("  %-16s %5s %5s %6s %8s %8s %8s",
           "----------------", "-----", "-----", "------", "--------", "--------", "--------");
    if (tcp_port > 0) printf("  ------");
    printf("\n");

    int total_sent = 0, total_recv = 0;

    for (int i = 0; i < g_result_count; i++) {
        test_result_t *r = &g_results[i];
        double loss = (r->sent > 0) ? 100.0 * (r->sent - r->received) / r->sent : 100.0;
        double avg = (r->received > 0) ? r->rtt_sum / r->received : 0;

        printf("  %-16s %5d %5d %5.1f%% %7.1fms %7.1fms %7.1fms",
               r->ip, r->sent, r->received, loss,
               r->rtt_min, avg, r->rtt_max);

        if (tcp_port > 0) {
            if (r->tcp_open == 1) printf("  OPEN");
            else if (r->tcp_open == 0) printf("  CLOSED");
            else printf("  -");
        }
        printf("\n");

        total_sent += r->sent;
        total_recv += r->received;
    }

    printf("\n  Summary: %d targets, %d/%d packets received (%.1f%% overall loss)\n\n",
           g_result_count, total_recv, total_sent,
           (total_sent > 0) ? 100.0 * (total_sent - total_recv) / total_sent : 0);
}

/* ---- Main ---- */

static void usage(void) {
    fprintf(stderr, "Usage: ironsim-test [options]\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --target <ip>   Add target IP to test\n");
    fprintf(stderr, "  --all           Test standard 3-node IPs (10.0.1.1, 10.0.1.254, 10.0.2.254, 10.0.2.1)\n");
    fprintf(stderr, "  --count <n>     Number of pings per target (default: 10)\n");
    fprintf(stderr, "  --tcp <port>    Also test TCP connectivity to this port\n");
    fprintf(stderr, "  --help          Show this help\n");
}

int main(int argc, char **argv) {
    int count = 10;
    int tcp_port = 0;
    int use_all = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) {
            if (g_result_count < MAX_TARGETS) {
                strncpy(g_results[g_result_count].ip, argv[++i], 31);
                g_results[g_result_count].tcp_open = -1;
                g_result_count++;
            }
        } else if (strcmp(argv[i], "--all") == 0) {
            use_all = 1;
        } else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--tcp") == 0 && i + 1 < argc) {
            tcp_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(); return 0;
        }
    }

    if (use_all) {
        const char *ips[] = {"10.0.1.1", "10.0.1.254", "10.0.2.254", "10.0.2.1"};
        g_result_count = 0;
        for (int i = 0; i < 4; i++) {
            strcpy(g_results[i].ip, ips[i]);
            g_results[i].tcp_open = -1;
            g_result_count++;
        }
    }

    if (g_result_count == 0) {
        fprintf(stderr, "Error: no targets specified. Use --target <ip> or --all\n");
        usage();
        return 1;
    }

    printf("  [ironsim-test] Testing %d targets, %d pings each", g_result_count, count);
    if (tcp_port > 0) printf(", TCP port %d", tcp_port);
    printf("\n\n");

    /* Run ping tests */
    for (int i = 0; i < g_result_count; i++) {
        printf("  Pinging %s...\n", g_results[i].ip);
        run_ping_test(&g_results[i], count);
    }

    /* Run TCP tests */
    if (tcp_port > 0) {
        printf("  Testing TCP/%d...\n", tcp_port);
        for (int i = 0; i < g_result_count; i++) {
            g_results[i].tcp_port = tcp_port;
            g_results[i].tcp_open = test_tcp_connect(g_results[i].ip, tcp_port, 2000);
        }
    }

    /* Print report */
    print_report(tcp_port);

    return 0;
}
