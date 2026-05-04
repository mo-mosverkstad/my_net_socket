#ifndef IRON_PROBE_H
#define IRON_PROBE_H

#include "types.h"

#define PROBE_MAX_PORTS    1024
#define PROBE_TIMEOUT_MS   100

typedef enum {
    PORT_OPEN,
    PORT_CLOSED,
    PORT_FILTERED
} port_state_t;

typedef struct {
    uint16_t port;
    port_state_t state;
    char service[32];  /* Fingerprinted service name */
} probe_port_result_t;

typedef struct {
    uint32_t target_ip;
    probe_port_result_t ports[PROBE_MAX_PORTS];
    int port_count;
    int open_count;
    int filtered_count;
    int closed_count;
} probe_scan_result_t;

/* Scan target using internal injection (no real network needed) */
int probe_tcp_scan(uint32_t target_ip, uint16_t port_start, uint16_t port_end,
                   probe_scan_result_t *result);
int probe_icmp_ping(uint32_t target_ip);
int probe_fingerprint(uint32_t target_ip, uint16_t port, char *service_out, int service_len);
int probe_acl_validate(uint32_t target_ip, const uint16_t *expect_open, int open_count,
                       const uint16_t *expect_filtered, int filtered_count,
                       int *mismatches);
void probe_print_result(probe_scan_result_t *result);

#endif /* IRON_PROBE_H */
