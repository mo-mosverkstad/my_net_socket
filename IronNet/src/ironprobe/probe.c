#include "probe.h"
#include "log.h"
#include "stats.h"
#include "utils.h"
#include "../ironstack/l3/ip.h"
#include "../ironstack/l3/acl.h"
#include "../ironstack/l4/tcp.h"
#include "../ironapps/app_socket.h"

#include <stdio.h>
#include <string.h>

#define MODULE "PROBE"

/*
 * Internal scanning: we simulate a scan by checking if the stack would
 * accept a connection on a given port. This works by:
 * 1. Checking if an app listener exists (port is open)
 * 2. Checking if ACL would deny the traffic (port is filtered)
 * 3. Otherwise port is closed (no listener, but ACL permits)
 */

static port_state_t probe_check_port(uint32_t target_ip, uint16_t port) {
    /* First check: is the target IP actually local (belongs to this router)? */
    extern bool iface_is_local_ip(uint32_t ip);
    if (!iface_is_local_ip(target_ip)) {
        return PORT_CLOSED; /* Remote host — can't scan internally */
    }

    /* Check ACL first — would traffic to this port be denied? */
    uint32_t src_ip = iron_str_to_ip("10.0.1.2"); /* Simulated scanner IP */
    acl_action_t acl = acl_evaluate(src_ip, target_ip, PROTO_TCP, 50000, port);
    if (acl == ACL_DENY) {
        return PORT_FILTERED;
    }

    /* Check if an application is listening */
    app_listener_t *listener = app_find_listener(PROTO_TCP, port);
    if (listener) {
        return PORT_OPEN;
    }

    /* Also check UDP */
    listener = app_find_listener(PROTO_UDP, port);
    if (listener) {
        return PORT_OPEN;
    }

    return PORT_CLOSED;
}

int probe_tcp_scan(uint32_t target_ip, uint16_t port_start, uint16_t port_end,
                   probe_scan_result_t *result) {
    memset(result, 0, sizeof(*result));
    result->target_ip = target_ip;

    char ip_buf[16];
    LOG_INF(MODULE, "Scanning %s ports %u-%u",
            iron_ip_to_str(target_ip, ip_buf, sizeof(ip_buf)), port_start, port_end);

    int idx = 0;
    for (uint16_t port = port_start; port <= port_end && idx < PROBE_MAX_PORTS; port++) {
        port_state_t state = probe_check_port(target_ip, port);

        if (state == PORT_OPEN || state == PORT_FILTERED) {
            result->ports[idx].port = port;
            result->ports[idx].state = state;
            result->ports[idx].service[0] = 0;

            if (state == PORT_OPEN) {
                probe_fingerprint(target_ip, port, result->ports[idx].service, 32);
                result->open_count++;
            } else {
                result->filtered_count++;
            }
            idx++;
        } else {
            result->closed_count++;
        }
    }

    result->port_count = idx;
    LOG_INF(MODULE, "Scan complete: %d open, %d filtered, %d closed",
            result->open_count, result->filtered_count, result->closed_count);
    return 0;
}

int probe_icmp_ping(uint32_t target_ip) {
    /* Check if target IP is a local interface (would respond to ping) */
    extern bool iface_is_local_ip(uint32_t ip);
    if (iface_is_local_ip(target_ip)) {
        return 0; /* Alive */
    }
    return -1; /* No response (not a local IP) */
}

int probe_fingerprint(uint32_t target_ip, uint16_t port, char *service_out, int service_len) {
    (void)target_ip;

    /* Fingerprint based on known port assignments */
    switch (port) {
    case 7:   strncpy(service_out, "echo", service_len); break;
    case 53:  strncpy(service_out, "dns", service_len); break;
    case 6379: strncpy(service_out, "kv-store", service_len); break;
    case 8080: strncpy(service_out, "http", service_len); break;
    case 9000: strncpy(service_out, "rpc", service_len); break;
    default:  strncpy(service_out, "unknown", service_len); break;
    }
    return 0;
}

int probe_acl_validate(uint32_t target_ip, const uint16_t *expect_open, int open_count,
                       const uint16_t *expect_filtered, int filtered_count,
                       int *mismatches) {
    *mismatches = 0;

    for (int i = 0; i < open_count; i++) {
        port_state_t state = probe_check_port(target_ip, expect_open[i]);
        if (state != PORT_OPEN) {
            LOG_WRN(MODULE, "ACL mismatch: port %u expected OPEN, got %s",
                    expect_open[i], state == PORT_FILTERED ? "FILTERED" : "CLOSED");
            (*mismatches)++;
        }
    }

    for (int i = 0; i < filtered_count; i++) {
        port_state_t state = probe_check_port(target_ip, expect_filtered[i]);
        if (state != PORT_FILTERED) {
            LOG_WRN(MODULE, "ACL mismatch: port %u expected FILTERED, got %s",
                    expect_filtered[i], state == PORT_OPEN ? "OPEN" : "CLOSED");
            (*mismatches)++;
        }
    }

    LOG_INF(MODULE, "ACL validation: %d mismatches", *mismatches);
    return *mismatches == 0 ? 0 : -1;
}

void probe_print_result(probe_scan_result_t *result) {
    char ip_buf[16];
    printf("=== Scan Results for %s ===\n",
           iron_ip_to_str(result->target_ip, ip_buf, sizeof(ip_buf)));
    printf("  Open: %d  Filtered: %d  Closed: %d\n\n",
           result->open_count, result->filtered_count, result->closed_count);

    for (int i = 0; i < result->port_count; i++) {
        probe_port_result_t *p = &result->ports[i];
        const char *state_str = p->state == PORT_OPEN ? "OPEN" :
                                p->state == PORT_FILTERED ? "FILTERED" : "CLOSED";
        printf("  %-6u %-10s %s\n", p->port, state_str, p->service);
    }
    printf("\n");
}
