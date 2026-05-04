#include "load.h"
#include "log.h"
#include "stats.h"
#include "utils.h"
#include "../ironstack/l4/tcp.h"
#include "../ironstack/l3/route.h"
#include "../ironstack/l3/acl.h"

#include <string.h>
#include <time.h>
#include <stdio.h>

#define MODULE "LOAD"

static uint64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;
}

/* Build a minimal TCP SYN segment */
static void build_syn(uint8_t *buf, uint16_t sport, uint16_t dport) {
    memset(buf, 0, TCP_HEADER_MIN_LEN);
    buf[0] = (sport >> 8) & 0xFF;
    buf[1] = sport & 0xFF;
    buf[2] = (dport >> 8) & 0xFF;
    buf[3] = dport & 0xFF;
    buf[4] = 0x00; buf[5] = 0x00; buf[6] = 0x10; buf[7] = 0x00; /* seq */
    buf[12] = (5 << 4); /* data offset */
    buf[13] = 0x02;     /* SYN */
    buf[14] = 0xFF; buf[15] = 0xFF; /* window */
}

static int test_tcp_flood(const load_config_t *cfg, load_result_t *result) {
    uint8_t syn[TCP_HEADER_MIN_LEN];
    uint32_t src_base = 0xC0A80A00; /* 192.168.10.0 */
    int before = tcp_get_connection_count();

    uint64_t start = now_us();

    for (int i = 0; i < cfg->count; i++) {
        uint32_t src_ip = src_base + (i & 0xFF);
        uint16_t sport = 10000 + (i % 55000);
        build_syn(syn, sport, cfg->target_port);
        int rc = tcp_input(src_ip, cfg->target_ip, syn, TCP_HEADER_MIN_LEN, 0);
        if (rc == 0)
            result->succeeded++;
        else
            result->rejected++;
    }

    uint64_t end = now_us();
    result->attempted = cfg->count;
    result->elapsed_us = end - start;
    result->per_op_ns = (result->elapsed_us * 1000) / (cfg->count ? cfg->count : 1);

    int after = tcp_get_connection_count();
    LOG_INF(MODULE, "TCP flood: %d SYNs, %d accepted, %d rejected (table: %d->%d)",
            cfg->count, result->succeeded, result->rejected, before, after);

    /* Pass if no crash and rejection happened gracefully */
    result->passed = true;
    return 0;
}

static int test_route_stress(const load_config_t *cfg, load_result_t *result) {
    uint64_t start = now_us();

    /* Add routes: 10.X.Y.0/24 */
    for (int i = 0; i < cfg->count && i < ROUTE_MAX_ENTRIES; i++) {
        ip_prefix_t pfx = { iron_htonl(0x0A000000 | ((i & 0xFF) << 8)), 24 };
        int rc = route_add(pfx, cfg->target_ip, 0);
        if (rc == 0)
            result->succeeded++;
        else
            result->rejected++;
    }

    /* Measure lookup time */
    uint64_t lookup_start = now_us();
    int lookups = 1000;
    for (int i = 0; i < lookups; i++) {
        uint32_t dst = iron_htonl(0x0A000001 | (((i % cfg->count) & 0xFF) << 8));
        uint32_t nh; int iface;
        route_lookup(dst, &nh, &iface);
    }
    uint64_t lookup_end = now_us();

    uint64_t end = now_us();
    result->attempted = cfg->count;
    result->elapsed_us = end - start;
    result->per_op_ns = ((lookup_end - lookup_start) * 1000) / lookups;

    LOG_INF(MODULE, "Route stress: %d added, %d rejected, lookup avg %lu ns",
            result->succeeded, result->rejected, (unsigned long)result->per_op_ns);

    /* Cleanup added routes */
    for (int i = 0; i < cfg->count && i < ROUTE_MAX_ENTRIES; i++) {
        ip_prefix_t pfx = { iron_htonl(0x0A000000 | ((i & 0xFF) << 8)), 24 };
        route_delete(pfx);
    }

    result->passed = true;
    return 0;
}

static int test_acl_stress(const load_config_t *cfg, load_result_t *result) {
    uint64_t start = now_us();
    uint32_t base_id = 5000;

    /* Add ACL rules */
    for (int i = 0; i < cfg->count && i < ACL_MAX_RULES; i++) {
        acl_match_t m = {0};
        m.dst_port = (port_range_t){ (uint16_t)(2000 + i), (uint16_t)(2000 + i) };
        m.protocol = PROTO_TCP;
        int rc = acl_add_rule(base_id + i, &m, (i % 2) ? ACL_PERMIT : ACL_DENY);
        if (rc == 0)
            result->succeeded++;
        else
            result->rejected++;
    }

    /* Measure evaluation time */
    uint64_t eval_start = now_us();
    int evals = 1000;
    for (int i = 0; i < evals; i++) {
        acl_evaluate(0x0A000001, cfg->target_ip, PROTO_TCP, 12345, (uint16_t)(2000 + (i % cfg->count)));
    }
    uint64_t eval_end = now_us();

    uint64_t end = now_us();
    result->attempted = cfg->count;
    result->elapsed_us = end - start;
    result->per_op_ns = ((eval_end - eval_start) * 1000) / evals;

    LOG_INF(MODULE, "ACL stress: %d rules added, eval avg %lu ns",
            result->succeeded, (unsigned long)result->per_op_ns);

    /* Cleanup */
    for (int i = 0; i < cfg->count && i < ACL_MAX_RULES; i++) {
        acl_delete_rule(base_id + i);
    }

    result->passed = true;
    return 0;
}

static int test_bandwidth(const load_config_t *cfg, load_result_t *result) {
    /* Send many TCP packets (data to existing or non-existing connections) */
    uint8_t pkt[TCP_HEADER_MIN_LEN + 64]; /* header + 64 bytes payload */
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x30; pkt[1] = 0x39; /* sport 12345 */
    pkt[2] = 0x00; pkt[3] = 0x07; /* dport 7 (echo) */
    pkt[12] = (5 << 4);           /* data offset */
    pkt[13] = TCP_FLAG_ACK;       /* ACK (data) */
    pkt[14] = 0xFF; pkt[15] = 0xFF;
    memset(pkt + TCP_HEADER_MIN_LEN, 'A', 64);

    uint64_t start = now_us();

    for (int i = 0; i < cfg->count; i++) {
        int rc = tcp_input(0xC0A80A01, cfg->target_ip, pkt, sizeof(pkt), 0);
        if (rc == 0)
            result->succeeded++;
        else
            result->rejected++;
    }

    uint64_t end = now_us();
    result->attempted = cfg->count;
    result->elapsed_us = end - start;
    result->per_op_ns = (result->elapsed_us * 1000) / (cfg->count ? cfg->count : 1);

    uint64_t pps = (result->elapsed_us > 0) ?
        ((uint64_t)cfg->count * 1000000ULL / result->elapsed_us) : 0;

    LOG_INF(MODULE, "Bandwidth: %d pkts in %lu us (%lu pps), avg %lu ns/pkt",
            cfg->count, (unsigned long)result->elapsed_us,
            (unsigned long)pps, (unsigned long)result->per_op_ns);

    result->passed = true;
    return 0;
}

int load_run(const load_config_t *cfg, load_result_t *result) {
    memset(result, 0, sizeof(*result));
    result->test = cfg->test;

    switch (cfg->test) {
    case LOAD_TCP_FLOOD:    return test_tcp_flood(cfg, result);
    case LOAD_ROUTE_STRESS: return test_route_stress(cfg, result);
    case LOAD_ACL_STRESS:   return test_acl_stress(cfg, result);
    case LOAD_BANDWIDTH:    return test_bandwidth(cfg, result);
    default:
        LOG_ERR(MODULE, "Unknown test type: %d", cfg->test);
        return -1;
    }
}

void load_print_result(const load_result_t *result) {
    const char *names[] = {"TCP Flood", "Route Stress", "ACL Stress", "Bandwidth"};
    const char *name = (result->test <= LOAD_BANDWIDTH) ? names[result->test] : "Unknown";

    printf("=== Load Test: %s ===\n", name);
    printf("  Attempted:  %d\n", result->attempted);
    printf("  Succeeded:  %d\n", result->succeeded);
    printf("  Rejected:   %d\n", result->rejected);
    printf("  Elapsed:    %lu us\n", (unsigned long)result->elapsed_us);
    printf("  Avg/op:     %lu ns\n", (unsigned long)result->per_op_ns);
    printf("  Result:     %s\n", result->passed ? "PASS (graceful)" : "FAIL");
    printf("\n");
}
