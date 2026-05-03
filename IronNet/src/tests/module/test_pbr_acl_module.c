#include <stdio.h>
#include <string.h>
#include "module_test.h"
#include "stats.h"
#include "utils.h"

/* Stubs for vnic */
#include "../ironstack/io/vnic.h"

static uint8_t g_last_tx_buf[2048];
static int g_last_tx_len = 0;
static int g_last_tx_iface = -1;

static uint8_t g_fake_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static vnic_t g_fake_vnic = { .name = "veth0", .fd = -1, .active = true };

int vnic_init(void) { return 0; }
void vnic_shutdown(void) {}
int vnic_create(const char *n, uint8_t m[6]) { (void)n; (void)m; return 0; }
int vnic_read(int i, uint8_t *b, int l) { (void)i; (void)b; (void)l; return -1; }
int vnic_write(int i, const uint8_t *b, int l) {
    g_last_tx_iface = i;
    memcpy(g_last_tx_buf, b, l);
    g_last_tx_len = l;
    return l;
}
int vnic_inject(int i, const uint8_t *b, int l) { return vnic_write(i, b, l); }
int vnic_get_count(void) { return 1; }
vnic_t *vnic_get(int i) { (void)i; memcpy(g_fake_vnic.mac, g_fake_mac, 6); return &g_fake_vnic; }

#include "../ironstack/l2/eth.h"
#include "../ironstack/l2/eth.c"
#include "../ironstack/l3/route.h"
#include "../ironstack/l3/route.c"
#include "../ironstack/l3/acl.h"
#include "../ironstack/l3/acl.c"
#include "../ironstack/l3/pbr.h"
#include "../ironstack/l3/pbr.c"
#include "../ironstack/l3/icmp.h"
#include "../ironstack/l3/icmp.c"
#include "../ironstack/l3/ip.h"
#include "../ironstack/l3/ip.c"
#include "../ironstack/l4/udp.h"
#include "../ironstack/l4/udp.c"
#include "../ironstack/l4/tcp.h"
#include "../ironstack/l4/tcp.c"

static void build_ip_packet(uint8_t *buf, int *len,
                            const char *src, const char *dst,
                            uint8_t proto, uint8_t ttl,
                            const uint8_t *payload, int payload_len) {
    ip_header_t *hdr = (ip_header_t *)buf;
    hdr->version_ihl = (4 << 4) | 5;
    hdr->tos = 0;
    hdr->total_len = iron_htons(20 + payload_len);
    hdr->id = 0;
    hdr->flags_frag = 0;
    hdr->ttl = ttl;
    hdr->protocol = proto;
    hdr->checksum = 0;
    hdr->src_ip = iron_str_to_ip(src);
    hdr->dst_ip = iron_str_to_ip(dst);
    if (payload_len > 0)
        memcpy(buf + 20, payload, payload_len);
    hdr->checksum = iron_checksum(buf, 20);
    *len = 20 + payload_len;
}

/* Test 1: ACL denies traffic to port 22 */
static mt_result_t test_acl_deny_ssh(void) {
    iron_stats_init();
    route_init();
    acl_init(ACL_DEFAULT_PERMIT);
    pbr_init();

    route_add((ip_prefix_t){iron_str_to_ip("10.0.2.0"), 24}, iron_str_to_ip("10.0.2.254"), 0);

    /* Deny TCP to port 22 */
    acl_match_t m = {0};
    m.protocol = PROTO_TCP;
    m.dst_port = (port_range_t){22, 22};
    acl_add_rule(1, &m, ACL_DENY);

    /* TCP packet: 10.0.1.1:5000 → 10.0.2.1:22 */
    uint8_t tcp_hdr[4] = {0x13, 0x88, 0x00, 0x16}; /* sport=5000, dport=22 */
    uint8_t pkt[128];
    int pkt_len;
    build_ip_packet(pkt, &pkt_len, "10.0.1.1", "10.0.2.1", PROTO_TCP, 64, tcp_hdr, 4);

    printf("  Packet: 10.0.1.1:5000 → 10.0.2.1:22 (TCP)\n");
    printf("  ACL Rule: DENY TCP dst-port 22\n");
    mt_hex_dump(pkt, pkt_len);

    g_last_tx_len = 0;
    int rc = ip_input(pkt, pkt_len, 0);

    printf("  Result: %s (rc=%d)\n", rc == -1 ? "DENIED by ACL" : "ERROR", rc);
    printf("  ACL drop counter: %lu\n", iron_stats_get(STAT_L3_DROPS_ACL));

    if (rc != -1) return MT_FAIL;
    if (iron_stats_get(STAT_L3_DROPS_ACL) != 1) return MT_FAIL;
    if (g_last_tx_len != 0) return MT_FAIL; /* Should NOT be forwarded */

    return MT_PASS;
}

/* Test 2: ACL permits traffic to port 80, packet forwarded */
static mt_result_t test_acl_permit_http(void) {
    iron_stats_init();
    route_init();
    acl_init(ACL_DEFAULT_DENY);
    pbr_init();

    route_add((ip_prefix_t){iron_str_to_ip("10.0.2.0"), 24}, iron_str_to_ip("10.0.2.254"), 0);

    /* Permit TCP to port 80 */
    acl_match_t m = {0};
    m.protocol = PROTO_TCP;
    m.dst_port = (port_range_t){80, 80};
    acl_add_rule(1, &m, ACL_PERMIT);

    /* TCP packet: 10.0.1.1:5000 → 10.0.2.1:80 */
    uint8_t tcp_hdr[4] = {0x13, 0x88, 0x00, 0x50}; /* sport=5000, dport=80 */
    uint8_t pkt[128];
    int pkt_len;
    build_ip_packet(pkt, &pkt_len, "10.0.1.1", "10.0.2.1", PROTO_TCP, 64, tcp_hdr, 4);

    printf("  Packet: 10.0.1.1:5000 → 10.0.2.1:80 (TCP)\n");
    printf("  ACL Rule: PERMIT TCP dst-port 80 (default: DENY)\n");
    mt_hex_dump(pkt, pkt_len);

    g_last_tx_len = 0;
    int rc = ip_input(pkt, pkt_len, 0);

    printf("  Result: %s (rc=%d)\n", rc == 0 ? "PERMITTED and FORWARDED" : "ERROR", rc);
    printf("  Forwarded counter: %lu\n", iron_stats_get(STAT_L3_FORWARDED));

    if (rc != 0) return MT_FAIL;
    if (iron_stats_get(STAT_L3_FORWARDED) != 1) return MT_FAIL;

    return MT_PASS;
}

/* Test 3: PBR redirects traffic from 10.0.1.0/24 to a different next-hop */
static mt_result_t test_pbr_redirect(void) {
    iron_stats_init();
    route_init();
    acl_init(ACL_DEFAULT_PERMIT);
    pbr_init();

    /* Normal route: 10.0.2.0/24 via iface 0 */
    route_add((ip_prefix_t){iron_str_to_ip("10.0.2.0"), 24}, iron_str_to_ip("10.0.2.254"), 0);

    /* PBR: traffic from 10.0.1.0/24 → redirect to iface 1 via 10.0.3.1 */
    pbr_match_t pm = {0};
    pm.src_ip = (ip_prefix_t){iron_str_to_ip("10.0.1.0"), 24};
    pm.protocol = PROTO_ANY;
    pbr_action_t pa = { .next_hop = iron_str_to_ip("10.0.3.1"), .out_iface = 1 };
    pbr_add_rule(1, &pm, &pa);

    uint8_t pkt[128];
    int pkt_len;
    build_ip_packet(pkt, &pkt_len, "10.0.1.5", "10.0.2.1", PROTO_TCP, 64, NULL, 0);

    printf("  Packet: 10.0.1.5 → 10.0.2.1 (TCP)\n");
    printf("  Normal route: 10.0.2.0/24 via iface 0\n");
    printf("  PBR Rule: src 10.0.1.0/24 → redirect to 10.0.3.1 iface 1\n");
    mt_hex_dump(pkt, pkt_len);

    g_last_tx_len = 0;
    g_last_tx_iface = -1;
    int rc = ip_input(pkt, pkt_len, 0);

    printf("  Result: %s (rc=%d)\n", rc == 0 ? "FORWARDED via PBR" : "ERROR", rc);
    printf("  Output interface: %d (expected: 1)\n", g_last_tx_iface);

    if (rc != 0) return MT_FAIL;
    if (g_last_tx_iface != 1) return MT_FAIL;

    return MT_PASS;
}

/* Test 4: PBR loop detection */
static mt_result_t test_pbr_loop_detection(void) {
    iron_stats_init();
    route_init();
    acl_init(ACL_DEFAULT_PERMIT);
    pbr_init();

    /* Test loop detection directly via pbr_lookup */
    pbr_match_t pm = {0};
    pm.protocol = PROTO_ANY;
    pbr_action_t pa = { .next_hop = iron_str_to_ip("10.0.5.1"), .out_iface = 0 };
    pbr_add_rule(1, &pm, &pa);

    pkt_context_t ctx;
    pkt_context_init(&ctx);
    ctx.acl_checked = true;

    /* First lookup: should succeed */
    uint32_t nh; int iface;
    int rc = pbr_lookup(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                        PROTO_TCP, &ctx, &nh, &iface);
    printf("  First PBR lookup: rc=%d (0=match)\n", rc);

    /* Simulate loop: same hop already in history */
    rc = pbr_lookup(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                    PROTO_TCP, &ctx, &nh, &iface);
    printf("  Second PBR lookup (same hop): rc=%d (-2=loop)\n", rc);

    if (rc != -2) return MT_FAIL;

    return MT_PASS;
}

int main(void) {
    mt_suite_t suite;
    mt_suite_init(&suite, "IronNet L3 Module Test — PBR & ACL");

    mt_suite_add(&suite, "PBR redirects traffic to different interface:", test_pbr_redirect);
    mt_suite_add(&suite, "PBR loop detection:", test_pbr_loop_detection);
    mt_suite_add(&suite, "ACL denies SSH traffic (port 22):", test_acl_deny_ssh);
    mt_suite_add(&suite, "ACL permits HTTP traffic (port 80), forwarded:", test_acl_permit_http);

    mt_suite_run(&suite);

    return suite.failed > 0 ? 1 : 0;
}
