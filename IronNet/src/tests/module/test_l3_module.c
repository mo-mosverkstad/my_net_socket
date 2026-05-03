#include <stdio.h>
#include <string.h>
#include "module_test.h"
#include "stats.h"
#include "utils.h"

/* Stubs for vnic (no real I/O in module test) */
#include "../ironstack/io/vnic.h"

static uint8_t g_last_tx_buf[2048];
static int g_last_tx_len = 0;

/* Minimal vnic stubs */
static uint8_t g_fake_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static vnic_t g_fake_vnic = { .name = "veth0", .fd = -1, .active = true };

int vnic_init(void) { return 0; }
void vnic_shutdown(void) {}
int vnic_create(const char *n, uint8_t m[6]) { (void)n; (void)m; return 0; }
int vnic_read(int i, uint8_t *b, int l) { (void)i; (void)b; (void)l; return -1; }
int vnic_write(int i, const uint8_t *b, int l) {
    (void)i;
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

static mt_result_t test_ip_parse_and_route(void) {
    iron_stats_init();
    route_init();
    acl_init(ACL_DEFAULT_PERMIT);
    pbr_init();

    route_add((ip_prefix_t){iron_str_to_ip("10.0.2.0"), 24}, iron_str_to_ip("10.0.2.254"), 0);

    uint8_t pkt[128];
    int pkt_len;
    build_ip_packet(pkt, &pkt_len, "10.0.1.1", "10.0.2.1", PROTO_TCP, 64, NULL, 0);

    printf("  Input IP packet (%d bytes):\n", pkt_len);
    mt_hex_dump(pkt, pkt_len);

    ip_header_t *hdr = (ip_header_t *)pkt;
    printf("  Src IP: %d.%d.%d.%d\n",
           ((uint8_t*)&hdr->src_ip)[0], ((uint8_t*)&hdr->src_ip)[1],
           ((uint8_t*)&hdr->src_ip)[2], ((uint8_t*)&hdr->src_ip)[3]);
    printf("  Dst IP: %d.%d.%d.%d\n",
           ((uint8_t*)&hdr->dst_ip)[0], ((uint8_t*)&hdr->dst_ip)[1],
           ((uint8_t*)&hdr->dst_ip)[2], ((uint8_t*)&hdr->dst_ip)[3]);
    printf("  TTL: %d, Protocol: %d\n", hdr->ttl, hdr->protocol);

    g_last_tx_len = 0;
    int rc = ip_input(pkt, pkt_len, 0);

    printf("  Route decision: %s\n", rc == 0 ? "FORWARDED" : "DROPPED");
    printf("  TTL after forward: %d\n", hdr->ttl);
    printf("  Forwarded counter: %lu\n", iron_stats_get(STAT_L3_FORWARDED));

    if (rc != 0) return MT_FAIL;
    if (iron_stats_get(STAT_L3_FORWARDED) != 1) return MT_FAIL;
    if (hdr->ttl != 63) return MT_FAIL;

    return MT_PASS;
}

static mt_result_t test_ip_ttl_expired(void) {
    iron_stats_init();
    route_init();
    acl_init(ACL_DEFAULT_PERMIT);
    pbr_init();

    route_add((ip_prefix_t){iron_str_to_ip("10.0.2.0"), 24}, iron_str_to_ip("10.0.2.254"), 0);

    uint8_t pkt[128];
    int pkt_len;
    build_ip_packet(pkt, &pkt_len, "10.0.1.1", "10.0.2.1", PROTO_TCP, 1, NULL, 0);

    printf("  Input IP packet with TTL=1:\n");
    mt_hex_dump(pkt, pkt_len);

    int rc = ip_input(pkt, pkt_len, 0);

    printf("  Result: %s (rc=%d)\n", rc == -1 ? "DROPPED (TTL expired)" : "ERROR", rc);
    printf("  TTL drop counter: %lu\n", iron_stats_get(STAT_L3_DROPS_TTL));

    if (rc != -1) return MT_FAIL;
    if (iron_stats_get(STAT_L3_DROPS_TTL) != 1) return MT_FAIL;

    return MT_PASS;
}

static mt_result_t test_ip_icmp_echo(void) {
    iron_stats_init();
    route_init();
    acl_init(ACL_DEFAULT_PERMIT);
    pbr_init();

    /* Add local address and route for reply */
    ip_add_local_addr(iron_str_to_ip("10.0.1.1"));
    route_add((ip_prefix_t){iron_str_to_ip("10.0.2.0"), 24}, iron_str_to_ip("10.0.2.254"), 0);

    /* Build ICMP echo request */
    uint8_t icmp_data[8];
    icmp_header_t *icmp = (icmp_header_t *)icmp_data;
    icmp->type = ICMP_TYPE_ECHO_REQUEST;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->id = iron_htons(1234);
    icmp->seq = iron_htons(1);
    icmp->checksum = iron_checksum(icmp_data, 8);

    uint8_t pkt[128];
    int pkt_len;
    build_ip_packet(pkt, &pkt_len, "10.0.2.1", "10.0.1.1", PROTO_ICMP, 64, icmp_data, 8);

    printf("  ICMP Echo Request packet (%d bytes):\n", pkt_len);
    mt_hex_dump(pkt, pkt_len);

    ip_header_t *hdr = (ip_header_t *)pkt;
    printf("  Src: %d.%d.%d.%d -> Dst: %d.%d.%d.%d\n",
           ((uint8_t*)&hdr->src_ip)[0], ((uint8_t*)&hdr->src_ip)[1],
           ((uint8_t*)&hdr->src_ip)[2], ((uint8_t*)&hdr->src_ip)[3],
           ((uint8_t*)&hdr->dst_ip)[0], ((uint8_t*)&hdr->dst_ip)[1],
           ((uint8_t*)&hdr->dst_ip)[2], ((uint8_t*)&hdr->dst_ip)[3]);
    printf("  ICMP Type: %d (Echo Request), ID: %d, Seq: %d\n",
           icmp->type, iron_ntohs(icmp->id), iron_ntohs(icmp->seq));

    g_last_tx_len = 0;
    int rc = ip_input(pkt, pkt_len, 0);

    printf("  Result: %s\n", rc == 0 ? "Processed (reply sent)" : "ERROR");
    printf("  Local deliver counter: %lu\n", iron_stats_get(STAT_L3_LOCAL_DELIVER));
    printf("  TX counter (reply): %lu\n", iron_stats_get(STAT_L3_TX_PACKETS));

    if (rc != 0) return MT_FAIL;
    if (iron_stats_get(STAT_L3_LOCAL_DELIVER) != 1) return MT_FAIL;
    if (iron_stats_get(STAT_L3_TX_PACKETS) != 1) return MT_FAIL;

    /* Verify reply was sent */
    if (g_last_tx_len > 0) {
        printf("  Echo Reply frame sent (%d bytes):\n", g_last_tx_len);
        mt_hex_dump(g_last_tx_buf, g_last_tx_len);
    }

    return MT_PASS;
}

int main(void) {
    mt_suite_t suite;
    mt_suite_init(&suite, "IronNet L3 Module Test — IP Processing");

    mt_suite_add(&suite, "IP packet parse and forward via routing:", test_ip_parse_and_route);
    mt_suite_add(&suite, "IP packet with TTL=1 (should be dropped):", test_ip_ttl_expired);
    mt_suite_add(&suite, "ICMP Echo Request → Echo Reply:", test_ip_icmp_echo);

    mt_suite_run(&suite);

    return suite.failed > 0 ? 1 : 0;
}
