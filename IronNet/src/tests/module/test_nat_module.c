#include <stdio.h>
#include <string.h>
#include "module_test.h"
#include "stats.h"
#include "utils.h"
#include "../ironstack/l3/nat.h"
#include "../ironstack/l3/nat.c"

/* Test 1: SNAT outbound + return traffic roundtrip */
static mt_result_t test_snat_roundtrip(void) {
    nat_init();
    nat_add_snat((ip_prefix_t){iron_str_to_ip("10.0.1.0"), 24}, iron_str_to_ip("203.0.113.1"));

    uint32_t src = iron_str_to_ip("10.0.1.5");
    uint32_t dst = iron_str_to_ip("8.8.8.8");
    uint16_t sport = 5000, dport = 443;
    char buf[16];

    printf("  SNAT rule: src 10.0.1.0/24 -> 203.0.113.1\n\n");
    printf("  Outbound: 10.0.1.5:5000 -> 8.8.8.8:443\n");

    int rc = nat_translate_outbound(&src, &dst, &sport, &dport, PROTO_TCP);
    printf("  After SNAT: %s:%u -> %s:%u\n",
           iron_ip_to_str(src, buf, sizeof(buf)), sport,
           iron_ip_to_str(dst, buf, sizeof(buf)), dport);
    if (rc != 0) return MT_FAIL;
    if (src != iron_str_to_ip("203.0.113.1")) return MT_FAIL;

    uint16_t nat_port = sport;
    printf("  Allocated port: %u\n\n", nat_port);

    /* Return traffic */
    uint32_t ret_src = iron_str_to_ip("8.8.8.8");
    uint32_t ret_dst = iron_str_to_ip("203.0.113.1");
    uint16_t ret_sport = 443, ret_dport = nat_port;

    printf("  Return: 8.8.8.8:443 -> 203.0.113.1:%u\n", nat_port);
    rc = nat_translate_inbound(&ret_src, &ret_dst, &ret_sport, &ret_dport, PROTO_TCP);
    printf("  After reverse-NAT: %s:%u -> %s:%u\n",
           iron_ip_to_str(ret_src, buf, sizeof(buf)), ret_sport,
           iron_ip_to_str(ret_dst, buf, sizeof(buf)), ret_dport);

    if (rc != 0) return MT_FAIL;
    if (ret_dst != iron_str_to_ip("10.0.1.5")) return MT_FAIL;
    if (ret_dport != 5000) return MT_FAIL;

    return MT_PASS;
}

/* Test 2: DNAT port forwarding */
static mt_result_t test_dnat_port_forward(void) {
    nat_init();
    nat_add_dnat(iron_str_to_ip("203.0.113.1"), 80,
                 iron_str_to_ip("10.0.1.100"), 8080);

    uint32_t src = iron_str_to_ip("1.2.3.4");
    uint32_t dst = iron_str_to_ip("203.0.113.1");
    uint16_t sport = 54321, dport = 80;
    char buf[16];

    printf("  DNAT rule: dst 203.0.113.1:80 -> 10.0.1.100:8080\n\n");
    printf("  Inbound: 1.2.3.4:54321 -> 203.0.113.1:80\n");

    int rc = nat_translate_inbound(&src, &dst, &sport, &dport, PROTO_TCP);
    printf("  After DNAT: %s:%u -> %s:%u\n",
           iron_ip_to_str(src, buf, sizeof(buf)), sport,
           iron_ip_to_str(dst, buf, sizeof(buf)), dport);

    if (rc != 0) return MT_FAIL;
    if (dst != iron_str_to_ip("10.0.1.100")) return MT_FAIL;
    if (dport != 8080) return MT_FAIL;

    return MT_PASS;
}

/* Test 3: Multiple internal hosts share one public IP */
static mt_result_t test_snat_multiple_hosts(void) {
    nat_init();
    nat_add_snat((ip_prefix_t){iron_str_to_ip("10.0.1.0"), 24}, iron_str_to_ip("203.0.113.1"));

    printf("  SNAT: 10.0.1.0/24 -> 203.0.113.1\n\n");

    uint32_t src1 = iron_str_to_ip("10.0.1.5"), dst1 = iron_str_to_ip("8.8.8.8");
    uint16_t sport1 = 5000, dport1 = 80;
    nat_translate_outbound(&src1, &dst1, &sport1, &dport1, PROTO_TCP);
    printf("  Host 10.0.1.5:5000 -> translated port %u\n", sport1);

    uint32_t src2 = iron_str_to_ip("10.0.1.6"), dst2 = iron_str_to_ip("8.8.8.8");
    uint16_t sport2 = 5000, dport2 = 80;
    nat_translate_outbound(&src2, &dst2, &sport2, &dport2, PROTO_TCP);
    printf("  Host 10.0.1.6:5000 -> translated port %u\n", sport2);

    uint32_t src3 = iron_str_to_ip("10.0.1.7"), dst3 = iron_str_to_ip("8.8.8.8");
    uint16_t sport3 = 5000, dport3 = 80;
    nat_translate_outbound(&src3, &dst3, &sport3, &dport3, PROTO_TCP);
    printf("  Host 10.0.1.7:5000 -> translated port %u\n", sport3);

    printf("  All share public IP 203.0.113.1, different ports\n");
    printf("  Mappings: %d\n", nat_get_mapping_count());

    if (sport1 == sport2 || sport2 == sport3 || sport1 == sport3) return MT_FAIL;
    if (nat_get_mapping_count() != 3) return MT_FAIL;

    return MT_PASS;
}

/* Test 4: No rule → pass-through (unchanged) */
static mt_result_t test_no_nat_passthrough(void) {
    nat_init();
    /* No rules added */

    uint32_t src = iron_str_to_ip("10.0.1.5");
    uint32_t dst = iron_str_to_ip("8.8.8.8");
    uint16_t sport = 5000, dport = 80;

    printf("  No NAT rules configured\n");
    printf("  Packet: 10.0.1.5:5000 -> 8.8.8.8:80\n");

    int rc = nat_translate_outbound(&src, &dst, &sport, &dport, PROTO_TCP);
    printf("  Result: rc=%d (%s)\n", rc, rc == 1 ? "pass-through, unchanged" : "ERROR");
    printf("  Src still: 10.0.1.5:%u (unchanged)\n", sport);

    if (rc != 1) return MT_FAIL;
    if (src != iron_str_to_ip("10.0.1.5")) return MT_FAIL;
    if (sport != 5000) return MT_FAIL;

    return MT_PASS;
}

int main(void) {
    mt_suite_t suite;
    mt_suite_init(&suite, "IronNet L3 Module Test — NAT");

    mt_suite_add(&suite, "SNAT outbound + return traffic roundtrip:", test_snat_roundtrip);
    mt_suite_add(&suite, "DNAT port forwarding (203.0.113.1:80 -> 10.0.1.100:8080):", test_dnat_port_forward);
    mt_suite_add(&suite, "Multiple hosts share one public IP (different ports):", test_snat_multiple_hosts);
    mt_suite_add(&suite, "No NAT rule → pass-through:", test_no_nat_passthrough);

    mt_suite_run(&suite);

    return suite.failed > 0 ? 1 : 0;
}
