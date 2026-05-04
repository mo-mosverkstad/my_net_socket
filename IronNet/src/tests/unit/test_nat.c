#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stats.h"
#include "utils.h"
#include "../ironstack/l3/nat.h"
#include "../ironstack/l3/nat.c"

#define TEST_ASSERT(cond) do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d\n", __FILE__, __LINE__); exit(1); } } while(0)

static void test_snat_outbound(void) {
    nat_init();
    nat_add_snat((ip_prefix_t){iron_str_to_ip("10.0.1.0"), 24}, iron_str_to_ip("203.0.113.1"));

    uint32_t src = iron_str_to_ip("10.0.1.5");
    uint32_t dst = iron_str_to_ip("8.8.8.8");
    uint16_t sport = 5000, dport = 80;

    int rc = nat_translate_outbound(&src, &dst, &sport, &dport, PROTO_TCP);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(src == iron_str_to_ip("203.0.113.1"));
    TEST_ASSERT(sport >= NAT_PORT_MIN && sport <= NAT_PORT_MAX);
    TEST_ASSERT(dst == iron_str_to_ip("8.8.8.8")); /* dst unchanged */
    TEST_ASSERT(nat_get_mapping_count() == 1);
    printf("[PASS] test_snat_outbound\n");
}

static void test_snat_return_traffic(void) {
    nat_init();
    nat_add_snat((ip_prefix_t){iron_str_to_ip("10.0.1.0"), 24}, iron_str_to_ip("203.0.113.1"));

    /* Outbound */
    uint32_t src = iron_str_to_ip("10.0.1.5");
    uint32_t dst = iron_str_to_ip("8.8.8.8");
    uint16_t sport = 5000, dport = 80;
    nat_translate_outbound(&src, &dst, &sport, &dport, PROTO_TCP);
    uint16_t translated_port = sport; /* Remember the allocated port */

    /* Return traffic: 8.8.8.8:80 → 203.0.113.1:translated_port */
    uint32_t ret_src = iron_str_to_ip("8.8.8.8");
    uint32_t ret_dst = iron_str_to_ip("203.0.113.1");
    uint16_t ret_sport = 80, ret_dport = translated_port;

    int rc = nat_translate_inbound(&ret_src, &ret_dst, &ret_sport, &ret_dport, PROTO_TCP);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(ret_dst == iron_str_to_ip("10.0.1.5")); /* Restored original */
    TEST_ASSERT(ret_dport == 5000);
    printf("[PASS] test_snat_return_traffic\n");
}

static void test_dnat_inbound(void) {
    nat_init();
    nat_add_dnat(iron_str_to_ip("203.0.113.1"), 80,
                 iron_str_to_ip("10.0.1.100"), 8080);

    uint32_t src = iron_str_to_ip("1.2.3.4");
    uint32_t dst = iron_str_to_ip("203.0.113.1");
    uint16_t sport = 9999, dport = 80;

    int rc = nat_translate_inbound(&src, &dst, &sport, &dport, PROTO_TCP);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(dst == iron_str_to_ip("10.0.1.100"));
    TEST_ASSERT(dport == 8080);
    TEST_ASSERT(src == iron_str_to_ip("1.2.3.4")); /* src unchanged */
    printf("[PASS] test_dnat_inbound\n");
}

static void test_no_rule_passthrough(void) {
    nat_init();

    uint32_t src = iron_str_to_ip("10.0.1.5");
    uint32_t dst = iron_str_to_ip("8.8.8.8");
    uint16_t sport = 5000, dport = 80;

    int rc = nat_translate_outbound(&src, &dst, &sport, &dport, PROTO_TCP);
    TEST_ASSERT(rc == 1); /* No rule matched, pass-through */
    TEST_ASSERT(src == iron_str_to_ip("10.0.1.5")); /* Unchanged */
    printf("[PASS] test_no_rule_passthrough\n");
}

static void test_snat_reuses_mapping(void) {
    nat_init();
    nat_add_snat((ip_prefix_t){iron_str_to_ip("10.0.1.0"), 24}, iron_str_to_ip("203.0.113.1"));

    uint32_t src = iron_str_to_ip("10.0.1.5");
    uint32_t dst = iron_str_to_ip("8.8.8.8");
    uint16_t sport = 5000, dport = 80;

    nat_translate_outbound(&src, &dst, &sport, &dport, PROTO_TCP);
    uint16_t first_port = sport;

    /* Same flow again → reuses existing mapping */
    src = iron_str_to_ip("10.0.1.5");
    dst = iron_str_to_ip("8.8.8.8");
    sport = 5000; dport = 80;
    nat_translate_outbound(&src, &dst, &sport, &dport, PROTO_TCP);

    TEST_ASSERT(sport == first_port); /* Same translated port */
    TEST_ASSERT(nat_get_mapping_count() == 1); /* No new mapping */
    printf("[PASS] test_snat_reuses_mapping\n");
}

static void test_different_flows_different_ports(void) {
    nat_init();
    nat_add_snat((ip_prefix_t){iron_str_to_ip("10.0.1.0"), 24}, iron_str_to_ip("203.0.113.1"));

    uint32_t src1 = iron_str_to_ip("10.0.1.5"), dst1 = iron_str_to_ip("8.8.8.8");
    uint16_t sport1 = 5000, dport1 = 80;
    nat_translate_outbound(&src1, &dst1, &sport1, &dport1, PROTO_TCP);

    uint32_t src2 = iron_str_to_ip("10.0.1.6"), dst2 = iron_str_to_ip("8.8.8.8");
    uint16_t sport2 = 5000, dport2 = 80;
    nat_translate_outbound(&src2, &dst2, &sport2, &dport2, PROTO_TCP);

    TEST_ASSERT(sport1 != sport2); /* Different translated ports */
    TEST_ASSERT(nat_get_mapping_count() == 2);
    printf("[PASS] test_different_flows_different_ports\n");
}

int main(void) {
    printf("=== IronNet NAT Unit Tests ===\n");
    test_snat_outbound();
    test_snat_return_traffic();
    test_dnat_inbound();
    test_no_rule_passthrough();
    test_snat_reuses_mapping();
    test_different_flows_different_ports();
    printf("=== All tests passed ===\n");
    return 0;
}
