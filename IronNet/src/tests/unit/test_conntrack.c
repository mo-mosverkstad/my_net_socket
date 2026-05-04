#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stats.h"
#include "utils.h"
#include "../ironstack/l3/conntrack.h"
#include "../ironstack/l3/conntrack.c"

#define TEST_ASSERT(cond) do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d\n", __FILE__, __LINE__); exit(1); } } while(0)

static void test_new_connection(void) {
    conntrack_init();

    conntrack_update(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                     PROTO_TCP, 5000, 80, TCP_FLAG_SYN);

    ct_state_t state = conntrack_get_state(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                                           PROTO_TCP, 5000, 80);
    TEST_ASSERT(state == CT_STATE_NEW);
    TEST_ASSERT(conntrack_get_count() == 1);
    printf("[PASS] test_new_connection\n");
}

static void test_reply_establishes(void) {
    conntrack_init();

    /* Original: SYN */
    conntrack_update(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                     PROTO_TCP, 5000, 80, TCP_FLAG_SYN);

    /* Reply: SYN+ACK (swapped src/dst) */
    conntrack_update(iron_str_to_ip("10.0.2.1"), iron_str_to_ip("10.0.1.1"),
                     PROTO_TCP, 80, 5000, TCP_FLAG_SYN | TCP_FLAG_ACK);

    ct_state_t state = conntrack_get_state(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                                           PROTO_TCP, 5000, 80);
    TEST_ASSERT(state == CT_STATE_ESTABLISHED);
    printf("[PASS] test_reply_establishes\n");
}

static void test_udp_established(void) {
    conntrack_init();

    /* First UDP packet */
    conntrack_update(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                     PROTO_UDP, 5000, 53, 0);
    TEST_ASSERT(conntrack_get_state(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                                    PROTO_UDP, 5000, 53) == CT_STATE_NEW);

    /* Reply */
    conntrack_update(iron_str_to_ip("10.0.2.1"), iron_str_to_ip("10.0.1.1"),
                     PROTO_UDP, 53, 5000, 0);
    TEST_ASSERT(conntrack_get_state(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                                    PROTO_UDP, 5000, 53) == CT_STATE_ESTABLISHED);
    printf("[PASS] test_udp_established\n");
}

static void test_bidirectional_lookup(void) {
    conntrack_init();

    conntrack_update(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                     PROTO_TCP, 5000, 80, TCP_FLAG_SYN);

    /* Lookup in original direction */
    ct_entry_t *e = conntrack_lookup(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                                     PROTO_TCP, 5000, 80);
    TEST_ASSERT(e != NULL);

    /* Lookup in reply direction */
    e = conntrack_lookup(iron_str_to_ip("10.0.2.1"), iron_str_to_ip("10.0.1.1"),
                         PROTO_TCP, 80, 5000);
    TEST_ASSERT(e != NULL);

    /* Lookup unrelated → NULL */
    e = conntrack_lookup(iron_str_to_ip("10.0.3.1"), iron_str_to_ip("10.0.4.1"),
                         PROTO_TCP, 9999, 9999);
    TEST_ASSERT(e == NULL);
    printf("[PASS] test_bidirectional_lookup\n");
}

static void test_unknown_is_invalid(void) {
    conntrack_init();

    ct_state_t state = conntrack_get_state(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                                           PROTO_TCP, 5000, 80);
    TEST_ASSERT(state == CT_STATE_INVALID);
    printf("[PASS] test_unknown_is_invalid\n");
}

static void test_packet_counters(void) {
    conntrack_init();

    /* 3 packets in original direction */
    conntrack_update(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                     PROTO_TCP, 5000, 80, TCP_FLAG_SYN);
    conntrack_update(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                     PROTO_TCP, 5000, 80, TCP_FLAG_ACK);
    conntrack_update(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                     PROTO_TCP, 5000, 80, TCP_FLAG_ACK);

    /* 1 packet in reply direction */
    conntrack_update(iron_str_to_ip("10.0.2.1"), iron_str_to_ip("10.0.1.1"),
                     PROTO_TCP, 80, 5000, TCP_FLAG_SYN | TCP_FLAG_ACK);

    ct_entry_t *e = conntrack_lookup(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                                     PROTO_TCP, 5000, 80);
    TEST_ASSERT(e != NULL);
    TEST_ASSERT(e->packets_orig == 3);
    TEST_ASSERT(e->packets_reply == 1);
    printf("[PASS] test_packet_counters\n");
}

int main(void) {
    printf("=== IronNet Connection Tracking Unit Tests ===\n");
    test_new_connection();
    test_reply_establishes();
    test_udp_established();
    test_bidirectional_lookup();
    test_unknown_is_invalid();
    test_packet_counters();
    printf("=== All tests passed ===\n");
    return 0;
}
