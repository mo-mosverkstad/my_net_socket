#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stats.h"
#include "utils.h"
#include "../ironstack/security/ipsec.h"
#include "../ironstack/security/ipsec.c"

#define TEST_ASSERT(cond) do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d\n", __FILE__, __LINE__); exit(1); } } while(0)

static void test_sa_add_find_delete(void) {
    ipsec_init();

    ipsec_sa_add(0x100, iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                 IPSEC_DIR_OUTBOUND, IPSEC_TRANSFORM_XOR, 0xAA);

    ipsec_sa_t *sa = ipsec_sa_find(0x100);
    TEST_ASSERT(sa != NULL);
    TEST_ASSERT(sa->spi == 0x100);
    TEST_ASSERT(sa->key == 0xAA);

    ipsec_sa_delete(0x100);
    sa = ipsec_sa_find(0x100);
    TEST_ASSERT(sa == NULL);

    printf("[PASS] test_sa_add_find_delete\n");
}

static void test_outbound_protect(void) {
    ipsec_init();

    ipsec_sa_add(0x200, iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                 IPSEC_DIR_OUTBOUND, IPSEC_TRANSFORM_XOR, 0xFF);

    ip_prefix_t any = {0, 0};
    ipsec_policy_add(any, any, PROTO_ANY, IPSEC_DIR_OUTBOUND, IPSEC_ACTION_PROTECT, 0x200);

    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    int rc = ipsec_outbound(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                            PROTO_TCP, data, 4);
    TEST_ASSERT(rc == 0);
    /* XOR with 0xFF: 0x01→0xFE, 0x02→0xFD, 0x03→0xFC, 0x04→0xFB */
    TEST_ASSERT(data[0] == 0xFE);
    TEST_ASSERT(data[1] == 0xFD);
    TEST_ASSERT(data[2] == 0xFC);
    TEST_ASSERT(data[3] == 0xFB);

    printf("[PASS] test_outbound_protect\n");
}

static void test_inbound_decrypt(void) {
    ipsec_init();

    ipsec_sa_add(0x300, iron_str_to_ip("10.0.2.1"), iron_str_to_ip("10.0.1.1"),
                 IPSEC_DIR_INBOUND, IPSEC_TRANSFORM_XOR, 0xFF);

    ip_prefix_t any = {0, 0};
    ipsec_policy_add(any, any, PROTO_ANY, IPSEC_DIR_INBOUND, IPSEC_ACTION_PROTECT, 0x300);

    /* Encrypted data (XOR 0xFF applied) */
    uint8_t data[] = {0xFE, 0xFD, 0xFC, 0xFB};
    int rc = ipsec_inbound(iron_str_to_ip("10.0.2.1"), iron_str_to_ip("10.0.1.1"),
                           PROTO_TCP, data, 4);
    TEST_ASSERT(rc == 0);
    /* XOR again reverses: 0xFE→0x01, 0xFD→0x02, etc. */
    TEST_ASSERT(data[0] == 0x01);
    TEST_ASSERT(data[1] == 0x02);
    TEST_ASSERT(data[2] == 0x03);
    TEST_ASSERT(data[3] == 0x04);

    printf("[PASS] test_inbound_decrypt\n");
}

static void test_discard_policy(void) {
    ipsec_init();

    ip_prefix_t any = {0, 0};
    ipsec_policy_add(any, any, PROTO_ANY, IPSEC_DIR_OUTBOUND, IPSEC_ACTION_DISCARD, 0);

    uint8_t data[] = {0x01, 0x02};
    int rc = ipsec_outbound(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                            PROTO_TCP, data, 2);
    TEST_ASSERT(rc == -1);

    printf("[PASS] test_discard_policy\n");
}

static void test_fail_closed_no_sa(void) {
    ipsec_init();

    ip_prefix_t any = {0, 0};
    /* Policy says PROTECT with SPI=0x999, but no SA exists */
    ipsec_policy_add(any, any, PROTO_ANY, IPSEC_DIR_OUTBOUND, IPSEC_ACTION_PROTECT, 0x999);

    uint8_t data[] = {0x01};
    int rc = ipsec_outbound(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                            PROTO_TCP, data, 1);
    TEST_ASSERT(rc == -1); /* Fail closed */

    printf("[PASS] test_fail_closed_no_sa\n");
}

int main(void) {
    printf("=== IronNet IPsec Unit Tests ===\n");
    test_sa_add_find_delete();
    test_outbound_protect();
    test_inbound_decrypt();
    test_discard_policy();
    test_fail_closed_no_sa();
    printf("=== All tests passed ===\n");
    return 0;
}
