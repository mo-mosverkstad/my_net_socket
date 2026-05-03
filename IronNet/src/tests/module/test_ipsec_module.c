#include <stdio.h>
#include <string.h>
#include "module_test.h"
#include "stats.h"
#include "utils.h"
#include "../ironstack/security/ipsec.h"
#include "../ironstack/security/ipsec.c"

/* Test 1: Outbound encrypt + inbound decrypt roundtrip */
static mt_result_t test_encrypt_decrypt_roundtrip(void) {
    ipsec_init();

    ipsec_sa_add(0x100, iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                 IPSEC_DIR_OUTBOUND, IPSEC_TRANSFORM_XOR, 0xAB);
    ipsec_sa_add(0x101, iron_str_to_ip("10.0.2.1"), iron_str_to_ip("10.0.1.1"),
                 IPSEC_DIR_INBOUND, IPSEC_TRANSFORM_XOR, 0xAB);

    ip_prefix_t any = {0, 0};
    ipsec_policy_add(any, any, PROTO_ANY, IPSEC_DIR_OUTBOUND, IPSEC_ACTION_PROTECT, 0x100);
    ipsec_policy_add(any, any, PROTO_ANY, IPSEC_DIR_INBOUND, IPSEC_ACTION_PROTECT, 0x101);

    uint8_t original[] = "Hello IronNet!";
    uint8_t data[16];
    int len = sizeof(original) - 1;
    memcpy(data, original, len);

    printf("  Original payload: \"%.*s\"\n", len, data);
    printf("  Original hex:\n");
    mt_hex_dump(data, len);

    /* Encrypt (outbound) */
    int rc = ipsec_outbound(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                            PROTO_TCP, data, len);
    printf("  After encrypt (XOR 0xAB):\n");
    mt_hex_dump(data, len);
    if (rc != 0) return MT_FAIL;

    /* Verify data is changed */
    if (memcmp(data, original, len) == 0) return MT_FAIL;

    /* Decrypt (inbound) — XOR is its own inverse */
    rc = ipsec_inbound(iron_str_to_ip("10.0.2.1"), iron_str_to_ip("10.0.1.1"),
                       PROTO_TCP, data, len);
    printf("  After decrypt (XOR 0xAB again):\n");
    mt_hex_dump(data, len);
    printf("  Recovered payload: \"%.*s\"\n", len, data);
    if (rc != 0) return MT_FAIL;

    /* Verify roundtrip */
    if (memcmp(data, original, len) != 0) return MT_FAIL;

    return MT_PASS;
}

/* Test 2: DISCARD policy drops traffic */
static mt_result_t test_discard_drops_traffic(void) {
    ipsec_init();

    ip_prefix_t src = {iron_str_to_ip("10.0.1.0"), 24};
    ip_prefix_t any = {0, 0};
    ipsec_policy_add(src, any, PROTO_ANY, IPSEC_DIR_OUTBOUND, IPSEC_ACTION_DISCARD, 0);

    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    printf("  Policy: DISCARD all outbound from 10.0.1.0/24\n");
    printf("  Packet: 10.0.1.5 → 10.0.2.1\n");

    int rc = ipsec_outbound(iron_str_to_ip("10.0.1.5"), iron_str_to_ip("10.0.2.1"),
                            PROTO_TCP, data, 4);
    printf("  Result: %s (rc=%d)\n", rc == -1 ? "DISCARDED" : "ERROR", rc);
    if (rc != -1) return MT_FAIL;

    /* Traffic from different source should bypass (no matching policy) */
    rc = ipsec_outbound(iron_str_to_ip("10.0.3.1"), iron_str_to_ip("10.0.2.1"),
                        PROTO_TCP, data, 4);
    printf("  Packet from 10.0.3.1 (no policy): %s (rc=%d)\n",
           rc == 0 ? "BYPASSED" : "ERROR", rc);
    if (rc != 0) return MT_FAIL;

    return MT_PASS;
}

/* Test 3: Fail closed — PROTECT policy but SA missing */
static mt_result_t test_fail_closed(void) {
    ipsec_init();

    ip_prefix_t any = {0, 0};
    /* Policy says PROTECT with SPI=0x999, but no SA exists */
    ipsec_policy_add(any, any, PROTO_ANY, IPSEC_DIR_OUTBOUND, IPSEC_ACTION_PROTECT, 0x999);

    uint8_t data[] = {0x01, 0x02};
    printf("  Policy: PROTECT with SPI=0x999 (SA does NOT exist)\n");
    printf("  Packet: 10.0.1.1 → 10.0.2.1\n");

    int rc = ipsec_outbound(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                            PROTO_TCP, data, 2);
    printf("  Result: %s (rc=%d)\n", rc == -1 ? "DROPPED (fail closed)" : "ERROR", rc);
    printf("  Data unchanged: 0x%02X 0x%02X\n", data[0], data[1]);

    if (rc != -1) return MT_FAIL;
    /* Data should NOT be modified since SA was not found */
    if (data[0] != 0x01 || data[1] != 0x02) return MT_FAIL;

    return MT_PASS;
}

/* Test 4: SA expiry */
static mt_result_t test_sa_expiry(void) {
    ipsec_init();

    ipsec_sa_add(0x400, iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                 IPSEC_DIR_OUTBOUND, IPSEC_TRANSFORM_XOR, 0x55);

    ipsec_sa_t *sa = ipsec_sa_find(0x400);
    printf("  SA SPI=0x400 created, active=%s\n", sa && sa->active ? "true" : "false");
    if (!sa || !sa->active) return MT_FAIL;

    /* Simulate expiry by backdating created_at */
    sa->created_at -= (IPSEC_SA_LIFETIME + 1);
    ipsec_timer_tick();

    sa = ipsec_sa_find(0x400);
    printf("  After timer tick (lifetime exceeded): SA found=%s\n", sa ? "yes" : "no (expired)");
    if (sa != NULL) return MT_FAIL;

    return MT_PASS;
}

int main(void) {
    mt_suite_t suite;
    mt_suite_init(&suite, "IronNet Security Module Test — IPsec");

    mt_suite_add(&suite, "Encrypt/decrypt roundtrip (XOR transform):", test_encrypt_decrypt_roundtrip);
    mt_suite_add(&suite, "DISCARD policy drops traffic:", test_discard_drops_traffic);
    mt_suite_add(&suite, "Fail closed (PROTECT but no SA):", test_fail_closed);
    mt_suite_add(&suite, "SA expiry via timer:", test_sa_expiry);

    mt_suite_run(&suite);

    return suite.failed > 0 ? 1 : 0;
}
