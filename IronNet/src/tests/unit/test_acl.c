#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stats.h"
#include "utils.h"
#include "../ironstack/l3/acl.h"
#include "../ironstack/l3/acl.c"

#define TEST_ASSERT(cond) do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d\n", __FILE__, __LINE__); exit(1); } } while(0)

static acl_match_t match_any(void) {
    acl_match_t m = {0};
    m.protocol = PROTO_ANY;
    return m;
}

static void test_default_deny(void) {
    iron_stats_init();
    acl_init(ACL_DEFAULT_DENY);

    acl_action_t r = acl_evaluate(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                                  PROTO_TCP, 1234, 80);
    TEST_ASSERT(r == ACL_DENY);
    TEST_ASSERT(iron_stats_get(STAT_L3_DROPS_ACL) == 1);
    printf("[PASS] test_default_deny\n");
}

static void test_default_permit(void) {
    iron_stats_init();
    acl_init(ACL_DEFAULT_PERMIT);

    acl_action_t r = acl_evaluate(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                                  PROTO_TCP, 1234, 80);
    TEST_ASSERT(r == ACL_PERMIT);
    printf("[PASS] test_default_permit\n");
}

static void test_permit_rule(void) {
    iron_stats_init();
    acl_init(ACL_DEFAULT_DENY);

    acl_match_t m = match_any();
    m.protocol = PROTO_TCP;
    m.dst_port = (port_range_t){80, 80};
    acl_add_rule(1, &m, ACL_PERMIT);

    /* Should match rule 1 */
    acl_action_t r = acl_evaluate(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                                  PROTO_TCP, 1234, 80);
    TEST_ASSERT(r == ACL_PERMIT);

    /* UDP port 80 should NOT match (protocol mismatch) → default deny */
    r = acl_evaluate(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                     PROTO_UDP, 1234, 80);
    TEST_ASSERT(r == ACL_DENY);

    printf("[PASS] test_permit_rule\n");
}

static void test_deny_rule(void) {
    iron_stats_init();
    acl_init(ACL_DEFAULT_PERMIT);

    acl_match_t m = match_any();
    m.dst_ip = (ip_prefix_t){iron_str_to_ip("10.0.2.0"), 24};
    acl_add_rule(1, &m, ACL_DENY);

    /* Traffic to 10.0.2.x should be denied */
    acl_action_t r = acl_evaluate(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.5"),
                                  PROTO_TCP, 1234, 80);
    TEST_ASSERT(r == ACL_DENY);

    /* Traffic to 10.0.3.x should be permitted (default) */
    r = acl_evaluate(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.3.5"),
                     PROTO_TCP, 1234, 80);
    TEST_ASSERT(r == ACL_PERMIT);

    printf("[PASS] test_deny_rule\n");
}

static void test_first_match_wins(void) {
    iron_stats_init();
    acl_init(ACL_DEFAULT_DENY);

    /* Rule 1: permit TCP port 80 */
    acl_match_t m1 = match_any();
    m1.protocol = PROTO_TCP;
    m1.dst_port = (port_range_t){80, 80};
    acl_add_rule(1, &m1, ACL_PERMIT);

    /* Rule 2: deny all TCP */
    acl_match_t m2 = match_any();
    m2.protocol = PROTO_TCP;
    acl_add_rule(2, &m2, ACL_DENY);

    /* TCP port 80 → hits rule 1 first (PERMIT) */
    acl_action_t r = acl_evaluate(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                                  PROTO_TCP, 1234, 80);
    TEST_ASSERT(r == ACL_PERMIT);

    /* TCP port 443 → skips rule 1, hits rule 2 (DENY) */
    r = acl_evaluate(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                     PROTO_TCP, 1234, 443);
    TEST_ASSERT(r == ACL_DENY);

    printf("[PASS] test_first_match_wins\n");
}

int main(void) {
    printf("=== IronNet ACL Unit Tests ===\n");
    test_default_deny();
    test_default_permit();
    test_permit_rule();
    test_deny_rule();
    test_first_match_wins();
    printf("=== All tests passed ===\n");
    return 0;
}
