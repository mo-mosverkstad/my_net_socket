#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stats.h"
#include "utils.h"
#include "../ironstack/l3/pbr.h"
#include "../ironstack/l3/pbr.c"

#define TEST_ASSERT(cond) do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d\n", __FILE__, __LINE__); exit(1); } } while(0)

static void test_pbr_match(void) {
    pbr_init();
    pbr_match_t m = {0};
    m.src_ip = (ip_prefix_t){iron_str_to_ip("10.0.1.0"), 24};
    m.protocol = PROTO_ANY;
    pbr_action_t a = { .next_hop = iron_str_to_ip("10.0.3.1"), .out_iface = 1 };
    pbr_add_rule(1, &m, &a);

    pkt_context_t ctx;
    pkt_context_init(&ctx);
    ctx.acl_checked = true;

    uint32_t nh; int iface;
    int rc = pbr_lookup(iron_str_to_ip("10.0.1.5"), iron_str_to_ip("10.0.2.1"),
                        PROTO_TCP, &ctx, &nh, &iface);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(nh == iron_str_to_ip("10.0.3.1"));
    TEST_ASSERT(iface == 1);
    printf("[PASS] test_pbr_match\n");
}

static void test_pbr_no_match(void) {
    pbr_init();
    pbr_match_t m = {0};
    m.src_ip = (ip_prefix_t){iron_str_to_ip("10.0.1.0"), 24};
    m.protocol = PROTO_ANY;
    pbr_action_t a = { .next_hop = iron_str_to_ip("10.0.3.1"), .out_iface = 1 };
    pbr_add_rule(1, &m, &a);

    pkt_context_t ctx;
    pkt_context_init(&ctx);
    ctx.acl_checked = true;

    uint32_t nh; int iface;
    int rc = pbr_lookup(iron_str_to_ip("10.0.9.1"), iron_str_to_ip("10.0.2.1"),
                        PROTO_TCP, &ctx, &nh, &iface);
    TEST_ASSERT(rc == -1); /* No match */
    printf("[PASS] test_pbr_no_match\n");
}

static void test_pbr_loop_detection(void) {
    pbr_init();
    pbr_match_t m = {0};
    m.protocol = PROTO_ANY;
    pbr_action_t a = { .next_hop = iron_str_to_ip("10.0.5.1"), .out_iface = 0 };
    pbr_add_rule(1, &m, &a);

    pkt_context_t ctx;
    pkt_context_init(&ctx);
    ctx.acl_checked = true;

    uint32_t nh; int iface;
    pbr_lookup(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
               PROTO_TCP, &ctx, &nh, &iface);

    /* Second lookup with same context → loop */
    int rc = pbr_lookup(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                        PROTO_TCP, &ctx, &nh, &iface);
    TEST_ASSERT(rc == -2);
    printf("[PASS] test_pbr_loop_detection\n");
}

static void test_pbr_delete(void) {
    pbr_init();
    pbr_match_t m = {0};
    m.protocol = PROTO_ANY;
    pbr_action_t a = { .next_hop = iron_str_to_ip("10.0.3.1"), .out_iface = 1 };
    pbr_add_rule(1, &m, &a);

    pkt_context_t ctx;
    pkt_context_init(&ctx);
    ctx.acl_checked = true;
    uint32_t nh; int iface;

    TEST_ASSERT(pbr_lookup(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                           PROTO_TCP, &ctx, &nh, &iface) == 0);

    pbr_delete_rule(1);
    pkt_context_init(&ctx);
    ctx.acl_checked = true;
    TEST_ASSERT(pbr_lookup(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                           PROTO_TCP, &ctx, &nh, &iface) == -1);
    printf("[PASS] test_pbr_delete\n");
}

int main(void) {
    printf("=== IronNet PBR Unit Tests ===\n");
    test_pbr_match();
    test_pbr_no_match();
    test_pbr_loop_detection();
    test_pbr_delete();
    printf("=== All tests passed ===\n");
    return 0;
}
