#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stats.h"
#include "../ironstack/l3/route.h"
#include "../ironstack/l3/route.c"

#define TEST_ASSERT(cond) do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d\n", __FILE__, __LINE__); exit(1); } } while(0)

/* Helper: build ip_prefix from dotted string */
static ip_prefix_t make_prefix(const char *ip_str, uint8_t prefix_len) {
    ip_prefix_t p;
    p.addr = iron_str_to_ip(ip_str);
    p.prefix_len = prefix_len;
    return p;
}

static void test_route_add_and_lookup(void) {
    iron_stats_init();
    route_init();

    route_add(make_prefix("10.0.1.0", 24), iron_str_to_ip("10.0.1.254"), 0);

    uint32_t nh; int iface;
    int rc = route_lookup(iron_str_to_ip("10.0.1.5"), &nh, &iface);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(iface == 0);
    TEST_ASSERT(nh == iron_str_to_ip("10.0.1.254"));

    printf("[PASS] test_route_add_and_lookup\n");
}

static void test_route_no_match(void) {
    iron_stats_init();
    route_init();

    route_add(make_prefix("10.0.1.0", 24), iron_str_to_ip("10.0.1.254"), 0);

    uint32_t nh; int iface;
    int rc = route_lookup(iron_str_to_ip("192.168.1.1"), &nh, &iface);
    TEST_ASSERT(rc == -1);

    printf("[PASS] test_route_no_match\n");
}

static void test_route_longest_prefix(void) {
    iron_stats_init();
    route_init();

    /* Default route */
    route_add(make_prefix("0.0.0.0", 0), iron_str_to_ip("10.0.0.1"), 0);
    /* /24 route */
    route_add(make_prefix("10.0.1.0", 24), iron_str_to_ip("10.0.1.254"), 1);
    /* /32 host route */
    route_add(make_prefix("10.0.1.100", 32), iron_str_to_ip("10.0.1.1"), 2);

    uint32_t nh; int iface;

    /* Should match /32 */
    route_lookup(iron_str_to_ip("10.0.1.100"), &nh, &iface);
    TEST_ASSERT(iface == 2);

    /* Should match /24 */
    route_lookup(iron_str_to_ip("10.0.1.50"), &nh, &iface);
    TEST_ASSERT(iface == 1);

    /* Should match default */
    route_lookup(iron_str_to_ip("8.8.8.8"), &nh, &iface);
    TEST_ASSERT(iface == 0);

    printf("[PASS] test_route_longest_prefix\n");
}

static void test_route_delete(void) {
    iron_stats_init();
    route_init();

    ip_prefix_t p = make_prefix("10.0.1.0", 24);
    route_add(p, iron_str_to_ip("10.0.1.254"), 0);

    uint32_t nh; int iface;
    TEST_ASSERT(route_lookup(iron_str_to_ip("10.0.1.5"), &nh, &iface) == 0);

    route_delete(p);
    TEST_ASSERT(route_lookup(iron_str_to_ip("10.0.1.5"), &nh, &iface) == -1);

    printf("[PASS] test_route_delete\n");
}

int main(void) {
    printf("=== IronNet L3 Route Unit Tests ===\n");
    test_route_add_and_lookup();
    test_route_no_match();
    test_route_longest_prefix();
    test_route_delete();
    printf("=== All tests passed ===\n");
    return 0;
}
