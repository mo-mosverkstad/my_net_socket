#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stats.h"
#include "utils.h"
#include "../ironstack/l3/route_table.h"
#include "../ironstack/l3/route_table.c"

#define TEST_ASSERT(cond) do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d\n", __FILE__, __LINE__); exit(1); } } while(0)

static void test_default_main_table(void) {
    route_table_init();

    int idx = route_table_find("main");
    TEST_ASSERT(idx == 0);
    printf("[PASS] test_default_main_table\n");
}

static void test_create_and_find(void) {
    route_table_init();

    int mgmt = route_table_create("mgmt");
    TEST_ASSERT(mgmt == 1);

    int found = route_table_find("mgmt");
    TEST_ASSERT(found == 1);

    int notfound = route_table_find("nonexist");
    TEST_ASSERT(notfound == -1);
    printf("[PASS] test_create_and_find\n");
}

static void test_independent_tables(void) {
    route_table_init();
    int mgmt = route_table_create("mgmt");

    /* Add different routes to different tables */
    route_table_add_route(ROUTE_TABLE_MAIN,
                          (ip_prefix_t){iron_str_to_ip("10.0.1.0"), 24},
                          iron_str_to_ip("10.0.1.254"), 0);

    route_table_add_route(mgmt,
                          (ip_prefix_t){iron_str_to_ip("10.0.1.0"), 24},
                          iron_str_to_ip("192.168.1.1"), 1);

    /* Same destination, different tables → different next-hop */
    uint32_t nh; int iface;

    route_table_lookup(ROUTE_TABLE_MAIN, iron_str_to_ip("10.0.1.5"), &nh, &iface);
    TEST_ASSERT(nh == iron_str_to_ip("10.0.1.254"));
    TEST_ASSERT(iface == 0);

    route_table_lookup(mgmt, iron_str_to_ip("10.0.1.5"), &nh, &iface);
    TEST_ASSERT(nh == iron_str_to_ip("192.168.1.1"));
    TEST_ASSERT(iface == 1);

    printf("[PASS] test_independent_tables\n");
}

static void test_longest_prefix_per_table(void) {
    route_table_init();

    route_table_add_route(ROUTE_TABLE_MAIN,
                          (ip_prefix_t){iron_str_to_ip("0.0.0.0"), 0},
                          iron_str_to_ip("10.0.0.1"), 0);
    route_table_add_route(ROUTE_TABLE_MAIN,
                          (ip_prefix_t){iron_str_to_ip("10.0.1.0"), 24},
                          iron_str_to_ip("10.0.1.254"), 1);

    uint32_t nh; int iface;

    /* /24 match */
    route_table_lookup(ROUTE_TABLE_MAIN, iron_str_to_ip("10.0.1.50"), &nh, &iface);
    TEST_ASSERT(iface == 1);

    /* Default route */
    route_table_lookup(ROUTE_TABLE_MAIN, iron_str_to_ip("8.8.8.8"), &nh, &iface);
    TEST_ASSERT(iface == 0);

    printf("[PASS] test_longest_prefix_per_table\n");
}

static void test_delete_route(void) {
    route_table_init();

    ip_prefix_t p = {iron_str_to_ip("10.0.1.0"), 24};
    route_table_add_route(ROUTE_TABLE_MAIN, p, iron_str_to_ip("10.0.1.254"), 0);

    uint32_t nh; int iface;
    TEST_ASSERT(route_table_lookup(ROUTE_TABLE_MAIN, iron_str_to_ip("10.0.1.5"), &nh, &iface) == 0);

    route_table_delete_route(ROUTE_TABLE_MAIN, p);
    TEST_ASSERT(route_table_lookup(ROUTE_TABLE_MAIN, iron_str_to_ip("10.0.1.5"), &nh, &iface) == -1);

    printf("[PASS] test_delete_route\n");
}

static void test_duplicate_table_name(void) {
    route_table_init();

    int first = route_table_create("custom");
    int second = route_table_create("custom"); /* Same name */
    TEST_ASSERT(first == second); /* Returns existing */

    printf("[PASS] test_duplicate_table_name\n");
}

int main(void) {
    printf("=== IronNet Route Table Unit Tests ===\n");
    test_default_main_table();
    test_create_and_find();
    test_independent_tables();
    test_longest_prefix_per_table();
    test_delete_route();
    test_duplicate_table_name();
    printf("=== All tests passed ===\n");
    return 0;
}
