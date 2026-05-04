#include <stdio.h>
#include <string.h>
#include "module_test.h"
#include "stats.h"
#include "utils.h"
#include "../ironstack/l3/route_table.h"
#include "../ironstack/l3/route_table.c"

/* Test 1: Same destination, different tables → different next-hop */
static mt_result_t test_independent_routing(void) {
    route_table_init();
    int mgmt = route_table_create("mgmt");

    /* Main table: 10.0.0.0/8 via 10.0.1.254 iface 0 */
    route_table_add_route(ROUTE_TABLE_MAIN,
                          (ip_prefix_t){iron_str_to_ip("10.0.0.0"), 8},
                          iron_str_to_ip("10.0.1.254"), 0);

    /* Mgmt table: 10.0.0.0/8 via 192.168.1.1 iface 1 */
    route_table_add_route(mgmt,
                          (ip_prefix_t){iron_str_to_ip("10.0.0.0"), 8},
                          iron_str_to_ip("192.168.1.1"), 1);

    uint32_t nh; int iface;
    char nh_buf[16];

    printf("  Destination: 10.0.5.1\n");
    printf("  Table 'main': 10.0.0.0/8 via 10.0.1.254 iface 0\n");
    printf("  Table 'mgmt': 10.0.0.0/8 via 192.168.1.1 iface 1\n\n");

    route_table_lookup(ROUTE_TABLE_MAIN, iron_str_to_ip("10.0.5.1"), &nh, &iface);
    printf("  Lookup in 'main': next_hop=%s iface=%d\n",
           iron_ip_to_str(nh, nh_buf, sizeof(nh_buf)), iface);
    if (iface != 0) return MT_FAIL;

    route_table_lookup(mgmt, iron_str_to_ip("10.0.5.1"), &nh, &iface);
    printf("  Lookup in 'mgmt': next_hop=%s iface=%d\n",
           iron_ip_to_str(nh, nh_buf, sizeof(nh_buf)), iface);
    if (iface != 1) return MT_FAIL;

    return MT_PASS;
}

/* Test 2: PBR selects alternate table (simulated) */
static mt_result_t test_pbr_table_selection(void) {
    route_table_init();
    int mgmt = route_table_create("mgmt");

    /* Main: default route via iface 0 */
    route_table_add_route(ROUTE_TABLE_MAIN,
                          (ip_prefix_t){iron_str_to_ip("0.0.0.0"), 0},
                          iron_str_to_ip("10.0.1.254"), 0);

    /* Mgmt: default route via iface 2 */
    route_table_add_route(mgmt,
                          (ip_prefix_t){iron_str_to_ip("0.0.0.0"), 0},
                          iron_str_to_ip("192.168.0.1"), 2);

    printf("  Scenario: PBR matches src 10.0.99.0/24 → use table 'mgmt'\n");
    printf("  Table 'main': default via 10.0.1.254 iface 0\n");
    printf("  Table 'mgmt': default via 192.168.0.1 iface 2\n\n");

    /* Simulate PBR decision: packet from 10.0.99.5 → use mgmt table */
    uint32_t src_ip = iron_str_to_ip("10.0.99.5");
    uint32_t dst_ip = iron_str_to_ip("8.8.8.8");
    int selected_table = ROUTE_TABLE_MAIN;

    /* PBR logic: if src matches 10.0.99.0/24, use mgmt */
    if (iron_ip_matches(src_ip, iron_str_to_ip("10.0.99.0"), 24)) {
        selected_table = mgmt;
    }

    uint32_t nh; int iface;
    char nh_buf[16];
    route_table_lookup(selected_table, dst_ip, &nh, &iface);

    printf("  Packet src=10.0.99.5 dst=8.8.8.8\n");
    printf("  PBR selected table: '%s' (id=%d)\n",
           selected_table == mgmt ? "mgmt" : "main", selected_table);
    printf("  Result: next_hop=%s iface=%d\n",
           iron_ip_to_str(nh, nh_buf, sizeof(nh_buf)), iface);

    if (selected_table != mgmt) return MT_FAIL;
    if (iface != 2) return MT_FAIL;

    /* Non-matching source uses main table */
    src_ip = iron_str_to_ip("10.0.1.5");
    selected_table = ROUTE_TABLE_MAIN;
    if (iron_ip_matches(src_ip, iron_str_to_ip("10.0.99.0"), 24)) {
        selected_table = mgmt;
    }
    route_table_lookup(selected_table, dst_ip, &nh, &iface);

    printf("  Packet src=10.0.1.5 dst=8.8.8.8 (no PBR match)\n");
    printf("  Result: table='main' next_hop=%s iface=%d\n",
           iron_ip_to_str(nh, nh_buf, sizeof(nh_buf)), iface);

    if (iface != 0) return MT_FAIL;

    return MT_PASS;
}

/* Test 3: Table isolation — route in one table doesn't affect another */
static mt_result_t test_table_isolation(void) {
    route_table_init();
    int custom = route_table_create("custom");

    /* Only add route to custom table */
    route_table_add_route(custom,
                          (ip_prefix_t){iron_str_to_ip("172.16.0.0"), 16},
                          iron_str_to_ip("172.16.0.1"), 3);

    uint32_t nh; int iface;

    printf("  Route 172.16.0.0/16 exists only in table 'custom'\n");

    int rc = route_table_lookup(custom, iron_str_to_ip("172.16.5.1"), &nh, &iface);
    printf("  Lookup in 'custom': %s (iface=%d)\n", rc == 0 ? "FOUND" : "NOT FOUND", iface);
    if (rc != 0) return MT_FAIL;

    rc = route_table_lookup(ROUTE_TABLE_MAIN, iron_str_to_ip("172.16.5.1"), &nh, &iface);
    printf("  Lookup in 'main': %s\n", rc == -1 ? "NOT FOUND (correct)" : "ERROR");
    if (rc != -1) return MT_FAIL;

    return MT_PASS;
}

int main(void) {
    mt_suite_t suite;
    mt_suite_init(&suite, "IronNet L3 Module Test — Multiple Routing Tables");

    mt_suite_add(&suite, "Same destination, different tables → different next-hop:", test_independent_routing);
    mt_suite_add(&suite, "PBR selects alternate routing table:", test_pbr_table_selection);
    mt_suite_add(&suite, "Table isolation (route in one doesn't affect another):", test_table_isolation);

    mt_suite_run(&suite);

    return suite.failed > 0 ? 1 : 0;
}
