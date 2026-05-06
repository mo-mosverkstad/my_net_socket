#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stats.h"
#include "utils.h"
#include "../ironstack/l3/route.h"
#include "../ironstack/l3/acl.h"
#include "../ironstack/core/iface.h"
#include "../ironstack/core/router_conf.h"
#include "../ironstack/core/router_conf.c"

/* Need route and acl implementations */
#include "../ironstack/l3/route.c"
#include "../ironstack/l3/acl.c"
#include "../ironstack/core/iface.c"

/* Stubs */
#include "../../ironmon/audit.h"
void audit_log_event(audit_event_type_t t, uint32_t s, uint32_t d,
                     uint8_t p, uint16_t sp, uint16_t dp, const char *det) {
    (void)t;(void)s;(void)d;(void)p;(void)sp;(void)dp;(void)det;
}

/* Stub vnic for iface_add */
#include "../ironstack/io/vnic.h"
int vnic_create(const char *name, uint8_t mac[IRON_MAC_LEN]) { (void)name;(void)mac; static int idx=0; return idx++; }

#define TEST_ASSERT(cond) do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d\n", __FILE__, __LINE__); exit(1); } } while(0)

static void test_load_config(void) {
    route_init();
    acl_init(ACL_DEFAULT_PERMIT);
    iface_init();

    /* Write a temp config file */
    const char *path = "/tmp/ironnet_test_conf.conf";
    FILE *f = fopen(path, "w");
    TEST_ASSERT(f != NULL);
    fprintf(f, "# Test config\n");
    fprintf(f, "interface iron0 mac 02:00:00:00:00:01 ip 10.0.1.1/24\n");
    fprintf(f, "route 10.0.1.0/24 dev iron0\n");
    fprintf(f, "route 0.0.0.0/0 via 10.0.1.254 dev iron0\n");
    fprintf(f, "acl permit tcp any any port 80\n");
    fprintf(f, "acl deny tcp any any port 22\n");
    fclose(f);

    int rc = router_conf_load(path);
    TEST_ASSERT(rc == 0);
    printf("[PASS] test_load_config\n");
}

static void test_interface_parsed(void) {
    iface_config_t *ifc = iface_find_by_name("iron0");
    TEST_ASSERT(ifc != NULL);
    TEST_ASSERT(ifc->ip == iron_str_to_ip("10.0.1.1"));
    TEST_ASSERT(ifc->prefix_len == 24);
    printf("[PASS] test_interface_parsed\n");
}

static void test_routes_parsed(void) {
    uint32_t nh; int iface;
    /* Connected route */
    int rc = route_lookup(iron_str_to_ip("10.0.1.5"), &nh, &iface);
    TEST_ASSERT(rc == 0);
    /* Default route */
    rc = route_lookup(iron_str_to_ip("8.8.8.8"), &nh, &iface);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(nh == iron_str_to_ip("10.0.1.254"));
    printf("[PASS] test_routes_parsed\n");
}

static void test_acl_parsed(void) {
    /* Port 80 should be permitted */
    acl_action_t a = acl_evaluate(0, 0, PROTO_TCP, 5000, 80);
    TEST_ASSERT(a == ACL_PERMIT);
    /* Port 22 should be denied */
    a = acl_evaluate(0, 0, PROTO_TCP, 5000, 22);
    TEST_ASSERT(a == ACL_DENY);
    printf("[PASS] test_acl_parsed\n");
}

static void test_missing_file(void) {
    /* Non-existent file should return 0 (graceful) */
    int rc = router_conf_load("/tmp/nonexistent_ironnet_conf.conf");
    TEST_ASSERT(rc == 0);
    printf("[PASS] test_missing_file\n");
}

int main(void) {
    printf("=== IronNet Router Config Unit Tests ===\n");
    test_load_config();
    test_interface_parsed();
    test_routes_parsed();
    test_acl_parsed();
    test_missing_file();
    printf("=== All tests passed ===\n");
    return 0;
}
