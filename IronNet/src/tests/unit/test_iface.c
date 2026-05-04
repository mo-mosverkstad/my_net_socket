#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stats.h"
#include "utils.h"

/* Stub vnic_create */
int vnic_create(const char *n, uint8_t m[6]) { (void)n; (void)m; return 0; }

#include "../ironstack/core/iface.h"
#include "../ironstack/core/iface.c"

#define TEST_ASSERT(cond) do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d\n", __FILE__, __LINE__); exit(1); } } while(0)

static void test_iface_add_and_get(void) {
    iface_init();
    uint8_t mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    int idx = iface_add("iron0", mac, iron_str_to_ip("10.0.1.1"), 24);
    TEST_ASSERT(idx == 0);
    TEST_ASSERT(iface_get_count() == 1);

    iface_config_t *ifc = iface_get(0);
    TEST_ASSERT(ifc != NULL);
    TEST_ASSERT(strcmp(ifc->name, "iron0") == 0);
    TEST_ASSERT(ifc->ip == iron_str_to_ip("10.0.1.1"));
    TEST_ASSERT(ifc->prefix_len == 24);
    printf("[PASS] test_iface_add_and_get\n");
}

static void test_iface_find_by_ip(void) {
    iface_init();
    uint8_t mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    iface_add("iron0", mac, iron_str_to_ip("10.0.1.1"), 24);

    iface_config_t *ifc = iface_find_by_ip(iron_str_to_ip("10.0.1.1"));
    TEST_ASSERT(ifc != NULL);
    TEST_ASSERT(strcmp(ifc->name, "iron0") == 0);

    ifc = iface_find_by_ip(iron_str_to_ip("10.0.2.1"));
    TEST_ASSERT(ifc == NULL);
    printf("[PASS] test_iface_find_by_ip\n");
}

static void test_iface_find_by_name(void) {
    iface_init();
    uint8_t mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    iface_add("iron0", mac, iron_str_to_ip("10.0.1.1"), 24);

    iface_config_t *ifc = iface_find_by_name("iron0");
    TEST_ASSERT(ifc != NULL);

    ifc = iface_find_by_name("iron99");
    TEST_ASSERT(ifc == NULL);
    printf("[PASS] test_iface_find_by_name\n");
}

static void test_iface_is_local_ip(void) {
    iface_init();
    uint8_t mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    iface_add("iron0", mac, iron_str_to_ip("10.0.1.1"), 24);
    iface_add("iron1", mac, iron_str_to_ip("10.0.2.1"), 24);

    TEST_ASSERT(iface_is_local_ip(iron_str_to_ip("10.0.1.1")) == true);
    TEST_ASSERT(iface_is_local_ip(iron_str_to_ip("10.0.2.1")) == true);
    TEST_ASSERT(iface_is_local_ip(iron_str_to_ip("10.0.3.1")) == false);
    printf("[PASS] test_iface_is_local_ip\n");
}

int main(void) {
    printf("=== IronNet Interface Unit Tests ===\n");
    test_iface_add_and_get();
    test_iface_find_by_ip();
    test_iface_find_by_name();
    test_iface_is_local_ip();
    printf("=== All tests passed ===\n");
    return 0;
}
