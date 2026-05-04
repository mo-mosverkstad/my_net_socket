#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stats.h"
#include "utils.h"
#include "../ironapps/app_socket.h"
#include "../ironapps/dns_server.h"
#include "../ironapps/dns_server.c"

/* Stubs */
int app_socket_listen(uint8_t p, uint16_t port, app_data_cb_t d, app_accept_cb_t a, app_close_cb_t c) {
    (void)p;(void)port;(void)d;(void)a;(void)c; return 0;
}
int app_socket_send(uint32_t di, uint16_t dp, uint32_t si, uint16_t sp, uint8_t p, const uint8_t *d, int l) {
    (void)di;(void)dp;(void)si;(void)sp;(void)p;(void)d;(void)l; return 0;
}
app_listener_t *app_find_listener(uint8_t p, uint16_t port) { (void)p;(void)port; return NULL; }
int app_socket_close_conn(uint32_t a, uint16_t b, uint32_t c, uint16_t d) { (void)a;(void)b;(void)c;(void)d; return 0; }

#include "../ironstack/core/iface.h"
iface_config_t *iface_get(int idx) { (void)idx; return NULL; }

#define TEST_ASSERT(cond) do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d\n", __FILE__, __LINE__); exit(1); } } while(0)

static void test_zone_lookup_found(void) {
    dns_server_start(); /* Initializes zone table */
    /* "ironnet.local" should resolve to 10.0.1.1 */
    uint32_t ip = dns_zone_lookup("ironnet.local");
    TEST_ASSERT(ip != 0);
    printf("[PASS] test_zone_lookup_found\n");
}

static void test_zone_lookup_not_found(void) {
    dns_server_start();
    uint32_t ip = dns_zone_lookup("nonexistent.com");
    TEST_ASSERT(ip == 0);
    printf("[PASS] test_zone_lookup_not_found\n");
}

static void test_zone_multiple_entries(void) {
    dns_server_start();
    TEST_ASSERT(dns_zone_lookup("example.com") != 0);
    TEST_ASSERT(dns_zone_lookup("ironnet.local") != 0);
    TEST_ASSERT(dns_zone_lookup("server.ironnet.local") != 0);
    printf("[PASS] test_zone_multiple_entries\n");
}

int main(void) {
    printf("=== IronNet DNS Server Unit Tests ===\n");
    test_zone_lookup_found();
    test_zone_lookup_not_found();
    test_zone_multiple_entries();
    printf("=== All tests passed ===\n");
    return 0;
}
