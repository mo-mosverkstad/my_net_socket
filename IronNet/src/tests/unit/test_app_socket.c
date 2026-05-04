#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stats.h"
#include "utils.h"
#include "../ironapps/app_socket.h"
#include "../ironapps/app_socket.c"

/* Stub ip_output (app_socket_send calls it) */
int ip_output(uint32_t s, uint32_t d, uint8_t p, const uint8_t *data, int len) {
    (void)s;(void)d;(void)p;(void)data;(void)len; return 0;
}

/* Stub tcp_find_conn (app_socket_send/close uses it) */
#include "../ironstack/l4/tcp.h"
tcp_conn_t *tcp_find_conn(uint32_t a, uint32_t b, uint16_t c, uint16_t d) {
    (void)a;(void)b;(void)c;(void)d; return NULL;
}

#define TEST_ASSERT(cond) do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d\n", __FILE__, __LINE__); exit(1); } } while(0)

static int g_data_called = 0;
static void dummy_on_data(int s, uint32_t ip, uint16_t port, const uint8_t *d, int l) {
    (void)s;(void)ip;(void)port;(void)d;(void)l; g_data_called++;
}

static void test_listen_and_find(void) {
    app_socket_init();
    int rc = app_socket_listen(PROTO_TCP, 80, dummy_on_data, NULL, NULL);
    TEST_ASSERT(rc == 0);

    app_listener_t *l = app_find_listener(PROTO_TCP, 80);
    TEST_ASSERT(l != NULL);
    TEST_ASSERT(l->port == 80);
    TEST_ASSERT(l->protocol == PROTO_TCP);
    TEST_ASSERT(l->on_data == dummy_on_data);
    printf("[PASS] test_listen_and_find\n");
}

static void test_find_wrong_port(void) {
    app_socket_init();
    app_socket_listen(PROTO_TCP, 80, dummy_on_data, NULL, NULL);

    app_listener_t *l = app_find_listener(PROTO_TCP, 443);
    TEST_ASSERT(l == NULL);
    printf("[PASS] test_find_wrong_port\n");
}

static void test_find_wrong_protocol(void) {
    app_socket_init();
    app_socket_listen(PROTO_TCP, 80, dummy_on_data, NULL, NULL);

    app_listener_t *l = app_find_listener(PROTO_UDP, 80);
    TEST_ASSERT(l == NULL);
    printf("[PASS] test_find_wrong_protocol\n");
}

static void test_multiple_listeners(void) {
    app_socket_init();
    app_socket_listen(PROTO_TCP, 7, dummy_on_data, NULL, NULL);
    app_socket_listen(PROTO_UDP, 53, dummy_on_data, NULL, NULL);
    app_socket_listen(PROTO_TCP, 8080, dummy_on_data, NULL, NULL);

    TEST_ASSERT(app_find_listener(PROTO_TCP, 7) != NULL);
    TEST_ASSERT(app_find_listener(PROTO_UDP, 53) != NULL);
    TEST_ASSERT(app_find_listener(PROTO_TCP, 8080) != NULL);
    TEST_ASSERT(app_find_listener(PROTO_TCP, 9999) == NULL);
    printf("[PASS] test_multiple_listeners\n");
}

int main(void) {
    printf("=== IronNet App Socket Unit Tests ===\n");
    test_listen_and_find();
    test_find_wrong_port();
    test_find_wrong_protocol();
    test_multiple_listeners();
    printf("=== All tests passed ===\n");
    return 0;
}
