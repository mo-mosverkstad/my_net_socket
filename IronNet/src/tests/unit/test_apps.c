#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stats.h"
#include "utils.h"
#include "../ironapps/app_socket.h"

/* Capture last response */
static uint8_t g_last_resp[512];
static int g_last_resp_len = 0;

/* Stubs */
int app_socket_listen(uint8_t p, uint16_t port, app_data_cb_t d, app_accept_cb_t a, app_close_cb_t c) {
    (void)p;(void)port;(void)d;(void)a;(void)c; return 0;
}
int app_socket_send(uint32_t di, uint16_t dp, uint32_t si, uint16_t sp, uint8_t p, const uint8_t *d, int l) {
    (void)di;(void)dp;(void)si;(void)sp;(void)p;
    if (l > 0 && l < (int)sizeof(g_last_resp)) {
        memcpy(g_last_resp, d, l);
        g_last_resp_len = l;
        g_last_resp[l] = 0;
    }
    return 0;
}
app_listener_t *app_find_listener(uint8_t p, uint16_t port) { (void)p;(void)port; return NULL; }
int app_socket_close_conn(uint32_t a, uint16_t b, uint32_t c, uint16_t d) { (void)a;(void)b;(void)c;(void)d; return 0; }

#include "../ironstack/core/iface.h"
static iface_config_t g_fake_iface = { .ip = 0x0100000A }; /* 10.0.0.1 */
iface_config_t *iface_get(int idx) { (void)idx; return &g_fake_iface; }

/* Include server implementations */
#include "../ironapps/kv_server.c"
#include "../ironapps/http_server.c"
#include "../ironapps/rpc_server.c"

#define TEST_ASSERT(cond) do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d\n", __FILE__, __LINE__); exit(1); } } while(0)

/* Helper: simulate data arriving at a server callback */
static void send_to_kv(const char *cmd) {
    g_last_resp_len = 0;
    kv_on_data(0, 0x0200000A, 5000, (const uint8_t *)cmd, strlen(cmd));
}
static void send_to_http(const char *req) {
    g_last_resp_len = 0;
    http_on_data(0, 0x0200000A, 5000, (const uint8_t *)req, strlen(req));
}
static void send_to_rpc(const uint8_t *data, int len) {
    g_last_resp_len = 0;
    rpc_on_data(0, 0x0200000A, 5000, data, len);
}

/* === KV Server Tests === */
static void test_kv_set_get(void) {
    kv_server_start();
    send_to_kv("SET mykey myvalue\n");
    TEST_ASSERT(strstr((char *)g_last_resp, "+OK") != NULL);
    send_to_kv("GET mykey\n");
    TEST_ASSERT(strstr((char *)g_last_resp, "$myvalue") != NULL);
    printf("[PASS] test_kv_set_get\n");
}

static void test_kv_get_nonexistent(void) {
    send_to_kv("GET nosuchkey\n");
    TEST_ASSERT(strstr((char *)g_last_resp, "$nil") != NULL);
    printf("[PASS] test_kv_get_nonexistent\n");
}

static void test_kv_del(void) {
    send_to_kv("SET delme val\n");
    send_to_kv("DEL delme\n");
    TEST_ASSERT(strstr((char *)g_last_resp, "+OK") != NULL);
    send_to_kv("GET delme\n");
    TEST_ASSERT(strstr((char *)g_last_resp, "$nil") != NULL);
    printf("[PASS] test_kv_del\n");
}

static void test_kv_unknown_cmd(void) {
    send_to_kv("BADCMD foo\n");
    TEST_ASSERT(strstr((char *)g_last_resp, "-ERR") != NULL);
    printf("[PASS] test_kv_unknown_cmd\n");
}

/* === HTTP Server Tests === */
static void test_http_get_root(void) {
    send_to_http("GET / HTTP/1.0\r\n\r\n");
    TEST_ASSERT(strstr((char *)g_last_resp, "200 OK") != NULL);
    TEST_ASSERT(strstr((char *)g_last_resp, "Welcome") != NULL);
    printf("[PASS] test_http_get_root\n");
}

static void test_http_get_404(void) {
    send_to_http("GET /nonexistent HTTP/1.0\r\n\r\n");
    TEST_ASSERT(strstr((char *)g_last_resp, "404") != NULL);
    printf("[PASS] test_http_get_404\n");
}

static void test_http_bad_method(void) {
    send_to_http("POST / HTTP/1.0\r\n\r\n");
    TEST_ASSERT(strstr((char *)g_last_resp, "400") != NULL);
    printf("[PASS] test_http_bad_method\n");
}

/* === RPC Server Tests === */
static void test_rpc_ping(void) {
    uint8_t req[] = {0x49, 0x52, 0x4F, 0x4E, 0x00, 0x01, 0x00, 0x00}; /* IRON + PING + len=0 */
    send_to_rpc(req, 8);
    TEST_ASSERT(g_last_resp_len >= 8);
    TEST_ASSERT(g_last_resp[4] == 0x80 && g_last_resp[5] == 0x01); /* PONG */
    printf("[PASS] test_rpc_ping\n");
}

static void test_rpc_echo(void) {
    uint8_t req[] = {0x49, 0x52, 0x4F, 0x4E, 0x00, 0x02, 0x00, 0x02, 'H', 'i'}; /* ECHO "Hi" */
    send_to_rpc(req, 10);
    TEST_ASSERT(g_last_resp_len >= 10);
    TEST_ASSERT(g_last_resp[4] == 0x80 && g_last_resp[5] == 0x02); /* ECHO_REPLY */
    TEST_ASSERT(g_last_resp[8] == 'H' && g_last_resp[9] == 'i');
    printf("[PASS] test_rpc_echo\n");
}

static void test_rpc_bad_magic(void) {
    uint8_t req[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x00, 0x00};
    send_to_rpc(req, 8);
    TEST_ASSERT(g_last_resp[4] == 0xFF && g_last_resp[5] == 0xFF); /* ERROR */
    TEST_ASSERT(strstr((char *)g_last_resp + 8, "bad magic") != NULL);
    printf("[PASS] test_rpc_bad_magic\n");
}

static void test_rpc_too_short(void) {
    uint8_t req[] = {0x49, 0x52, 0x4F}; /* Only 3 bytes */
    send_to_rpc(req, 3);
    TEST_ASSERT(g_last_resp[4] == 0xFF && g_last_resp[5] == 0xFF); /* ERROR */
    printf("[PASS] test_rpc_too_short\n");
}

int main(void) {
    printf("=== IronNet Application Server Unit Tests ===\n");
    test_kv_set_get();
    test_kv_get_nonexistent();
    test_kv_del();
    test_kv_unknown_cmd();
    test_http_get_root();
    test_http_get_404();
    test_http_bad_method();
    test_rpc_ping();
    test_rpc_echo();
    test_rpc_bad_magic();
    test_rpc_too_short();
    printf("=== All tests passed ===\n");
    return 0;
}
