#include "../ironapps/app_socket.h"
#include <stddef.h>

/* Stub implementation for tests */
int app_socket_init(void) { return 0; }
int app_socket_listen(uint8_t p, uint16_t port, app_data_cb_t d, app_accept_cb_t a, app_close_cb_t c) {
    (void)p;(void)port;(void)d;(void)a;(void)c; return 0;
}
app_listener_t *app_find_listener(uint8_t protocol, uint16_t port) {
    (void)protocol;(void)port; return NULL;
}
int app_socket_send(uint32_t di, uint16_t dp, uint32_t si, uint16_t sp, uint8_t p, const uint8_t *d, int l) {
    (void)di;(void)dp;(void)si;(void)sp;(void)p;(void)d;(void)l; return 0;
}
int app_socket_close_conn(uint32_t di, uint16_t dp, uint32_t si, uint16_t sp) {
    (void)di;(void)dp;(void)si;(void)sp; return 0;
}
