#ifndef IRON_APP_SOCKET_H
#define IRON_APP_SOCKET_H

#include "types.h"

#define APP_MAX_LISTENERS  32
#define APP_MAX_RECV_BUF   4096

/* Callback when data arrives for a registered app */
typedef void (*app_data_cb_t)(int sock_id, uint32_t src_ip, uint16_t src_port,
                              const uint8_t *data, int data_len);

/* Callback when a new TCP connection is accepted */
typedef void (*app_accept_cb_t)(int sock_id, uint32_t src_ip, uint16_t src_port);

/* Callback when connection is closed */
typedef void (*app_close_cb_t)(int sock_id);

typedef struct {
    uint8_t protocol;       /* PROTO_TCP or PROTO_UDP */
    uint16_t port;
    app_data_cb_t on_data;
    app_accept_cb_t on_accept;
    app_close_cb_t on_close;
    bool active;
} app_listener_t;

int app_socket_init(void);
int app_socket_listen(uint8_t protocol, uint16_t port,
                      app_data_cb_t on_data,
                      app_accept_cb_t on_accept,
                      app_close_cb_t on_close);
int app_socket_send(uint32_t dst_ip, uint16_t dst_port,
                    uint32_t src_ip, uint16_t src_port,
                    uint8_t protocol,
                    const uint8_t *data, int data_len);
int app_socket_close_conn(uint32_t dst_ip, uint16_t dst_port,
                          uint32_t src_ip, uint16_t src_port);

/* Called by TCP/UDP when data arrives — dispatches to registered app */
app_listener_t *app_find_listener(uint8_t protocol, uint16_t port);

#endif /* IRON_APP_SOCKET_H */
