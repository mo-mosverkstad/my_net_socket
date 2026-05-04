#include "echo_server.h"
#include "app_socket.h"
#include "log.h"
#include "../ironstack/core/iface.h"

#include <string.h>

#define MODULE "ECHO"
#define ECHO_PORT 7

static void echo_tcp_data(int sock_id, uint32_t src_ip, uint16_t src_port,
                          const uint8_t *data, int data_len) {
    (void)sock_id;

    /* Find our local IP (first interface) */
    iface_config_t *ifc = iface_get(0);
    uint32_t local_ip = ifc ? ifc->ip : 0;

    LOG_DBG(MODULE, "TCP echo: %d bytes from port %u", data_len, src_port);

    /* Echo back the same data */
    app_socket_send(src_ip, src_port, local_ip, ECHO_PORT,
                    PROTO_TCP, data, data_len);
}

static void echo_tcp_accept(int sock_id, uint32_t src_ip, uint16_t src_port) {
    (void)sock_id;
    (void)src_ip;
    (void)src_port;
    LOG_DBG(MODULE, "TCP echo: connection accepted from port %u", src_port);
}

static void echo_udp_data(int sock_id, uint32_t src_ip, uint16_t src_port,
                          const uint8_t *data, int data_len) {
    (void)sock_id;

    iface_config_t *ifc = iface_get(0);
    uint32_t local_ip = ifc ? ifc->ip : 0;

    LOG_DBG(MODULE, "UDP echo: %d bytes from port %u", data_len, src_port);

    /* Echo back */
    app_socket_send(src_ip, src_port, local_ip, ECHO_PORT,
                    PROTO_UDP, data, data_len);
}

int echo_server_start(void) {
    app_socket_listen(PROTO_TCP, ECHO_PORT, echo_tcp_data, echo_tcp_accept, NULL);
    app_socket_listen(PROTO_UDP, ECHO_PORT, echo_udp_data, NULL, NULL);
    LOG_INF(MODULE, "Echo server started on TCP/UDP port %d", ECHO_PORT);
    return 0;
}
