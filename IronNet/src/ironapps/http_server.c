#include "http_server.h"
#include "app_socket.h"
#include "log.h"
#include "utils.h"
#include "../ironstack/core/iface.h"

#include <string.h>
#include <stdio.h>

#define MODULE "HTTP"
#define HTTP_PORT 8080

static const char *RESP_200 =
    "HTTP/1.0 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 24\r\n"
    "\r\n"
    "Welcome to IronNet!\r\n\r\n";

static const char *RESP_404 =
    "HTTP/1.0 404 Not Found\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 14\r\n"
    "\r\n"
    "Not Found.\r\n\r\n";

static const char *RESP_400 =
    "HTTP/1.0 400 Bad Request\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 16\r\n"
    "\r\n"
    "Bad Request.\r\n\r\n";

static void http_on_data(int sock_id, uint32_t src_ip, uint16_t src_port,
                         const uint8_t *data, int data_len) {
    (void)sock_id;

    iface_config_t *ifc = iface_get(0);
    uint32_t local_ip = ifc ? ifc->ip : 0;

    /* Parse first line: GET /path HTTP/1.x */
    char req[512];
    int len = data_len < 511 ? data_len : 511;
    memcpy(req, data, len);
    req[len] = 0;

    const char *resp;
    int resp_len;

    if (strncmp(req, "GET ", 4) != 0) {
        resp = RESP_400;
        resp_len = strlen(RESP_400);
        LOG_INF(MODULE, "400 Bad Request from port %u", src_port);
    } else {
        /* Extract path */
        char *path = req + 4;
        char *space = strchr(path, ' ');
        if (space) *space = 0;

        LOG_INF(MODULE, "GET %s from port %u", path, src_port);

        if (strcmp(path, "/") == 0 || strcmp(path, "/index") == 0) {
            resp = RESP_200;
            resp_len = strlen(RESP_200);
        } else {
            resp = RESP_404;
            resp_len = strlen(RESP_404);
        }
    }

    app_socket_send(src_ip, src_port, local_ip, HTTP_PORT,
                    PROTO_TCP, (uint8_t *)resp, resp_len);
}

int http_server_start(void) {
    app_socket_listen(PROTO_TCP, HTTP_PORT, http_on_data, NULL, NULL);
    LOG_INF(MODULE, "HTTP server started on TCP port %d", HTTP_PORT);
    return 0;
}
