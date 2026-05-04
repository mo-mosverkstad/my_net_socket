#include "rpc_server.h"
#include "app_socket.h"
#include "log.h"
#include "utils.h"
#include "../ironstack/core/iface.h"

#include <string.h>

#define MODULE "RPC"
#define RPC_PORT 9000

/* Protocol: [MAGIC 4B][CMD 2B][LENGTH 2B][PAYLOAD...] */
#define RPC_MAGIC 0x49524F4E  /* "IRON" */
#define RPC_HEADER_LEN 8

#define RPC_CMD_PING   0x0001
#define RPC_CMD_ECHO   0x0002
#define RPC_CMD_STATUS 0x0003

#define RPC_CMD_PONG   0x8001
#define RPC_CMD_ECHO_REPLY 0x8002
#define RPC_CMD_STATUS_REPLY 0x8003
#define RPC_CMD_ERROR  0xFFFF

static int rpc_build_response(uint8_t *out, uint16_t cmd, const uint8_t *payload, uint16_t payload_len) {
    /* Magic */
    out[0] = (RPC_MAGIC >> 24) & 0xFF;
    out[1] = (RPC_MAGIC >> 16) & 0xFF;
    out[2] = (RPC_MAGIC >> 8) & 0xFF;
    out[3] = RPC_MAGIC & 0xFF;
    /* Command */
    out[4] = (cmd >> 8) & 0xFF;
    out[5] = cmd & 0xFF;
    /* Length */
    out[6] = (payload_len >> 8) & 0xFF;
    out[7] = payload_len & 0xFF;
    /* Payload */
    if (payload_len > 0 && payload)
        memcpy(out + RPC_HEADER_LEN, payload, payload_len);
    return RPC_HEADER_LEN + payload_len;
}

static void rpc_on_data(int sock_id, uint32_t src_ip, uint16_t src_port,
                        const uint8_t *data, int data_len) {
    (void)sock_id;

    iface_config_t *ifc = iface_get(0);
    uint32_t local_ip = ifc ? ifc->ip : 0;

    if (data_len < RPC_HEADER_LEN) {
        LOG_DBG(MODULE, "Packet too short: %d bytes", data_len);
        uint8_t resp[64];
        const char *err = "too short";
        int resp_len = rpc_build_response(resp, RPC_CMD_ERROR, (uint8_t *)err, strlen(err));
        app_socket_send(src_ip, src_port, local_ip, RPC_PORT, PROTO_TCP, resp, resp_len);
        return;
    }

    /* Parse header */
    uint32_t magic = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    uint16_t cmd = (data[4] << 8) | data[5];
    uint16_t payload_len = (data[6] << 8) | data[7];

    if (magic != RPC_MAGIC) {
        LOG_DBG(MODULE, "Invalid magic: 0x%08X", magic);
        uint8_t resp[64];
        const char *err = "bad magic";
        int resp_len = rpc_build_response(resp, RPC_CMD_ERROR, (uint8_t *)err, strlen(err));
        app_socket_send(src_ip, src_port, local_ip, RPC_PORT, PROTO_TCP, resp, resp_len);
        return;
    }

    const uint8_t *payload = data + RPC_HEADER_LEN;
    uint8_t resp[512];
    int resp_len = 0;

    switch (cmd) {
    case RPC_CMD_PING:
        LOG_DBG(MODULE, "PING from port %u", src_port);
        resp_len = rpc_build_response(resp, RPC_CMD_PONG, NULL, 0);
        break;

    case RPC_CMD_ECHO:
        LOG_DBG(MODULE, "ECHO %d bytes from port %u", payload_len, src_port);
        resp_len = rpc_build_response(resp, RPC_CMD_ECHO_REPLY, payload, payload_len);
        break;

    case RPC_CMD_STATUS: {
        LOG_DBG(MODULE, "STATUS from port %u", src_port);
        const char *status = "IronNet RPC OK";
        resp_len = rpc_build_response(resp, RPC_CMD_STATUS_REPLY,
                                      (uint8_t *)status, strlen(status));
        break;
    }

    default:
        LOG_DBG(MODULE, "Unknown command: 0x%04X", cmd);
        const char *err = "unknown cmd";
        resp_len = rpc_build_response(resp, RPC_CMD_ERROR, (uint8_t *)err, strlen(err));
        break;
    }

    if (resp_len > 0) {
        app_socket_send(src_ip, src_port, local_ip, RPC_PORT, PROTO_TCP, resp, resp_len);
    }
}

int rpc_server_start(void) {
    app_socket_listen(PROTO_TCP, RPC_PORT, rpc_on_data, NULL, NULL);
    LOG_INF(MODULE, "RPC server started on TCP port %d", RPC_PORT);
    return 0;
}
