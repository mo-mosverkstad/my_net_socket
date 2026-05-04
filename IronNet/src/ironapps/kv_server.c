#include "kv_server.h"
#include "app_socket.h"
#include "log.h"
#include "utils.h"
#include "../ironstack/core/iface.h"

#include <string.h>
#include <stdio.h>

#define MODULE "KV"
#define KV_PORT 6379
#define KV_MAX_ENTRIES 256
#define KV_MAX_KEY 64
#define KV_MAX_VALUE 256

typedef struct {
    char key[KV_MAX_KEY];
    char value[KV_MAX_VALUE];
    bool active;
} kv_entry_t;

static kv_entry_t g_kv_store[KV_MAX_ENTRIES];
static int g_kv_count = 0;

static kv_entry_t *kv_find(const char *key) {
    for (int i = 0; i < KV_MAX_ENTRIES; i++) {
        if (g_kv_store[i].active && strcmp(g_kv_store[i].key, key) == 0)
            return &g_kv_store[i];
    }
    return NULL;
}

static int kv_set(const char *key, const char *value) {
    kv_entry_t *e = kv_find(key);
    if (!e) {
        if (g_kv_count >= KV_MAX_ENTRIES) return -1;
        for (int i = 0; i < KV_MAX_ENTRIES; i++) {
            if (!g_kv_store[i].active) { e = &g_kv_store[i]; break; }
        }
        if (!e) return -1;
        g_kv_count++;
    }
    strncpy(e->key, key, KV_MAX_KEY - 1);
    strncpy(e->value, value, KV_MAX_VALUE - 1);
    e->active = true;
    return 0;
}

static int kv_del(const char *key) {
    kv_entry_t *e = kv_find(key);
    if (!e) return -1;
    e->active = false;
    g_kv_count--;
    return 0;
}

static void kv_on_data(int sock_id, uint32_t src_ip, uint16_t src_port,
                       const uint8_t *data, int data_len) {
    (void)sock_id;

    iface_config_t *ifc = iface_get(0);
    uint32_t local_ip = ifc ? ifc->ip : 0;

    /* Parse command: SET key value / GET key / DEL key */
    char cmd[512];
    int len = data_len < 511 ? data_len : 511;
    memcpy(cmd, data, len);
    cmd[len] = 0;
    /* Strip trailing newline */
    while (len > 0 && (cmd[len-1] == '\n' || cmd[len-1] == '\r')) cmd[--len] = 0;

    char resp[512];
    int resp_len = 0;

    if (strncmp(cmd, "SET ", 4) == 0) {
        char *key = cmd + 4;
        char *val = strchr(key, ' ');
        if (val) {
            *val = 0; val++;
            if (kv_set(key, val) == 0)
                resp_len = snprintf(resp, sizeof(resp), "+OK\r\n");
            else
                resp_len = snprintf(resp, sizeof(resp), "-ERR store full\r\n");
        } else {
            resp_len = snprintf(resp, sizeof(resp), "-ERR usage: SET key value\r\n");
        }
    } else if (strncmp(cmd, "GET ", 4) == 0) {
        char *key = cmd + 4;
        kv_entry_t *e = kv_find(key);
        if (e)
            resp_len = snprintf(resp, sizeof(resp), "$%s\r\n", e->value);
        else
            resp_len = snprintf(resp, sizeof(resp), "$nil\r\n");
    } else if (strncmp(cmd, "DEL ", 4) == 0) {
        char *key = cmd + 4;
        if (kv_del(key) == 0)
            resp_len = snprintf(resp, sizeof(resp), "+OK\r\n");
        else
            resp_len = snprintf(resp, sizeof(resp), "-ERR not found\r\n");
    } else {
        resp_len = snprintf(resp, sizeof(resp), "-ERR unknown command\r\n");
    }

    if (resp_len > 0) {
        app_socket_send(src_ip, src_port, local_ip, KV_PORT,
                        PROTO_TCP, (uint8_t *)resp, resp_len);
    }
}

int kv_server_start(void) {
    memset(g_kv_store, 0, sizeof(g_kv_store));
    g_kv_count = 0;
    app_socket_listen(PROTO_TCP, KV_PORT, kv_on_data, NULL, NULL);
    LOG_INF(MODULE, "KV server started on TCP port %d", KV_PORT);
    return 0;
}
