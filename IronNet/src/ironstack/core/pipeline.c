#include "pipeline.h"
#include "iface.h"
#include "router_conf.h"
#include "log.h"
#include "stats.h"
#include "../io/vnic.h"
#include "../l2/eth.h"
#include "../l2/arp.h"
#include "../l3/route.h"
#include "../l3/acl.h"
#include "../l3/pbr.h"
#include "../l3/ip_frag.h"
#include "../l4/tcp.h"
#include "../ironmon/audit.h"
#include "../ironapps/app_socket.h"
#include "../ironapps/echo_server.h"
#include "../ironapps/dns_server.h"
#include "../ironapps/kv_server.h"
#include "../ironapps/http_server.h"
#include "../ironapps/rpc_server.h"
#include "../security/defense.h"

#include <unistd.h>
#include <time.h>

#define MODULE "PIPELINE"
#define RX_BUF_SIZE 2048

static uint8_t rx_buf[RX_BUF_SIZE];
static const char *g_conf_file = NULL;
static uint64_t g_last_tick_sec = 0;

static uint64_t pipeline_now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec;
}

void iron_pipeline_set_config(const char *conf_file) {
    g_conf_file = conf_file;
}

int iron_pipeline_init(void) {
    if (vnic_init() != 0) return -1;
    if (iface_init() != 0) return -1;
    if (arp_init() != 0) return -1;
    if (route_init() != 0) return -1;
    if (acl_init(ACL_DEFAULT_PERMIT) != 0) return -1;
    if (pbr_init() != 0) return -1;
    if (tcp_init() != 0) return -1;
    audit_init(AUDIT_DEFAULT_FILE);
    app_socket_init();
    defense_init();
    echo_server_start();
    dns_server_start();
    kv_server_start();
    http_server_start();
    rpc_server_start();

    /* Load config file if specified */
    if (g_conf_file) {
        router_conf_load(g_conf_file);
    }

    LOG_INF(MODULE, "Pipeline initialized");
    return 0;
}

void iron_pipeline_run_once(void) {
    int count = vnic_get_count();

    if (count == 0) {
        usleep(100000); /* No interfaces yet, idle */
        return;
    }

    for (int i = 0; i < count; i++) {
        int n = vnic_read(i, rx_buf, RX_BUF_SIZE);
        if (n <= 0) continue;

        eth_frame_t frame;
        if (eth_parse(rx_buf, n, i, &frame) == 0) {
            eth_dispatch(&frame);
        }
    }

    /* 1-second timer tick for all subsystems */
    uint64_t now = pipeline_now_sec();
    if (now != g_last_tick_sec) {
        g_last_tick_sec = now;
        tcp_timer_tick();
        arp_timer_tick();
        ip_frag_timer_tick();
        rate_limit_tick();
    }

    usleep(1000); /* 1ms poll interval */
}

void iron_pipeline_shutdown(void) {
    vnic_shutdown();
    LOG_INF(MODULE, "Pipeline shutdown");
}
