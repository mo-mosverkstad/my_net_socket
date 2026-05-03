#include "pipeline.h"
#include "log.h"
#include "stats.h"
#include "../io/vnic.h"
#include "../l2/eth.h"
#include "../l3/route.h"
#include "../l3/acl.h"
#include "../l3/pbr.h"

#include <unistd.h>

#define MODULE "PIPELINE"
#define RX_BUF_SIZE 2048

static uint8_t rx_buf[RX_BUF_SIZE];

int iron_pipeline_init(void) {
    if (vnic_init() != 0) return -1;
    if (route_init() != 0) return -1;
    if (acl_init(ACL_DEFAULT_PERMIT) != 0) return -1;
    if (pbr_init() != 0) return -1;
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

    usleep(1000); /* 1ms poll interval */
}

void iron_pipeline_shutdown(void) {
    vnic_shutdown();
    LOG_INF(MODULE, "Pipeline shutdown");
}
