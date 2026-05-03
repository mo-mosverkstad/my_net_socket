#include "pipeline.h"
#include "log.h"
#include "stats.h"
#include <unistd.h>

#define MODULE "PIPELINE"

int iron_pipeline_init(void) {
    LOG_INF(MODULE, "Pipeline initialized");
    return 0;
}

void iron_pipeline_run_once(void) {
    /* Placeholder: will read from TUN/TAP and process packets in Phase 2 */
    usleep(100000); /* 100ms idle loop until I/O is connected */
}

void iron_pipeline_shutdown(void) {
    LOG_INF(MODULE, "Pipeline shutdown");
}
