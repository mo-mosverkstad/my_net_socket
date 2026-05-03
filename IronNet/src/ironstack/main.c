#include <stdio.h>
#include <signal.h>
#include "log.h"
#include "stats.h"
#include "core/pipeline.h"
#include "core/config.h"

#define MODULE "MAIN"

static volatile int g_running = 1;

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    LOG_INF(MODULE, "IronNet v0.1.0 starting...");

    iron_stats_init();

    if (iron_config_init() != 0) {
        LOG_ERR(MODULE, "Config initialization failed");
        return 1;
    }

    if (iron_pipeline_init() != 0) {
        LOG_ERR(MODULE, "Pipeline initialization failed");
        return 1;
    }

    LOG_INF(MODULE, "IronNet running. Press Ctrl+C to stop.");

    while (g_running) {
        iron_pipeline_run_once();
    }

    LOG_INF(MODULE, "Shutting down...");
    iron_stats_dump();
    iron_pipeline_shutdown();
    iron_config_shutdown();

    LOG_INF(MODULE, "IronNet stopped.");
    return 0;
}
