#include <stdio.h>
#include <string.h>
#include <signal.h>
#include "log.h"
#include "stats.h"
#include "core/pipeline.h"
#include "core/config.h"
#include "../ironctl/cli.h"

#define MODULE "MAIN"

static volatile int g_running = 1;

/* Allow CLI to signal shutdown */
void iron_request_shutdown(void) {
    g_running = 0;
}

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [-d] [config_file]\n", prog);
    fprintf(stderr, "  -d    Enable debug logging\n");
    fprintf(stderr, "  config_file  Path to router.conf\n");
}

int main(int argc, char *argv[]) {
    const char *conf_file = NULL;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) {
            iron_log_set_level(LOG_DEBUG);
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            conf_file = argv[i];
        }
    }

    LOG_INF(MODULE, "IronNet v0.1.0 starting...");

    iron_stats_init();

    if (iron_config_init() != 0) {
        LOG_ERR(MODULE, "Config initialization failed");
        return 1;
    }

    if (conf_file) {
        iron_pipeline_set_config(conf_file);
    }

    if (iron_pipeline_init() != 0) {
        LOG_ERR(MODULE, "Pipeline initialization failed");
        return 1;
    }

    LOG_INF(MODULE, "IronNet running. Press Ctrl+C to stop.");

    /* Start CLI thread */
    cli_start();

    while (g_running) {
        iron_pipeline_run_once();
    }

    LOG_INF(MODULE, "Shutting down...");
    cli_stop();
    iron_stats_dump();
    iron_pipeline_shutdown();
    iron_config_shutdown();

    LOG_INF(MODULE, "IronNet stopped.");
    return 0;
}
