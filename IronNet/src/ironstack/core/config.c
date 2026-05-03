#include "config.h"
#include "log.h"

#define MODULE "CONFIG"

int iron_config_init(void) {
    LOG_INF(MODULE, "Config manager initialized");
    return 0;
}

void iron_config_shutdown(void) {
    LOG_INF(MODULE, "Config manager shutdown");
}
