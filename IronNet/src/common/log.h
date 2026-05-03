#ifndef IRON_LOG_H
#define IRON_LOG_H

#include <stdio.h>
#include <time.h>

typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_FATAL
} log_level_t;

static log_level_t g_log_level = LOG_INFO;

static inline const char *log_level_str(log_level_t level) {
    switch (level) {
        case LOG_DEBUG: return "DEBUG";
        case LOG_INFO:  return "INFO ";
        case LOG_WARN:  return "WARN ";
        case LOG_ERROR: return "ERROR";
        case LOG_FATAL: return "FATAL";
        default:        return "?????";
    }
}

#define IRON_LOG(level, module, fmt, ...)                              \
    do {                                                               \
        if ((level) >= g_log_level) {                                  \
            struct timespec _ts;                                        \
            clock_gettime(CLOCK_MONOTONIC, &_ts);                      \
            fprintf(stderr, "[%ld.%06ld] [%s] [%s] " fmt "\n",        \
                    _ts.tv_sec, _ts.tv_nsec / 1000,                    \
                    log_level_str(level), (module),                     \
                    ##__VA_ARGS__);                                     \
        }                                                              \
    } while (0)

#define LOG_DBG(module, fmt, ...) IRON_LOG(LOG_DEBUG, module, fmt, ##__VA_ARGS__)
#define LOG_INF(module, fmt, ...) IRON_LOG(LOG_INFO,  module, fmt, ##__VA_ARGS__)
#define LOG_WRN(module, fmt, ...) IRON_LOG(LOG_WARN,  module, fmt, ##__VA_ARGS__)
#define LOG_ERR(module, fmt, ...) IRON_LOG(LOG_ERROR, module, fmt, ##__VA_ARGS__)

static inline void iron_log_set_level(log_level_t level) {
    g_log_level = level;
}

#endif /* IRON_LOG_H */
