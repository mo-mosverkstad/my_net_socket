#ifndef IRON_LOAD_H
#define IRON_LOAD_H

#include "types.h"

#define LOAD_DEFAULT_RATE   1000
#define LOAD_DEFAULT_COUNT  256

typedef enum {
    LOAD_TCP_FLOOD,      /* Fill TCP connection table with SYNs */
    LOAD_ROUTE_STRESS,   /* Add many routes, measure lookup time */
    LOAD_ACL_STRESS,     /* Add many ACL rules, measure eval time */
    LOAD_BANDWIDTH       /* Send max-rate packets through pipeline */
} load_test_t;

typedef struct {
    load_test_t test;
    int count;           /* Number of items (connections, routes, rules, packets) */
    uint32_t target_ip;
    uint16_t target_port;
} load_config_t;

typedef struct {
    load_test_t test;
    int attempted;
    int succeeded;
    int rejected;
    uint64_t elapsed_us;     /* Total time in microseconds */
    uint64_t per_op_ns;      /* Average nanoseconds per operation */
    bool passed;             /* Graceful degradation (no crash) */
} load_result_t;

int load_run(const load_config_t *cfg, load_result_t *result);
void load_print_result(const load_result_t *result);

#endif /* IRON_LOAD_H */
