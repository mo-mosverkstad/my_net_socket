#ifndef IRON_FUZZ_H
#define IRON_FUZZ_H

#include "types.h"

#define FUZZ_MAX_CORPUS     256
#define FUZZ_MAX_PACKET     2048
#define FUZZ_MAX_MUTATIONS  8

typedef enum {
    MUTATE_BIT_FLIP,       /* Flip random bits */
    MUTATE_BYTE_FLIP,      /* Flip random bytes */
    MUTATE_TRUNCATE,       /* Shorten packet */
    MUTATE_EXTEND,         /* Add random bytes */
    MUTATE_BOUNDARY,       /* Insert boundary values (0, 0xFF, 0xFFFF) */
    MUTATE_INSERT,         /* Insert bytes at random position */
    MUTATE_DELETE,         /* Delete bytes from random position */
    MUTATE_FIELD_AWARE     /* Mutate specific protocol fields */
} fuzz_mutation_t;

typedef struct {
    uint8_t data[FUZZ_MAX_PACKET];
    int len;
    char name[32];
} fuzz_seed_t;

typedef struct {
    uint64_t iterations;
    uint64_t crashes;
    uint64_t timeouts;
    uint64_t unique_paths;
    uint64_t mutations_applied;
} fuzz_stats_t;

typedef struct {
    fuzz_seed_t corpus[FUZZ_MAX_CORPUS];
    int corpus_count;
    fuzz_stats_t stats;
    bool running;
} fuzz_engine_t;

int fuzz_init(fuzz_engine_t *engine);
int fuzz_add_seed(fuzz_engine_t *engine, const char *name,
                  const uint8_t *data, int len);
int fuzz_mutate(const uint8_t *input, int input_len,
                uint8_t *output, int output_max, int *output_len);
int fuzz_run(fuzz_engine_t *engine, int iterations,
             int (*target_fn)(const uint8_t *data, int len));
void fuzz_print_stats(fuzz_engine_t *engine);

/* Pre-built seed generators */
int fuzz_seed_tcp_syn(uint8_t *buf, int buf_len);
int fuzz_seed_dns_query(uint8_t *buf, int buf_len);
int fuzz_seed_http_get(uint8_t *buf, int buf_len);
int fuzz_seed_rpc_ping(uint8_t *buf, int buf_len);

#endif /* IRON_FUZZ_H */
