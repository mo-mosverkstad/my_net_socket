#include "fuzz.h"
#include "log.h"
#include "utils.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>

#define MODULE "FUZZ"

static unsigned int g_fuzz_seed_val = 0;

static unsigned int fuzz_rand(void) {
    /* Simple LCG for reproducibility */
    g_fuzz_seed_val = g_fuzz_seed_val * 1103515245 + 12345;
    return (g_fuzz_seed_val >> 16) & 0x7FFF;
}

static void fuzz_srand(unsigned int seed) {
    g_fuzz_seed_val = seed;
}

int fuzz_init(fuzz_engine_t *engine) {
    memset(engine, 0, sizeof(*engine));
    fuzz_srand((unsigned int)time(NULL));
    LOG_INF(MODULE, "Fuzzer initialized");
    return 0;
}

int fuzz_add_seed(fuzz_engine_t *engine, const char *name,
                  const uint8_t *data, int len) {
    if (engine->corpus_count >= FUZZ_MAX_CORPUS) return -1;
    if (len > FUZZ_MAX_PACKET) len = FUZZ_MAX_PACKET;

    fuzz_seed_t *s = &engine->corpus[engine->corpus_count];
    memcpy(s->data, data, len);
    s->len = len;
    strncpy(s->name, name, sizeof(s->name) - 1);
    engine->corpus_count++;
    return 0;
}

int fuzz_mutate(const uint8_t *input, int input_len,
                uint8_t *output, int output_max, int *output_len) {
    if (input_len <= 0 || input_len > output_max) return -1;

    /* Start with a copy */
    memcpy(output, input, input_len);
    *output_len = input_len;

    /* Apply 1-3 random mutations */
    int num_mutations = (fuzz_rand() % 3) + 1;

    for (int m = 0; m < num_mutations; m++) {
        fuzz_mutation_t strategy = fuzz_rand() % (MUTATE_FIELD_AWARE + 1);

        switch (strategy) {
        case MUTATE_BIT_FLIP: {
            if (*output_len > 0) {
                int pos = fuzz_rand() % *output_len;
                int bit = fuzz_rand() % 8;
                output[pos] ^= (1 << bit);
            }
            break;
        }
        case MUTATE_BYTE_FLIP: {
            if (*output_len > 0) {
                int pos = fuzz_rand() % *output_len;
                output[pos] = fuzz_rand() & 0xFF;
            }
            break;
        }
        case MUTATE_TRUNCATE: {
            if (*output_len > 1) {
                *output_len = (fuzz_rand() % (*output_len - 1)) + 1;
            }
            break;
        }
        case MUTATE_EXTEND: {
            int add = (fuzz_rand() % 32) + 1;
            if (*output_len + add <= output_max) {
                for (int i = 0; i < add; i++)
                    output[*output_len + i] = fuzz_rand() & 0xFF;
                *output_len += add;
            }
            break;
        }
        case MUTATE_BOUNDARY: {
            if (*output_len >= 2) {
                int pos = fuzz_rand() % (*output_len - 1);
                int val = fuzz_rand() % 4;
                switch (val) {
                case 0: output[pos] = 0x00; output[pos+1] = 0x00; break;
                case 1: output[pos] = 0xFF; output[pos+1] = 0xFF; break;
                case 2: output[pos] = 0x7F; output[pos+1] = 0xFF; break;
                case 3: output[pos] = 0x80; output[pos+1] = 0x00; break;
                }
            }
            break;
        }
        case MUTATE_INSERT: {
            if (*output_len < output_max - 4) {
                int pos = fuzz_rand() % (*output_len + 1);
                int insert_len = (fuzz_rand() % 4) + 1;
                memmove(output + pos + insert_len, output + pos, *output_len - pos);
                for (int i = 0; i < insert_len; i++)
                    output[pos + i] = fuzz_rand() & 0xFF;
                *output_len += insert_len;
            }
            break;
        }
        case MUTATE_DELETE: {
            if (*output_len > 4) {
                int pos = fuzz_rand() % (*output_len - 1);
                int del_len = (fuzz_rand() % 4) + 1;
                if (pos + del_len > *output_len) del_len = *output_len - pos;
                memmove(output + pos, output + pos + del_len, *output_len - pos - del_len);
                *output_len -= del_len;
            }
            break;
        }
        case MUTATE_FIELD_AWARE: {
            /* Mutate common protocol fields */
            if (*output_len >= 20) {
                int field = fuzz_rand() % 4;
                switch (field) {
                case 0: /* IP TTL position (byte 8) */
                    output[8] = fuzz_rand() & 0xFF; break;
                case 1: /* TCP flags position (byte 13 of TCP, ~33 of IP+TCP) */
                    if (*output_len > 33) output[33] = fuzz_rand() & 0x3F; break;
                case 2: /* Length fields */
                    output[2] = fuzz_rand() & 0xFF;
                    output[3] = fuzz_rand() & 0xFF; break;
                case 3: /* Port fields */
                    output[0] = fuzz_rand() & 0xFF;
                    output[1] = fuzz_rand() & 0xFF; break;
                }
            }
            break;
        }
        }
    }

    return 0;
}

int fuzz_run(fuzz_engine_t *engine, int iterations,
             int (*target_fn)(const uint8_t *data, int len)) {
    if (engine->corpus_count == 0) {
        LOG_ERR(MODULE, "No seeds in corpus");
        return -1;
    }

    engine->running = true;
    LOG_INF(MODULE, "Fuzzing started: %d iterations, %d seeds",
            iterations, engine->corpus_count);

    for (int i = 0; i < iterations && engine->running; i++) {
        /* Pick random seed */
        int seed_idx = fuzz_rand() % engine->corpus_count;
        fuzz_seed_t *seed = &engine->corpus[seed_idx];

        /* Mutate */
        uint8_t mutated[FUZZ_MAX_PACKET];
        int mutated_len;
        fuzz_mutate(seed->data, seed->len, mutated, sizeof(mutated), &mutated_len);
        engine->stats.mutations_applied++;

        /* Feed to target */
        int rc = target_fn(mutated, mutated_len);
        engine->stats.iterations++;

        if (rc < -1) {
            /* Crash or assertion failure */
            engine->stats.crashes++;
            LOG_WRN(MODULE, "CRASH at iteration %lu (seed: %s, len: %d)",
                    engine->stats.iterations, seed->name, mutated_len);
        }
    }

    engine->running = false;
    LOG_INF(MODULE, "Fuzzing complete: %lu iterations, %lu crashes",
            engine->stats.iterations, engine->stats.crashes);
    return 0;
}

void fuzz_print_stats(fuzz_engine_t *engine) {
    printf("=== Fuzzer Statistics ===\n");
    printf("  Iterations:   %lu\n", engine->stats.iterations);
    printf("  Crashes:      %lu\n", engine->stats.crashes);
    printf("  Timeouts:     %lu\n", engine->stats.timeouts);
    printf("  Mutations:    %lu\n", engine->stats.mutations_applied);
    printf("  Corpus size:  %d seeds\n", engine->corpus_count);
    printf("\n");
}

/* --- Pre-built seed generators --- */

int fuzz_seed_tcp_syn(uint8_t *buf, int buf_len) {
    if (buf_len < 20) return -1;
    memset(buf, 0, 20);
    buf[0] = 0x13; buf[1] = 0x88; /* src port 5000 */
    buf[2] = 0x00; buf[3] = 0x07; /* dst port 7 */
    buf[4] = 0x00; buf[5] = 0x00; buf[6] = 0x03; buf[7] = 0xE8; /* seq=1000 */
    buf[12] = (5 << 4); /* data offset */
    buf[13] = 0x02; /* SYN flag */
    buf[14] = 0xFF; buf[15] = 0xFF; /* window */
    return 20;
}

int fuzz_seed_dns_query(uint8_t *buf, int buf_len) {
    if (buf_len < 29) return -1;
    /* DNS query for "ironnet.local" */
    uint8_t dns[] = {
        0x00, 0x01, /* ID */
        0x01, 0x00, /* Flags: standard query */
        0x00, 0x01, /* QDCOUNT=1 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* AN/NS/AR=0 */
        0x07, 'i','r','o','n','n','e','t',
        0x05, 'l','o','c','a','l',
        0x00,       /* End of name */
        0x00, 0x01, /* Type A */
        0x00, 0x01  /* Class IN */
    };
    int len = sizeof(dns);
    memcpy(buf, dns, len);
    return len;
}

int fuzz_seed_http_get(uint8_t *buf, int buf_len) {
    const char *req = "GET / HTTP/1.0\r\nHost: ironnet\r\n\r\n";
    int len = strlen(req);
    if (buf_len < len) return -1;
    memcpy(buf, req, len);
    return len;
}

int fuzz_seed_rpc_ping(uint8_t *buf, int buf_len) {
    if (buf_len < 8) return -1;
    buf[0] = 0x49; buf[1] = 0x52; buf[2] = 0x4F; buf[3] = 0x4E; /* IRON */
    buf[4] = 0x00; buf[5] = 0x01; /* CMD: PING */
    buf[6] = 0x00; buf[7] = 0x00; /* Length: 0 */
    return 8;
}
