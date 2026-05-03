#ifndef IRON_MODULE_TEST_H
#define IRON_MODULE_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MT_MAX_TESTS 64

typedef enum {
    MT_PASS,
    MT_FAIL
} mt_result_t;

typedef mt_result_t (*mt_test_fn)(void);

typedef struct {
    const char *name;
    mt_test_fn fn;
} mt_test_case_t;

typedef struct {
    const char *suite_name;
    mt_test_case_t tests[MT_MAX_TESTS];
    int count;
    int passed;
    int failed;
} mt_suite_t;

static inline void mt_suite_init(mt_suite_t *suite, const char *name) {
    memset(suite, 0, sizeof(*suite));
    suite->suite_name = name;
}

static inline void mt_suite_add(mt_suite_t *suite, const char *name, mt_test_fn fn) {
    if (suite->count >= MT_MAX_TESTS) return;
    suite->tests[suite->count].name = name;
    suite->tests[suite->count].fn = fn;
    suite->count++;
}

static inline void mt_suite_run(mt_suite_t *suite) {
    printf("=== %s ===\n\n", suite->suite_name);

    for (int i = 0; i < suite->count; i++) {
        mt_test_case_t *tc = &suite->tests[i];
        printf("[%d] %s\n", i + 1, tc->name);

        mt_result_t result = tc->fn();

        if (result == MT_PASS) {
            suite->passed++;
        } else {
            suite->failed++;
            printf("  *** FAILED ***\n");
        }
        printf("\n");
    }

    printf("=== Summary: %d passed, %d failed, %d total ===\n",
           suite->passed, suite->failed, suite->count);
}

/* Utilities */

static inline void mt_hex_dump(const uint8_t *data, int len) {
    printf("    ");
    for (int i = 0; i < len; i++) {
        if (i > 0 && i % 16 == 0) printf("\n    ");
        printf("%02X ", data[i]);
    }
    printf("\n");
}

static inline void mt_print_mac(const uint8_t *mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

#endif /* IRON_MODULE_TEST_H */
