#include <stdio.h>
#include <stdlib.h>
#include "stats.h"

#define TEST_ASSERT(cond) do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d\n", __FILE__, __LINE__); exit(1); } } while(0)

static void test_stats_init(void) {
    iron_stats_init();
    for (int i = 0; i < STAT_COUNT; i++) {
        TEST_ASSERT(iron_stats_get(i) == 0);
    }
    printf("[PASS] test_stats_init\n");
}

static void test_stats_increment(void) {
    iron_stats_init();
    iron_stats_increment(STAT_L2_RX_FRAMES);
    iron_stats_increment(STAT_L2_RX_FRAMES);
    iron_stats_increment(STAT_L2_RX_FRAMES);
    TEST_ASSERT(iron_stats_get(STAT_L2_RX_FRAMES) == 3);
    printf("[PASS] test_stats_increment\n");
}

static void test_stats_add(void) {
    iron_stats_init();
    iron_stats_add(STAT_TCP_CONN_CREATED, 100);
    TEST_ASSERT(iron_stats_get(STAT_TCP_CONN_CREATED) == 100);
    printf("[PASS] test_stats_add\n");
}

static void test_stats_decrement(void) {
    iron_stats_init();
    iron_stats_increment(STAT_TCP_HALF_OPEN);
    iron_stats_increment(STAT_TCP_HALF_OPEN);
    iron_stats_decrement(STAT_TCP_HALF_OPEN);
    TEST_ASSERT(iron_stats_get(STAT_TCP_HALF_OPEN) == 1);

    /* Should not go below zero */
    iron_stats_init();
    iron_stats_decrement(STAT_TCP_HALF_OPEN);
    TEST_ASSERT(iron_stats_get(STAT_TCP_HALF_OPEN) == 0);
    printf("[PASS] test_stats_decrement\n");
}

static void test_stats_name(void) {
    TEST_ASSERT(iron_stats_name(STAT_L2_RX_FRAMES) != NULL);
    TEST_ASSERT(iron_stats_name(STAT_COUNT) != NULL); /* returns "unknown" */
    printf("[PASS] test_stats_name\n");
}

int main(void) {
    printf("=== IronNet Stats Unit Tests ===\n");
    test_stats_init();
    test_stats_increment();
    test_stats_add();
    test_stats_decrement();
    test_stats_name();
    printf("=== All tests passed ===\n");
    return 0;
}
