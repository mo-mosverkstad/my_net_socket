#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stats.h"
#include "../ironstack/security/defense.h"
#include "../ironstack/security/defense.c"

#define TEST_ASSERT(cond) do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d\n", __FILE__, __LINE__); exit(1); } } while(0)

static void test_init_all_disabled(void) {
    defense_init();
    TEST_ASSERT(!defense_is_enabled("syn-cookies"));
    TEST_ASSERT(!defense_is_enabled("rate-limit"));
    TEST_ASSERT(!defense_is_enabled("arp-inspection"));
    TEST_ASSERT(!defense_is_enabled("vlan-strict"));
    printf("[PASS] test_init_all_disabled\n");
}

static void test_enable_disable(void) {
    defense_init();
    defense_enable("syn-cookies");
    TEST_ASSERT(defense_is_enabled("syn-cookies"));
    TEST_ASSERT(!defense_is_enabled("rate-limit"));

    defense_disable("syn-cookies");
    TEST_ASSERT(!defense_is_enabled("syn-cookies"));
    printf("[PASS] test_enable_disable\n");
}

static void test_syncookie_generate_validate(void) {
    defense_init();
    uint32_t cookie = syncookie_generate(0x0A000101, 0x0A000201, 1234, 80, 1000);
    TEST_ASSERT(cookie != 0);

    /* Validate: ack should be cookie + 1 */
    bool ok = syncookie_validate(0x0A000101, 0x0A000201, 1234, 80, cookie, cookie + 1);
    TEST_ASSERT(ok);

    /* Wrong ack should fail */
    bool bad = syncookie_validate(0x0A000101, 0x0A000201, 1234, 80, cookie, 9999);
    TEST_ASSERT(!bad);
    printf("[PASS] test_syncookie_generate_validate\n");
}

static void test_rate_limit(void) {
    defense_init();
    rate_limit_set(3);

    uint32_t src = 0x0A000105;
    TEST_ASSERT(rate_limit_check(src) == true);  /* 1 */
    TEST_ASSERT(rate_limit_check(src) == true);  /* 2 */
    TEST_ASSERT(rate_limit_check(src) == true);  /* 3 */
    TEST_ASSERT(rate_limit_check(src) == false); /* 4 > limit */

    /* Different source should be independent */
    TEST_ASSERT(rate_limit_check(0x0A000106) == true);

    /* After tick, counters reset */
    rate_limit_tick();
    TEST_ASSERT(rate_limit_check(src) == true);
    printf("[PASS] test_rate_limit\n");
}

static void test_unknown_defense(void) {
    defense_init();
    TEST_ASSERT(!defense_is_enabled("nonexistent"));
    /* Disable unknown returns -1 */
    TEST_ASSERT(defense_disable("nonexistent") == -1);
    printf("[PASS] test_unknown_defense\n");
}

int main(void) {
    printf("=== IronNet Defense Unit Tests ===\n");
    test_init_all_disabled();
    test_enable_disable();
    test_syncookie_generate_validate();
    test_rate_limit();
    test_unknown_defense();
    printf("=== All tests passed ===\n");
    return 0;
}
