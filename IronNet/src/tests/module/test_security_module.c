#include <stdio.h>
#include <string.h>
#include "module_test.h"
#include "stats.h"
#include "utils.h"

#define MT_ASSERT(cond) do { if (!(cond)) { printf("  ASSERT FAILED: %s:%d\n", __FILE__, __LINE__); return MT_FAIL; } } while(0)

/* Include fuzz directly (self-contained) */
#include "../ironfuzz/fuzz.h"
#include "../ironfuzz/fuzz.c"

/* Include route directly (self-contained) */
#include "../ironstack/l3/route.h"
#include "../ironstack/l3/route.c"

static int test_fuzz_no_crash(void) {
    printf("\n[1] Fuzz TCP seed (500 iterations, 0 crashes expected):\n");

    fuzz_engine_t engine;
    fuzz_init(&engine);

    uint8_t seed[64];
    int seed_len = fuzz_seed_tcp_syn(seed, sizeof(seed));
    fuzz_add_seed(&engine, "tcp_syn", seed, seed_len);

    seed_len = fuzz_seed_dns_query(seed, sizeof(seed));
    fuzz_add_seed(&engine, "dns_query", seed, seed_len);

    seed_len = fuzz_seed_rpc_ping(seed, sizeof(seed));
    fuzz_add_seed(&engine, "rpc_ping", seed, seed_len);

    /* Dummy target that never crashes */
    int dummy_target(const uint8_t *data, int len) { (void)data;(void)len; return 0; }
    fuzz_run(&engine, 500, dummy_target);

    printf("  Seeds:      %d\n", engine.corpus_count);
    printf("  Iterations: %lu\n", (unsigned long)engine.stats.iterations);
    printf("  Crashes:    %lu\n", (unsigned long)engine.stats.crashes);
    printf("  Mutations:  %lu\n", (unsigned long)engine.stats.mutations_applied);

    MT_ASSERT(engine.stats.iterations == 500);
    MT_ASSERT(engine.stats.crashes == 0);
    MT_ASSERT(engine.corpus_count == 3);
    return MT_PASS;
}

static int test_fuzz_mutation_changes_data(void) {
    printf("\n[2] Fuzz mutation produces different output:\n");

    uint8_t input[20];
    memset(input, 0xAA, 20);
    uint8_t output[64];
    int output_len;

    /* Run many mutations, at least one should differ */
    int changed = 0;
    for (int i = 0; i < 50; i++) {
        fuzz_mutate(input, 20, output, sizeof(output), &output_len);
        if (memcmp(input, output, 20) != 0 || output_len != 20)
            changed++;
    }

    printf("  50 mutations applied, %d produced different output\n", changed);
    MT_ASSERT(changed > 0);
    return MT_PASS;
}

static int test_route_stress_lookup(void) {
    printf("\n[3] Route stress (100 routes, verify lookup):\n");
    route_init();

    int added = 0;
    for (int i = 0; i < 100; i++) {
        ip_prefix_t pfx = { iron_htonl(0x0A000000 | ((i & 0xFF) << 8)), 24 };
        if (route_add(pfx, iron_str_to_ip("10.0.1.254"), 0) == 0) added++;
    }
    printf("  Routes added: %d / 100\n", added);
    MT_ASSERT(added == 100);

    /* Verify lookups */
    uint32_t nh; int iface;
    int found = 0;
    for (int i = 0; i < 100; i++) {
        uint32_t dst = iron_htonl(0x0A000001 | ((i & 0xFF) << 8));
        if (route_lookup(dst, &nh, &iface) == 0) found++;
    }
    printf("  Lookups found: %d / 100\n", found);
    MT_ASSERT(found == 100);

    /* Non-existent route */
    int rc = route_lookup(iron_str_to_ip("192.168.1.1"), &nh, &iface);
    printf("  Lookup 192.168.1.1 (no route): %s\n", rc == 0 ? "FOUND" : "NOT FOUND");
    MT_ASSERT(rc != 0);

    return MT_PASS;
}

int main(void) {
    mt_suite_t suite;
    mt_suite_init(&suite, "IronNet Security Tools Module Test");
    mt_suite_add(&suite, "Fuzz no crash (500 iters)", test_fuzz_no_crash);
    mt_suite_add(&suite, "Fuzz mutation changes data", test_fuzz_mutation_changes_data);
    mt_suite_add(&suite, "Route stress (100 routes)", test_route_stress_lookup);
    mt_suite_run(&suite);
    return 0;
}
