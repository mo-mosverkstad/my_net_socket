#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../ironstack/security/covert_detect.h"
#include "../../ironstack/security/covert_detect.c"

/* Stubs */
#include "../../ironmon/audit.h"
void audit_log_event(audit_event_type_t t, uint32_t s, uint32_t d,
                     uint8_t p, uint16_t sp, uint16_t dp, const char *det) {
    (void)t;(void)s;(void)d;(void)p;(void)sp;(void)dp;(void)det;
}
#include "../../ironstack/security/defense.h"
bool defense_is_enabled(const char *n) { (void)n; return true; }

#define TEST_ASSERT(cond) do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d\n", __FILE__, __LINE__); exit(1); } } while(0)

static void test_icmp_low_entropy_no_alert(void) {
    /* Normal ping: incrementing bytes 0x10-0x37 (48 bytes) */
    uint8_t payload[56]; /* 8 ICMP header + 48 data */
    memset(payload, 0, 8); /* ICMP header */
    payload[0] = 8; /* echo request */
    for (int i = 0; i < 48; i++) payload[8 + i] = 0x10 + i;
    int rc = covert_detect_icmp(payload, 56, 0x0A000102, 0x0A000101);
    TEST_ASSERT(rc == 0); /* No alert for normal ping pattern */
    printf("[PASS] test_icmp_low_entropy_no_alert\n");
}

static void test_icmp_high_ascii_alert(void) {
    /* Covert: ASCII text in ICMP payload */
    uint8_t payload[48];
    memset(payload, 0, 8);
    payload[0] = 8;
    memcpy(payload + 8, "This is hidden secret data!!!!!!!!!!!!!!", 40);
    int rc = covert_detect_icmp(payload, 48, 0x0A000102, 0x0A000101);
    TEST_ASSERT(rc == 1); /* Alert: high ASCII ratio */
    printf("[PASS] test_icmp_high_ascii_alert\n");
}

static void test_isn_random_no_alert(void) {
    covert_detect_reset();
    /* Random ISNs (non-ASCII bytes) */
    uint32_t random_isns[] = {0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0};
    int rc = 0;
    for (int i = 0; i < 4; i++)
        rc = covert_detect_isn(random_isns[i], 0x0A000102, 0x0A000101);
    TEST_ASSERT(rc == 0); /* No alert for random ISNs */
    printf("[PASS] test_isn_random_no_alert\n");
}

static void test_isn_ascii_alert(void) {
    covert_detect_reset();
    /* ASCII-encoded ISNs: "HELL", "O WO", "RLD!", "SECR" */
    uint32_t ascii_isns[] = {0x4C4C4548, 0x4F57204F, 0x20444C52, 0x52434553};
    int rc = 0;
    for (int i = 0; i < 4; i++)
        rc = covert_detect_isn(ascii_isns[i], 0x0A000102, 0x0A000101);
    TEST_ASSERT(rc == 1); /* Alert: high ASCII ratio in ISNs */
    printf("[PASS] test_isn_ascii_alert\n");
}

static void test_dns_normal_no_alert(void) {
    int rc = covert_detect_dns("ironnet.local", 0x0A000102, 0x0A000101);
    TEST_ASSERT(rc == 0); /* No alert for normal domain */
    printf("[PASS] test_dns_normal_no_alert\n");
}

static void test_dns_base64_alert(void) {
    /* Base64-encoded subdomain (high entropy) */
    int rc = covert_detect_dns("dG9wIHNlY3JldCBtZXNzYWdl.covert.ironnet.local",
                               0x0A000102, 0x0A000101);
    TEST_ASSERT(rc == 1); /* Alert: high entropy label */
    printf("[PASS] test_dns_base64_alert\n");
}

static void test_dns_short_label_no_alert(void) {
    /* Short labels are never flagged (< 8 chars) */
    int rc = covert_detect_dns("www.ironnet.local", 0x0A000102, 0x0A000101);
    TEST_ASSERT(rc == 0);
    printf("[PASS] test_dns_short_label_no_alert\n");
}

int main(void) {
    printf("=== IronNet Covert Detect Unit Tests ===\n");
    test_icmp_low_entropy_no_alert();
    test_icmp_high_ascii_alert();
    test_isn_random_no_alert();
    test_isn_ascii_alert();
    test_dns_normal_no_alert();
    test_dns_base64_alert();
    test_dns_short_label_no_alert();
    printf("=== All tests passed ===\n");
    return 0;
}
