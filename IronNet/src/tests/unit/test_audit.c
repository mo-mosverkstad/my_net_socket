#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stats.h"
#include "utils.h"
#include "../ironmon/audit.h"
#include "../ironmon/audit.c"

#define TEST_ASSERT(cond) do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d\n", __FILE__, __LINE__); exit(1); } } while(0)

static void test_log_and_retrieve(void) {
    audit_init(NULL); /* No file output */
    audit_log_event(AUDIT_ACL_DENY, 0x0A000101, 0x0A000201, 6, 12345, 22, "rule 3");

    audit_event_t events[10];
    int count = audit_get_recent(events, 10);
    TEST_ASSERT(count == 1);
    TEST_ASSERT(events[0].type == AUDIT_ACL_DENY);
    TEST_ASSERT(events[0].src_ip == 0x0A000101);
    TEST_ASSERT(events[0].dst_ip == 0x0A000201);
    TEST_ASSERT(events[0].protocol == 6);
    TEST_ASSERT(events[0].src_port == 12345);
    TEST_ASSERT(events[0].dst_port == 22);
    TEST_ASSERT(strcmp(events[0].detail, "rule 3") == 0);
    printf("[PASS] test_log_and_retrieve\n");
}

static void test_ring_buffer_wraps(void) {
    audit_init(NULL);
    /* Fill ring beyond capacity */
    for (int i = 0; i < AUDIT_RING_SIZE + 10; i++) {
        audit_log_event(AUDIT_ACL_DENY, i, 0, 0, 0, 0, "wrap");
    }
    audit_event_t events[AUDIT_RING_SIZE];
    int count = audit_get_recent(events, AUDIT_RING_SIZE);
    TEST_ASSERT(count == AUDIT_RING_SIZE);
    /* Oldest should be event #10 (first 10 overwritten) */
    TEST_ASSERT(events[0].src_ip == 10);
    /* Newest should be AUDIT_RING_SIZE + 9 */
    TEST_ASSERT(events[count - 1].src_ip == (uint32_t)(AUDIT_RING_SIZE + 9));
    printf("[PASS] test_ring_buffer_wraps\n");
}

static void test_disable_suppresses(void) {
    audit_init(NULL);
    audit_disable();
    audit_log_event(AUDIT_ARP_ANOMALY, 1, 2, 0, 0, 0, "should not appear");

    audit_event_t events[10];
    int count = audit_get_recent(events, 10);
    TEST_ASSERT(count == 0);
    printf("[PASS] test_disable_suppresses\n");
}

static void test_enable_resumes(void) {
    audit_init(NULL);
    audit_disable();
    audit_log_event(AUDIT_ACL_DENY, 1, 2, 0, 0, 0, "suppressed");
    audit_enable();
    audit_log_event(AUDIT_ACL_DENY, 3, 4, 0, 0, 0, "visible");

    audit_event_t events[10];
    int count = audit_get_recent(events, 10);
    TEST_ASSERT(count == 1);
    TEST_ASSERT(events[0].src_ip == 3);
    printf("[PASS] test_enable_resumes\n");
}

static void test_multiple_types(void) {
    audit_init(NULL);
    audit_log_event(AUDIT_ACL_DENY, 1, 0, 6, 0, 22, "acl");
    audit_log_event(AUDIT_ARP_ANOMALY, 2, 0, 0, 0, 0, "arp");
    audit_log_event(AUDIT_VLAN_MISMATCH, 3, 0, 0, 0, 0, "vlan");

    audit_event_t events[10];
    int count = audit_get_recent(events, 10);
    TEST_ASSERT(count == 3);
    TEST_ASSERT(events[0].type == AUDIT_ACL_DENY);
    TEST_ASSERT(events[1].type == AUDIT_ARP_ANOMALY);
    TEST_ASSERT(events[2].type == AUDIT_VLAN_MISMATCH);
    printf("[PASS] test_multiple_types\n");
}

int main(void) {
    printf("=== IronNet Audit Unit Tests ===\n");
    test_log_and_retrieve();
    test_ring_buffer_wraps();
    test_disable_suppresses();
    test_enable_resumes();
    test_multiple_types();
    printf("=== All tests passed ===\n");
    return 0;
}
