#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stats.h"
#include "utils.h"
#include "../ironstack/l2/vlan.h"
#include "../ironstack/l2/vlan.c"

#define TEST_ASSERT(cond) do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d\n", __FILE__, __LINE__); exit(1); } } while(0)

/* Build a simple untagged Ethernet frame */
static int build_untagged_frame(uint8_t *buf, uint16_t ethertype) {
    memset(buf, 0, 64);
    /* dst mac */
    buf[0] = 0xFF; buf[1] = 0xFF; buf[2] = 0xFF;
    buf[3] = 0xFF; buf[4] = 0xFF; buf[5] = 0xFF;
    /* src mac */
    buf[6] = 0x02; buf[7] = 0x00; buf[8] = 0x00;
    buf[9] = 0x00; buf[10] = 0x00; buf[11] = 0x01;
    /* ethertype */
    buf[12] = (ethertype >> 8) & 0xFF;
    buf[13] = ethertype & 0xFF;
    return 64;
}

/* Build a tagged Ethernet frame (802.1Q) */
static int build_tagged_frame(uint8_t *buf, uint16_t vlan_id, uint16_t ethertype) {
    memset(buf, 0, 68);
    /* dst mac */
    buf[0] = 0xFF; buf[1] = 0xFF; buf[2] = 0xFF;
    buf[3] = 0xFF; buf[4] = 0xFF; buf[5] = 0xFF;
    /* src mac */
    buf[6] = 0x02; buf[7] = 0x00; buf[8] = 0x00;
    buf[9] = 0x00; buf[10] = 0x00; buf[11] = 0x01;
    /* VLAN tag: TPID=0x8100, TCI=vlan_id */
    buf[12] = 0x81; buf[13] = 0x00;
    buf[14] = (vlan_id >> 8) & 0x0F; buf[15] = vlan_id & 0xFF;
    /* ethertype */
    buf[16] = (ethertype >> 8) & 0xFF;
    buf[17] = ethertype & 0xFF;
    return 68;
}

static void test_access_port_untagged(void) {
    vlan_init();
    vlan_port_set_access(0, 10);

    uint8_t frame[64];
    int len = build_untagged_frame(frame, 0x0800);
    uint16_t vid;

    int rc = vlan_ingress(frame, &len, 0, &vid);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(vid == 10);
    TEST_ASSERT(len == 64); /* Unchanged */

    printf("[PASS] test_access_port_untagged\n");
}

static void test_access_port_wrong_vlan_tag(void) {
    vlan_init();
    vlan_port_set_access(0, 10);

    uint8_t frame[68];
    int len = build_tagged_frame(frame, 20, 0x0800); /* VLAN 20, but port is VLAN 10 */
    uint16_t vid;

    int rc = vlan_ingress(frame, &len, 0, &vid);
    TEST_ASSERT(rc == -1); /* Dropped */

    printf("[PASS] test_access_port_wrong_vlan_tag\n");
}

static void test_trunk_port_tagged(void) {
    vlan_init();
    uint16_t allowed[] = {10, 20, 30};
    vlan_port_set_trunk(0, allowed, 3);

    uint8_t frame[68];
    int len = build_tagged_frame(frame, 20, 0x0800);
    uint16_t vid;

    int rc = vlan_ingress(frame, &len, 0, &vid);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(vid == 20);
    TEST_ASSERT(len == 64); /* Tag stripped */

    printf("[PASS] test_trunk_port_tagged\n");
}

static void test_trunk_port_vlan_not_allowed(void) {
    vlan_init();
    uint16_t allowed[] = {10, 20};
    vlan_port_set_trunk(0, allowed, 2);

    uint8_t frame[68];
    int len = build_tagged_frame(frame, 99, 0x0800); /* VLAN 99 not allowed */
    uint16_t vid;

    int rc = vlan_ingress(frame, &len, 0, &vid);
    TEST_ASSERT(rc == -1); /* Dropped */

    printf("[PASS] test_trunk_port_vlan_not_allowed\n");
}

static void test_trunk_port_untagged_dropped(void) {
    vlan_init();
    uint16_t allowed[] = {10};
    vlan_port_set_trunk(0, allowed, 1);

    uint8_t frame[64];
    int len = build_untagged_frame(frame, 0x0800);
    uint16_t vid;

    int rc = vlan_ingress(frame, &len, 0, &vid);
    TEST_ASSERT(rc == -1); /* Trunk requires tagged */

    printf("[PASS] test_trunk_port_untagged_dropped\n");
}

static void test_egress_trunk_inserts_tag(void) {
    vlan_init();
    uint16_t allowed[] = {10, 20};
    vlan_port_set_trunk(1, allowed, 2);

    uint8_t frame[64];
    int len = build_untagged_frame(frame, 0x0800);

    uint8_t out[128];
    int out_len = vlan_egress(frame, len, 1, 10, out, sizeof(out));

    TEST_ASSERT(out_len == len + VLAN_TAG_LEN); /* 68 bytes */
    /* Check TPID at offset 12 */
    TEST_ASSERT(out[12] == 0x81 && out[13] == 0x00);
    /* Check VID */
    uint16_t vid = ((out[14] & 0x0F) << 8) | out[15];
    TEST_ASSERT(vid == 10);
    /* Original ethertype now at offset 16 */
    TEST_ASSERT(out[16] == 0x08 && out[17] == 0x00);

    printf("[PASS] test_egress_trunk_inserts_tag\n");
}

static void test_egress_access_no_tag(void) {
    vlan_init();
    vlan_port_set_access(1, 10);

    uint8_t frame[64];
    int len = build_untagged_frame(frame, 0x0800);

    uint8_t out[128];
    int out_len = vlan_egress(frame, len, 1, 10, out, sizeof(out));

    TEST_ASSERT(out_len == len); /* No tag added */
    TEST_ASSERT(memcmp(out, frame, len) == 0);

    printf("[PASS] test_egress_access_no_tag\n");
}

int main(void) {
    printf("=== IronNet VLAN Unit Tests ===\n");
    test_access_port_untagged();
    test_access_port_wrong_vlan_tag();
    test_trunk_port_tagged();
    test_trunk_port_vlan_not_allowed();
    test_trunk_port_untagged_dropped();
    test_egress_trunk_inserts_tag();
    test_egress_access_no_tag();
    printf("=== All tests passed ===\n");
    return 0;
}
