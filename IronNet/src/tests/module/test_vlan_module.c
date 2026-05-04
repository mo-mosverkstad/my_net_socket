#include <stdio.h>
#include <string.h>
#include "module_test.h"
#include "stats.h"
#include "utils.h"
#include "../ironstack/l2/vlan.h"
#include "../ironstack/l2/vlan.c"

/* Test 1: Trunk egress inserts VLAN tag — visible in hex */
static mt_result_t test_vlan_tag_insertion(void) {
    vlan_init();
    uint16_t allowed[] = {10, 20, 30};
    vlan_port_set_trunk(0, allowed, 3);

    /* Build untagged frame: dst=broadcast, src=02:00:00:00:00:01, ethertype=0x0800 */
    uint8_t frame[64];
    memset(frame, 0, sizeof(frame));
    memset(frame, 0xFF, 6);  /* dst broadcast */
    frame[6] = 0x02; frame[11] = 0x01; /* src */
    frame[12] = 0x08; frame[13] = 0x00; /* IPv4 */
    /* Fake payload */
    memcpy(frame + 14, "HELLO", 5);
    int len = 64;

    printf("  Original frame (untagged, %d bytes):\n", len);
    mt_hex_dump(frame, 20);

    uint8_t out[128];
    int out_len = vlan_egress(frame, len, 0, 20, out, sizeof(out));

    printf("  After trunk egress (VLAN 20 tag inserted, %d bytes):\n", out_len);
    mt_hex_dump(out, 24);

    printf("  Tag bytes: TPID=%02X%02X TCI=%02X%02X (VID=%d)\n",
           out[12], out[13], out[14], out[15],
           ((out[14] & 0x0F) << 8) | out[15]);
    printf("  Original EtherType now at offset 16: %02X%02X\n", out[16], out[17]);

    if (out_len != len + 4) return MT_FAIL;
    if (out[12] != 0x81 || out[13] != 0x00) return MT_FAIL;
    uint16_t vid = ((out[14] & 0x0F) << 8) | out[15];
    if (vid != 20) return MT_FAIL;

    return MT_PASS;
}

/* Test 2: Trunk ingress strips VLAN tag */
static mt_result_t test_vlan_tag_stripping(void) {
    vlan_init();
    uint16_t allowed[] = {10, 20};
    vlan_port_set_trunk(0, allowed, 2);

    /* Build tagged frame: VLAN 10 */
    uint8_t frame[68];
    memset(frame, 0, sizeof(frame));
    memset(frame, 0xFF, 6);
    frame[6] = 0x02; frame[11] = 0x01;
    frame[12] = 0x81; frame[13] = 0x00; /* TPID */
    frame[14] = 0x00; frame[15] = 0x0A; /* VID=10 */
    frame[16] = 0x08; frame[17] = 0x00; /* IPv4 */
    memcpy(frame + 18, "DATA", 4);
    int len = 68;

    printf("  Tagged frame (VLAN 10, %d bytes):\n", len);
    mt_hex_dump(frame, 22);

    uint16_t vid;
    int rc = vlan_ingress(frame, &len, 0, &vid);

    printf("  After trunk ingress (tag stripped, %d bytes):\n", len);
    mt_hex_dump(frame, 18);
    printf("  Extracted VLAN ID: %d\n", vid);
    printf("  EtherType back at offset 12: %02X%02X\n", frame[12], frame[13]);

    if (rc != 0) return MT_FAIL;
    if (vid != 10) return MT_FAIL;
    if (len != 64) return MT_FAIL;
    if (frame[12] != 0x08 || frame[13] != 0x00) return MT_FAIL;

    return MT_PASS;
}

/* Test 3: Access port assigns VLAN to untagged frame */
static mt_result_t test_access_port_assigns_vlan(void) {
    vlan_init();
    vlan_port_set_access(0, 100);

    uint8_t frame[64];
    memset(frame, 0, sizeof(frame));
    memset(frame, 0xFF, 6);
    frame[6] = 0x02; frame[11] = 0x01;
    frame[12] = 0x08; frame[13] = 0x00;
    int len = 64;

    printf("  Untagged frame on access port (VLAN 100):\n");
    mt_hex_dump(frame, 16);

    uint16_t vid;
    int rc = vlan_ingress(frame, &len, 0, &vid);

    printf("  Assigned VLAN ID: %d\n", vid);
    printf("  Frame unchanged (still %d bytes, no tag added internally)\n", len);

    if (rc != 0) return MT_FAIL;
    if (vid != 100) return MT_FAIL;
    if (len != 64) return MT_FAIL;

    return MT_PASS;
}

/* Test 4: VLAN isolation — wrong VLAN dropped */
static mt_result_t test_vlan_isolation(void) {
    vlan_init();
    vlan_port_set_access(0, 10);

    /* Tagged frame with VLAN 20 on access port configured for VLAN 10 */
    uint8_t frame[68];
    memset(frame, 0, sizeof(frame));
    memset(frame, 0xFF, 6);
    frame[6] = 0x02; frame[11] = 0x01;
    frame[12] = 0x81; frame[13] = 0x00;
    frame[14] = 0x00; frame[15] = 0x14; /* VID=20 */
    frame[16] = 0x08; frame[17] = 0x00;
    int len = 68;

    printf("  Tagged frame (VLAN 20) on access port (VLAN 10):\n");
    mt_hex_dump(frame, 18);

    uint16_t vid;
    int rc = vlan_ingress(frame, &len, 0, &vid);

    printf("  Result: %s (rc=%d)\n", rc == -1 ? "DROPPED (wrong VLAN)" : "ERROR", rc);

    if (rc != -1) return MT_FAIL;

    return MT_PASS;
}

int main(void) {
    mt_suite_t suite;
    mt_suite_init(&suite, "IronNet L2 Module Test — VLAN (802.1Q)");

    mt_suite_add(&suite, "Trunk egress inserts VLAN tag:", test_vlan_tag_insertion);
    mt_suite_add(&suite, "Trunk ingress strips VLAN tag:", test_vlan_tag_stripping);
    mt_suite_add(&suite, "Access port assigns VLAN to untagged frame:", test_access_port_assigns_vlan);
    mt_suite_add(&suite, "VLAN isolation (wrong VLAN dropped):", test_vlan_isolation);

    mt_suite_run(&suite);

    return suite.failed > 0 ? 1 : 0;
}
