#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stats.h"

/* Stub ip_input for unit test (L3 not under test here) */
int ip_input(uint8_t *data, int len, int iface_idx) {
    (void)data; (void)len; (void)iface_idx;
    return 0;
}

/* Stub arp_input for unit test */
int arp_input(uint8_t *data, int len, int iface_idx) {
    (void)data; (void)len; (void)iface_idx;
    return 0;
}

/* Include eth.h directly — we test parsing logic without TUN/TAP */
#include "../ironstack/l2/eth.h"
#include "../ironstack/l2/eth.c"

#define TEST_ASSERT(cond) do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d\n", __FILE__, __LINE__); exit(1); } } while(0)

static void test_parse_valid_ipv4_frame(void) {
    iron_stats_init();

    uint8_t raw[64];
    memset(raw, 0, sizeof(raw));

    /* dst mac */
    raw[0] = 0xFF; raw[1] = 0xFF; raw[2] = 0xFF;
    raw[3] = 0xFF; raw[4] = 0xFF; raw[5] = 0xFF;
    /* src mac */
    raw[6] = 0x02; raw[7] = 0x00; raw[8] = 0x00;
    raw[9] = 0x00; raw[10] = 0x00; raw[11] = 0x01;
    /* ethertype: IPv4 (0x0800) big-endian */
    raw[12] = 0x08; raw[13] = 0x00;

    eth_frame_t frame;
    int rc = eth_parse(raw, 64, 0, &frame);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(frame.payload_len == 50);
    TEST_ASSERT(frame.iface_idx == 0);
    TEST_ASSERT(iron_stats_get(STAT_L2_RX_DROPS) == 0);

    printf("[PASS] test_parse_valid_ipv4_frame\n");
}

static void test_parse_too_short(void) {
    iron_stats_init();

    uint8_t raw[10];
    memset(raw, 0, sizeof(raw));

    eth_frame_t frame;
    int rc = eth_parse(raw, 10, 0, &frame);
    TEST_ASSERT(rc == -1);
    TEST_ASSERT(iron_stats_get(STAT_L2_RX_DROPS) == 1);

    printf("[PASS] test_parse_too_short\n");
}

static void test_parse_unknown_ethertype(void) {
    iron_stats_init();

    uint8_t raw[64];
    memset(raw, 0, sizeof(raw));
    /* ethertype: 0x9999 (unknown) */
    raw[12] = 0x99; raw[13] = 0x99;

    eth_frame_t frame;
    int rc = eth_parse(raw, 64, 0, &frame);
    TEST_ASSERT(rc == -1);
    TEST_ASSERT(iron_stats_get(STAT_L2_RX_DROPS) == 1);

    printf("[PASS] test_parse_unknown_ethertype\n");
}

static void test_build_frame(void) {
    uint8_t dst[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t src[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t payload[20];
    memset(payload, 0xAB, sizeof(payload));

    uint8_t out[128];
    int len = eth_build(dst, src, ETHERTYPE_IPV4, payload, 20, out, sizeof(out));

    TEST_ASSERT(len == ETH_HEADER_LEN + 20);
    TEST_ASSERT(out[12] == 0x08 && out[13] == 0x00);
    TEST_ASSERT(out[14] == 0xAB); /* first payload byte */

    printf("[PASS] test_build_frame\n");
}

static void test_build_frame_too_large(void) {
    uint8_t dst[6] = {0};
    uint8_t src[6] = {0};
    uint8_t payload[1600]; /* exceeds ETH_MAX_FRAME */
    memset(payload, 0, sizeof(payload));

    uint8_t out[2048];
    int len = eth_build(dst, src, ETHERTYPE_IPV4, payload, 1600, out, sizeof(out));
    TEST_ASSERT(len == -1);

    printf("[PASS] test_build_frame_too_large\n");
}

int main(void) {
    printf("=== IronNet L2 Ethernet Unit Tests ===\n");
    test_parse_valid_ipv4_frame();
    test_parse_too_short();
    test_parse_unknown_ethertype();
    test_build_frame();
    test_build_frame_too_large();
    printf("=== All tests passed ===\n");
    return 0;
}
