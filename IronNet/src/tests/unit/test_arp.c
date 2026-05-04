#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stats.h"
#include "utils.h"

/* Stubs */
#include "../ironstack/io/vnic.h"
static uint8_t g_tx_buf[2048];
static int g_tx_len = 0;
int vnic_init(void) { return 0; }
void vnic_shutdown(void) {}
int vnic_create(const char *n, uint8_t m[6]) { (void)n; (void)m; return 0; }
int vnic_read(int i, uint8_t *b, int l) { (void)i; (void)b; (void)l; return -1; }
int vnic_write(int i, const uint8_t *b, int l) { (void)i; memcpy(g_tx_buf, b, l); g_tx_len = l; return l; }
int vnic_inject(int i, const uint8_t *b, int l) { return vnic_write(i, b, l); }
int vnic_get_count(void) { return 1; }
static vnic_t g_fake_vnic = { .name = "p0", .fd = -1, .active = true };
vnic_t *vnic_get(int i) { (void)i; return &g_fake_vnic; }

#include "../ironstack/core/iface.h"
static uint8_t g_iface_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
static uint32_t g_iface_ip = 0;
static iface_config_t g_fake_iface;
bool iface_is_local_ip(uint32_t ip) { return ip == g_iface_ip; }
iface_config_t *iface_get(int idx) {
    (void)idx;
    memcpy(g_fake_iface.mac, g_iface_mac, 6);
    g_fake_iface.ip = g_iface_ip;
    g_fake_iface.vnic_idx = 0;
    strncpy(g_fake_iface.name, "p0", IRON_MAX_NAME);
    return &g_fake_iface;
}

#include "../ironstack/l2/eth.h"
int eth_build(const uint8_t *d, const uint8_t *s, uint16_t et,
              const uint8_t *p, int pl, uint8_t *o, int ol) {
    int total = 14 + pl;
    if (total > ol) return -1;
    memcpy(o, d, 6); memcpy(o+6, s, 6);
    o[12] = (et>>8)&0xFF; o[13] = et&0xFF;
    memcpy(o+14, p, pl);
    return total;
}

#include "../ironstack/l2/arp.h"
#include "../ironstack/l2/arp.c"

#define TEST_ASSERT(cond) do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d\n", __FILE__, __LINE__); exit(1); } } while(0)

static void test_add_and_resolve(void) {
    arp_init();
    uint8_t mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    arp_add_entry(iron_str_to_ip("10.0.1.5"), mac);

    uint8_t out[6];
    int rc = arp_resolve(iron_str_to_ip("10.0.1.5"), 0, out);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(memcmp(out, mac, 6) == 0);
    printf("[PASS] test_add_and_resolve\n");
}

static void test_resolve_unknown_sends_request(void) {
    arp_init();
    g_iface_ip = iron_str_to_ip("10.0.1.1");
    g_tx_len = 0;

    uint8_t out[6];
    int rc = arp_resolve(iron_str_to_ip("10.0.1.99"), 0, out);
    TEST_ASSERT(rc == -1); /* Not resolved */
    TEST_ASSERT(g_tx_len > 0); /* ARP request sent */
    printf("[PASS] test_resolve_unknown_sends_request\n");
}

static void test_arp_reply_on_request(void) {
    arp_init();
    g_iface_ip = iron_str_to_ip("10.0.1.1");

    /* Build ARP request: who-has 10.0.1.1 tell 10.0.1.2 */
    arp_packet_t req;
    req.hw_type = iron_htons(ARP_HW_ETHERNET);
    req.proto_type = iron_htons(ARP_PROTO_IPV4);
    req.hw_len = 6;
    req.proto_len = 4;
    req.opcode = iron_htons(ARP_OP_REQUEST);
    uint8_t sender_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    memcpy(req.sender_mac, sender_mac, 6);
    req.sender_ip = iron_str_to_ip("10.0.1.2");
    memset(req.target_mac, 0, 6);
    req.target_ip = iron_str_to_ip("10.0.1.1");

    g_tx_len = 0;
    arp_input((uint8_t *)&req, sizeof(req), 0);

    TEST_ASSERT(g_tx_len > 0); /* Reply sent */

    /* Verify sender was learned */
    uint8_t out[6];
    int rc = arp_resolve(iron_str_to_ip("10.0.1.2"), 0, out);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(memcmp(out, sender_mac, 6) == 0);
    printf("[PASS] test_arp_reply_on_request\n");
}

static void test_arp_entry_update(void) {
    arp_init();
    uint8_t mac1[6] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    uint8_t mac2[6] = {0x02, 0x02, 0x02, 0x02, 0x02, 0x02};

    arp_add_entry(iron_str_to_ip("10.0.1.5"), mac1);
    arp_add_entry(iron_str_to_ip("10.0.1.5"), mac2); /* Update */

    uint8_t out[6];
    arp_resolve(iron_str_to_ip("10.0.1.5"), 0, out);
    TEST_ASSERT(memcmp(out, mac2, 6) == 0);
    printf("[PASS] test_arp_entry_update\n");
}

int main(void) {
    printf("=== IronNet ARP Unit Tests ===\n");
    test_add_and_resolve();
    test_resolve_unknown_sends_request();
    test_arp_reply_on_request();
    test_arp_entry_update();
    printf("=== All tests passed ===\n");
    return 0;
}
