#include <stdio.h>
#include <string.h>
#include "module_test.h"
#include "stats.h"
#include "utils.h"

/* VNIC stubs — capture output per port */
#include "../ironstack/io/vnic.h"

#define MAX_TX_CAPTURE 8
static struct { uint8_t buf[2048]; int len; int port; } g_tx[MAX_TX_CAPTURE];
static int g_tx_count = 0;

int vnic_init(void) { return 0; }
void vnic_shutdown(void) {}
int vnic_create(const char *n, uint8_t m[6]) { (void)n; (void)m; return 0; }
int vnic_read(int i, uint8_t *b, int l) { (void)i; (void)b; (void)l; return -1; }
int vnic_write(int i, const uint8_t *b, int l) {
    if (g_tx_count < MAX_TX_CAPTURE) {
        g_tx[g_tx_count].port = i;
        memcpy(g_tx[g_tx_count].buf, b, l);
        g_tx[g_tx_count].len = l;
        g_tx_count++;
    }
    return l;
}
int vnic_inject(int i, const uint8_t *b, int l) { return vnic_write(i, b, l); }
int vnic_get_count(void) { return 4; }
static vnic_t g_fake_vnic = { .name = "p0", .fd = -1, .active = true };
vnic_t *vnic_get(int i) { (void)i; return &g_fake_vnic; }

#include "../ironstack/l2/vlan.h"
#include "../ironstack/l2/vlan.c"
#include "../ironstack/l2/bridge.h"
#include "../ironstack/l2/bridge.c"

static void build_frame(uint8_t *buf, int *len,
                        const uint8_t *dst, const uint8_t *src, uint16_t ethertype) {
    memset(buf, 0, 64);
    memcpy(buf, dst, 6);
    memcpy(buf + 6, src, 6);
    buf[12] = (ethertype >> 8) & 0xFF;
    buf[13] = ethertype & 0xFF;
    *len = 64;
}

/* Test 1: MAC learning and unicast forwarding */
static mt_result_t test_mac_learning_and_forward(void) {
    vlan_init();
    bridge_init();

    /* All ports access VLAN 10 */
    vlan_port_set_access(0, 10);
    vlan_port_set_access(1, 10);
    vlan_port_set_access(2, 10);

    int br = bridge_create("br0");
    bridge_add_port(br, 0);
    bridge_add_port(br, 1);
    bridge_add_port(br, 2);

    uint8_t mac_a[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0A};
    uint8_t mac_b[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0B};

    /* Frame from A (port 0) to B — B unknown, should flood */
    uint8_t frame[64]; int len;
    build_frame(frame, &len, mac_b, mac_a, 0x0800);

    printf("  Frame: A→B (B unknown), ingress port 0\n");
    printf("  Src MAC: 02:00:00:00:00:0A  Dst MAC: 02:00:00:00:00:0B\n");

    g_tx_count = 0;
    bridge_input(frame, len, 0, 10);

    printf("  Result: flooded to %d ports (expected 2)\n", g_tx_count);
    if (g_tx_count != 2) return MT_FAIL;

    /* Now frame from B (port 1) to A — A is learned on port 0 */
    build_frame(frame, &len, mac_a, mac_b, 0x0800);

    printf("  Frame: B→A (A learned on port 0), ingress port 1\n");

    g_tx_count = 0;
    bridge_input(frame, len, 1, 10);

    printf("  Result: forwarded to %d port(s), port=%d (expected port 0)\n",
           g_tx_count, g_tx_count > 0 ? g_tx[0].port : -1);
    if (g_tx_count != 1) return MT_FAIL;
    if (g_tx[0].port != 0) return MT_FAIL;

    return MT_PASS;
}

/* Test 2: Broadcast flooding */
static mt_result_t test_broadcast_flood(void) {
    vlan_init();
    bridge_init();

    vlan_port_set_access(0, 10);
    vlan_port_set_access(1, 10);
    vlan_port_set_access(2, 10);

    int br = bridge_create("br0");
    bridge_add_port(br, 0);
    bridge_add_port(br, 1);
    bridge_add_port(br, 2);

    uint8_t mac_a[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0A};
    uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    uint8_t frame[64]; int len;
    build_frame(frame, &len, bcast, mac_a, 0x0806); /* ARP broadcast */

    printf("  Broadcast frame from port 0 (ARP)\n");

    g_tx_count = 0;
    bridge_input(frame, len, 0, 10);

    printf("  Result: flooded to %d ports (expected 2, excluding ingress)\n", g_tx_count);
    if (g_tx_count != 2) return MT_FAIL;

    return MT_PASS;
}

/* Test 3: VLAN isolation — different VLANs don't bridge */
static mt_result_t test_vlan_isolation(void) {
    vlan_init();
    bridge_init();

    vlan_port_set_access(0, 10);
    vlan_port_set_access(1, 10);
    vlan_port_set_access(2, 20); /* Different VLAN */

    int br = bridge_create("br0");
    bridge_add_port(br, 0);
    bridge_add_port(br, 1);
    bridge_add_port(br, 2);

    uint8_t mac_a[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0A};
    uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    uint8_t frame[64]; int len;
    build_frame(frame, &len, bcast, mac_a, 0x0800);

    printf("  Broadcast from port 0 (VLAN 10)\n");
    printf("  Port 0: VLAN 10, Port 1: VLAN 10, Port 2: VLAN 20\n");

    g_tx_count = 0;
    bridge_input(frame, len, 0, 10);

    printf("  Result: flooded to %d port(s) (expected 1, only port 1 in VLAN 10)\n", g_tx_count);

    /* Should only flood to port 1 (same VLAN), not port 2 (different VLAN) */
    if (g_tx_count != 1) return MT_FAIL;
    if (g_tx[0].port != 1) return MT_FAIL;

    return MT_PASS;
}

/* Test 4: Same-port drop (no hairpin) */
static mt_result_t test_same_port_drop(void) {
    vlan_init();
    bridge_init();

    vlan_port_set_access(0, 10);
    vlan_port_set_access(1, 10);

    int br = bridge_create("br0");
    bridge_add_port(br, 0);
    bridge_add_port(br, 1);

    uint8_t mac_a[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0A};
    uint8_t mac_b[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x0B};

    /* Learn B on port 0 */
    uint8_t frame[64]; int len;
    build_frame(frame, &len, mac_a, mac_b, 0x0800);
    g_tx_count = 0;
    bridge_input(frame, len, 0, 10);

    /* Now send from A (port 0) to B — but B was learned on port 0 too */
    build_frame(frame, &len, mac_b, mac_a, 0x0800);
    g_tx_count = 0;
    bridge_input(frame, len, 0, 10);

    printf("  Unicast to MAC learned on same port (hairpin)\n");
    printf("  Result: %d frames sent (expected 0, dropped)\n", g_tx_count);

    if (g_tx_count != 0) return MT_FAIL;

    return MT_PASS;
}

int main(void) {
    mt_suite_t suite;
    mt_suite_init(&suite, "IronNet L2 Module Test — Bridge");

    mt_suite_add(&suite, "MAC learning and unicast forwarding:", test_mac_learning_and_forward);
    mt_suite_add(&suite, "Broadcast flooding:", test_broadcast_flood);
    mt_suite_add(&suite, "VLAN isolation (different VLANs don't bridge):", test_vlan_isolation);
    mt_suite_add(&suite, "Same-port drop (no hairpin):", test_same_port_drop);

    mt_suite_run(&suite);

    return suite.failed > 0 ? 1 : 0;
}
