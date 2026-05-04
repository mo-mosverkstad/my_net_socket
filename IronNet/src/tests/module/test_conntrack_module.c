#include <stdio.h>
#include <string.h>
#include "module_test.h"
#include "stats.h"
#include "utils.h"
#include "../ironstack/l3/conntrack.h"
#include "../ironstack/l3/conntrack.c"

static const char *state_name(ct_state_t s) {
    switch (s) {
    case CT_STATE_NEW: return "NEW";
    case CT_STATE_ESTABLISHED: return "ESTABLISHED";
    case CT_STATE_RELATED: return "RELATED";
    case CT_STATE_INVALID: return "INVALID";
    default: return "?";
    }
}

/* Test 1: TCP connection lifecycle */
static mt_result_t test_tcp_lifecycle(void) {
    conntrack_init();

    uint32_t client = iron_str_to_ip("10.0.1.1");
    uint32_t server = iron_str_to_ip("10.0.2.1");

    printf("  TCP 10.0.1.1:5000 -> 10.0.2.1:80\n\n");

    /* SYN */
    conntrack_update(client, server, PROTO_TCP, 5000, 80, TCP_FLAG_SYN);
    ct_state_t s = conntrack_get_state(client, server, PROTO_TCP, 5000, 80);
    printf("  [SYN]     State: %s\n", state_name(s));
    if (s != CT_STATE_NEW) return MT_FAIL;

    /* SYN+ACK (reply) */
    conntrack_update(server, client, PROTO_TCP, 80, 5000, TCP_FLAG_SYN | TCP_FLAG_ACK);
    s = conntrack_get_state(client, server, PROTO_TCP, 5000, 80);
    printf("  [SYN+ACK] State: %s\n", state_name(s));
    if (s != CT_STATE_ESTABLISHED) return MT_FAIL;

    /* Data (original direction) */
    conntrack_update(client, server, PROTO_TCP, 5000, 80, TCP_FLAG_ACK);
    s = conntrack_get_state(client, server, PROTO_TCP, 5000, 80);
    printf("  [ACK]     State: %s\n", state_name(s));
    if (s != CT_STATE_ESTABLISHED) return MT_FAIL;

    /* FIN */
    conntrack_update(client, server, PROTO_TCP, 5000, 80, TCP_FLAG_FIN | TCP_FLAG_ACK);
    s = conntrack_get_state(client, server, PROTO_TCP, 5000, 80);
    printf("  [FIN+ACK] State: %s (will timeout quickly)\n", state_name(s));

    ct_entry_t *e = conntrack_lookup(client, server, PROTO_TCP, 5000, 80);
    printf("  Packets: orig=%lu reply=%lu\n", e->packets_orig, e->packets_reply);
    if (e->packets_orig != 3) return MT_FAIL;
    if (e->packets_reply != 1) return MT_FAIL;

    return MT_PASS;
}

/* Test 2: UDP stateful tracking */
static mt_result_t test_udp_stateful(void) {
    conntrack_init();

    uint32_t client = iron_str_to_ip("10.0.1.1");
    uint32_t dns = iron_str_to_ip("10.0.2.53");

    printf("  UDP 10.0.1.1:12345 -> 10.0.2.53:53 (DNS query)\n\n");

    /* DNS query */
    conntrack_update(client, dns, PROTO_UDP, 12345, 53, 0);
    ct_state_t s = conntrack_get_state(client, dns, PROTO_UDP, 12345, 53);
    printf("  [Query]   State: %s\n", state_name(s));
    if (s != CT_STATE_NEW) return MT_FAIL;

    /* DNS reply */
    conntrack_update(dns, client, PROTO_UDP, 53, 12345, 0);
    s = conntrack_get_state(client, dns, PROTO_UDP, 12345, 53);
    printf("  [Reply]   State: %s\n", state_name(s));
    if (s != CT_STATE_ESTABLISHED) return MT_FAIL;

    return MT_PASS;
}

/* Test 3: Stateful ACL simulation — return traffic permitted */
static mt_result_t test_stateful_acl(void) {
    conntrack_init();

    uint32_t internal = iron_str_to_ip("10.0.1.1");
    uint32_t external = iron_str_to_ip("8.8.8.8");

    printf("  Scenario: internal host initiates, return traffic should be permitted\n\n");

    /* Internal initiates connection */
    conntrack_update(internal, external, PROTO_TCP, 5000, 443, TCP_FLAG_SYN);
    printf("  Internal 10.0.1.1:5000 -> 8.8.8.8:443 [SYN]\n");

    /* External replies */
    conntrack_update(external, internal, PROTO_TCP, 443, 5000, TCP_FLAG_SYN | TCP_FLAG_ACK);
    printf("  External 8.8.8.8:443 -> 10.0.1.1:5000 [SYN+ACK]\n");

    /* Simulate stateful ACL check on return traffic */
    ct_state_t state = conntrack_get_state(external, internal, PROTO_TCP, 443, 5000);
    printf("  Stateful ACL check on return traffic: state=%s\n", state_name(state));
    printf("  Decision: %s\n", state == CT_STATE_ESTABLISHED ? "PERMIT (established)" : "DENY");
    if (state != CT_STATE_ESTABLISHED) return MT_FAIL;

    /* Unsolicited inbound (no conntrack entry) */
    ct_state_t unsolicited = conntrack_get_state(
        iron_str_to_ip("1.2.3.4"), internal, PROTO_TCP, 9999, 22);
    printf("\n  Unsolicited 1.2.3.4:9999 -> 10.0.1.1:22: state=%s\n", state_name(unsolicited));
    printf("  Decision: %s\n", unsolicited == CT_STATE_INVALID ? "DENY (no entry)" : "ERROR");
    if (unsolicited != CT_STATE_INVALID) return MT_FAIL;

    return MT_PASS;
}

/* Test 4: Timeout expiry */
static mt_result_t test_timeout_expiry(void) {
    conntrack_init();

    conntrack_update(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                     PROTO_UDP, 5000, 53, 0);

    printf("  UDP entry created, count=%d\n", conntrack_get_count());
    if (conntrack_get_count() != 1) return MT_FAIL;

    /* Simulate timeout by backdating */
    ct_entry_t *e = conntrack_lookup(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                                     PROTO_UDP, 5000, 53);
    e->last_seen -= (CONNTRACK_UDP_SEC + 1);

    conntrack_timer_tick();

    printf("  After timer tick (UDP timeout=%ds exceeded): count=%d\n",
           CONNTRACK_UDP_SEC, conntrack_get_count());
    if (conntrack_get_count() != 0) return MT_FAIL;

    return MT_PASS;
}

int main(void) {
    mt_suite_t suite;
    mt_suite_init(&suite, "IronNet L3 Module Test — Connection Tracking");

    mt_suite_add(&suite, "TCP connection lifecycle (NEW → ESTABLISHED → closing):", test_tcp_lifecycle);
    mt_suite_add(&suite, "UDP stateful tracking (query → reply → ESTABLISHED):", test_udp_stateful);
    mt_suite_add(&suite, "Stateful ACL (return traffic permitted, unsolicited denied):", test_stateful_acl);
    mt_suite_add(&suite, "Timeout expiry:", test_timeout_expiry);

    mt_suite_run(&suite);

    return suite.failed > 0 ? 1 : 0;
}
