#include <stdio.h>
#include <string.h>
#include "module_test.h"
#include "stats.h"
#include "utils.h"
#include "../ironstack/l4/tcp.h"
#include "../ironstack/l4/tcp.c"
#include "../ironstack/l4/udp.h"
#include "../ironstack/l4/udp.c"

static void build_tcp_seg(uint8_t *buf, int *len,
                          uint16_t sport, uint16_t dport,
                          uint32_t seq, uint32_t ack_num, uint8_t flags) {
    tcp_header_t *hdr = (tcp_header_t *)buf;
    memset(buf, 0, TCP_HEADER_MIN_LEN);
    hdr->src_port = iron_htons(sport);
    hdr->dst_port = iron_htons(dport);
    hdr->seq = iron_htonl(seq);
    hdr->ack = iron_htonl(ack_num);
    hdr->data_offset = (5 << 4);
    hdr->flags = flags;
    hdr->window = iron_htons(65535);
    *len = TCP_HEADER_MIN_LEN;
}

/* Test 1: Full TCP 3-way handshake */
static mt_result_t test_tcp_handshake(void) {
    iron_stats_init();
    tcp_init();

    uint8_t seg[64]; int seg_len;
    uint32_t src = iron_str_to_ip("10.0.1.1");
    uint32_t dst = iron_str_to_ip("10.0.2.1");

    /* SYN */
    build_tcp_seg(seg, &seg_len, 5000, 80, 1000, 0, TCP_FLAG_SYN);
    printf("  [SYN] 10.0.1.1:5000 → 10.0.2.1:80 seq=1000\n");
    mt_hex_dump(seg, seg_len);
    tcp_input(src, dst, seg, seg_len, 0);

    tcp_conn_t *conn = tcp_find_conn(src, dst, 5000, 80);
    printf("  State: %s\n", conn ? "SYN_RECV" : "ERROR");
    if (!conn || conn->state != TCP_SYN_RECV) return MT_FAIL;

    /* ACK (completes handshake) */
    build_tcp_seg(seg, &seg_len, 5000, 80, 1001, 1001, TCP_FLAG_ACK);
    printf("  [ACK] 10.0.1.1:5000 → 10.0.2.1:80 seq=1001 ack=1001\n");
    tcp_input(src, dst, seg, seg_len, 0);

    printf("  State: %s\n", conn->state == TCP_ESTABLISHED ? "ESTABLISHED" : "ERROR");
    printf("  Half-open: %lu, Created: %lu\n",
           iron_stats_get(STAT_TCP_HALF_OPEN), iron_stats_get(STAT_TCP_CONN_CREATED));
    if (conn->state != TCP_ESTABLISHED) return MT_FAIL;

    return MT_PASS;
}

/* Test 2: TCP graceful close (FIN sequence) */
static mt_result_t test_tcp_close(void) {
    iron_stats_init();
    tcp_init();

    uint8_t seg[64]; int seg_len;
    uint32_t src = iron_str_to_ip("10.0.1.1");
    uint32_t dst = iron_str_to_ip("10.0.2.1");

    /* Establish first */
    build_tcp_seg(seg, &seg_len, 5000, 80, 1000, 0, TCP_FLAG_SYN);
    tcp_input(src, dst, seg, seg_len, 0);
    build_tcp_seg(seg, &seg_len, 5000, 80, 1001, 1001, TCP_FLAG_ACK);
    tcp_input(src, dst, seg, seg_len, 0);

    tcp_conn_t *conn = tcp_find_conn(src, dst, 5000, 80);
    printf("  Connection established: 10.0.1.1:5000 → 10.0.2.1:80\n");

    /* FIN → FIN_WAIT_1 */
    build_tcp_seg(seg, &seg_len, 5000, 80, 1001, 1001, TCP_FLAG_FIN);
    tcp_input(src, dst, seg, seg_len, 0);
    printf("  [FIN] → State: %s\n", conn->state == TCP_FIN_WAIT_1 ? "FIN_WAIT_1" : "ERROR");
    if (conn->state != TCP_FIN_WAIT_1) return MT_FAIL;

    /* ACK → FIN_WAIT_2 */
    build_tcp_seg(seg, &seg_len, 5000, 80, 1002, 1001, TCP_FLAG_ACK);
    tcp_input(src, dst, seg, seg_len, 0);
    printf("  [ACK] → State: %s\n", conn->state == TCP_FIN_WAIT_2 ? "FIN_WAIT_2" : "ERROR");
    if (conn->state != TCP_FIN_WAIT_2) return MT_FAIL;

    /* FIN → TIME_WAIT */
    build_tcp_seg(seg, &seg_len, 5000, 80, 1002, 1001, TCP_FLAG_FIN);
    tcp_input(src, dst, seg, seg_len, 0);
    printf("  [FIN] → State: %s\n", conn->state == TCP_TIME_WAIT ? "TIME_WAIT" : "ERROR");
    if (conn->state != TCP_TIME_WAIT) return MT_FAIL;

    return MT_PASS;
}

/* Test 3: Invalid flags rejected, no state created */
static mt_result_t test_tcp_invalid_flags(void) {
    iron_stats_init();
    tcp_init();

    uint8_t seg[64]; int seg_len;
    uint32_t src = iron_str_to_ip("10.0.1.1");
    uint32_t dst = iron_str_to_ip("10.0.2.1");

    /* SYN+FIN */
    build_tcp_seg(seg, &seg_len, 5000, 80, 1000, 0, TCP_FLAG_SYN | TCP_FLAG_FIN);
    printf("  [SYN+FIN] flags=0x%02X (invalid)\n", TCP_FLAG_SYN | TCP_FLAG_FIN);
    mt_hex_dump(seg, seg_len);
    int rc = tcp_input(src, dst, seg, seg_len, 0);

    printf("  Result: %s (rc=%d)\n", rc == -1 ? "REJECTED" : "ERROR", rc);
    printf("  Connections: %d (expected 0)\n", tcp_get_connection_count());
    printf("  Invalid flags counter: %lu\n", iron_stats_get(STAT_TCP_INVALID_FLAGS));

    if (rc != -1) return MT_FAIL;
    if (tcp_get_connection_count() != 0) return MT_FAIL;

    return MT_PASS;
}

/* Test 4: UDP packet received */
static mt_result_t test_udp_receive(void) {
    iron_stats_init();

    /* Build UDP packet: sport=5000, dport=53, length=12, payload="ABCD" */
    uint8_t udp_pkt[12];
    udp_header_t *hdr = (udp_header_t *)udp_pkt;
    hdr->src_port = iron_htons(5000);
    hdr->dst_port = iron_htons(53);
    hdr->length = iron_htons(12);
    hdr->checksum = 0;
    memcpy(udp_pkt + 8, "ABCD", 4);

    printf("  UDP 10.0.1.1:5000 → 10.0.2.1:53 payload=\"ABCD\"\n");
    mt_hex_dump(udp_pkt, 12);

    int rc = udp_input(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                       udp_pkt, 12, 0);

    printf("  Result: %s (rc=%d)\n", rc == 0 ? "RECEIVED" : "ERROR", rc);
    printf("  UDP RX counter: %lu\n", iron_stats_get(STAT_UDP_RX));

    if (rc != 0) return MT_FAIL;
    if (iron_stats_get(STAT_UDP_RX) != 1) return MT_FAIL;

    return MT_PASS;
}

int main(void) {
    mt_suite_t suite;
    mt_suite_init(&suite, "IronNet L4 Module Test — TCP & UDP");

    mt_suite_add(&suite, "TCP 3-way handshake (SYN → ACK → ESTABLISHED):", test_tcp_handshake);
    mt_suite_add(&suite, "TCP graceful close (FIN → FIN_WAIT → TIME_WAIT):", test_tcp_close);
    mt_suite_add(&suite, "TCP invalid flags rejected (SYN+FIN):", test_tcp_invalid_flags);
    mt_suite_add(&suite, "UDP packet received and parsed:", test_udp_receive);

    mt_suite_run(&suite);

    return suite.failed > 0 ? 1 : 0;
}
