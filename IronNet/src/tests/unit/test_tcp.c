#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stats.h"
#include "utils.h"
#include "../ironstack/l4/tcp.h"
#include "../ironstack/l4/tcp.c"

#define TEST_ASSERT(cond) do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d\n", __FILE__, __LINE__); exit(1); } } while(0)

static void build_tcp_segment(uint8_t *buf, int *len,
                              uint16_t sport, uint16_t dport,
                              uint32_t seq, uint32_t ack_num, uint8_t flags) {
    tcp_header_t *hdr = (tcp_header_t *)buf;
    memset(buf, 0, TCP_HEADER_MIN_LEN);
    hdr->src_port = iron_htons(sport);
    hdr->dst_port = iron_htons(dport);
    hdr->seq = iron_htonl(seq);
    hdr->ack = iron_htonl(ack_num);
    hdr->data_offset = (5 << 4); /* 20 bytes */
    hdr->flags = flags;
    hdr->window = iron_htons(65535);
    *len = TCP_HEADER_MIN_LEN;
}

static void test_syn_creates_connection(void) {
    iron_stats_init();
    tcp_init();

    uint8_t seg[64]; int seg_len;
    build_tcp_segment(seg, &seg_len, 1234, 80, 100, 0, TCP_FLAG_SYN);

    int rc = tcp_input(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"),
                       seg, seg_len, 0);
    TEST_ASSERT(rc == 0);
    TEST_ASSERT(tcp_get_connection_count() == 1);
    TEST_ASSERT(iron_stats_get(STAT_TCP_CONN_CREATED) == 1);
    TEST_ASSERT(iron_stats_get(STAT_TCP_HALF_OPEN) == 1);

    tcp_conn_t *conn = tcp_find_conn(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"), 1234, 80);
    TEST_ASSERT(conn != NULL);
    TEST_ASSERT(conn->state == TCP_SYN_RECV);

    printf("[PASS] test_syn_creates_connection\n");
}

static void test_ack_establishes_connection(void) {
    iron_stats_init();
    tcp_init();

    uint8_t seg[64]; int seg_len;

    /* SYN */
    build_tcp_segment(seg, &seg_len, 1234, 80, 100, 0, TCP_FLAG_SYN);
    tcp_input(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"), seg, seg_len, 0);

    /* ACK (from same direction) */
    build_tcp_segment(seg, &seg_len, 1234, 80, 101, 1001, TCP_FLAG_ACK);
    tcp_input(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"), seg, seg_len, 0);

    tcp_conn_t *conn = tcp_find_conn(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"), 1234, 80);
    TEST_ASSERT(conn != NULL);
    TEST_ASSERT(conn->state == TCP_ESTABLISHED);
    TEST_ASSERT(iron_stats_get(STAT_TCP_HALF_OPEN) == 0);

    printf("[PASS] test_ack_establishes_connection\n");
}

static void test_fin_closes_connection(void) {
    iron_stats_init();
    tcp_init();

    uint8_t seg[64]; int seg_len;

    /* SYN → SYN_RECV */
    build_tcp_segment(seg, &seg_len, 1234, 80, 100, 0, TCP_FLAG_SYN);
    tcp_input(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"), seg, seg_len, 0);

    /* ACK → ESTABLISHED */
    build_tcp_segment(seg, &seg_len, 1234, 80, 101, 1001, TCP_FLAG_ACK);
    tcp_input(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"), seg, seg_len, 0);

    /* FIN → FIN_WAIT_1 */
    build_tcp_segment(seg, &seg_len, 1234, 80, 101, 1001, TCP_FLAG_FIN);
    tcp_input(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"), seg, seg_len, 0);

    tcp_conn_t *conn = tcp_find_conn(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"), 1234, 80);
    TEST_ASSERT(conn != NULL);
    TEST_ASSERT(conn->state == TCP_FIN_WAIT_1);

    /* ACK → FIN_WAIT_2 */
    build_tcp_segment(seg, &seg_len, 1234, 80, 102, 1001, TCP_FLAG_ACK);
    tcp_input(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"), seg, seg_len, 0);
    TEST_ASSERT(conn->state == TCP_FIN_WAIT_2);

    /* FIN → TIME_WAIT */
    build_tcp_segment(seg, &seg_len, 1234, 80, 102, 1001, TCP_FLAG_FIN);
    tcp_input(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"), seg, seg_len, 0);
    TEST_ASSERT(conn->state == TCP_TIME_WAIT);

    printf("[PASS] test_fin_closes_connection\n");
}

static void test_invalid_flags_rejected(void) {
    iron_stats_init();
    tcp_init();

    uint8_t seg[64]; int seg_len;

    /* SYN+FIN (invalid) */
    build_tcp_segment(seg, &seg_len, 1234, 80, 100, 0, TCP_FLAG_SYN | TCP_FLAG_FIN);
    int rc = tcp_input(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"), seg, seg_len, 0);
    TEST_ASSERT(rc == -1);
    TEST_ASSERT(tcp_get_connection_count() == 0);
    TEST_ASSERT(iron_stats_get(STAT_TCP_INVALID_FLAGS) == 1);

    /* SYN+RST (invalid) */
    build_tcp_segment(seg, &seg_len, 1234, 80, 100, 0, TCP_FLAG_SYN | TCP_FLAG_RST);
    rc = tcp_input(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"), seg, seg_len, 0);
    TEST_ASSERT(rc == -1);
    TEST_ASSERT(tcp_get_connection_count() == 0);
    TEST_ASSERT(iron_stats_get(STAT_TCP_INVALID_FLAGS) == 2);

    printf("[PASS] test_invalid_flags_rejected\n");
}

static void test_connection_table_full(void) {
    iron_stats_init();
    tcp_init();

    uint8_t seg[64]; int seg_len;

    /* Fill the table */
    for (int i = 0; i < TCP_MAX_CONNECTIONS; i++) {
        build_tcp_segment(seg, &seg_len, 1000 + i, 80, 100, 0, TCP_FLAG_SYN);
        tcp_input(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"), seg, seg_len, 0);
    }
    TEST_ASSERT(tcp_get_connection_count() == TCP_MAX_CONNECTIONS);

    /* Next SYN should fail */
    build_tcp_segment(seg, &seg_len, 9999, 80, 100, 0, TCP_FLAG_SYN);
    int rc = tcp_input(iron_str_to_ip("10.0.1.1"), iron_str_to_ip("10.0.2.1"), seg, seg_len, 0);
    TEST_ASSERT(rc == -1);
    TEST_ASSERT(iron_stats_get(STAT_TCP_DROPS_RESOURCE) == 1);

    printf("[PASS] test_connection_table_full\n");
}

int main(void) {
    printf("=== IronNet TCP Unit Tests ===\n");
    test_syn_creates_connection();
    test_ack_establishes_connection();
    test_fin_closes_connection();
    test_invalid_flags_rejected();
    test_connection_table_full();
    printf("=== All tests passed ===\n");
    return 0;
}
