#include <stdio.h>
#include <string.h>
#include "module_test.h"
#include "stats.h"
#include "utils.h"
#include "l2/eth.h"
#include "l2/eth.c"

static void print_frame_info(eth_frame_t *frame, int total_len) {
    printf("--- Ethernet Frame ---\n");
    printf("  Dst MAC: "); mt_print_mac(frame->header->dst_mac); printf("\n");
    printf("  Src MAC: "); mt_print_mac(frame->header->src_mac); printf("\n");
    printf("  EtherType: 0x%04X\n", iron_ntohs(frame->header->ethertype));
    printf("  Total length: %d bytes\n", total_len);
    printf("  Payload length: %d bytes\n", frame->payload_len);
    printf("  Payload hex:\n");
    mt_hex_dump(frame->payload, frame->payload_len);
    printf("  Payload ASCII: ");
    for (int i = 0; i < frame->payload_len; i++) {
        char c = frame->payload[i];
        printf("%c", (c >= 32 && c < 127) ? c : '.');
    }
    printf("\n");
}

static mt_result_t test_text_payload_frame(void) {
    iron_stats_init();

    uint8_t dst[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t src[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    const char *msg = "Hello IronNet!";
    uint8_t buf[128];

    int len = eth_build(dst, src, ETHERTYPE_IPV4, (const uint8_t *)msg, strlen(msg), buf, sizeof(buf));
    if (len <= 0) return MT_FAIL;

    printf("  Raw frame hex:\n");
    mt_hex_dump(buf, len);

    eth_frame_t frame;
    if (eth_parse(buf, len, 0, &frame) != 0) return MT_FAIL;
    print_frame_info(&frame, len);

    if (frame.payload_len != (int)strlen(msg)) return MT_FAIL;
    if (memcmp(frame.payload, msg, strlen(msg)) != 0) return MT_FAIL;

    return MT_PASS;
}

static mt_result_t test_ipv4_tcp_syn_frame(void) {
    iron_stats_init();

    uint8_t dst[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    uint8_t src[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t ip_pkt[] = {
        0x45, 0x00, 0x00, 0x28,  /* IPv4, IHL=5, total len=40 */
        0x00, 0x01, 0x00, 0x00,  /* ID=1, no fragment */
        0x40, 0x06, 0x00, 0x00,  /* TTL=64, proto=TCP, checksum=0 */
        0x0A, 0x00, 0x01, 0x01,  /* src: 10.0.1.1 */
        0x0A, 0x00, 0x02, 0x01,  /* dst: 10.0.2.1 */
        /* TCP header */
        0x04, 0xD2, 0x00, 0x50,  /* src port 1234, dst port 80 */
        0x00, 0x00, 0x00, 0x01,  /* seq = 1 */
        0x00, 0x00, 0x00, 0x00,  /* ack = 0 */
        0x50, 0x02, 0xFF, 0xFF,  /* data offset=5, SYN, window=65535 */
        0x00, 0x00, 0x00, 0x00,  /* checksum=0, urgent=0 */
    };
    uint8_t buf[128];

    int len = eth_build(dst, src, ETHERTYPE_IPV4, ip_pkt, sizeof(ip_pkt), buf, sizeof(buf));
    if (len <= 0) return MT_FAIL;

    printf("  Raw frame hex:\n");
    mt_hex_dump(buf, len);

    eth_frame_t frame;
    if (eth_parse(buf, len, 0, &frame) != 0) return MT_FAIL;
    print_frame_info(&frame, len);

    /* Decode IP fields */
    uint8_t version = (frame.payload[0] >> 4) & 0xF;
    uint8_t ihl = frame.payload[0] & 0xF;
    uint8_t ttl = frame.payload[8];
    uint8_t proto = frame.payload[9];
    uint16_t src_port = (frame.payload[20] << 8) | frame.payload[21];
    uint16_t dst_port = (frame.payload[22] << 8) | frame.payload[23];

    printf("\n  --- Decoded IP header ---\n");
    printf("    Version: %d\n", version);
    printf("    IHL: %d\n", ihl);
    printf("    TTL: %d\n", ttl);
    printf("    Protocol: %d (TCP=6)\n", proto);
    printf("    Src IP: %d.%d.%d.%d\n", frame.payload[12], frame.payload[13], frame.payload[14], frame.payload[15]);
    printf("    Dst IP: %d.%d.%d.%d\n", frame.payload[16], frame.payload[17], frame.payload[18], frame.payload[19]);
    printf("    Src Port: %d\n", src_port);
    printf("    Dst Port: %d\n", dst_port);

    if (version != 4) return MT_FAIL;
    if (ttl != 64) return MT_FAIL;
    if (proto != 6) return MT_FAIL;
    if (src_port != 1234) return MT_FAIL;
    if (dst_port != 80) return MT_FAIL;

    return MT_PASS;
}

static mt_result_t test_invalid_frames(void) {
    iron_stats_init();
    eth_frame_t frame;

    /* Too short */
    uint8_t short_frame[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    int rc = eth_parse(short_frame, 8, 0, &frame);
    printf("  Result: %s (rc=%d)\n", rc == -1 ? "DROPPED" : "ERROR", rc);
    if (rc != -1) return MT_FAIL;

    printf("  Drop counter: %lu\n", iron_stats_get(STAT_L2_RX_DROPS));

    return MT_PASS;
}

int main(void) {
    mt_suite_t suite;
    mt_suite_init(&suite, "IronNet L2 Module Test — Ethernet Frame Visibility");

    mt_suite_add(&suite, "Built frame with text payload:", test_text_payload_frame);
    mt_suite_add(&suite, "Built frame with simulated IPv4+TCP SYN:", test_ipv4_tcp_syn_frame);
    mt_suite_add(&suite, "Parsing invalid frame (8 bytes, too short):", test_invalid_frames);

    mt_suite_run(&suite);

    return suite.failed > 0 ? 1 : 0;
}
