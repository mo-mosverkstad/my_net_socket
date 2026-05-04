#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stats.h"
#include "utils.h"
#include "../ironstack/l3/ip.h"
#include "../ironstack/l3/ip_frag.h"
#include "../ironstack/l3/ip_frag.c"

#define TEST_ASSERT(cond) do { if (!(cond)) { fprintf(stderr, "FAIL: %s:%d\n", __FILE__, __LINE__); exit(1); } } while(0)

static void build_ip_pkt(uint8_t *buf, int *len, int payload_size, uint16_t id, uint16_t flags_frag) {
    ip_header_t *hdr = (ip_header_t *)buf;
    hdr->version_ihl = (4 << 4) | 5;
    hdr->tos = 0;
    hdr->total_len = iron_htons(20 + payload_size);
    hdr->id = iron_htons(id);
    hdr->flags_frag = iron_htons(flags_frag);
    hdr->ttl = 64;
    hdr->protocol = 6;
    hdr->checksum = 0;
    hdr->src_ip = iron_str_to_ip("10.0.1.1");
    hdr->dst_ip = iron_str_to_ip("10.0.2.1");
    memset(buf + 20, 0xAB, payload_size);
    hdr->checksum = iron_checksum(buf, 20);
    *len = 20 + payload_size;
}

static void test_no_fragmentation_needed(void) {
    uint8_t pkt[128]; int pkt_len;
    build_ip_pkt(pkt, &pkt_len, 100, 1, 0);

    uint8_t out[2048]; int frag_count = 0;
    int rc = ip_fragment(pkt, pkt_len, 1500, out, sizeof(out), &frag_count);
    TEST_ASSERT(rc == pkt_len);
    TEST_ASSERT(frag_count == 1);
    TEST_ASSERT(memcmp(out, pkt, pkt_len) == 0);
    printf("[PASS] test_no_fragmentation_needed\n");
}

static void test_fragmentation(void) {
    uint8_t pkt[1600]; int pkt_len;
    build_ip_pkt(pkt, &pkt_len, 1480, 42, 0); /* 1500 bytes total, MTU=800 */

    uint8_t out[4096]; int frag_count = 0;
    int rc = ip_fragment(pkt, pkt_len, 800, out, sizeof(out), &frag_count);
    TEST_ASSERT(rc > 0);
    TEST_ASSERT(frag_count > 1);

    /* Verify first fragment has MF flag */
    ip_header_t *f1 = (ip_header_t *)out;
    uint16_t ff = iron_ntohs(f1->flags_frag);
    TEST_ASSERT(ff & IP_FLAG_MF);
    printf("[PASS] test_fragmentation (count=%d)\n", frag_count);
}

static void test_df_flag_prevents_fragmentation(void) {
    uint8_t pkt[1600]; int pkt_len;
    build_ip_pkt(pkt, &pkt_len, 1480, 1, IP_FLAG_DF); /* DF set */

    uint8_t out[4096]; int frag_count = 0;
    int rc = ip_fragment(pkt, pkt_len, 800, out, sizeof(out), &frag_count);
    TEST_ASSERT(rc == -1); /* Cannot fragment */
    printf("[PASS] test_df_flag_prevents_fragmentation\n");
}

static void test_reassembly(void) {
    /* Create two fragments: 56 bytes payload each (above min size) */
    uint8_t frag1[128], frag2[128];
    memset(frag1, 0, sizeof(frag1));
    memset(frag2, 0, sizeof(frag2));
    ip_header_t *h1 = (ip_header_t *)frag1;
    ip_header_t *h2 = (ip_header_t *)frag2;

    /* Fragment 1: offset=0, MF=1, payload=56 bytes */
    h1->version_ihl = (4 << 4) | 5;
    h1->total_len = iron_htons(76); /* 20 + 56 */
    h1->id = iron_htons(100);
    h1->flags_frag = iron_htons(IP_FLAG_MF); /* offset=0, MF=1 */
    h1->ttl = 64; h1->protocol = 6;
    h1->src_ip = iron_str_to_ip("10.0.1.1");
    h1->dst_ip = iron_str_to_ip("10.0.2.1");
    h1->checksum = 0;
    memset(frag1 + 20, 0xAA, 56);
    h1->checksum = iron_checksum(frag1, 20);

    /* Fragment 2: offset=7 (=56 bytes), MF=0, payload=24 bytes (last frag, can be small) */
    h2->version_ihl = (4 << 4) | 5;
    h2->total_len = iron_htons(44); /* 20 + 24 */
    h2->id = iron_htons(100);
    h2->flags_frag = iron_htons(7); /* offset=7 (56 bytes), MF=0 */
    h2->ttl = 64; h2->protocol = 6;
    h2->src_ip = iron_str_to_ip("10.0.1.1");
    h2->dst_ip = iron_str_to_ip("10.0.2.1");
    h2->checksum = 0;
    memset(frag2 + 20, 0xBB, 24);
    h2->checksum = iron_checksum(frag2, 20);

    uint8_t out[256];
    int rc = ip_reassemble(frag1, 76, out, sizeof(out));
    TEST_ASSERT(rc == 0); /* Not complete yet */

    rc = ip_reassemble(frag2, 44, out, sizeof(out));
    TEST_ASSERT(rc > 0); /* Complete: 20 + 80 = 100 */

    /* Verify payload */
    TEST_ASSERT(out[20] == 0xAA);  /* First fragment data */
    TEST_ASSERT(out[75] == 0xAA);  /* End of first fragment */
    TEST_ASSERT(out[76] == 0xBB);  /* Start of second fragment */
    TEST_ASSERT(out[99] == 0xBB);  /* End of second fragment */
    printf("[PASS] test_reassembly\n");
}

int main(void) {
    printf("=== IronNet IP Fragmentation Unit Tests ===\n");
    test_no_fragmentation_needed();
    test_fragmentation();
    test_df_flag_prevents_fragmentation();
    test_reassembly();
    printf("=== All tests passed ===\n");
    return 0;
}
