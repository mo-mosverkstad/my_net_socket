#include <stdint.h>

/* Stub ip_output for test_tcp (tcp.c calls it for SYN+ACK) */
int ip_output(uint32_t src, uint32_t dst, uint8_t proto,
              const uint8_t *payload, int len) {
    (void)src;(void)dst;(void)proto;(void)payload;(void)len;
    return 0;
}
