#include "../../ironstack/security/covert_detect.h"
int covert_detect_icmp(const uint8_t *p, int l, uint32_t s, uint32_t d) { (void)p;(void)l;(void)s;(void)d; return 0; }
int covert_detect_timing(uint32_t s, uint32_t d) { (void)s;(void)d; return 0; }
int covert_detect_isn(uint32_t seq, uint32_t s, uint32_t d) { (void)seq;(void)s;(void)d; return 0; }
int covert_detect_dns(const char *q, uint32_t s, uint32_t d) { (void)q;(void)s;(void)d; return 0; }
void covert_detect_reset(void) {}
