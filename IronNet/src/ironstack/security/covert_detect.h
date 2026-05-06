#ifndef IRON_COVERT_DETECT_H
#define IRON_COVERT_DETECT_H

#include <stdint.h>

/* Analyze ICMP payload for high entropy (hidden data) */
int covert_detect_icmp(const uint8_t *payload, int payload_len,
                       uint32_t src_ip, uint32_t dst_ip);

/* Analyze inter-packet timing for bimodal pattern (timing channel) */
int covert_detect_timing(uint32_t src_ip, uint32_t dst_ip);

/* Analyze TCP ISN for encoded data (ASCII content in seq numbers) */
int covert_detect_isn(uint32_t seq, uint32_t src_ip, uint32_t dst_ip);

/* Analyze DNS query label for high entropy (base64 exfiltration) */
int covert_detect_dns(const char *qname, uint32_t src_ip, uint32_t dst_ip);

/* Reset detection state */
void covert_detect_reset(void);

#endif
