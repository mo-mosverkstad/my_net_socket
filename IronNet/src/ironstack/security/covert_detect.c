/*
 * covert_detect.c — Covert channel detection (Phase 19c)
 *
 * Analyzes incoming traffic for covert channel indicators:
 *   1. ICMP payload entropy (high entropy = possible hidden data)
 *   2. Timing bimodality (bimodal delays = timing channel)
 *   3. TCP ISN structure (non-random ISNs = ISN channel)
 *   4. DNS label entropy (high-entropy subdomains = DNS exfiltration)
 *
 * Enabled via: defense covert-detect enable
 * Alerts logged to audit log as AUDIT_COVERT_CHANNEL events.
 */

#include "covert_detect.h"
#include "../ironmon/audit.h"
#include "log.h"

#include <string.h>
#include <math.h>
#include <time.h>

#define MODULE "COVERT"

/* --- Shannon entropy calculation --- */
static double calc_entropy(const uint8_t *data, int len) {
    if (len <= 0) return 0.0;
    int freq[256] = {0};
    for (int i = 0; i < len; i++) freq[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / len;
        entropy -= p * log2(p);
    }
    return entropy; /* 0.0 = uniform, 8.0 = max random */
}

/* --- ICMP payload analysis --- */
#define ICMP_ENTROPY_THRESHOLD 5.5 /* Normal ping ~5.3 (timestamp+pattern); base64/binary > 5.5 */
#define ICMP_ASCII_THRESHOLD 0.7  /* Normal ping payload is mostly non-printable; text > 70% printable */

int covert_detect_icmp(const uint8_t *payload, int payload_len,
                       uint32_t src_ip, uint32_t dst_ip) {
    if (payload_len < 8) return 0;

    /* ICMP payload starts after 8-byte ICMP header */
    const uint8_t *data = payload + 8;
    int data_len = payload_len - 8;
    if (data_len < 4) return 0;

    /* Check 1: entropy */
    double entropy = calc_entropy(data, data_len);

    /* Check 2: ASCII ratio (normal ping payload is non-printable bytes) */
    int ascii_count = 0;
    for (int i = 0; i < data_len; i++) {
        if (data[i] >= 0x20 && data[i] <= 0x7E) ascii_count++;
    }
    double ascii_ratio = (double)ascii_count / data_len;

    /* Alert if high entropy OR high ASCII ratio (either indicates hidden data) */
    if (entropy > ICMP_ENTROPY_THRESHOLD || ascii_ratio > ICMP_ASCII_THRESHOLD) {
        LOG_WRN(MODULE, "ICMP payload anomaly: entropy=%.2f ascii=%.0f%% — possible covert channel",
                entropy, ascii_ratio * 100);
        audit_log_event(AUDIT_COVERT_CHANNEL, src_ip, dst_ip, 1, 0, 0,
                       "ICMP high entropy payload");
        return 1;
    }
    return 0;
}

/* --- Timing analysis (bimodal detection) --- */
#define TIMING_HISTORY 32
#define TIMING_BIMODAL_THRESHOLD 0.7 /* >70% of gaps in two clusters = bimodal */

static uint64_t g_timing_history[TIMING_HISTORY];
static int g_timing_count = 0;
static uint64_t g_last_pkt_time = 0;

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int covert_detect_timing(uint32_t src_ip, uint32_t dst_ip) {
    uint64_t now = now_ms();
    if (g_last_pkt_time == 0) { g_last_pkt_time = now; return 0; }

    uint64_t gap = now - g_last_pkt_time;
    g_last_pkt_time = now;

    /* Store gap in circular buffer */
    g_timing_history[g_timing_count % TIMING_HISTORY] = gap;
    g_timing_count++;

    if (g_timing_count < TIMING_HISTORY) return 0; /* Need enough samples */

    /* Check for bimodal distribution: count gaps near 10ms and near 100ms */
    int low_cluster = 0, high_cluster = 0;
    for (int i = 0; i < TIMING_HISTORY; i++) {
        uint64_t g = g_timing_history[i];
        if (g >= 5 && g <= 30) low_cluster++;      /* ~10ms cluster */
        else if (g >= 70 && g <= 150) high_cluster++; /* ~100ms cluster */
    }

    double bimodal_ratio = (double)(low_cluster + high_cluster) / TIMING_HISTORY;
    if (bimodal_ratio > TIMING_BIMODAL_THRESHOLD && low_cluster > 3 && high_cluster > 3) {
        LOG_WRN(MODULE, "Timing bimodal: %d low + %d high / %d (ratio %.2f) — possible timing channel",
                low_cluster, high_cluster, TIMING_HISTORY, bimodal_ratio);
        audit_log_event(AUDIT_COVERT_CHANNEL, src_ip, dst_ip, 1, 0, 0,
                       "Bimodal timing pattern");
        g_timing_count = 0; /* Reset to avoid repeated alerts */
        return 1;
    }
    return 0;
}

/* --- TCP ISN analysis --- */
#define ISN_HISTORY 4
#define ISN_ENTROPY_THRESHOLD 2.5 /* Random ISNs have high byte entropy; structured = lower */

static uint32_t g_isn_history[ISN_HISTORY];
static int g_isn_count = 0;

int covert_detect_isn(uint32_t seq, uint32_t src_ip, uint32_t dst_ip) {
    g_isn_history[g_isn_count % ISN_HISTORY] = seq;
    g_isn_count++;

    if (g_isn_count < ISN_HISTORY) return 0;

    /* Check if ISNs contain ASCII-range bytes (sign of encoded text) */
    int ascii_bytes = 0;
    int total_bytes = ISN_HISTORY * 4;
    uint8_t *raw = (uint8_t *)g_isn_history;
    for (int i = 0; i < total_bytes; i++) {
        if (raw[i] >= 0x20 && raw[i] <= 0x7E) ascii_bytes++;
    }

    double ascii_ratio = (double)ascii_bytes / total_bytes;
    /* Random ISNs: ~37% ASCII bytes. Encoded text: >70% ASCII */
    if (ascii_ratio > 0.65) {
        LOG_WRN(MODULE, "TCP ISN ASCII ratio %.2f (%d/%d) — possible ISN covert channel",
                ascii_ratio, ascii_bytes, total_bytes);
        audit_log_event(AUDIT_COVERT_CHANNEL, src_ip, dst_ip, 6, 0, 0,
                       "TCP ISN high ASCII ratio");
        g_isn_count = 0;
        return 1;
    }
    return 0;
}

/* --- DNS label entropy analysis --- */
#define DNS_LABEL_ENTROPY_THRESHOLD 3.5 /* Normal domains: low entropy. Base64: high */

int covert_detect_dns(const char *qname, uint32_t src_ip, uint32_t dst_ip) {
    /* Analyze first label (before first dot) */
    int label_len = 0;
    const char *dot = strchr(qname, '.');
    label_len = dot ? (int)(dot - qname) : (int)strlen(qname);

    if (label_len < 8) return 0; /* Short labels are normal */

    double entropy = calc_entropy((const uint8_t *)qname, label_len);

    if (entropy > DNS_LABEL_ENTROPY_THRESHOLD) {
        LOG_WRN(MODULE, "DNS label entropy %.2f (len=%d) for '%s' — possible DNS exfiltration",
                entropy, label_len, qname);
        audit_log_event(AUDIT_COVERT_CHANNEL, src_ip, dst_ip, 17, 0, 53,
                       "DNS high entropy label");
        return 1;
    }
    return 0;
}

/* --- Reset state --- */
void covert_detect_reset(void) {
    g_timing_count = 0;
    g_last_pkt_time = 0;
    g_isn_count = 0;
    memset(g_timing_history, 0, sizeof(g_timing_history));
    memset(g_isn_history, 0, sizeof(g_isn_history));
}
