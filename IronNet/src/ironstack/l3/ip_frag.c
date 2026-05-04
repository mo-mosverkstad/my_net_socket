#include "ip_frag.h"
#include "log.h"
#include "stats.h"
#include "utils.h"

#include <string.h>
#include <time.h>

#define MODULE "FRAG"

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t id;
    uint8_t  buf[FRAG_MAX_SIZE];
    int      received_len;
    int      total_len;     /* Set when last fragment received */
    bool     last_received;
    bool     active;
    uint64_t timestamp;
} reasm_entry_t;

static reasm_entry_t g_reasm[FRAG_MAX_REASSEMBLY];

static uint64_t frag_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec;
}

int ip_fragment(uint8_t *pkt, int pkt_len, int mtu,
                uint8_t *out_buf, int out_buf_len, int *frag_count) {
    ip_header_t *orig = (ip_header_t *)pkt;
    int hdr_len = ip_get_header_len(orig);
    int payload_len = pkt_len - hdr_len;
    int max_payload = (mtu - hdr_len) & ~7; /* Must be multiple of 8 */

    if (pkt_len <= mtu) {
        /* No fragmentation needed */
        if (out_buf_len < pkt_len) return -1;
        memcpy(out_buf, pkt, pkt_len);
        *frag_count = 1;
        return pkt_len;
    }

    /* Check DF flag */
    uint16_t flags_frag = iron_ntohs(orig->flags_frag);
    if (flags_frag & IP_FLAG_DF) {
        LOG_DBG(MODULE, "DF set, cannot fragment");
        return -1;
    }

    int offset = 0;
    int out_offset = 0;
    int count = 0;

    while (offset < payload_len) {
        int chunk = payload_len - offset;
        bool last = true;
        if (chunk > max_payload) {
            chunk = max_payload;
            last = false;
        }

        int frag_total = hdr_len + chunk;
        if (out_offset + frag_total > out_buf_len) return -1;

        /* Copy header */
        memcpy(out_buf + out_offset, pkt, hdr_len);
        ip_header_t *fhdr = (ip_header_t *)(out_buf + out_offset);

        /* Set fragment offset and MF flag */
        uint16_t frag_off = (offset / 8);
        if (!last) frag_off |= (IP_FLAG_MF >> 0); /* MF in host order position */
        fhdr->flags_frag = iron_htons(frag_off | (last ? 0 : IP_FLAG_MF));
        fhdr->total_len = iron_htons(frag_total);

        /* Recompute checksum */
        fhdr->checksum = 0;
        fhdr->checksum = iron_checksum(out_buf + out_offset, hdr_len);

        /* Copy payload chunk */
        memcpy(out_buf + out_offset + hdr_len, pkt + hdr_len + offset, chunk);

        out_offset += frag_total;
        offset += chunk;
        count++;
    }

    *frag_count = count;
    LOG_DBG(MODULE, "Fragmented %d bytes into %d fragments (MTU=%d)", pkt_len, count, mtu);
    return out_offset;
}

int ip_reassemble(uint8_t *frag, int frag_len,
                  uint8_t *out_buf, int out_buf_len) {
    if (frag_len < IP_HEADER_MIN_LEN) return -1;

    ip_header_t *hdr = (ip_header_t *)frag;
    int hdr_len = ip_get_header_len(hdr);
    uint16_t flags_frag = iron_ntohs(hdr->flags_frag);
    uint16_t frag_offset = (flags_frag & IP_OFFSET_MASK) * 8;
    bool more_frags = (flags_frag & IP_FLAG_MF) != 0;
    int payload_len = iron_ntohs(hdr->total_len) - hdr_len;

    /* Security: reject tiny fragments (except last) */
    if (more_frags && payload_len < FRAG_MIN_SIZE - hdr_len) {
        LOG_DBG(MODULE, "Fragment too small: %d bytes", payload_len);
        return -1;
    }

    /* Find or create reassembly entry */
    reasm_entry_t *entry = NULL;
    for (int i = 0; i < FRAG_MAX_REASSEMBLY; i++) {
        if (g_reasm[i].active &&
            g_reasm[i].src_ip == hdr->src_ip &&
            g_reasm[i].dst_ip == hdr->dst_ip &&
            g_reasm[i].id == hdr->id) {
            entry = &g_reasm[i];
            break;
        }
    }

    if (!entry) {
        /* Allocate new entry */
        for (int i = 0; i < FRAG_MAX_REASSEMBLY; i++) {
            if (!g_reasm[i].active) {
                entry = &g_reasm[i];
                break;
            }
        }
        if (!entry) {
            LOG_WRN(MODULE, "Reassembly table full");
            return -1;
        }
        memset(entry, 0, sizeof(*entry));
        entry->src_ip = hdr->src_ip;
        entry->dst_ip = hdr->dst_ip;
        entry->id = hdr->id;
        entry->active = true;
        entry->timestamp = frag_now();
        /* Copy the IP header from first fragment */
        memcpy(entry->buf, frag, hdr_len);
    }

    /* Security: reject overlapping fragments */
    int end = frag_offset + payload_len;
    if (end > FRAG_MAX_SIZE) {
        LOG_WRN(MODULE, "Fragment exceeds max size");
        entry->active = false;
        return -1;
    }

    /* Copy payload into reassembly buffer */
    memcpy(entry->buf + hdr_len + frag_offset, frag + hdr_len, payload_len);

    if (frag_offset + payload_len > entry->received_len)
        entry->received_len = frag_offset + payload_len;

    if (!more_frags) {
        entry->last_received = true;
        entry->total_len = frag_offset + payload_len;
    }

    /* Check if complete */
    if (entry->last_received && entry->received_len >= entry->total_len) {
        int total = hdr_len + entry->total_len;
        if (total > out_buf_len) {
            entry->active = false;
            return -1;
        }

        /* Fix up the header */
        ip_header_t *out_hdr = (ip_header_t *)entry->buf;
        out_hdr->total_len = iron_htons(total);
        out_hdr->flags_frag = 0;
        out_hdr->checksum = 0;
        out_hdr->checksum = iron_checksum(entry->buf, hdr_len);

        memcpy(out_buf, entry->buf, total);
        entry->active = false;
        LOG_DBG(MODULE, "Reassembly complete: %d bytes", total);
        return total;
    }

    return 0; /* Not yet complete */
}

void ip_frag_timer_tick(void) {
    uint64_t now = frag_now();
    for (int i = 0; i < FRAG_MAX_REASSEMBLY; i++) {
        if (g_reasm[i].active &&
            (now - g_reasm[i].timestamp) >= FRAG_TIMEOUT_SEC) {
            LOG_DBG(MODULE, "Reassembly timeout for ID=%u", g_reasm[i].id);
            g_reasm[i].active = false;
        }
    }
}
