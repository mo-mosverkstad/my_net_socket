#include "trace.h"
#include "log.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#define MODULE "TRACE"

/* pcap file format constants */
#define PCAP_MAGIC      0xA1B2C3D4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define PCAP_SNAPLEN    65535
#define PCAP_LINKTYPE_ETHERNET 1
#define PCAP_LINKTYPE_RAW      101  /* Raw IP */

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
} pcap_global_header_t;

typedef struct __attribute__((packed)) {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_packet_header_t;

static FILE *g_trace_file = NULL;
static int   g_layer_mask = 0;
static int   g_packet_count = 0;
static char  g_filename[256] = "";

int trace_init(void) {
    g_trace_file = NULL;
    g_layer_mask = 0;
    g_packet_count = 0;
    g_filename[0] = 0;
    return 0;
}

int trace_start(const char *filename, int layer_mask) {
    if (g_trace_file) {
        LOG_WRN(MODULE, "Trace already active, stopping previous");
        trace_stop();
    }

    g_trace_file = fopen(filename, "wb");
    if (!g_trace_file) {
        LOG_ERR(MODULE, "Cannot open trace file: %s", filename);
        return -1;
    }

    /* Write pcap global header */
    pcap_global_header_t hdr = {
        .magic = PCAP_MAGIC,
        .version_major = PCAP_VERSION_MAJOR,
        .version_minor = PCAP_VERSION_MINOR,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = PCAP_SNAPLEN,
        .linktype = (layer_mask & TRACE_L2) ? PCAP_LINKTYPE_ETHERNET : PCAP_LINKTYPE_RAW
    };
    fwrite(&hdr, sizeof(hdr), 1, g_trace_file);

    g_layer_mask = layer_mask;
    g_packet_count = 0;
    strncpy(g_filename, filename, sizeof(g_filename) - 1);

    LOG_INF(MODULE, "Trace started: %s (layers: %s%s%s)",
            filename,
            (layer_mask & TRACE_L2) ? "L2 " : "",
            (layer_mask & TRACE_L3) ? "L3 " : "",
            (layer_mask & TRACE_L4) ? "L4 " : "");
    return 0;
}

void trace_stop(void) {
    if (g_trace_file) {
        fclose(g_trace_file);
        g_trace_file = NULL;
        LOG_INF(MODULE, "Trace stopped: %d packets captured to %s",
                g_packet_count, g_filename);
    }
    g_layer_mask = 0;
}

void trace_capture(int layer, trace_dir_t dir, const uint8_t *data, int len) {
    (void)dir;
    if (!g_trace_file) return;
    if (!(g_layer_mask & layer)) return;
    if (len <= 0 || !data) return;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    pcap_packet_header_t phdr = {
        .ts_sec = (uint32_t)ts.tv_sec,
        .ts_usec = (uint32_t)(ts.tv_nsec / 1000),
        .incl_len = (uint32_t)len,
        .orig_len = (uint32_t)len
    };

    fwrite(&phdr, sizeof(phdr), 1, g_trace_file);
    fwrite(data, 1, len, g_trace_file);
    fflush(g_trace_file);
    g_packet_count++;
}

bool trace_is_active(void) {
    return g_trace_file != NULL;
}

void trace_status(void) {
    if (g_trace_file) {
        printf("  Trace: ACTIVE\n");
        printf("  File:  %s\n", g_filename);
        printf("  Layers: %s%s%s\n",
               (g_layer_mask & TRACE_L2) ? "L2 " : "",
               (g_layer_mask & TRACE_L3) ? "L3 " : "",
               (g_layer_mask & TRACE_L4) ? "L4 " : "");
        printf("  Packets: %d\n", g_packet_count);
    } else {
        printf("  Trace: INACTIVE\n");
    }
}
