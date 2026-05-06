/*
 * vuln_server.c — Intentionally vulnerable application (Phase 18a)
 * with exploit mitigations added (Phase 18c)
 *
 * TCP port 9999 — contains deliberate security flaws for exploitation study:
 *   1. Stack buffer overflow (strcpy into 64-byte buffer)
 *   2. Format string vulnerability (printf with user-controlled format)
 *   3. Integer overflow in length field (small alloc + large copy)
 *
 * Commands:
 *   ECHO <text>     — echoes text (uses unsafe strcpy → overflow if >64 bytes)
 *   FMT <text>      — prints text as format string (format string vuln)
 *   READ <len>      — reads <len> bytes from a buffer (integer overflow in len)
 *   SAFE <text>     — safe echo using strncpy (for comparison)
 *   CANARY <text>   — echo with stack canary protection (Phase 18c)
 *   BOUNDS <text>   — echo with bounds checking + input validation (Phase 18c)
 *   ASLR <text>     — echo with randomized buffer address (Phase 18c)
 *   HELP            — show commands
 *
 * ASAN (Debug build) will catch these at runtime. In Release builds,
 * these produce undefined behavior / segfaults / code execution.
 */

#include "vuln_server.h"
#include "app_socket.h"
#include "log.h"
#include "utils.h"
#include "../ironstack/core/iface.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define MODULE "VULN"
#define VULN_PORT 9999
#define VULN_BUF_SIZE 64  /* Intentionally small buffer */

/* Secret data that an attacker might try to leak via format string */
static const char *g_secret = "SECRET_KEY_12345";
static int g_auth_flag = 0;

/* Stack canary value (randomized at startup) */
static uint64_t g_canary = 0;

/*
 * Vulnerability 1: Stack buffer overflow
 * strcpy() copies without bounds checking. If input > 64 bytes,
 * it overwrites the stack (return address, saved registers, etc.)
 */
static void vuln_echo_unsafe(const char *input, char *resp, int *resp_len) {
    char local_buf[VULN_BUF_SIZE]; /* 64 bytes on stack */

    /* VULNERABLE: no bounds check — overflow if strlen(input) > 63 */
    strcpy(local_buf, input);

    *resp_len = snprintf(resp, 256, "+ECHO %s\r\n", local_buf);
}

/*
 * Vulnerability 2: Format string
 * printf(user_input) allows attacker to use %x, %s, %n to:
 *   - Read stack memory (%x leaks stack values)
 *   - Read arbitrary memory (%s dereferences stack values as pointers)
 *   - Write to memory (%n writes byte count to address on stack)
 */
static void vuln_format_string(const char *input, char *resp, int *resp_len) {
    char fmt_buf[256];

    /* VULNERABLE: user input used directly as format string */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-security"
    snprintf(fmt_buf, sizeof(fmt_buf), input);
#pragma GCC diagnostic pop

    *resp_len = snprintf(resp, 256, "+FMT %s\r\n", fmt_buf);
}

/*
 * Vulnerability 3: Integer overflow in length
 * If attacker sends a large length value that wraps around when cast
 * to a smaller type, a small buffer is used but a large read occurs.
 */
static void vuln_read_overflow(const char *len_str, char *resp, int *resp_len) {
    static char data_pool[256] = "AAAA_NORMAL_DATA_BBBB_PADDING_CCCC_"
                                 "MORE_DATA_HERE_FOR_TESTING_OVERFLOW_"
                                 "SENSITIVE_INFO_SHOULD_NOT_LEAK_OUT__"
                                 "END_OF_POOL_BUFFER_AREA_XXXXXXXXXXX";

    int requested = atoi(len_str);

    /* VULNERABLE: if requested is negative (from overflow) or very large,
     * we might read beyond the buffer. Also, uint8_t cast wraps:
     * e.g., requested=256 → (uint8_t)256 = 0, but we use 'requested' for memcpy */
    uint8_t alloc_size = (uint8_t)requested; /* Integer truncation! */

    if (alloc_size == 0) {
        *resp_len = snprintf(resp, 256, "-ERR zero length\r\n");
        return;
    }

    /* Use the (possibly truncated) alloc_size for bounds display,
     * but copy 'requested' bytes — mismatch = overflow */
    char read_buf[256];
    int copy_len = requested < (int)sizeof(read_buf) ? requested : (int)sizeof(read_buf);
    if (copy_len < 0) copy_len = 0;
    memcpy(read_buf, data_pool, copy_len);
    read_buf[copy_len < 255 ? copy_len : 255] = 0;

    *resp_len = snprintf(resp, 256, "+READ(%d alloc=%u) %s\r\n",
                         requested, alloc_size, read_buf);
}

/* Safe version for comparison */
static void vuln_echo_safe(const char *input, char *resp, int *resp_len) {
    char local_buf[VULN_BUF_SIZE];

    /* SAFE: bounds-checked copy */
    strncpy(local_buf, input, VULN_BUF_SIZE - 1);
    local_buf[VULN_BUF_SIZE - 1] = 0;

    *resp_len = snprintf(resp, 256, "+SAFE %s\r\n", local_buf);
}

/*
 * Mitigation 1: Stack canary (Phase 18c)
 * A random value is placed between the buffer and the return address.
 * After copy, we check if the canary was overwritten. If so, report violation.
 * Note: Uses manual memcpy to simulate overflow without triggering ASAN's
 * strcpy interceptor (so the canary check actually runs in Debug builds).
 */
static void vuln_echo_canary(const char *input, char *resp, int *resp_len) {
    /* Layout: [local_buf 64B][canary 8B] — canary sits right after buffer */
    uint8_t frame[VULN_BUF_SIZE + 8];
    uint64_t *canary_ptr = (uint64_t *)(frame + VULN_BUF_SIZE);
    *canary_ptr = g_canary; /* Place canary after buffer */

    int input_len = strlen(input);

    /* Copy input into buffer — if > 64 bytes, overwrites canary */
    int copy_len = input_len < (int)sizeof(frame) ? input_len : (int)sizeof(frame) - 1;
    memcpy(frame, input, copy_len);
    frame[copy_len] = 0;

    /* Check canary BEFORE using the buffer */
    if (*canary_ptr != g_canary) {
        *resp_len = snprintf(resp, 256,
            "-CANARY VIOLATION: stack smashing detected! (expected 0x%016lX, got 0x%016lX)\r\n",
            (unsigned long)g_canary, (unsigned long)*canary_ptr);
        LOG_WRN(MODULE, "Stack canary violation detected! Overflow blocked.");
        return;
    }

    *resp_len = snprintf(resp, 256, "+CANARY %s\r\n", (char *)frame);
}

/*
 * Mitigation 2: Bounds checking (Phase 18c)
 * Validate input length BEFORE copying. Reject oversized input.
 */
static void vuln_echo_bounds(const char *input, char *resp, int *resp_len) {
    int input_len = strlen(input);

    /* MITIGATION: reject input that would overflow the buffer */
    if (input_len >= VULN_BUF_SIZE) {
        *resp_len = snprintf(resp, 256,
            "-BOUNDS REJECTED: input %d bytes exceeds buffer %d bytes\r\n",
            input_len, VULN_BUF_SIZE - 1);
        LOG_WRN(MODULE, "Bounds check rejected input: %d bytes (max %d)",
                input_len, VULN_BUF_SIZE - 1);
        return;
    }

    char local_buf[VULN_BUF_SIZE];
    strncpy(local_buf, input, VULN_BUF_SIZE - 1);
    local_buf[VULN_BUF_SIZE - 1] = 0;

    *resp_len = snprintf(resp, 256, "+BOUNDS %s\r\n", local_buf);
}

/*
 * Mitigation 3: ASLR simulation (Phase 18c)
 * Randomize the buffer's position by adding a random-sized pad before it.
 * Attacker can't predict where the buffer (or return address) is.
 */
static void vuln_echo_aslr(const char *input, char *resp, int *resp_len) {
    /* Random pad: 0-256 bytes of dead space before the real buffer */
    int pad_size = rand() % 256;
    char pad_and_buf[256 + VULN_BUF_SIZE];
    char *buf_ptr = pad_and_buf + pad_size; /* Buffer at random offset */

    /* Use strncpy (safe) but report the randomized address */
    strncpy(buf_ptr, input, VULN_BUF_SIZE - 1);
    buf_ptr[VULN_BUF_SIZE - 1] = 0;

    *resp_len = snprintf(resp, 256,
        "+ASLR (buf@offset+%d) %s\r\n", pad_size, buf_ptr);
}

static void vuln_on_data(int sock_id, uint32_t src_ip, uint16_t src_port,
                         const uint8_t *data, int data_len) {
    (void)sock_id;
    (void)g_secret;
    (void)g_auth_flag;

    iface_config_t *ifc = iface_get(0);
    uint32_t local_ip = ifc ? ifc->ip : 0;

    /* Parse command */
    char cmd[512];
    int len = data_len < 511 ? data_len : 511;
    memcpy(cmd, data, len);
    cmd[len] = 0;
    while (len > 0 && (cmd[len-1] == '\n' || cmd[len-1] == '\r')) cmd[--len] = 0;

    char resp[256];
    int resp_len = 0;

    if (strncmp(cmd, "ECHO ", 5) == 0) {
        vuln_echo_unsafe(cmd + 5, resp, &resp_len);
    } else if (strncmp(cmd, "FMT ", 4) == 0) {
        vuln_format_string(cmd + 4, resp, &resp_len);
    } else if (strncmp(cmd, "READ ", 5) == 0) {
        vuln_read_overflow(cmd + 5, resp, &resp_len);
    } else if (strncmp(cmd, "SAFE ", 5) == 0) {
        vuln_echo_safe(cmd + 5, resp, &resp_len);
    } else if (strncmp(cmd, "CANARY ", 7) == 0) {
        vuln_echo_canary(cmd + 7, resp, &resp_len);
    } else if (strncmp(cmd, "BOUNDS ", 7) == 0) {
        vuln_echo_bounds(cmd + 7, resp, &resp_len);
    } else if (strncmp(cmd, "ASLR ", 5) == 0) {
        vuln_echo_aslr(cmd + 5, resp, &resp_len);
    } else if (strncmp(cmd, "HELP", 4) == 0) {
        resp_len = snprintf(resp, sizeof(resp),
            "+COMMANDS: ECHO, FMT, READ, SAFE, CANARY, BOUNDS, ASLR, HELP\r\n");
    } else {
        resp_len = snprintf(resp, sizeof(resp), "-ERR unknown command\r\n");
    }

    if (resp_len > 0) {
        app_socket_send(src_ip, src_port, local_ip, VULN_PORT,
                        PROTO_TCP, (uint8_t *)resp, resp_len);
    }
}

int vuln_server_start(void) {
    /* Initialize stack canary with random value */
    srand(time(NULL) ^ (uintptr_t)&g_canary);
    g_canary = ((uint64_t)rand() << 32) | rand();

    app_socket_listen(PROTO_TCP, VULN_PORT, vuln_on_data, NULL, NULL);
    LOG_INF(MODULE, "Vulnerable server started on TCP port %d (INTENTIONALLY INSECURE)", VULN_PORT);
    return 0;
}
