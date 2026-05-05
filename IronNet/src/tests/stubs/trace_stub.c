#include "../../irontrace/trace.h"

int  trace_init(void) { return 0; }
int  trace_start(const char *f, int m) { (void)f;(void)m; return 0; }
void trace_stop(void) {}
void trace_capture(int l, trace_dir_t d, const uint8_t *data, int len) {
    (void)l;(void)d;(void)data;(void)len;
}
void trace_status(void) {}
bool trace_is_active(void) { return false; }
