#include "../ironmon/audit.h"

/* Stub implementation for tests */
int audit_init(const char *f) { (void)f; return 0; }
void audit_shutdown(void) {}
void audit_log_event(audit_event_type_t type, uint32_t s, uint32_t d,
                     uint8_t p, uint16_t sp, uint16_t dp, const char *det) {
    (void)type;(void)s;(void)d;(void)p;(void)sp;(void)dp;(void)det;
}
void audit_enable(void) {}
void audit_disable(void) {}
int audit_get_recent(audit_event_t *o, int m) { (void)o;(void)m; return 0; }
void audit_dump(void) {}
void audit_dump_json(void) {}
