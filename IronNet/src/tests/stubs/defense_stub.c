#include "../../ironstack/security/defense.h"

int  defense_init(void) { return 0; }
int  defense_enable(const char *name) { (void)name; return 0; }
int  defense_disable(const char *name) { (void)name; return 0; }
bool defense_is_enabled(const char *name) { (void)name; return false; }
void defense_dump(void) {}
uint32_t syncookie_generate(uint32_t a, uint32_t b, uint16_t c, uint16_t d, uint32_t e) {
    (void)a;(void)b;(void)c;(void)d;(void)e; return 0;
}
bool syncookie_validate(uint32_t a, uint32_t b, uint16_t c, uint16_t d, uint32_t e, uint32_t f) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f; return false;
}
void rate_limit_set(int m) { (void)m; }
bool rate_limit_check(uint32_t ip) { (void)ip; return true; }
void rate_limit_tick(void) {}
