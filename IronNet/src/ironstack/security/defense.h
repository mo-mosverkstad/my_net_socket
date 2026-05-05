#ifndef IRON_DEFENSE_H
#define IRON_DEFENSE_H

#include "types.h"

#define DEFENSE_MAX         16
#define DEFENSE_NAME_LEN    32
#define RATE_LIMIT_BUCKETS  64
#define RATE_LIMIT_DEFAULT  100  /* SYNs per second per source */

typedef struct {
    char name[DEFENSE_NAME_LEN];
    bool enabled;
} defense_entry_t;

int  defense_init(void);
int  defense_enable(const char *name);
int  defense_disable(const char *name);
bool defense_is_enabled(const char *name);
void defense_dump(void);

/* SYN cookies */
uint32_t syncookie_generate(uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port, uint32_t seq);
bool     syncookie_validate(uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            uint32_t cookie, uint32_t ack);

/* Rate limiting */
void     rate_limit_set(int max_per_sec);
bool     rate_limit_check(uint32_t src_ip); /* true = allowed, false = drop */
void     rate_limit_tick(void);             /* call once per second to reset */

#endif /* IRON_DEFENSE_H */
