#ifndef IRON_AUDIT_H
#define IRON_AUDIT_H

#include "types.h"

#define AUDIT_RING_SIZE    256
#define AUDIT_MAX_LINE     256
#define AUDIT_DEFAULT_FILE "/tmp/ironnet_audit.log"

typedef enum {
    AUDIT_ACL_DENY,
    AUDIT_IPSEC_DROP,
    AUDIT_TCP_INVALID_FLAGS,
    AUDIT_TCP_TABLE_FULL,
    AUDIT_ARP_ANOMALY,
    AUDIT_NAT_EXHAUSTION,
    AUDIT_CONNTRACK_INVALID,
    AUDIT_FRAGMENT_DROP,
    AUDIT_VLAN_MISMATCH,
    AUDIT_TTL_EXPIRED,
    AUDIT_COVERT_CHANNEL
} audit_event_type_t;

typedef struct {
    uint64_t timestamp;
    audit_event_type_t type;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t  protocol;
    uint16_t src_port;
    uint16_t dst_port;
    char     detail[64];
} audit_event_t;

int audit_init(const char *log_file);
void audit_shutdown(void);
void audit_log_event(audit_event_type_t type,
                     uint32_t src_ip, uint32_t dst_ip,
                     uint8_t protocol, uint16_t src_port, uint16_t dst_port,
                     const char *detail);
void audit_enable(void);
void audit_disable(void);
int audit_get_recent(audit_event_t *out, int max_count);
void audit_dump(void);
void audit_dump_json(void);

#endif /* IRON_AUDIT_H */
