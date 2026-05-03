#ifndef IRON_TYPES_H
#define IRON_TYPES_H

#include <stdint.h>
#include <stdbool.h>

#define IRON_MAC_LEN      6
#define IRON_MAX_IFACE    16
#define IRON_MAX_NAME     32

typedef struct {
    uint32_t addr;
    uint8_t  prefix_len;
} ip_prefix_t;

typedef struct {
    uint16_t min;
    uint16_t max;
} port_range_t;

typedef enum {
    PROTO_ANY  = 0,
    PROTO_ICMP = 1,
    PROTO_TCP  = 6,
    PROTO_UDP  = 17
} ip_protocol_t;

typedef enum {
    DECISION_FORWARD,
    DECISION_LOCAL_DELIVER,
    DECISION_DROP
} route_decision_t;

typedef enum {
    DROP_NONE = 0,
    DROP_ACL,
    DROP_NO_ROUTE,
    DROP_PBR_LOOP,
    DROP_TCP_INVALID_STATE,
    DROP_RESOURCE_LIMIT,
    DROP_IPSEC_NO_SA,
    DROP_TTL_EXPIRED,
    DROP_INVALID_HEADER,
    DROP_INVALID_CHECKSUM,
    DROP_INVALID_FLAGS,
    DROP_COUNT
} drop_reason_t;

#endif /* IRON_TYPES_H */
