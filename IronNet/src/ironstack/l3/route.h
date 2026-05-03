#ifndef IRON_ROUTE_H
#define IRON_ROUTE_H

#include "types.h"

#define ROUTE_MAX_ENTRIES 128

typedef struct {
    ip_prefix_t prefix;
    uint32_t next_hop;
    int out_iface;
    bool active;
    uint64_t hit_count;
} route_entry_t;

int route_init(void);
int route_add(ip_prefix_t prefix, uint32_t next_hop, int out_iface);
int route_delete(ip_prefix_t prefix);
int route_lookup(uint32_t dst_ip, uint32_t *next_hop, int *out_iface);
void route_dump(void);

#endif /* IRON_ROUTE_H */
