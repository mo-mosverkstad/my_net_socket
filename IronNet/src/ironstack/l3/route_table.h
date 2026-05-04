#ifndef IRON_ROUTE_TABLE_H
#define IRON_ROUTE_TABLE_H

#include "types.h"
#include "route.h"

#define ROUTE_TABLE_MAX       8
#define ROUTE_TABLE_NAME_LEN  32
#define ROUTE_TABLE_MAIN      0  /* Default table index */

typedef struct {
    char name[ROUTE_TABLE_NAME_LEN];
    route_entry_t entries[ROUTE_MAX_ENTRIES];
    int entry_count;
    bool active;
} route_table_t;

int route_table_init(void);
int route_table_create(const char *name);
int route_table_find(const char *name);
int route_table_add_route(int table_id, ip_prefix_t prefix, uint32_t next_hop, int out_iface);
int route_table_delete_route(int table_id, ip_prefix_t prefix);
int route_table_lookup(int table_id, uint32_t dst_ip, uint32_t *next_hop, int *out_iface);
void route_table_dump(void);

#endif /* IRON_ROUTE_TABLE_H */
