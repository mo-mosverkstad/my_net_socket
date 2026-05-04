#include "route_table.h"
#include "log.h"
#include "utils.h"

#include <string.h>

#define MODULE "RTABLE"

static route_table_t g_tables[ROUTE_TABLE_MAX];
static int g_table_count = 0;

int route_table_init(void) {
    memset(g_tables, 0, sizeof(g_tables));
    g_table_count = 0;

    /* Create default "main" table */
    route_table_create("main");

    LOG_INF(MODULE, "Route tables initialized (default: main)");
    return 0;
}

int route_table_create(const char *name) {
    if (g_table_count >= ROUTE_TABLE_MAX) {
        LOG_ERR(MODULE, "Max routing tables reached");
        return -1;
    }

    /* Check for duplicate */
    for (int i = 0; i < g_table_count; i++) {
        if (g_tables[i].active && strcmp(g_tables[i].name, name) == 0) {
            return i; /* Already exists */
        }
    }

    route_table_t *t = &g_tables[g_table_count];
    strncpy(t->name, name, ROUTE_TABLE_NAME_LEN - 1);
    t->entry_count = 0;
    t->active = true;

    int idx = g_table_count;
    g_table_count++;
    LOG_INF(MODULE, "Table '%s' created (id=%d)", name, idx);
    return idx;
}

int route_table_find(const char *name) {
    for (int i = 0; i < g_table_count; i++) {
        if (g_tables[i].active && strcmp(g_tables[i].name, name) == 0)
            return i;
    }
    return -1;
}

int route_table_add_route(int table_id, ip_prefix_t prefix, uint32_t next_hop, int out_iface) {
    if (table_id < 0 || table_id >= g_table_count) return -1;
    route_table_t *t = &g_tables[table_id];
    if (!t->active) return -1;
    if (t->entry_count >= ROUTE_MAX_ENTRIES) {
        LOG_ERR(MODULE, "Table '%s' full", t->name);
        return -1;
    }

    route_entry_t *r = &t->entries[t->entry_count];
    r->prefix = prefix;
    r->next_hop = next_hop;
    r->out_iface = out_iface;
    r->active = true;
    r->hit_count = 0;
    t->entry_count++;

    char ip_buf[16];
    LOG_INF(MODULE, "Route added to '%s': %s/%d iface %d",
            t->name,
            iron_ip_to_str(prefix.addr, ip_buf, sizeof(ip_buf)),
            prefix.prefix_len, out_iface);
    return 0;
}

int route_table_delete_route(int table_id, ip_prefix_t prefix) {
    if (table_id < 0 || table_id >= g_table_count) return -1;
    route_table_t *t = &g_tables[table_id];
    if (!t->active) return -1;

    for (int i = 0; i < t->entry_count; i++) {
        if (t->entries[i].active &&
            t->entries[i].prefix.addr == prefix.addr &&
            t->entries[i].prefix.prefix_len == prefix.prefix_len) {
            t->entries[i].active = false;
            return 0;
        }
    }
    return -1;
}

int route_table_lookup(int table_id, uint32_t dst_ip, uint32_t *next_hop, int *out_iface) {
    if (table_id < 0 || table_id >= g_table_count) return -1;
    route_table_t *t = &g_tables[table_id];
    if (!t->active) return -1;

    int best_idx = -1;
    uint8_t best_prefix_len = 0;

    for (int i = 0; i < t->entry_count; i++) {
        if (!t->entries[i].active) continue;

        if (iron_ip_matches(dst_ip, t->entries[i].prefix.addr, t->entries[i].prefix.prefix_len)) {
            if (t->entries[i].prefix.prefix_len >= best_prefix_len) {
                best_prefix_len = t->entries[i].prefix.prefix_len;
                best_idx = i;
            }
        }
    }

    if (best_idx < 0) return -1;

    t->entries[best_idx].hit_count++;
    *next_hop = t->entries[best_idx].next_hop;
    *out_iface = t->entries[best_idx].out_iface;
    return 0;
}

void route_table_dump(void) {
    char ip_buf[16], nh_buf[16];
    for (int t = 0; t < g_table_count; t++) {
        if (!g_tables[t].active) continue;
        LOG_INF(MODULE, "--- Table '%s' (id=%d) ---", g_tables[t].name, t);
        for (int i = 0; i < g_tables[t].entry_count; i++) {
            if (!g_tables[t].entries[i].active) continue;
            route_entry_t *r = &g_tables[t].entries[i];
            LOG_INF(MODULE, "  %s/%d via %s iface %d (hits: %lu)",
                    iron_ip_to_str(r->prefix.addr, ip_buf, sizeof(ip_buf)),
                    r->prefix.prefix_len,
                    iron_ip_to_str(r->next_hop, nh_buf, sizeof(nh_buf)),
                    r->out_iface, r->hit_count);
        }
    }
}
