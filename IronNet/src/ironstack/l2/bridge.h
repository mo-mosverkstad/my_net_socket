#ifndef IRON_BRIDGE_H
#define IRON_BRIDGE_H

#include "types.h"

#define BRIDGE_MAX          4
#define BRIDGE_MAX_PORTS    16
#define BRIDGE_MAC_TABLE_SIZE 256
#define BRIDGE_MAC_AGING_SEC  300  /* 5 minutes */

typedef struct {
    uint8_t mac[IRON_MAC_LEN];
    int port_idx;
    uint16_t vlan_id;
    uint64_t timestamp;
    bool valid;
} bridge_mac_entry_t;

typedef struct {
    char name[IRON_MAX_NAME];
    int ports[BRIDGE_MAX_PORTS];
    int port_count;
    bridge_mac_entry_t mac_table[BRIDGE_MAC_TABLE_SIZE];
    bool active;
    uint64_t frames_forwarded;
    uint64_t frames_flooded;
    uint64_t frames_dropped;
} bridge_t;

int bridge_init(void);
int bridge_create(const char *name);
int bridge_add_port(int bridge_idx, int port_idx);
int bridge_input(uint8_t *frame, int frame_len, int port_idx, uint16_t vlan_id);
void bridge_timer_tick(void);
void bridge_dump(void);

#endif /* IRON_BRIDGE_H */
