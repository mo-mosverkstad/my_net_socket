#ifndef IRON_IFACE_H
#define IRON_IFACE_H

#include "types.h"

#define IFACE_MAX 8

typedef struct {
    char name[IRON_MAX_NAME];
    uint8_t mac[IRON_MAC_LEN];
    uint32_t ip;
    uint8_t prefix_len;
    int vnic_idx;       /* index into vnic table */
    bool up;
    bool configured;
} iface_config_t;

int iface_init(void);
int iface_add(const char *name, uint8_t mac[IRON_MAC_LEN],
              uint32_t ip, uint8_t prefix_len);
iface_config_t *iface_get(int idx);
iface_config_t *iface_find_by_ip(uint32_t ip);
iface_config_t *iface_find_by_name(const char *name);
int iface_get_count(void);
bool iface_is_local_ip(uint32_t ip);

#endif /* IRON_IFACE_H */
