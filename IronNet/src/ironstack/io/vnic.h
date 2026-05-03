#ifndef IRON_VNIC_H
#define IRON_VNIC_H

#include "types.h"

#define VNIC_MTU 1500
#define VNIC_MAX_INTERFACES 8

typedef struct {
    char name[IRON_MAX_NAME];
    uint8_t mac[IRON_MAC_LEN];
    int fd;
    bool active;
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_drops;
} vnic_t;

int vnic_init(void);
void vnic_shutdown(void);

int vnic_create(const char *name, uint8_t mac[IRON_MAC_LEN]);
int vnic_read(int iface_idx, uint8_t *buf, int buf_len);
int vnic_write(int iface_idx, const uint8_t *buf, int len);
int vnic_inject(int iface_idx, const uint8_t *buf, int len);

int vnic_get_count(void);
vnic_t *vnic_get(int iface_idx);

#endif /* IRON_VNIC_H */
