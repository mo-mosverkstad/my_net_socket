#ifndef IRON_VLAN_H
#define IRON_VLAN_H

#include "types.h"
#include "utils.h"

#define VLAN_TAG_LEN       4
#define VLAN_TPID          0x8100
#define VLAN_MAX_ID        4095
#define VLAN_ID_NONE       0
#define VLAN_MAX_PORTS     16

typedef enum {
    VLAN_PORT_ACCESS,   /* Untagged, single VLAN */
    VLAN_PORT_TRUNK     /* Tagged, multiple VLANs */
} vlan_port_mode_t;

typedef struct {
    int port_idx;               /* Interface/vnic index */
    vlan_port_mode_t mode;
    uint16_t access_vlan;       /* VLAN ID for access port */
    uint16_t trunk_allowed[VLAN_MAX_ID / 16 + 1]; /* Bitmap for trunk */
    bool configured;
} vlan_port_t;

typedef struct __attribute__((packed)) {
    uint16_t tpid;      /* 0x8100 */
    uint16_t tci;       /* PCP(3) + DEI(1) + VID(12) */
} vlan_tag_t;

static inline uint16_t vlan_get_vid(const vlan_tag_t *tag) {
    return iron_ntohs(tag->tci) & 0x0FFF;
}

static inline uint16_t vlan_make_tci(uint16_t vid) {
    return iron_htons(vid & 0x0FFF);
}

int vlan_init(void);
int vlan_port_set_access(int port_idx, uint16_t vlan_id);
int vlan_port_set_trunk(int port_idx, const uint16_t *allowed_vlans, int count);
vlan_port_t *vlan_port_get(int port_idx);

/* Returns VLAN ID for the frame. Strips tag if from trunk port. */
int vlan_ingress(uint8_t *frame, int *frame_len, int port_idx, uint16_t *vlan_id);

/* Inserts tag if egress port is trunk. Returns new frame length. */
int vlan_egress(uint8_t *frame, int frame_len, int port_idx,
                uint16_t vlan_id, uint8_t *out_buf, int out_buf_len);

#endif /* IRON_VLAN_H */
