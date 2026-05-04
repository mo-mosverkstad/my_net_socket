#include "vlan.h"
#include "eth.h"
#include "log.h"

#include <string.h>

#define MODULE "VLAN"

static vlan_port_t g_vlan_ports[VLAN_MAX_PORTS];

int vlan_init(void) {
    memset(g_vlan_ports, 0, sizeof(g_vlan_ports));
    LOG_INF(MODULE, "VLAN initialized");
    return 0;
}

int vlan_port_set_access(int port_idx, uint16_t vlan_id) {
    if (port_idx < 0 || port_idx >= VLAN_MAX_PORTS) return -1;
    if (vlan_id > VLAN_MAX_ID) return -1;

    vlan_port_t *p = &g_vlan_ports[port_idx];
    p->port_idx = port_idx;
    p->mode = VLAN_PORT_ACCESS;
    p->access_vlan = vlan_id;
    p->configured = true;

    LOG_INF(MODULE, "Port %d set to ACCESS vlan %u", port_idx, vlan_id);
    return 0;
}

int vlan_port_set_trunk(int port_idx, const uint16_t *allowed_vlans, int count) {
    if (port_idx < 0 || port_idx >= VLAN_MAX_PORTS) return -1;

    vlan_port_t *p = &g_vlan_ports[port_idx];
    p->port_idx = port_idx;
    p->mode = VLAN_PORT_TRUNK;
    p->configured = true;
    memset(p->trunk_allowed, 0, sizeof(p->trunk_allowed));

    for (int i = 0; i < count; i++) {
        uint16_t vid = allowed_vlans[i];
        if (vid <= VLAN_MAX_ID) {
            p->trunk_allowed[vid / 16] |= (1 << (vid % 16));
        }
    }

    LOG_INF(MODULE, "Port %d set to TRUNK (%d VLANs allowed)", port_idx, count);
    return 0;
}

static bool trunk_allows_vlan(vlan_port_t *p, uint16_t vid) {
    if (vid > VLAN_MAX_ID) return false;
    return (p->trunk_allowed[vid / 16] & (1 << (vid % 16))) != 0;
}

vlan_port_t *vlan_port_get(int port_idx) {
    if (port_idx < 0 || port_idx >= VLAN_MAX_PORTS) return NULL;
    if (!g_vlan_ports[port_idx].configured) return NULL;
    return &g_vlan_ports[port_idx];
}

int vlan_ingress(uint8_t *frame, int *frame_len, int port_idx, uint16_t *vlan_id) {
    vlan_port_t *port = vlan_port_get(port_idx);

    /* If port not configured for VLAN, pass through with VLAN_ID_NONE */
    if (!port) {
        *vlan_id = VLAN_ID_NONE;
        return 0;
    }

    /* Check if frame has a VLAN tag (EtherType at offset 12 == 0x8100) */
    if (*frame_len < ETH_HEADER_LEN + VLAN_TAG_LEN) {
        /* Too short to have a tag */
        if (port->mode == VLAN_PORT_ACCESS) {
            *vlan_id = port->access_vlan;
            return 0;
        }
        return -1; /* Trunk port requires tagged frame */
    }

    uint16_t ethertype_at_12 = (frame[12] << 8) | frame[13];
    bool has_tag = (ethertype_at_12 == VLAN_TPID);

    if (port->mode == VLAN_PORT_ACCESS) {
        if (has_tag) {
            /* Tagged frame on access port — check if it matches */
            vlan_tag_t *tag = (vlan_tag_t *)(frame + 12);
            uint16_t vid = vlan_get_vid(tag);
            if (vid != port->access_vlan) {
                LOG_DBG(MODULE, "Access port %d: dropping tagged frame (vlan %u != %u)",
                        port_idx, vid, port->access_vlan);
                return -1; /* Wrong VLAN, drop */
            }
            /* Strip the tag: move first 12 bytes (MACs) forward by 4 */
            memmove(frame + VLAN_TAG_LEN, frame, 12);
            /* Shift frame pointer and reduce length */
            memmove(frame, frame + VLAN_TAG_LEN, *frame_len - VLAN_TAG_LEN);
            *frame_len -= VLAN_TAG_LEN;
        }
        *vlan_id = port->access_vlan;
        return 0;
    }

    if (port->mode == VLAN_PORT_TRUNK) {
        if (!has_tag) {
            LOG_DBG(MODULE, "Trunk port %d: dropping untagged frame", port_idx);
            return -1; /* Trunk requires tagged */
        }

        vlan_tag_t *tag = (vlan_tag_t *)(frame + 12);
        uint16_t vid = vlan_get_vid(tag);

        if (!trunk_allows_vlan(port, vid)) {
            LOG_DBG(MODULE, "Trunk port %d: vlan %u not allowed", port_idx, vid);
            return -1;
        }

        /* Strip tag for internal processing */
        memmove(frame + VLAN_TAG_LEN, frame, 12);
        memmove(frame, frame + VLAN_TAG_LEN, *frame_len - VLAN_TAG_LEN);
        *frame_len -= VLAN_TAG_LEN;

        *vlan_id = vid;
        return 0;
    }

    return -1;
}

int vlan_egress(uint8_t *frame, int frame_len, int port_idx,
                uint16_t vlan_id, uint8_t *out_buf, int out_buf_len) {
    vlan_port_t *port = vlan_port_get(port_idx);

    /* If port not configured, pass through unchanged */
    if (!port) {
        if (frame_len > out_buf_len) return -1;
        memcpy(out_buf, frame, frame_len);
        return frame_len;
    }

    if (port->mode == VLAN_PORT_ACCESS) {
        /* Access port: send untagged (frame as-is) */
        if (vlan_id != port->access_vlan) {
            return -1; /* Frame not for this port's VLAN */
        }
        if (frame_len > out_buf_len) return -1;
        memcpy(out_buf, frame, frame_len);
        return frame_len;
    }

    if (port->mode == VLAN_PORT_TRUNK) {
        /* Trunk port: insert VLAN tag */
        if (!trunk_allows_vlan(port, vlan_id)) {
            return -1; /* VLAN not allowed on this trunk */
        }

        int out_len = frame_len + VLAN_TAG_LEN;
        if (out_len > out_buf_len) return -1;

        /* Copy dst+src MAC (12 bytes) */
        memcpy(out_buf, frame, 12);

        /* Insert VLAN tag */
        vlan_tag_t tag;
        tag.tpid = iron_htons(VLAN_TPID);
        tag.tci = vlan_make_tci(vlan_id);
        memcpy(out_buf + 12, &tag, VLAN_TAG_LEN);

        /* Copy rest of frame (original ethertype + payload) */
        memcpy(out_buf + 12 + VLAN_TAG_LEN, frame + 12, frame_len - 12);

        return out_len;
    }

    return -1;
}
