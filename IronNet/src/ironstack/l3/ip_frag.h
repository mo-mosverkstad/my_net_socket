#ifndef IRON_IP_FRAG_H
#define IRON_IP_FRAG_H

#include "types.h"
#include "../l3/ip.h"

#define FRAG_MAX_REASSEMBLY  32
#define FRAG_MAX_SIZE        65535
#define FRAG_TIMEOUT_SEC     30
#define FRAG_MIN_SIZE        68   /* Minimum fragment size (RFC 791) */

#define IP_FLAG_MF           0x2000  /* More Fragments */
#define IP_FLAG_DF           0x4000  /* Don't Fragment */
#define IP_OFFSET_MASK       0x1FFF

/* Fragment a packet into pieces fitting within MTU */
int ip_fragment(uint8_t *pkt, int pkt_len, int mtu,
                uint8_t *out_buf, int out_buf_len, int *frag_count);

/* Submit a fragment for reassembly. Returns complete packet when all fragments received. */
int ip_reassemble(uint8_t *frag, int frag_len,
                  uint8_t *out_buf, int out_buf_len);

/* Clean up expired reassembly entries */
void ip_frag_timer_tick(void);

#endif /* IRON_IP_FRAG_H */
