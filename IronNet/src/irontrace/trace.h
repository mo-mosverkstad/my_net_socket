#ifndef IRON_TRACE_H
#define IRON_TRACE_H

#include "types.h"

#define TRACE_L2    0x01
#define TRACE_L3    0x02
#define TRACE_L4    0x04
#define TRACE_ALL   0x07

typedef enum {
    TRACE_DIR_RX,
    TRACE_DIR_TX
} trace_dir_t;

int  trace_init(void);
int  trace_start(const char *filename, int layer_mask);
void trace_stop(void);
void trace_capture(int layer, trace_dir_t dir, const uint8_t *data, int len);
void trace_status(void);
bool trace_is_active(void);

#endif /* IRON_TRACE_H */
