#include "stats_json.h"
#include "stats.h"

#include <stdio.h>

void iron_stats_dump_json(void) {
    printf("{\n");
    int first = 1;
    for (int i = 0; i < STAT_COUNT; i++) {
        uint64_t val = iron_stats_get(i);
        if (val > 0) {
            if (!first) printf(",\n");
            printf("  \"%s\": %lu", iron_stats_name(i), val);
            first = 0;
        }
    }
    printf("\n}\n");
}
