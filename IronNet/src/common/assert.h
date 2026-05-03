#ifndef IRON_ASSERT_H
#define IRON_ASSERT_H

#include <stdio.h>
#include <stdlib.h>
#include "stats.h"

#define IRON_ASSERT(cond, category, fmt, ...)                          \
    do {                                                               \
        if (!(cond)) {                                                 \
            fprintf(stderr,                                            \
                "[ASSERT FAIL] [%s] %s:%d: " fmt "\n",                 \
                (category), __FILE__, __LINE__,                         \
                ##__VA_ARGS__);                                         \
            iron_stats_increment(STAT_ASSERT_FAILURES);                \
            abort();                                                    \
        }                                                              \
    } while (0)

/* TCP-specific invariant assertions */

#define TCP_ASSERT_VALID_STATE(conn)                                   \
    IRON_ASSERT(                                                       \
        (conn)->state >= TCP_CLOSED &&                                 \
        (conn)->state <= TCP_TIME_WAIT,                                \
        "TCP_STATE",                                                   \
        "Invalid TCP state: %d", (conn)->state)

#define TCP_ASSERT_TRANSITION(old_state, new_state)                    \
    IRON_ASSERT(                                                       \
        tcp_is_valid_transition((old_state), (new_state)),             \
        "TCP_TRANSITION",                                              \
        "Illegal TCP transition %d -> %d", (old_state), (new_state))

#define TCP_ASSERT_SEQ_MONOTONIC(prev, next)                           \
    IRON_ASSERT(                                                       \
        (next) >= (prev),                                              \
        "TCP_SEQ",                                                     \
        "Sequence regression: %u -> %u", (prev), (next))

#define TCP_ASSERT_INVALID_FLAGS(pkt)                                  \
    IRON_ASSERT(                                                       \
        !((pkt)->syn && (pkt)->fin) &&                                 \
        !((pkt)->syn && (pkt)->rst),                                   \
        "TCP_FLAGS",                                                   \
        "Invalid TCP flags combination")

/* Routing invariant assertions */

#define ROUTE_ASSERT_ACL_FIRST(ctx)                                    \
    IRON_ASSERT(                                                       \
        (ctx)->acl_checked,                                            \
        "ROUTE_ORDER",                                                 \
        "PBR evaluated before ACL")

#define ROUTE_ASSERT_NO_LOOP(pkt, hop)                                 \
    IRON_ASSERT(                                                       \
        !route_seen_hop((pkt), (hop)),                                 \
        "ROUTE_LOOP",                                                  \
        "Routing loop detected at hop %u", (hop))

#define ROUTE_ASSERT_SINGLE_DECISION(decision)                         \
    IRON_ASSERT(                                                       \
        (decision) != DECISION_DROP || 1,                              \
        "ROUTING",                                                     \
        "Packet left routing undecided")

#endif /* IRON_ASSERT_H */
