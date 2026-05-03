# IronNet — Implementation Plan

## Overview

This document provides a concrete, step-by-step implementation plan for the IronNet project: a research-grade, instrumented network stack and security testing platform built in C/C++ on WSL Ubuntu.

---

## Phase 1: Foundation & Build System (Week 1–2)

### Goals
- Set up project skeleton and build infrastructure
- Establish coding conventions, logging, and assertion framework

### Tasks

1. **Initialize project structure**
   ```
   IronNet/
   ├── ideas.md            # Project vision & design notes
   ├── study.md            # Implementation plan & architecture
   ├── build.md            # Build & test instructions
   ├── todo.md             # Task tracking
   ├── build/              # Build output (out-of-source)
   └── src/                # All source code
       ├── CMakeLists.txt
       ├── common/          # Shared utilities
       ├── ironstack/       # Core protocol stack
       ├── ironctl/         # CLI / configuration
       ├── ironmon/         # Telemetry & metrics
       ├── ironapps/        # Target applications
       ├── ironfuzz/        # Fuzzing framework
       ├── ironprobe/       # Network scanner
       ├── ironload/        # Stress tester
       ├── ironsim/         # Network emulator
       ├── irontrace/       # Packet capture/replay
       └── tests/           # Unit & regression tests
   ```

2. **CMake build system**
   - Top-level CMakeLists.txt with subdirectory targets
   - Debug build with AddressSanitizer (ASAN) enabled by default
   - Release build with optimizations

3. **Common utilities (`common/`)**
   - `log.h` — structured logging with severity levels
   - `stats.h` — per-module counter infrastructure
   - `assert.h` — IRON_ASSERT macro (see ideas.md for design)
   - `types.h` — common network types (ip_prefix, port_range, etc.)
   - `utils.c` — memory helpers, byte-order conversion

4. **Validation**
   - Compile empty skeleton on WSL Ubuntu
   - Verify ASAN integration works

---

## Phase 2: Virtual NIC & L2 Layer (Week 3–4)

### Goals
- Implement packet I/O abstraction using TUN/TAP
- Build L2 Ethernet frame parsing and dispatch

### Tasks

1. **Virtual NIC abstraction (`ironstack/io/`)**
   - TUN/TAP device open/close/read/write
   - Interface registry (multiple virtual interfaces)
   - Raw packet injection hook for testing

2. **L2 Ethernet module (`ironstack/l2/`)**
   - Frame parsing: dst_mac, src_mac, ethertype
   - Frame validation: minimum size, ethertype whitelist
   - Dispatch to L3 based on ethertype
   - Per-interface RX/TX counters

3. **Key data structures**
   ```c
   struct l2_frame {
       uint8_t dst_mac[6];
       uint8_t src_mac[6];
       uint16_t ethertype;
       uint8_t payload[];
   };

   struct iface {
       char name[16];
       uint8_t mac[6];
       int fd;
       struct iface_stats stats;
   };
   ```

4. **Validation**
   - Unit test: parse valid/invalid frames
   - Inject oversized frame → verify drop + counter increment

---

## Phase 3: L3 IP Layer (Week 5–7)

### Goals
- IP header parsing, validation, and forwarding
- Routing table (FIB) with longest-prefix match
- ICMP echo for basic diagnostics

### Tasks

1. **IP processing (`ironstack/l3/ip.c`)**
   - Header parsing and validation (version, IHL, checksum, TTL)
   - TTL decrement and drop on zero
   - Local delivery vs forwarding decision

2. **Routing table (`ironstack/l3/route.c`)**
   - FIB with longest-prefix match
   - Add/delete routes via API
   - Default route support
   - Lookup returns: next_hop + out_iface or DROP

3. **ICMP (`ironstack/l3/icmp.c`)**
   - Echo request/reply
   - TTL exceeded
   - Destination unreachable

4. **Packet pipeline integration**
   ```
   L2 RX → IP Validation → Routing Lookup → Forward / Local / Drop
   ```

5. **Invariants to enforce**
   - ROUTE_ASSERT_SINGLE_DECISION — every packet gets exactly one outcome
   - TTL must decrement exactly once per hop

6. **Validation**
   - Ping between two virtual interfaces
   - Route lookup correctness tests
   - Invalid IP header → drop with reason code

---

## Phase 4: ACL & PBR Engines (Week 8–9)

### Goals
- Implement ACL (first-match, top-down evaluation)
- Implement PBR (policy-based routing override)
- Enforce ACL-before-PBR ordering invariant

### Tasks

1. **ACL engine (`ironstack/l3/acl.c`)**
   ```c
   struct acl_rule {
       uint32_t rule_id;
       struct acl_match match;  // src_ip, dst_ip, protocol, ports
       enum acl_action action;  // PERMIT or DENY
       uint64_t hit_count;
   };
   ```
   - Top-down, first-match-wins evaluation
   - Default policy (configurable: deny or permit)
   - Per-rule hit counters
   - Drop reason: DROP_ACL

2. **PBR engine (`ironstack/l3/pbr.c`)**
   ```c
   struct pbr_rule {
       uint32_t rule_id;
       struct pbr_match match;
       struct pbr_action action;  // next_hop override
       uint64_t hit_count;
   };
   ```
   - Evaluated only after ACL permits
   - Override routing decision if matched
   - Loop detection (visited hop tracking)

3. **Pipeline integration**
   ```
   IP Validation → ACL Check → PBR Lookup → FIB Lookup → Forward/Drop
   ```

4. **Invariants**
   - ROUTE_ASSERT_ACL_FIRST — PBR never evaluated before ACL
   - ROUTE_ASSERT_NO_LOOP — no forwarding loops via PBR

5. **Validation**
   - ACL blocks traffic → verify drop reason and counter
   - PBR redirects traffic → verify next-hop override
   - Reorder ACL rules → observe behavior change (misconfiguration study)

---

## Phase 5: L4 — UDP & TCP (Week 10–14)

### Goals
- Implement UDP (stateless, simple dispatch)
- Implement research-grade TCP state machine
- Connection table with resource limits

### Tasks

1. **UDP (`ironstack/l4/udp.c`)**
   - Header parsing
   - Port-based dispatch to applications
   - No state management

2. **TCP state machine (`ironstack/l4/tcp.c`, `tcp_state.c`)**
   ```c
   enum tcp_state {
       TCP_CLOSED, TCP_SYN_RECV, TCP_ESTABLISHED,
       TCP_FIN_WAIT_1, TCP_FIN_WAIT_2, TCP_TIME_WAIT
   };

   struct tcp_conn {
       uint32_t src_ip, dst_ip;
       uint16_t src_port, dst_port;
       enum tcp_state state;
       uint32_t snd_nxt, rcv_nxt;
       uint64_t last_activity;
   };
   ```

3. **TCP connection table**
   - Hash-based lookup by 4-tuple
   - Maximum connection limit (TCP_MAX_CONNECTIONS)
   - TIME_WAIT timeout and cleanup

4. **TCP invariants (enforced via IRON_ASSERT)**
   - T-S1: State always valid
   - T-S2: Only legal transitions
   - T-Q1: Sequence numbers monotonically increase
   - T-R1: Connection count ≤ max limit
   - T-R2: TIME_WAIT entries expire
   - T-SEC1: Invalid flag combos (SYN+FIN, SYN+RST) rejected without state change

5. **Validation**
   - Full 3-way handshake → ESTABLISHED
   - Graceful close → TIME_WAIT → CLOSED
   - Invalid flags → no state created, counter incremented
   - Connection table full → new SYN rejected

---

## Phase 6: IPsec (Simulated) (Week 15–16)

### Goals
- Implement Security Association (SA) lifecycle
- Policy enforcement (encrypt/decrypt decision points)
- Dummy crypto (focus on control flow, not real encryption)

### Tasks

1. **SA database (`ironstack/security/ipsec.c`)**
   - SA creation, lookup, expiry
   - Policy: which traffic requires protection

2. **Enforcement points**
   - Outbound: match policy → apply SA (dummy transform)
   - Inbound: verify SA exists → accept or drop

3. **Research focus**
   - Does enforcement fail open or fail closed?
   - SA expiry during active flow — what happens?

---

## Phase 7: Control Plane — ironctl (Week 17–18)

### Goals
- CLI for real-time configuration
- In-memory config database with live application

### Tasks

1. **CLI parser (`ironctl/cli.cpp`, `parser.cpp`)**
   ```
   interface add veth0 10.0.0.1/24
   route add 0.0.0.0/0 via 10.0.0.254
   acl add permit tcp src any dst any port 80
   pbr add match src 10.0.0.0/8 next-hop 10.0.1.1
   ipsec sa add ...
   show stats
   show routes
   show tcp connections
   ```

2. **Config manager (`ironstack/core/config.c`)**
   - Atomic config application
   - Event dispatch to data plane modules
   - Config change tracing (for debugging)

3. **Validation**
   - Add route via CLI → verify FIB updated
   - Add ACL rule → verify traffic blocked immediately

---

## Phase 8: Telemetry — ironmon (Week 19–20)

### Goals
- Real-time metrics export
- Per-layer counters, drop reasons, state table utilization

### Tasks

1. **Metrics infrastructure**
   ```c
   struct tcp_stats {
       uint64_t conn_created;
       uint64_t conn_closed;
       uint64_t half_open;
       uint64_t retransmissions;
   };
   ```

2. **Drop reason taxonomy**
   ```
   DROP_ACL, DROP_NO_ROUTE, DROP_PBR_LOOP,
   DROP_TCP_INVALID_STATE, DROP_RESOURCE_LIMIT,
   DROP_IPSEC_NO_SA, DROP_TTL_EXPIRED
   ```

3. **Export interface**
   - CLI: `show stats`
   - Structured output (JSON or plain text) for scripting

---

## Phase 9: Target Applications — ironapps (Week 21–22)

### Goals
- Build simple applications as attack targets
- Stateful, input-parsing, resource-consuming

### Tasks

1. **Echo server** — basic connectivity validation
2. **Key-Value TCP server** — stateful, memory-consuming
3. **Custom binary RPC** — complex parsing (ideal fuzz target)
4. **Simple HTTP-like service** — text protocol parsing

All apps register with ironstack via a socket-like API and run on top of the custom TCP/UDP.

---

## Phase 10: Security Testing — ironfuzz, ironprobe, ironload (Week 23–28)

### Goals
- Network scanner for attack surface validation
- Protocol fuzzer with state-aware mutation
- Stress tester for resource exhaustion analysis

### Tasks

1. **ironprobe (scanner)**
   - Port presence checks
   - ICMP probing
   - Service response fingerprinting
   - ACL correctness validation

2. **ironfuzz (fuzzer)**
   - Corpus manager (seed packets)
   - Mutation engine:
     - Length variation
     - Field bit-flip
     - Reordered packets
     - Invalid state transitions
     - Partial payloads
   - Packet injector (feeds into ironstack)
   - Crash/metric monitor (ASAN + assertion failures)
   - Coverage tracking:
     - TCP state coverage
     - Transition coverage
     - Drop-reason coverage
     - Config × packet interaction coverage

3. **ironload (stress tester)**
   - Connection table pressure (many SYNs)
   - Routing lookup overload (large FIB)
   - ACL complexity impact (many rules)
   - Metrics: drop patterns, latency escalation, degradation behavior

---

## Phase 11: Network Emulator — ironsim (Week 29–30)

### Goals
- Run multiple ironstack instances as network nodes
- Simulate topologies with configurable link properties

### Tasks

1. **Node management** — spawn multiple stack instances
2. **Virtual links** — configurable delay, drop rate, reorder
3. **Topology definition** — scripted multi-node setups
4. **Traffic generation** — automated flows between nodes

---

## Phase 12: Packet Tools — irontrace (Week 31–32)

### Goals
- Capture packets at any pipeline stage
- Replay captured traces for regression testing

### Tasks

1. **Capture** — hook at L2/L3/L4 boundaries, write to file
2. **Replay** — read capture file, inject into stack
3. **Regression workflow** — capture failure → fix → replay → verify

---

## Testing Strategy

### Unit Tests
- Per-module correctness (routing lookup, ACL evaluation, TCP transitions)

### Property-Based Tests
- Randomized (config, packet sequence, timing) → all invariants must hold
- Generators: packet fields, ACL permutations, temporal schedules
- Oracle: invariant preservation (not output matching)

### Regression Tests
- Captured failure traces replayed after fixes
- CI integration: all tests pass before merge

### Coverage Criteria
- 100% TCP states visited
- 100% legal transitions exercised
- 100% drop reasons triggered
- No new failures after N fuzzing iterations

---

## Bug vs Misconfiguration Classification

| Signal | Bug | Misconfiguration |
|--------|-----|------------------|
| Same input → random output | ✅ | ❌ |
| Affects all flows | ✅ | ❌ |
| Affects specific CIDR/port | ❌ | ✅ |
| Appears under load only | ✅ (resource bug) | ❌ |
| Crash / memory corruption | ✅ | ❌ |
| Rule hit count = 0 | ❌ | ✅ |

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Core stack (ironstack) | C |
| CLI / Apps (ironctl, ironapps) | C++ |
| Build system | CMake |
| Debugging | gdb, AddressSanitizer, Valgrind |
| Platform | WSL Ubuntu |
| Version control | Git |

---

## Key Design Principles

1. **Correctness before performance** — research-grade, not RFC-perfect
2. **Observability is mandatory** — every drop, every state change is logged
3. **Invariants are contracts** — violations abort immediately
4. **Separation of concerns** — control plane vs data plane, clearly separated
5. **Misconfiguration is a research signal** — not hidden, but measured

---

## Summary Timeline

| Phase | Component | Duration |
|-------|-----------|----------|
| 1 | Foundation & Build | Week 1–2 |
| 2 | Virtual NIC & L2 | Week 3–4 |
| 3 | L3 IP & Routing | Week 5–7 |
| 4 | ACL & PBR | Week 8–9 |
| 5 | UDP & TCP | Week 10–14 |
| 6 | IPsec (simulated) | Week 15–16 |
| 7 | ironctl (CLI) | Week 17–18 |
| 8 | ironmon (telemetry) | Week 19–20 |
| 9 | ironapps (targets) | Week 21–22 |
| 10 | ironfuzz / ironprobe / ironload | Week 23–28 |
| 11 | ironsim (emulator) | Week 29–30 |
| 12 | irontrace (capture/replay) | Week 31–32 |

**Total estimated duration: ~8 months (part-time development)**

---

## Next Steps

1. Set up WSL Ubuntu development environment
2. Create Git repository with initial CMake skeleton
3. Implement `common/` utilities and IRON_ASSERT framework
4. Begin Phase 2: TUN/TAP integration and L2 parsing

---

## Software Architecture Diagram

### System Context Diagram

```
+===========================================================================+
|                          Developer Workstation                             |
|                                                                           |
|  +---------------------------------------------------------------------+  |
|  |                        WSL Ubuntu Environment                        |  |
|  |                                                                      |  |
|  |  +---------------------------------------------------------------+  |  |
|  |  |                      IronNet Platform                          |  |  |
|  |  |                                                                |  |  |
|  |  |   +-----------+    +-----------+    +-----------+              |  |  |
|  |  |   | ironprobe |    | ironfuzz  |    | ironload  |              |  |  |
|  |  |   | (scanner) |    | (fuzzer)  |    | (stress)  |              |  |  |
|  |  |   +-----+-----+    +-----+-----+    +-----+-----+             |  |  |
|  |  |         |                 |                 |                   |  |  |
|  |  |         +--------+--------+---------+-------+                  |  |  |
|  |  |                  |  Packet Injection |                         |  |  |
|  |  |                  v                   v                         |  |  |
|  |  |   +---------------------------------------------------+       |  |  |
|  |  |   |              ironapps (Target Apps)                |       |  |  |
|  |  |   |  Echo | KV Store | Binary RPC | HTTP-like          |       |  |  |
|  |  |   +-------------------------+-------------------------+       |  |  |
|  |  |                             |                                  |  |  |
|  |  |                      Socket-like API                           |  |  |
|  |  |                             |                                  |  |  |
|  |  |   +-------------------------v-------------------------+       |  |  |
|  |  |   |               ironstack (Protocol Stack)           |       |  |  |
|  |  |   |                                                    |       |  |  |
|  |  |   |  +------+  +------+  +------+  +--------+         |       |  |  |
|  |  |   |  |  L4  |  |  L3  |  |  L2  |  |Security|         |       |  |  |
|  |  |   |  | TCP  |  |  IP  |  | Eth  |  | IPsec  |         |       |  |  |
|  |  |   |  | UDP  |  | ICMP |  |      |  |        |         |       |  |  |
|  |  |   |  +------+  | ACL  |  +------+  +--------+         |       |  |  |
|  |  |   |            | PBR  |                                |       |  |  |
|  |  |   |            | FIB  |                                |       |  |  |
|  |  |   |            +------+                                |       |  |  |
|  |  |   +-------------------------+-------------------------+       |  |  |
|  |  |                             |                                  |  |  |
|  |  |   +-------------------------v-------------------------+       |  |  |
|  |  |   |         Virtual NIC (TUN/TAP Abstraction)          |       |  |  |
|  |  |   +---------------------------------------------------+       |  |  |
|  |  |                                                                |  |  |
|  |  |   +------------------+  +------------------+                   |  |  |
|  |  |   |    ironctl       |  |    ironmon       |                   |  |  |
|  |  |   |  (CLI/Config)    |  |  (Telemetry)     |                   |  |  |
|  |  |   +------------------+  +------------------+                   |  |  |
|  |  |                                                                |  |  |
|  |  |   +------------------+  +------------------+                   |  |  |
|  |  |   |    ironsim       |  |    irontrace     |                   |  |  |
|  |  |   |  (Emulator)      |  |  (Capture/Replay)|                   |  |  |
|  |  |   +------------------+  +------------------+                   |  |  |
|  |  |                                                                |  |  |
|  |  +---------------------------------------------------------------+  |  |
|  |                                                                      |  |
|  +---------------------------------------------------------------------+  |
|                                                                           |
+===========================================================================+
```

---

### Component Architecture (Internal Module Relationships)

```
                        +-------------------+
                        |     ironctl       |
                        |  CLI / Config API |
                        +--------+----------+
                                 |
                          Config Commands
                                 |
                                 v
+----------------+     +--------+----------+     +----------------+
|   ironmon      |<----|   Config Manager   |---->|   Event Log    |
| (Metrics API)  |     | (In-Memory DB)    |     | (Trace Output) |
+-------+--------+     +--------+----------+     +----------------+
        ^                        |
        |                 Event Dispatch
        |                        |
        |                        v
        |         +==================================+
        |         |        ironstack Core            |
        |         +==================================+
        |         |                                  |
        |         |  +----------------------------+  |
        |         |  |     Application Dispatch   |  |
        |         |  +-------------+--------------+  |
        |         |                |                  |
        |         |  +-------------v--------------+  |
        |         |  |     L4 Transport Layer     |  |
        |         |  |  +-------+    +--------+   |  |
        +---------|--|--| TCP   |    |  UDP   |   |  |
        |         |  |  | State |    | Simple |   |  |
        |         |  |  | Engine|    | Demux  |   |  |
        |         |  |  +---+---+    +----+---+   |  |
        |         |  +------|--------------+------+  |
        |         |         v              |         |
        |         |  +------+----+---------v------+  |
        |         |  |     L3 Network Layer       |  |
        |         |  |                            |  |
        |         |  |  +---------+  +---------+  |  |
        +---------|--|--| IP Core |  | IPsec   |  |  |
        |         |  |  | Parse   |  | Policy  |  |  |
        |         |  |  | Validate|  | SA Mgmt |  |  |
        |         |  |  +----+----+  +----+----+  |  |
        |         |  |       |             |      |  |
        |         |  |       v             v      |  |
        |         |  |  +----+----+  +----+----+  |  |
        +---------|--|--| ACL     |  | ICMP    |  |  |
                  |  |  | Engine  |  | Handler |  |  |
                  |  |  +----+----+  +---------+  |  |
                  |  |       |                    |  |
                  |  |       v                    |  |
                  |  |  +----+----+               |  |
                  |  |  | PBR     |               |  |
                  |  |  | Engine  |               |  |
                  |  |  +----+----+               |  |
                  |  |       |                    |  |
                  |  |       v                    |  |
                  |  |  +----+----+               |  |
                  |  |  | FIB     |               |  |
                  |  |  | Routing |               |  |
                  |  |  +----+----+               |  |
                  |  +-------+--------------------+  |
                  |          |                       |
                  |  +-------v--------------------+  |
                  |  |     L2 Link Layer          |  |
                  |  |  Frame Parse / Dispatch    |  |
                  |  +-------------+--------------+  |
                  +================|=================+
                                   |
                  +----------------v-----------------+
                  |     Virtual NIC Abstraction      |
                  |  TUN/TAP | Raw Socket | SHM Ring |
                  +---------+-----------+-----------+
                            |           |
                       +----v---+  +----v---+
                       | veth0  |  | veth1  |
                       +--------+  +--------+
```

---

### Data Plane Packet Processing Pipeline

```
                    Ingress                              Egress
                      |                                    ^
                      v                                    |
+---------------------+------------------------------------+-------------------+
|                                                                              |
|  +----------+    +----------+    +-------+    +-------+    +----------+      |
|  |  L2 RX   |--->| IP Valid |--->|  ACL  |--->|  PBR  |--->| FIB      |      |
|  |  Parse   |    | Checksum |    | Check |    | Check |    | Lookup   |      |
|  |  Dispatch|    | TTL      |    |       |    |       |    |          |      |
|  +----------+    +-----+----+    +---+---+    +---+---+    +----+-----+      |
|                        |             |             |             |            |
|                        v             v             v             v            |
|                   +----+----+   +----+----+   +----+----+   +---+-----+      |
|                   |  DROP   |   |  DROP   |   |  DROP   |   | FORWARD |      |
|                   | Invalid |   | ACL Deny|   | PBR Loop|   | or LOCAL|      |
|                   +---------+   +---------+   +---------+   +----+----+      |
|                                                                  |           |
|                                                                  v           |
|                                                         +--------+--------+  |
|                                                         | IPsec Policy    |  |
|                                                         | (encrypt/pass)  |  |
|                                                         +--------+--------+  |
|                                                                  |           |
|                                                    +-------------+------+    |
|                                                    |                    |    |
|                                                    v                    v    |
|                                             +------+-----+     +-------+-+  |
|                                             | Local      |     | L2 TX   |  |
|                                             | Deliver    |     | Forward |  |
|                                             | (L4 Demux) |     +---------+  |
|                                             +------+-----+                   |
|                                                    |                         |
|                                          +---------+---------+               |
|                                          |                   |               |
|                                          v                   v               |
|                                    +-----+-----+      +-----+-----+         |
|                                    |    TCP    |      |    UDP    |         |
|                                    | State Eng |      |   Demux   |         |
|                                    +-----+-----+      +-----+-----+         |
|                                          |                   |               |
|                                          v                   v               |
|                                    +-----+-------------------+-----+         |
|                                    |     Application Dispatch      |         |
|                                    +-------------------------------+         |
|                                                                              |
+------------------------------[ ironstack ]-----------------------------------+

Legend:
  ---> = Packet flow (success path)
  DROP = Packet discarded with reason code + counter increment
```

---

### Security Testing Framework Architecture

```
+===========================================================================+
|                    Security Testing Framework                              |
+===========================================================================+
|                                                                           |
|  +---------------------------+                                            |
|  |       ironprobe           |                                            |
|  |  (Network Scanner)        |                                            |
|  |                           |                                            |
|  |  - Port scan              |                                            |
|  |  - ICMP probe             |         +-----------------------------+    |
|  |  - Service fingerprint    |-------->|                             |    |
|  |  - ACL validation         |         |                             |    |
|  +---------------------------+         |                             |    |
|                                        |      ironstack              |    |
|  +---------------------------+         |      (Target Under Test)    |    |
|  |       ironfuzz            |         |                             |    |
|  |  (Protocol Fuzzer)        |         |         +                   |    |
|  |                           |         |         |                   |    |
|  |  +--------+  +--------+  |         |    ironapps                 |    |
|  |  | Corpus |->| Mutator|  |-------->|    (Target Apps)            |    |
|  |  | Manager|  | Engine |  |         |                             |    |
|  |  +--------+  +--------+  |         +----+------------------------+    |
|  |  +--------+  +--------+  |              |                              |
|  |  |Injector|  |Coverage|  |              | Metrics / Crashes            |
|  |  |        |  |Tracker |  |              |                              |
|  |  +--------+  +--------+  |              v                              |
|  +---------------------------+    +--------+------------------------+     |
|                                   |       ironmon                   |     |
|  +---------------------------+    |  (Telemetry & Crash Monitor)    |     |
|  |       ironload            |    |                                 |     |
|  |  (Stress Tester)          |    |  - Assertion failure capture    |     |
|  |                           |    |  - ASAN report collection       |     |
|  |  - SYN pressure           |    |  - Drop reason analysis        |     |
|  |  - FIB overload           |--->|  - State table monitoring       |     |
|  |  - ACL complexity         |    |  - Latency tracking             |     |
|  |  - Connection exhaustion  |    +--------+------------------------+     |
|  +---------------------------+             |                              |
|                                            v                              |
|                                   +--------+------------------------+     |
|                                   |       irontrace                 |     |
|                                   |  (Capture & Replay)             |     |
|                                   |                                 |     |
|                                   |  - Record failure packets       |     |
|                                   |  - Replay for regression        |     |
|                                   |  - Diff before/after fix        |     |
|                                   +---------------------------------+     |
|                                                                           |
+===========================================================================+
```

---

## Deployment Diagram

### Single-Node Development Deployment

```
+===========================================================================+
|                     Windows Host Machine                                   |
|                                                                           |
|  +-------------------------------------------------------------------+   |
|  |                    WSL 2 (Ubuntu 22.04+)                           |   |
|  |                                                                    |   |
|  |  +-------------------------------------------------------------+  |   |
|  |  |                  IronNet Runtime                              |  |   |
|  |  |                                                              |  |   |
|  |  |  Process 1: ironstack + ironapps                             |  |   |
|  |  |  +---------------------------------------------------------+ |  |   |
|  |  |  | ironstack daemon                                         | |  |   |
|  |  |  |   - L2/L3/L4 packet processing                          | |  |   |
|  |  |  |   - ACL/PBR/IPsec engines                                | |  |   |
|  |  |  |   - TCP connection table                                 | |  |   |
|  |  |  |   - Embedded ironapps (echo, KV, RPC, HTTP)              | |  |   |
|  |  |  +---------------------------------------------------------+ |  |   |
|  |  |       |              ^              ^                         |  |   |
|  |  |       | TUN/TAP      | Unix Socket  | Shared Memory          |  |   |
|  |  |       v              |              |                         |  |   |
|  |  |  +----+----+    +----+----+    +----+----+                    |  |   |
|  |  |  | tun0    |    | ironctl |    | ironmon |                    |  |   |
|  |  |  | (vNIC)  |    | (CLI)   |    | (Stats) |                    |  |   |
|  |  |  +---------+    +---------+    +---------+                    |  |   |
|  |  |                                                              |  |   |
|  |  |  Process 2: Security Testing (on-demand)                     |  |   |
|  |  |  +---------------------------------------------------------+ |  |   |
|  |  |  | ironfuzz | ironprobe | ironload                          | |  |   |
|  |  |  |   - Injects packets via TUN/TAP or raw injection API     | |  |   |
|  |  |  |   - Monitors ironmon for crash/metric signals            | |  |   |
|  |  |  +---------------------------------------------------------+ |  |   |
|  |  |                                                              |  |   |
|  |  +-------------------------------------------------------------+  |   |
|  |                                                                    |   |
|  |  Build Tools:                                                      |   |
|  |    - CMake 3.20+                                                   |   |
|  |    - GCC 12+ / Clang 15+                                           |   |
|  |    - GDB, Valgrind, AddressSanitizer                               |   |
|  |                                                                    |   |
|  |  Storage:                                                          |   |
|  |    - ~/ironnet/          (source code)                             |   |
|  |    - ~/ironnet/build/    (build artifacts)                         |   |
|  |    - ~/ironnet/traces/   (packet captures)                         |   |
|  |    - ~/ironnet/corpus/   (fuzz seeds & crashes)                    |   |
|  |                                                                    |   |
|  +-------------------------------------------------------------------+   |
|                                                                           |
|  IDE: VS Code + Remote WSL Extension                                      |
|                                                                           |
+===========================================================================+
```

---

### Multi-Node Emulation Deployment (ironsim)

```
+===========================================================================+
|                     WSL 2 Ubuntu — ironsim Topology                        |
+===========================================================================+
|                                                                           |
|  ironsim orchestrator                                                     |
|  +-------------------------------------------------------------------+   |
|  |  Topology: 3-node linear network                                   |   |
|  |                                                                    |   |
|  |  +-------------+       +-------------+       +-------------+      |   |
|  |  |   Node A    |       |   Node B    |       |   Node C    |      |   |
|  |  |  (Client)   |       |  (Router)   |       |  (Server)   |      |   |
|  |  |-------------|       |-------------|       |-------------|      |   |
|  |  | ironstack   |       | ironstack   |       | ironstack   |      |   |
|  |  | 10.0.1.1/24 |       | 10.0.1.254  |       | 10.0.2.1/24 |      |   |
|  |  |             |       | 10.0.2.254  |       |             |      |   |
|  |  | ironapps:   |       |             |       | ironapps:   |      |   |
|  |  |  (client)   |       | ACL + PBR   |       |  KV Server  |      |   |
|  |  +------+------+       | FIB routing |       |  Echo Svc   |      |   |
|  |         |              +------+------+       +------+------+      |   |
|  |         |                     |                     |             |   |
|  |         |    Virtual Link 1   |   Virtual Link 2    |             |   |
|  |         +---------------------+---------------------+             |   |
|  |              (configurable)         (configurable)                 |   |
|  |              delay: 5ms             delay: 10ms                    |   |
|  |              loss: 0.1%             loss: 0.5%                     |   |
|  |              reorder: off           reorder: on                    |   |
|  |                                                                    |   |
|  +-------------------------------------------------------------------+   |
|                                                                           |
|  Security Testing Against Topology:                                       |
|  +-------------------------------------------------------------------+   |
|  |                                                                    |   |
|  |  ironprobe ──> scans Node C through Node B                         |   |
|  |                (validates ACL enforcement on router)                |   |
|  |                                                                    |   |
|  |  ironfuzz  ──> injects malformed packets at Node A                 |   |
|  |                (observes crash/drop behavior at all nodes)          |   |
|  |                                                                    |   |
|  |  ironload  ──> floods Node B with connections                      |   |
|  |                (measures routing degradation under stress)          |   |
|  |                                                                    |   |
|  +-------------------------------------------------------------------+   |
|                                                                           |
+===========================================================================+
```

---

### Process Communication Model

```
+-----------------------------------------------------------------------+
|                     Inter-Process Communication                         |
+-----------------------------------------------------------------------+

  +----------+         +-------------------+         +-----------+
  | ironctl  |--Unix-->| ironstack daemon  |--SHM--->| ironmon   |
  | (CLI)    | Socket  | (main process)    | Ring    | (metrics) |
  +----------+         +---+----------+----+         +-----------+
                            |          |
                       TUN/TAP    Raw Inject API
                            |          |
              +-------------+          +-------------+
              |                                      |
              v                                      v
  +-----------+----------+            +--------------+-----------+
  | OS Kernel (TUN/TAP)  |            | ironfuzz / ironprobe     |
  | Virtual Interface    |            | (direct packet injection)|
  +----------------------+            +--------------------------+


  Communication Mechanisms:
  ┌──────────────────────────────────────────────────────────────┐
  │ Channel              │ Purpose              │ Mechanism       │
  ├──────────────────────┼──────────────────────┼─────────────────┤
  │ ironctl → ironstack  │ Config commands       │ Unix socket     │
  │ ironmon ← ironstack  │ Metrics export        │ Shared memory   │
  │ ironfuzz → ironstack │ Packet injection      │ Raw API / TUN   │
  │ irontrace ← stack   │ Packet capture        │ Hook callbacks  │
  │ ironsim nodes        │ Inter-node traffic    │ Socketpair/pipe │
  └──────────────────────┴──────────────────────┴─────────────────┘
```

---

### Build & CI Pipeline

```
+-----------------------------------------------------------------------+
|                        Build & Test Pipeline                            |
+-----------------------------------------------------------------------+

  Source Code (Git)
       |
       v
  +----+----+
  | CMake   |
  | Config  |
  +----+----+
       |
       +------------------+------------------+
       |                  |                  |
       v                  v                  v
  +----+----+       +-----+-----+      +----+----+
  | Debug   |       | Release   |      | Fuzz    |
  | Build   |       | Build     |      | Build   |
  | (ASAN)  |       | (-O2)     |      | (AFL++) |
  +----+----+       +-----+-----+      +----+----+
       |                  |                  |
       v                  v                  v
  +----+----+       +-----+-----+      +----+----+
  | Unit    |       | Perf      |      | Fuzz    |
  | Tests   |       | Bench     |      | Campaign|
  +----+----+       +-----+-----+      +----+----+
       |                  |                  |
       +------------------+------------------+
                          |
                          v
                   +------+------+
                   | Regression  |
                   | Test Suite  |
                   | (irontrace) |
                   +------+------+
                          |
                          v
                   +------+------+
                   |   PASS /    |
                   |   FAIL      |
                   +-------------+
```

---

### File System Layout (Deployed)

```
IronNet/
├── ideas.md                      # Project vision & design
├── study.md                      # Implementation plan & architecture
├── build.md                      # Build & test instructions
├── todo.md                       # Task tracking
│
├── src/                          # All source code
│   ├── CMakeLists.txt
│   ├── common/                   # Shared utilities
│   ├── ironstack/                # Core protocol stack
│   ├── ironctl/                  # CLI / configuration
│   ├── ironmon/                  # Telemetry & metrics
│   ├── ironapps/                 # Target applications
│   ├── ironfuzz/                 # Fuzzing framework
│   │   └── corpus/              # Fuzz seeds & crashes
│   ├── ironprobe/                # Network scanner
│   ├── ironload/                 # Stress tester
│   ├── ironsim/                  # Network emulator
│   ├── irontrace/                # Packet capture/replay
│   └── tests/                    # Test infrastructure
│       ├── unit/                 # Per-module unit tests
│       ├── regression/           # Replay-based regression
│       └── stress/               # Load test scripts
│
└── build/                        # Build output (out-of-source, generated)
    ├── ironstack/                # ironstack binary
    ├── tests/                    # Test binaries
    └── common/                   # libiron_common.a
```
