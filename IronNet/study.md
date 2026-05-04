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
       └── tests/           # Test infrastructure
           ├── unit/        # Fast correctness checks
           └── module/      # Verbose integration tests
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
   - Unit test: parse valid/invalid frames (`test_eth`)
   - Module test: visible frame building, parsing, hex dump, ASCII payload (`test_l2_module`)
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
   - Unit test: routing add/delete/lookup/longest-prefix match (`test_route`)
   - Module test: IP forwarding with TTL decrement, TTL expiry drop, ICMP echo request→reply (`test_l3_module`)
   - Invalid IP header → drop with reason code and counter

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
   IP Validation → PBR Lookup → ACL Check → FIB Lookup (fallback) → Forward/Drop
   ```

4. **Invariants**
   - PBR has highest routing priority (evaluated before FIB)
   - ACL is applied on the output path (after routing decision)
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

## Phase 7: Virtual Router (Week 17–18)

### Goals
- Wire all data plane modules into a working router with real TAP interfaces
- Implement ARP for MAC address resolution
- Implement IP fragmentation and reassembly
- Implement interface-to-IP binding (not just a global IP list)
- Create a startup configuration file parser
- Route packets between interfaces end-to-end on WSL

### Tasks

1. **Interface configuration model**
   - Bind IP address + prefix to a specific interface
   - Each interface has: name, MAC, IP/prefix, link state (up/down)
   - Replace global ip_add_local_addr() with per-interface IP binding

2. **ARP (Address Resolution Protocol)**
   - ARP request/reply handling (who-has / is-at)
   - ARP table: IP → MAC mapping with timeout
   - Proxy ARP (optional)
   - ARP used to resolve next-hop MAC before L2 TX (replaces broadcast MAC hack)

3. **IP fragmentation and reassembly**
   - Fragment outbound packets exceeding interface MTU
   - Reassemble inbound fragments before L4 delivery
   - Fragment timeout (drop incomplete reassembly after N seconds)
   - Security: reject overlapping fragments, enforce minimum fragment size

4. **Startup config file parser (router.conf)**
   - Parse interface definitions, routes, ACLs, PBR rules at startup
   - Simple line-based format

5. **End-to-end packet flow with real TAP devices**
   - Create TAP interfaces at startup (requires sudo)
   - Pipeline reads from all interfaces, forwards between them
   - Packets arriving on iron0 destined for 10.0.2.x are forwarded out iron1

6. **IPsec integration into forwarding path**
   - Call ipsec_outbound() before L2 TX on forward
   - Call ipsec_inbound() on local delivery

7. **Validation**
   - ARP resolution: send packet, verify ARP request sent, inject ARP reply, verify forwarding
   - Fragmentation: send oversized packet, verify fragments on output
   - Reassembly: inject fragments, verify reassembled packet delivered to L4
   - Start router with config file, ping between two TAP interfaces from WSL
   - Verify ACL blocks SSH (port 22) but permits HTTP (port 80)
   - Module test: end-to-end packet routing through the virtual router

---

## Phase 8: VLAN, Bridge, NAT & Connection Tracking (Week 19–21)

This phase is split into 5 sub-phases due to its scope.

### Phase 8a: VLAN (802.1Q) (Week 19)

#### Goals
- Implement 802.1Q VLAN tagging and trunk/access port modes

#### Tasks

1. **VLAN tag parsing and insertion**
   - Parse 4-byte VLAN tag (TPID 0x8100 + TCI) in Ethernet frames
   - Insert tag on egress (access port → trunk port)
   - Strip tag on ingress (trunk port → access port)

2. **Port modes**
   - Access port: untagged, belongs to single VLAN
   - Trunk port: tagged, carries multiple VLANs
   - Per-port VLAN membership configuration

3. **VLAN-aware dispatch**
   - L2 dispatch considers VLAN ID
   - Frames only forwarded within same VLAN

4. **Validation**
   - Module test: VLAN tag visible in hex dump (insert/strip)
   - Access port drops tagged frames from wrong VLAN
   - Trunk port carries multiple VLANs

---

### Phase 8b: Bridge (L2 Forwarding) (Week 19–20)

#### Goals
- Build a software bridge for L2 forwarding within a VLAN

#### Tasks

1. **MAC address learning table**
   - Learn: src MAC → ingress port mapping
   - Aging: entries expire after timeout (300s)
   - Max entries limit

2. **Forwarding decisions**
   - Known unicast: forward to learned port
   - Unknown unicast: flood to all ports in same VLAN
   - Broadcast: flood to all ports in same VLAN

3. **Loop detection**
   - Simplified STP or TTL-based loop prevention
   - Per-bridge statistics (learned, flooded, dropped)

4. **Validation**
   - Module test: MAC learning and unicast forwarding
   - Unknown destination → flood
   - VLAN isolation: bridge does not forward across VLANs

---

### Phase 8c: Multiple Routing Tables (Week 20)

#### Goals
- Support multiple independent FIBs (VRF-lite)
- PBR can select which routing table to use

#### Tasks

1. **Named routing tables**
   - Table registry: "main", "mgmt", custom names
   - Each table has independent FIB with longest-prefix match
   - Default table ("main") used when no PBR match

2. **PBR integration**
   - PBR action extended: `next_hop` + `out_iface` + `table_id`
   - PBR can redirect to a different routing table instead of (or in addition to) a next-hop

3. **Config file support**
   ```
   table mgmt
   route 192.168.0.0/16 via 10.0.1.254 table mgmt
   pbr match src 10.0.99.0/24 table mgmt
   ```

4. **Validation**
   - Module test: same destination, different source → different routing table → different next-hop
   - Default table fallback when no PBR match

---

### Phase 8d: Connection Tracking (Week 20–21)

#### Goals
- Track all connections with state for stateful filtering
- Enable "permit established" ACL rules

#### Tasks

1. **Connection tracking table (conntrack)**
   - Track by 5-tuple: src_ip, dst_ip, protocol, src_port, dst_port
   - States: NEW, ESTABLISHED, RELATED, INVALID
   - Bidirectional: original + reply direction

2. **State transitions**
   - TCP: SYN=NEW, SYN+ACK=ESTABLISHED, FIN=closing
   - UDP: first packet=NEW, reply=ESTABLISHED
   - ICMP: request=NEW, reply=RELATED

3. **Timeouts per protocol**
   - TCP established: 300s
   - TCP other: 60s
   - UDP: 30s
   - ICMP: 10s

4. **Stateful ACL integration**
   - New ACL match: `state established` or `state new`
   - "permit established" allows return traffic without explicit rule

5. **Validation**
   - Module test: outbound SYN creates NEW entry, reply makes it ESTABLISHED
   - Stateful ACL permits return traffic
   - Timeout expiry removes entries

---

### Phase 8e: NAT (Network Address Translation) (Week 21)

#### Goals
- Implement SNAT and DNAT
- Use connection tracking for return-path translation

#### Tasks

1. **SNAT (Source NAT / Masquerade)**
   - Rewrite source IP + port for outbound traffic
   - Port allocation pool (e.g., 10000–65000)
   - Applied after routing decision (post-routing)

2. **DNAT (Destination NAT / Port forwarding)**
   - Rewrite destination IP + port for inbound traffic
   - Applied before routing decision (pre-routing)

3. **NAT table**
   - Maps original 5-tuple → translated 5-tuple
   - Linked to conntrack entries
   - Return traffic automatically reverse-translated

4. **Config file support**
   ```
   nat snat src 10.0.1.0/24 to 203.0.113.1 pool 10000-65000
   nat dnat dst 203.0.113.1 port 80 to 10.0.1.100 port 8080
   ```

5. **Validation**
   - Module test: outbound packet gets SNAT applied, reply gets reverse-translated
   - DNAT: external traffic to public IP reaches internal server
   - Port allocation does not collide

---

### Phase 8 Sub-phase Summary

| Sub-phase | Component | Week | Dependencies |
|-----------|-----------|------|--------------|
| 8a | VLAN (802.1Q) | Week 19 | Tag parse/insert, access/trunk ports |
| 8b | Bridge (L2 forwarding) | Week 19–20 | MAC learning, flooding, loop detection (needs 8a) |
| 8c | Multiple Routing Tables | Week 20 | Named FIBs, PBR table selection (independent) |
| 8d | Connection Tracking | Week 20–21 | Conntrack states, stateful ACL (needed by 8e) |
| 8e | NAT | Week 21 | SNAT/DNAT, port pool, return-path (needs 8d) |

---

## Phase 9: Control Plane — ironctl (Week 21–22)

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

## Phase 10: Telemetry & Audit Logging — ironmon (Week 23–24)

### Goals
- Real-time metrics export
- Per-layer counters, drop reasons, state table utilization
- Security audit trail for penetration testing analysis

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
   DROP_IPSEC_NO_SA, DROP_TTL_EXPIRED,
   DROP_NAT_NO_POOL, DROP_CONNTRACK_INVALID,
   DROP_FRAGMENT_OVERLAP, DROP_ARP_INSPECTION
   ```

3. **Security audit log**
   - Log all security-relevant events with timestamp, src/dst, action, reason
   - Events: ACL deny, IPsec drop, invalid flags, connection table full, ARP anomaly
   - Structured format (parseable for automated analysis)
   - Configurable verbosity (summary vs detailed)
   - Supports post-incident forensic analysis

4. **Export interface**
   - CLI: `show stats`, `show audit-log`
   - Structured output (JSON or plain text) for scripting
   - File export for offline analysis

---

## Phase 11: Target Applications — ironapps (Week 25–26)

### Goals
- Build simple applications as attack targets
- Stateful, input-parsing, resource-consuming

### Tasks

1. **Echo server** — basic connectivity validation
2. **Key-Value TCP server** — stateful, memory-consuming
3. **Custom binary RPC** — complex parsing (ideal fuzz target)
4. **Simple HTTP-like service** — text protocol parsing
5. **DNS server (simplified)** — UDP-based name resolution
   - Responds to A record queries from a static zone file
   - Attack surface: DNS amplification, spoofing, cache poisoning study
   - Common penetration testing entry point

All apps register with ironstack via a socket-like API and run on top of the custom TCP/UDP.

### Scope note

Dynamic routing protocols (OSPF, BGP) are **out of scope** for IronNet. The project uses static routing only. Dynamic routing may be added as a future extension if needed.

---

## Phase 12: Security Testing — ironfuzz, ironprobe, ironload (Week 27–32)

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

## Phase 13: Attack Simulation & Defense (Week 33–36)

### Goals
- Simulate specific network attack techniques against the protocol stack
- Implement defense mechanisms and study their effectiveness
- Provide a structured penetration testing workflow

### Tasks

1. **Attack simulation tools (ironattack)**
   - SYN flood: overwhelm TCP connection table
   - ARP spoofing: inject fake ARP replies to poison MAC tables
   - VLAN hopping: craft double-tagged frames to escape VLAN isolation
   - IP spoofing: forge source IP to bypass ACLs
   - TCP RST injection: disrupt established connections
   - ICMP redirect: manipulate routing via crafted ICMP messages
   - Slowloris-style: hold connections open to exhaust resources
   - Fragmentation attacks: overlapping fragments, tiny fragments

2. **Defense mechanisms (irondefense)**
   - SYN cookies: stateless SYN handling under flood
   - Rate limiting: per-source connection rate caps
   - Connection tracking: stateful inspection for return traffic
   - Anomaly detection: flag unusual packet patterns (invalid flags, unusual sizes)
   - Blackhole routing: drop traffic to known-bad destinations
   - ARP inspection: validate ARP against known IP-MAC bindings
   - VLAN access control: strict trunk/access enforcement

3. **Penetration testing workflow**
   - Reconnaissance: ironprobe scans to discover services and ACL gaps
   - Enumeration: identify open ports, protocol versions, OS fingerprints
   - Exploitation: use ironattack to test specific vulnerabilities
   - Post-exploitation: verify what access was gained, lateral movement
   - Reporting: automated test results with pass/fail per defense

4. **Attack-defense matrix**
   - Map each attack to its corresponding defense
   - Measure: does the defense detect? mitigate? log?
   - Study: what happens when defense is misconfigured?

5. **Validation**
   - SYN flood with/without SYN cookies: measure connection table behavior
   - VLAN hopping attempt with/without strict trunk mode
   - ARP spoofing with/without ARP inspection
   - TCP RST injection with/without connection tracking
   - Full penetration test report generated automatically

---

## Phase 14: Network Emulator — ironsim (Week 37–38)

### Goals
- Run multiple ironstack instances as network nodes
- Simulate topologies with configurable link properties

### Tasks

1. **Node management** — spawn multiple stack instances
2. **Virtual links** — configurable delay, drop rate, reorder
3. **Topology definition** — scripted multi-node setups
4. **Traffic generation** — automated flows between nodes

---

## Phase 15: Packet Tools — irontrace (Week 39–40)

### Goals
- Capture packets at any pipeline stage
- Replay captured traces for regression testing

### Tasks

1. **Capture** — hook at L2/L3/L4 boundaries, write to file
2. **Replay** — read capture file, inject into stack
3. **Regression workflow** — capture failure → fix → replay → verify

---

## Testing Strategy

### Unit Tests (`src/tests/unit/`)
- Fast, minimal-output correctness checks
- Per-module validation (stats, routing lookup, ACL evaluation, TCP transitions)
- Output: simple PASS/FAIL per assertion
- Example: `test_stats.c`, `test_eth.c`

### Module Tests (`src/tests/module/`)
- Integration tests with visible, verbose output
- Builds real packets, parses them, and displays hex dumps + decoded fields
- Uses `module_test.h` framework for test registration, execution, and reporting
- Output: formatted test suite report with hex dumps, ASCII payloads, decoded protocol fields
- Example: `test_l2_module.c` (3 test cases: text payload, IPv4+TCP SYN, invalid frames)

### Property-Based Tests
- Randomized (config, packet sequence, timing) → all invariants must hold
- Generators: packet fields, ACL permutations, temporal schedules
- Oracle: invariant preservation (not output matching)

### Regression Tests (`src/tests/regression/`)
- Captured failure traces replayed after fixes
- CI integration: all tests pass before merge

### Stress Tests (`src/tests/stress/`)
- Load and resource exhaustion scenarios
- Metrics: drop patterns, latency escalation, degradation behavior

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
| 7 | Virtual Router (end-to-end) | Week 17–18 |
| 8 | VLAN, Bridge, NAT & Connection Tracking | Week 19–21 |
| 9 | ironctl (CLI) | Week 21–22 |
| 10 | ironmon (telemetry) | Week 23–24 |
| 11 | ironapps (targets) | Week 25–26 |
| 12 | ironfuzz / ironprobe / ironload | Week 27–32 |
| 13 | Attack Simulation & Defense | Week 33–36 |
| 14 | ironsim (emulator) | Week 37–38 |
| 15 | irontrace (capture/replay) | Week 39–40 |

**Total estimated duration: ~10 months (part-time development)**

---

## Next Steps

1. ~~Set up WSL Ubuntu development environment~~ ✅
2. ~~Create Git repository with initial CMake skeleton~~ ✅
3. ~~Implement `common/` utilities and IRON_ASSERT framework~~ ✅
4. ~~Phase 2: TUN/TAP integration and L2 parsing~~ ✅
5. ~~Phase 3: L3 IP layer, routing table, ICMP~~ ✅
6. ~~Phase 4: ACL & PBR engines~~ ✅
7. ~~Phase 5: L4 UDP & TCP~~ ✅
8. ~~Phase 6: IPsec (simulated)~~ ✅
9. Begin Phase 7: Virtual Router (end-to-end integration)

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
|  |  L2 RX   |--->| IP Valid |--->|  PBR  |--->|  ACL  |--->| FIB      |      |
|  |  Parse   |    | Checksum |    | Check |    | Check |    | Lookup   |      |
|  |  Dispatch|    | TTL      |    | (high)|    |(output|    | (fallback|      |
|  +----------+    +-----+----+    +---+---+    +---+---+    +----+-----+      |
|                        |             |             |             |            |
|                        v             v             v             v            |
|                   +----+----+   +----+----+   +----+----+   +---+-----+      |
|                   |  DROP   |   |  DROP   |   |  DROP   |   | FORWARD |      |
|                   | Invalid |   | PBR Loop|   | ACL Deny|   | or LOCAL|      |
|                   +---------+   +---------+   +---------+   +----+----+      |
|                                                                  |           |
|                                                                  v           |
|                                                         +--------+--------+  |
|                                                         | Conntrack +     |  |
|                                                         | NAT + IPsec    |  |
|                                                         +--------+--------+  |
|                                                                  |           |
|                                                    +-------------+------+    |
|                                                    |                    |    |
|                                                    v                    v    |
|                                             +------+-----+     +-------+-+  |
|                                             | Local      |     | ARP     |  |
|                                             | Deliver    |     | Resolve |  |
|                                             | (L4 Demux) |     | + L2 TX |  |
|                                             +------+-----+     +---------+  |
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

Pipeline order (vendor-standard):
  PBR (highest priority) → ACL (output filter) → FIB (fallback routing)

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
│       ├── unit/                 # Fast correctness checks (PASS/FAIL)
│       ├── module/               # Verbose integration tests (hex dumps, decoded fields)
│       │   └── module_test.h     # Module test framework
│       ├── regression/           # Replay-based regression
│       └── stress/               # Load test scripts
│
└── build/                        # Build output (out-of-source, generated)
    ├── ironstack/                # ironstack binary
    ├── tests/                    # Test binaries (unit + module)
    └── common/                   # libiron_common.a
```
