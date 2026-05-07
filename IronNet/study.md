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

#### Concepts

A **VLAN (Virtual LAN)** divides a physical network into multiple isolated broadcast domains. Devices in VLAN 10 cannot communicate at Layer 2 with devices in VLAN 20, even if they share the same physical switch or cable.

**802.1Q** is the IEEE standard that defines how VLAN membership is carried in Ethernet frames by inserting a 4-byte tag:

```
Normal frame:  [Dst MAC 6B][Src MAC 6B][EtherType 2B][Payload...]
Tagged frame:  [Dst MAC 6B][Src MAC 6B][TPID 2B][TCI 2B][EtherType 2B][Payload...]
```

- **TPID** = 0x8100 (identifies a VLAN-tagged frame)
- **TCI** = PCP (3 bits, priority) + DEI (1 bit) + **VID** (12 bits, VLAN ID 0–4095)

**Port modes:**
- **Access port** — connects to end devices (PCs, servers). Frames are untagged on the wire. The switch assigns a VLAN ID internally.
- **Trunk port** — connects switches together. Frames carry VLAN tags so multiple VLANs share one link.

**Why VLANs matter for security research:**
- VLAN hopping attacks (double-tagging to escape isolation)
- Misconfigured trunk ports leaking traffic between VLANs
- ACL bypass via VLAN manipulation

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

#### Concepts

A **bridge** (or Layer 2 switch) connects multiple ports and forwards Ethernet frames between them based on MAC addresses. Unlike a hub (which floods everything), a bridge **learns** which MAC addresses are reachable on which port and forwards unicast traffic only to the correct port.

**MAC learning:**
- When a frame arrives on port X with source MAC AA:BB:CC:DD:EE:FF, the bridge records: "MAC AA:BB:CC:DD:EE:FF is reachable via port X"
- This mapping is stored in the **MAC address table** (also called FDB — Forwarding Database)
- Entries age out after a timeout (typically 300 seconds) to handle devices moving between ports

**Forwarding decisions:**
- **Known unicast** — destination MAC is in the table → forward to the learned port only
- **Unknown unicast** — destination MAC not in the table → flood to all ports (except ingress)
- **Broadcast** (FF:FF:FF:FF:FF:FF) → flood to all ports (except ingress)
- **Multicast** (bit 0 of first byte = 1) → flood to all ports (except ingress)

**VLAN-aware bridging:**
- A bridge only forwards frames within the **same VLAN**
- Flooding only goes to ports that belong to the frame's VLAN
- This enforces VLAN isolation at Layer 2

**Loop prevention:**
- If two switches are connected by multiple links, frames can loop forever (broadcast storm)
- Real networks use STP (Spanning Tree Protocol) to block redundant paths
- IronNet uses simplified loop detection (TTL-based or port blocking)

**Why bridges matter for security research:**
- MAC flooding attacks (overflow the MAC table → bridge falls back to flooding → attacker sees all traffic)
- MAC spoofing (impersonate another device's MAC to intercept traffic)
- CAM table exhaustion (denial of service)

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

### Design Options

| Option | Architecture | Pros | Cons |
|--------|-------------|------|------|
| **1. Embedded CLI (chosen)** | CLI thread inside ironstack process | Simple, fast to build, easy to debug, no IPC | Single process, no remote access |
| 2. Separate process | ironctl connects to ironstack via Unix socket | Realistic (like vtysh/FRR), remote capable | Requires IPC, serialization, more complex |

**Decision:** Option 1 (Embedded CLI) — a dedicated thread reads stdin for commands while the main loop processes packets. This is sufficient for a research project and demonstrates all control plane concepts without IPC complexity.

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

### Analysis: What already exists vs what's needed

| Component | Already implemented | What's missing |
|-----------|--------------------|-----------------|
| Per-layer counters | ✅ `stats.h/c` (STAT_L2_*, STAT_L3_*, STAT_TCP_*, STAT_UDP_*) | More granular counters (per-interface, per-VLAN, per-ACL-rule) |
| Drop reasons | ✅ `drop_reason_t` enum in types.h | Not all reasons tracked in stats yet (NAT, conntrack, fragment) |
| Stats dump | ✅ `iron_stats_dump()` prints non-zero counters | No structured export (JSON), no file output |
| CLI show | ✅ `show stats` in ironctl | No `show audit-log`, no filtering |
| Logging | ✅ `log.h` with levels (DEBUG/INFO/WARN/ERROR) | Not structured for machine parsing, no audit-specific log |
| ACL deny logging | ✅ Prints at INFO level with src/dst/port | Not written to audit file |

### Design decision

| Option | Approach | Chosen? |
|--------|----------|---------|
| **1. Enhance existing stats + add audit log file** | Extend stats.h, add audit_log.c with file output | ✅ Yes |
| 2. Full monitoring daemon (separate process) | ironmon as separate process with shared memory | No (overkill for research) |

**Decision:** Enhance the existing infrastructure rather than building a separate monitoring daemon. Add:
- Per-interface and per-rule counters
- Structured audit log (file-based, one event per line)
- JSON export for stats
- `show audit-log` CLI command

### Goals
- Real-time metrics export
- Per-layer counters, drop reasons, state table utilization
- Security audit trail for penetration testing analysis

### Tasks

1. **Enhanced metrics infrastructure**
   - Per-interface counters (rx/tx/drops per iface)
   - Per-ACL-rule hit counters (already exists, expose via CLI)
   - Per-VLAN counters
   - Connection tracking stats (new/established/expired counts)
   - NAT mapping stats (active/allocated/exhausted)

2. **Drop reason taxonomy (complete)**
   ```
   DROP_ACL, DROP_NO_ROUTE, DROP_PBR_LOOP,
   DROP_TCP_INVALID_STATE, DROP_RESOURCE_LIMIT,
   DROP_IPSEC_NO_SA, DROP_TTL_EXPIRED,
   DROP_NAT_NO_POOL, DROP_CONNTRACK_INVALID,
   DROP_FRAGMENT_OVERLAP, DROP_ARP_INSPECTION,
   DROP_VLAN_MISMATCH, DROP_BRIDGE_LOOP
   ```

3. **Security audit log (`audit_log.c`)**
   - Log all security-relevant events with timestamp, src/dst, action, reason
   - Events: ACL deny, IPsec drop, invalid flags, connection table full, ARP anomaly, NAT exhaustion
   - Structured format: `timestamp|event_type|src_ip|dst_ip|proto|port|action|reason`
   - Configurable: enable/disable, verbosity (summary vs detailed)
   - File output: `/tmp/ironnet_audit.log` (configurable path)
   - Ring buffer in memory for `show audit-log` (last N events)

4. **JSON export**
   - `show stats json` — output all counters as JSON
   - `show audit-log json` — output recent events as JSON array
   - Useful for scripting and automated analysis

5. **CLI integration**
   - `show stats` — human-readable (existing)
   - `show stats json` — machine-readable
   - `show audit-log` — last N security events
   - `show audit-log json` — JSON format
   - `audit enable/disable` — toggle audit logging

6. **Validation**
   - Generate traffic that triggers ACL deny → verify audit log entry
   - Generate traffic that triggers NAT → verify stats updated
   - Export JSON → verify parseable by external tool
   - Module test: audit log captures events correctly

---

## Phase 11: Target Applications — ironapps (Week 25–28)

### Analysis: What exists vs what's needed

| Aspect | Current state | Gap |
|--------|--------------|-----|
| Socket API | TCP/UDP modules process packets but have no app-facing interface | Need `socket_listen()` / `socket_accept()` / `socket_send()` / `socket_recv()` |
| TCP response | TCP receives SYN, creates SYN_RECV, but never sends SYN+ACK back | Need TCP to generate response packets (SYN+ACK, data, FIN) |
| UDP response | UDP receives packets but cannot send replies | Need UDP send capability from application layer |
| App registration | Not implemented | Need port-to-application dispatch table |
| Data delivery | TCP tracks state but doesn't deliver payload to apps | Need callback or buffer for app to read received data |

### Key challenge

The biggest gap is that **ironstack currently has no way to send TCP/UDP responses**. The TCP state machine tracks state but doesn't generate packets. To make applications work, we need:
1. TCP output — generate SYN+ACK, ACK, data segments, FIN
2. Application socket API — apps register on ports, receive data, send responses
3. Application dispatch — when TCP/UDP delivers data, route it to the registered app

### Design: Sub-phases

This phase is split into 3 sub-phases due to its scope:

| Sub-phase | Component | Scope |
|-----------|-----------|-------|
| 11a | Socket API + TCP output | App registration, TCP generates SYN+ACK/data/FIN, socket send/recv |
| 11b | Echo server + DNS server | Simple apps that prove the API works |
| 11c | KV server + HTTP-like + Binary RPC | Complex apps as fuzz/attack targets |

### Phase 11a: Socket API + TCP Output (Week 25–26)

#### Goals
- Create application-facing socket API
- Enable TCP to generate response packets (SYN+ACK, ACK, data, FIN)
- Enable UDP to send reply packets
- Port-based application dispatch

#### Tasks

1. **Application socket API (`ironapps/socket_api.h`)**
   ```c
   int iron_socket_listen(uint8_t protocol, uint16_t port, app_callback_t callback);
   int iron_socket_send(int sock_id, const uint8_t *data, int len);
   int iron_socket_close(int sock_id);
   ```

2. **TCP output (extend `tcp.c`)**
   - Generate SYN+ACK when SYN received on a listening port
   - Generate ACK for received data
   - Generate data segments when app calls `iron_socket_send()`
   - Generate FIN when app calls `iron_socket_close()`
   - Recompute checksums for outbound segments

3. **UDP output (extend `udp.c`)**
   - `udp_send(src_ip, dst_ip, src_port, dst_port, data, len)` — build and send UDP packet

4. **Application dispatch table**
   - Register: protocol + port → callback function
   - When TCP delivers data or UDP receives packet → call registered callback
   - Max 32 registered applications

5. **Validation**
   - Module test: register echo callback on port 7, send data, verify reply
   - TCP handshake completes (SYN → SYN+ACK → ACK)
   - `nc` to port 7 actually gets a response

### Phase 11b: Echo Server + DNS Server (Week 26–27)

#### Goals
- Implement simple applications that validate the socket API

#### Tasks

1. **Echo server (TCP, port 7)**
   - Accepts connection
   - Echoes back any received data
   - Closes when client closes

2. **Echo server (UDP, port 7)**
   - Receives UDP packet
   - Sends back same payload to sender

3. **DNS server (UDP, port 53)**
   - Parses DNS query (A record only)
   - Looks up name in static zone table
   - Sends DNS response with IP address
   - Attack surface: amplification, spoofing, malformed queries

4. **Validation**
   - `nc 10.0.1.1 7` → type text → see echo
   - `dig @10.0.1.1 example.com` → get response
   - Module test: DNS query/response roundtrip

### Phase 11c: KV Server + HTTP-like + Binary RPC (Week 27–28)

#### Goals
- Build complex applications as attack/fuzz targets

#### Tasks

1. **Key-Value TCP server (port 6379)**
   - Commands: `SET key value`, `GET key`, `DEL key`
   - In-memory hash table
   - Attack surface: memory exhaustion, command injection, buffer overflow

2. **Simple HTTP-like service (port 8080)**
   - Parses `GET /path HTTP/1.0` requests
   - Returns static responses
   - Attack surface: header parsing, path traversal, oversized headers

3. **Custom binary RPC (port 9000)**
   - Fixed-size header: `[magic 4B][cmd 2B][length 2B][payload...]`
   - Commands: PING, ECHO, STATUS
   - Attack surface: length field manipulation, invalid commands, truncated packets

4. **Validation**
   - KV: `SET foo bar` then `GET foo` → returns `bar`
   - HTTP: `GET / HTTP/1.0` → returns 200 OK
   - RPC: send PING → receive PONG
   - Fuzz: malformed inputs don't crash (ASAN validates)

### Scope note

Dynamic routing protocols (OSPF, BGP) are **out of scope** for IronNet. The project uses static routing only. Dynamic routing may be added as a future extension if needed.

---

## Phase 12: Security Testing — ironfuzz, ironprobe, ironload (Week 29–34)

### Analysis: What exists vs what's needed

| Component | What exists | What's needed |
|-----------|------------|---------------|
| Target stack | ✅ Full L2-L4 stack with 5 apps running | Ready to be tested |
| Packet injection | ✅ `vnic_inject()` API exists | Can send raw frames into the stack |
| Crash detection | ✅ ASAN enabled in Debug builds | Crashes caught automatically |
| Metrics | ✅ Stats counters, audit log | Can observe effects of testing |
| Scanner | ❌ Not implemented | Need ironprobe |
| Fuzzer | ❌ Not implemented | Need ironfuzz |
| Stress tester | ❌ Not implemented | Need ironload |

### Design decision

| Option | Architecture | Chosen? |
|--------|-------------|---------|
| **A. Internal tools** | Run inside same process, inject packets directly into pipeline | ✅ Yes (fast, automated, no sudo needed) |
| B. External tools | Separate binaries sending real packets via TAP | Also supported (for realistic testing against live router) |

**Decision:** Build tools that can run both ways — internally for automated testing (module tests, CI), and externally against the live router for realistic validation.

### Relationship to Phase 13

- **Phase 12** builds **generic testing tools** (scan, fuzz, stress)
- **Phase 13** uses these tools to simulate **specific named attacks** (SYN flood, ARP spoofing, VLAN hopping) and implements **defenses** against them

### Design: Sub-phases

| Sub-phase | Component | Scope |
|-----------|-----------|-------|
| 12a | ironprobe (scanner) | Port scan, ICMP probe, service fingerprint, ACL validation |
| 12b | ironfuzz (fuzzer) | Mutation engine, corpus, packet injection, crash monitoring |
| 12c | ironload (stress tester) | SYN flood, connection exhaustion, FIB overload |

### Phase 12a: ironprobe — Network Scanner (Week 29–30)

#### Goals
- Discover open ports and services on the target stack
- Validate ACL enforcement (verify blocked ports are actually blocked)
- Fingerprint services by their responses

#### Tasks

1. **Port scanner**
   - TCP SYN scan: send SYN, check for SYN+ACK (open) or no response (filtered)
   - UDP scan: send probe, check for response (open) or ICMP unreachable (closed)
   - Scan range: configurable port range

2. **ICMP prober**
   - Ping sweep: discover live hosts
   - TTL-based traceroute: discover path

3. **Service fingerprinting**
   - Connect to open port, send probe, classify response
   - Identify: echo, DNS, KV, HTTP, RPC by response pattern

4. **ACL validation**
   - Given a set of expected-open and expected-closed ports
   - Verify ACL is correctly blocking/permitting
   - Report mismatches

5. **Validation**
   - Module test: scan ports 1-100, verify ports 7,53,6379,8080,9000 detected as open
   - ACL test: verify port 22 shows as filtered

### Phase 12b: ironfuzz — Protocol Fuzzer (Week 30–32)

#### Goals
- Automatically generate malformed packets to find crashes and bugs
- State-aware mutation (fuzz at different TCP states)
- Coverage-guided (track which code paths are exercised)

#### Tasks

1. **Corpus manager**
   - Seed packets: valid examples for each protocol (TCP SYN, HTTP GET, DNS query, RPC PING)
   - Store interesting inputs (those that trigger new coverage)
   - Crash inputs saved for reproduction

2. **Mutation engine**
   - Bit-flip: random bit changes
   - Byte-flip: random byte changes
   - Length mutation: truncate, extend, zero-length
   - Field-aware: mutate specific protocol fields (ports, flags, lengths)
   - Insertion/deletion: add or remove bytes
   - Boundary values: 0, 1, 0xFF, 0xFFFF, max values

3. **Packet injector**
   - Internal mode: call `ip_input()` or `tcp_input()` directly
   - External mode: write to TAP device
   - Rate control: configurable packets/second

4. **Crash/anomaly monitor**
   - ASAN: detects memory errors (use-after-free, buffer overflow)
   - Assertion failures: IRON_ASSERT violations
   - Metric anomalies: unexpected counter spikes
   - Timeout detection: stuck processing

5. **Coverage tracking**
   - TCP state coverage: which states were reached
   - Drop-reason coverage: which drop paths were triggered
   - Code coverage: (optional, via gcov/llvm-cov)

6. **Validation**
   - Fuzz echo server: 10000 mutations, no crashes
   - Fuzz DNS server: malformed queries, no crashes
   - Fuzz RPC server: invalid magic/length, no crashes
   - Fuzz TCP state machine: invalid flag sequences, no state corruption

### Phase 12c: ironload — Stress Tester (Week 33–34)

#### Goals
- Test resource limits and graceful degradation under load
- Measure performance boundaries

#### Tasks

1. **TCP connection pressure**
   - Send many SYNs rapidly (fill connection table)
   - Measure: how many connections before rejection?
   - Observe: does the stack degrade gracefully or crash?

2. **Routing table stress**
   - Add many routes (fill FIB)
   - Measure: lookup latency vs table size
   - Observe: does longest-prefix match slow down?

3. **ACL complexity stress**
   - Add many ACL rules
   - Measure: per-packet evaluation time vs rule count
   - Observe: linear degradation or cliff?

4. **Bandwidth flooding**
   - Send maximum rate traffic through the pipeline
   - Measure: packets/second throughput
   - Observe: drop patterns under overload

5. **Report generation**
   - Summary: max connections, max throughput, degradation point
   - Per-test: pass/fail based on configurable thresholds

6. **Validation**
   - Fill TCP table (256 connections) → verify graceful rejection
   - 10000 packets/second → measure drop rate
   - 128 routes → verify lookup still works

### Phase 12 Sub-phase Summary

| Sub-phase | Component | Week | Output |
|-----------|-----------|------|--------|
| 12a | ironprobe (scanner) | Week 29–30 | Port scan results, ACL validation report |
| 12b | ironfuzz (fuzzer) | Week 30–32 | Crash reports, coverage metrics |
| 12c | ironload (stress) | Week 33–34 | Performance report, degradation analysis |

---

## Phase 13: Attack Simulation & Defense (Week 35–40)

This phase is split into 5 sub-phases due to its scope.

### Key difference from Phase 12

| Aspect | Phase 12 (Security Testing) | Phase 13 (Attack & Defense) |
|--------|---------------------------|-----------------------------|
| Tools | Generic (scan, fuzz, stress) | Specific named attacks |
| Mode | Internal (inject into pipeline directly) | **External (real packets via TAP)** |
| Purpose | Find bugs and crashes | Study attack/defense effectiveness |
| Binaries | Libraries linked into ironstack | **Separate executables** |
| Network | No real network needed | Real TAP interfaces, multiple terminals |

### Architecture

```
Terminal 1: Router (target)
  sudo ./ironstack/ironstack ../src/configs/router.conf

Terminal 2: Attack tools (attacker)
  sudo ./ironattack syn-flood --target 10.0.1.1 --port 7 --rate 1000
  sudo ./ironattack arp-spoof --target 10.0.1.1 --impersonate 10.0.1.254
  sudo ./ironprobe-ext --target 10.0.1.1 --ports 1-65535

Terminal 3: Monitor
  sudo tcpdump -i iron0 -XX -n
  # Or watch audit log:
  tail -f /tmp/ironnet_audit.log
```

Attack tools are **separate binaries** that:
- Open the TAP interface (or use raw sockets)
- Craft and send real Ethernet frames / IP packets
- Simulate real-world attack traffic
- Measure response (or lack thereof) from the router

### Goals
- Simulate specific network attack techniques against the protocol stack
- Implement defense mechanisms and study their effectiveness
- Provide a structured penetration testing workflow
- All attacks use **real packets** through the TAP interface (not internal injection)

### Attack-defense matrix

| Attack | Defense | Metric |
|--------|---------|--------|
| SYN flood | SYN cookies + rate limit | Connection table usage under attack |
| ARP spoofing | ARP inspection | Poisoned entries detected/blocked |
| VLAN hopping | VLAN strict mode | Double-tagged frames dropped |
| IP spoofing | Source IP validation (uRPF) | Spoofed packets dropped |
| TCP RST injection | Connection tracking + RST validation | Forged RSTs rejected |
| ICMP redirect | ICMP redirect disable | Routing table unchanged |
| Slowloris | Connection timeout + rate limit | Resources recovered |
| Fragmentation | Fragment validation | Overlapping/tiny frags dropped |

### Penetration testing workflow

- **Reconnaissance**: `ironprobe-ext` scans to discover services and ACL gaps
- **Enumeration**: identify open ports, protocol versions, service fingerprints
- **Exploitation**: `ironattack` tests specific vulnerabilities
- **Post-exploitation**: verify what access was gained, lateral movement
- **Reporting**: automated test results with pass/fail per defense

---

### Phase 13a: Infrastructure + SYN Flood Attack/Defense (Week 35–36)

#### DoS and DDoS Concepts

**Denial of Service (DoS)** makes a service unavailable by exhausting its resources. Three categories:

| Category | Target | Example | IronNet demo |
|----------|--------|---------|-------------|
| **Volumetric** | Bandwidth | UDP flood, DNS amplification | ironload bandwidth test |
| **Protocol** | Connection state | SYN flood, RST flood | ironattack syn-flood |
| **Application** | App resources | Slowloris, HTTP flood | ironattack slowloris |

**DDoS (Distributed DoS):** Same attacks launched from many sources simultaneously. Harder to block because traffic comes from thousands of IPs (can't just block one source).

**Amplification attacks:** Attacker sends small request with spoofed source IP to a reflector (DNS, NTP, memcached). Reflector sends large response to the victim. Amplification factor: DNS=28x-54x, NTP=556x, memcached=51000x.

```
Attacker (spoofed src=victim) → DNS server: "query ANY for example.com" (60 bytes)
DNS server → Victim: full response (3000 bytes) — 50x amplification!
```

**IronNet demonstrates DoS through:**
- `ironattack syn-flood` — protocol-layer DoS (fills TCP connection table)
- `ironattack slowloris` — application-layer DoS (holds connections open)
- `ironload tcp` — measures exact resource limits (256 connections)
- `ironattack mac-flood` (Phase 20) — L2 DoS (bridge table overflow)
- `defense syn-cookies` + `defense rate-limit` — mitigation

**Why no separate DDoS phase:** DDoS is the same attack from multiple sources. ironsim can simulate this by running `syn-flood` from multiple nodes simultaneously. No new attack logic is needed — the defense (rate limiting, SYN cookies) works the same regardless of source count.

#### Goals
- Build the ironattack binary skeleton with TAP-based packet crafting
- Implement SYN flood attack (first external attack)
- Implement SYN cookies and rate limiting defenses
- Establish the `defense` CLI command framework

#### Tasks

1. **Packet crafting library (`ironattack/craft.h`, `craft.c`)**
   - Build raw Ethernet frames from scratch (dst_mac, src_mac, ethertype, payload)
   - Build IP packets (version, TTL, protocol, src/dst, checksum)
   - Build TCP segments (ports, seq, flags, checksum with pseudo-header)
   - Build ARP packets (request/reply, sender/target HW+proto addr)
   - Build ICMP packets (type, code, checksum)
   - TAP write helper: open TAP device by name, write raw frame

2. **ironattack binary skeleton (`ironattack/main.c`)**
   - Subcommand dispatch: `ironattack <subcommand> [options]`
   - Common options: `--target`, `--port`, `--iface`, `--rate`, `--count`
   - Opens TAP interface (e.g., iron0) for packet injection
   - Rate control: configurable packets/second via usleep

3. **SYN flood attack (`ironattack/attack_syn_flood.c`)**
   ```bash
   sudo ./ironattack syn-flood --target 10.0.1.1 --port 7 --rate 1000 --count 5000
   ```
   - Send TCP SYN packets from randomized source IPs
   - Randomize source port per packet
   - Configurable rate (packets/second) and total count
   - Report: packets sent, elapsed time, effective rate

4. **Defense module (`ironstack/security/defense.h`, `defense.c`)**
   - Defense registry: named defenses with enable/disable state
   - `defense_init()` — initialize all defenses as disabled
   - `defense_enable(name)` / `defense_disable(name)`
   - `defense_is_enabled(name)` — check if active

5. **SYN cookies defense**
   - When enabled: do NOT allocate connection table entry on SYN
   - Encode connection info into the SYN+ACK sequence number (cookie)
   - On ACK: validate cookie, only then create connection entry
   - Effect: connection table stays empty during flood, legitimate clients still connect

6. **Rate limiting defense**
   - Per-source IP SYN rate tracking
   - Configurable threshold (e.g., 100 SYNs/second per source)
   - Excess SYNs dropped with audit log event
   - `defense rate-limit <N>/s` CLI command

7. **CLI integration**
   ```
   ironctl> defense syn-cookies enable
   ironctl> defense syn-cookies disable
   ironctl> defense rate-limit 100/s
   ironctl> defense show
   ```

8. **Validation**
   - SYN flood WITHOUT defenses: connection table fills at 256, new SYNs rejected
   - SYN flood WITH SYN cookies: connection table stays near 0, legitimate client still connects
   - SYN flood WITH rate limit: excess SYNs dropped, audit log shows drops
   - ironattack reports packets sent and effective rate

---

### Phase 13b: ARP Spoofing + VLAN Hopping (Week 36–37)

#### Goals
- Implement ARP spoofing attack (poison router's ARP table)
- Implement VLAN hopping attack (double-tagged 802.1Q frames)
- Implement ARP inspection and VLAN strict mode defenses

#### Tasks

1. **ARP spoof attack (`ironattack/attack_arp_spoof.c`)**
   ```bash
   sudo ./ironattack arp-spoof --target 10.0.1.1 --impersonate 10.0.1.254 --iface iron0
   ```
   - Craft ARP reply: "10.0.1.254 is at [attacker's MAC]"
   - Send repeatedly (every 1 second) to keep poisoning active
   - Effect: router thinks gateway 10.0.1.254 is at attacker's MAC → traffic redirected
   - Report: ARP replies sent, duration

2. **VLAN hopping attack (`ironattack/attack_vlan_hop.c`)**
   ```bash
   sudo ./ironattack vlan-hop --target-vlan 20 --iface iron0
   ```
   - Craft double-tagged frame: outer tag = native VLAN, inner tag = target VLAN
   - When outer tag is stripped by first switch, inner tag remains → frame enters target VLAN
   - Send ICMP ping inside the double-tagged frame to verify reachability
   - Report: frames sent, whether response received from target VLAN

3. **ARP inspection defense**
   - Maintain trusted IP-MAC binding table (static entries from config or learned at startup)
   - On ARP reply received: check if sender IP-MAC matches trusted table
   - If mismatch: drop ARP, log audit event (AUDIT_ARP_ANOMALY), do NOT update ARP table
   - `defense arp-inspection enable`
   - Config: `arp-trust 10.0.1.254 02:00:00:00:00:FE` (trusted binding)

4. **VLAN strict mode defense**
   - On access ports: reject any frame that has a VLAN tag (TPID 0x8100) at offset 12
   - Specifically rejects double-tagged frames (which have 0x8100 as outer tag)
   - `defense vlan-strict enable`
   - Audit log: AUDIT_VLAN_MISMATCH when double-tagged frame dropped

5. **Validation**
   - ARP spoof WITHOUT inspection: ARP table poisoned, `show arp` shows wrong MAC
   - ARP spoof WITH inspection: ARP table unchanged, audit log shows blocked attempts
   - VLAN hop WITHOUT strict mode: frame reaches target VLAN
   - VLAN hop WITH strict mode: double-tagged frame dropped at ingress

---

### Phase 13c: TCP RST Injection + IP Spoofing (Week 37–38)

#### Goals
- Implement TCP RST injection attack (kill established connections)
- Implement IP spoofing attack (bypass source-based ACLs)
- Implement RST validation and uRPF defenses

#### Tasks

1. **TCP RST injection attack (`ironattack/attack_rst_inject.c`)**
   ```bash
   sudo ./ironattack rst-inject --target 10.0.1.1 --port 7 --iface iron0
   ```
   - Craft TCP RST packet with guessed sequence number
   - Source IP = spoofed client IP (e.g., 10.0.1.2)
   - Try multiple sequence numbers in window (brute-force approach)
   - Effect: established TCP connection torn down
   - Report: RSTs sent, connection status after attack

2. **IP spoofing attack (`ironattack/attack_ip_spoof.c`)**
   ```bash
   sudo ./ironattack ip-spoof --src 10.0.99.1 --dst 10.0.1.1 --port 7 --iface iron0
   ```
   - Craft TCP SYN with forged source IP (10.0.99.1)
   - Purpose: bypass ACL rules that permit traffic from specific sources
   - Send to a port that has source-based ACL (e.g., only 10.0.1.0/24 permitted)
   - Report: packets sent, whether connection was established

3. **RST validation defense**
   - When RST received for an existing connection:
     - Check if RST sequence number falls within the expected receive window
     - If outside window: drop RST silently (forged)
     - If inside window: accept RST (legitimate close)
   - Uses conntrack to know expected sequence range
   - `defense rst-validation enable`

4. **uRPF (unicast Reverse Path Forwarding) defense**
   - On packet ingress: check if source IP is reachable via the interface it arrived on
   - Lookup source IP in routing table → if best route points to a different interface → drop
   - Prevents spoofed packets from entering the network
   - `defense urpf enable`
   - Audit log: source IP validation failure

5. **Validation**
   - Establish connection (nc to echo server), then RST inject WITHOUT defense: connection killed
   - Same test WITH RST validation: forged RSTs rejected, connection survives
   - IP spoof WITHOUT uRPF: spoofed packet reaches application
   - IP spoof WITH uRPF: spoofed packet dropped at ingress (source not reachable via iron0)

---

### Phase 13d: Slowloris + Fragmentation Attacks (Week 38–39)

#### Goals
- Implement Slowloris attack (exhaust connections with slow data)
- Implement fragmentation attacks (overlapping/tiny fragments)
- Implement connection timeout and fragment validation defenses

#### Tasks

1. **Slowloris attack (`ironattack/attack_slowloris.c`)**
   ```bash
   sudo ./ironattack slowloris --target 10.0.1.1 --port 8080 --conns 200 --iface iron0
   ```
   - Open many TCP connections (complete 3-way handshake)
   - Send partial HTTP headers very slowly (1 byte every few seconds)
   - Never complete the request → connection stays open indefinitely
   - Effect: all connection slots consumed, legitimate clients cannot connect
   - Report: connections opened, target connection table usage

2. **Fragmentation attack (`ironattack/attack_frag.c`)**
   ```bash
   sudo ./ironattack frag-attack --target 10.0.1.1 --overlap --iface iron0
   sudo ./ironattack frag-attack --target 10.0.1.1 --tiny --iface iron0
   ```
   - **Overlapping fragments**: send fragments where offset ranges overlap (confuses reassembly)
   - **Tiny fragments**: send fragments smaller than minimum (68 bytes) to evade inspection
   - **Out-of-order**: send last fragment first, then first fragment
   - Effect: bypass ACL/IDS inspection, crash vulnerable reassembly code
   - Report: fragments sent, whether reassembled packet was delivered

3. **Connection idle timeout defense**
   - Track last data activity per connection (already have `last_activity` in tcp_conn_t)
   - If connection in ESTABLISHED state has no data for N seconds → send RST and close
   - Configurable timeout: `defense conn-timeout 30`
   - Slowloris connections get cleaned up after timeout
   - Audit log: connection closed due to idle timeout

4. **Fragment validation defense (enhanced)**
   - Reject fragments smaller than minimum size (68 bytes) unless last fragment
   - Reject overlapping fragments (fragment offset + length overlaps with existing fragment)
   - Reject excessive fragment count per packet ID (max 64 fragments)
   - `defense frag-strict enable`
   - Audit log: AUDIT_FRAGMENT_DROP with reason (overlap/tiny/excessive)

5. **Validation**
   - Slowloris WITHOUT timeout: 200 connections fill table, legitimate client rejected
   - Slowloris WITH conn-timeout 30: idle connections cleaned up, legitimate client connects
   - Overlapping fragments WITHOUT frag-strict: reassembly confused or crashes
   - Overlapping fragments WITH frag-strict: fragments dropped, audit log entry
   - Tiny fragments WITH frag-strict: dropped at ingress

---

### Phase 13e: ICMP Redirect + External Scanner + Reporting (Week 39–40)

#### Goals
- Implement ICMP redirect attack (manipulate routing)
- Implement ICMP redirect disable defense
- Build ironprobe-ext (real SYN scan via TAP)
- Build automated attack-defense test report

#### Tasks

1. **ICMP redirect attack (`ironattack/attack_icmp_redirect.c`)**
   ```bash
   sudo ./ironattack icmp-redirect --target 10.0.1.1 --new-gw 10.0.1.99 --iface iron0
   ```
   - Craft ICMP Redirect message (type=5, code=1)
   - Tell the router: "for destination X, use gateway 10.0.1.99 instead"
   - Effect: router adds a host route pointing to attacker-controlled gateway
   - Report: redirects sent, whether routing table changed

2. **ICMP redirect disable defense**
   - When enabled: ignore all incoming ICMP Redirect messages
   - Do not modify routing table based on ICMP redirects
   - `defense icmp-redirect-disable enable`
   - Audit log: ICMP redirect received and ignored

3. **External scanner — ironprobe-ext (separate binary)**
   ```bash
   sudo ./ironprobe-ext --target 10.0.1.1 --ports 1-65535 --iface iron0
   sudo ./ironprobe-ext --target 10.0.1.1 --udp --ports 53,67,123 --iface iron0
   ```
   - Opens TAP interface, sends real TCP SYN packets
   - Listens for SYN+ACK (open) or RST (closed) or timeout (filtered)
   - UDP: sends probe, listens for response or ICMP unreachable
   - Reports: open/closed/filtered per port
   - Service fingerprinting: classify response patterns

4. **Automated attack-defense test report**
   - Script or binary that runs all attacks with defenses OFF, then with defenses ON
   - For each attack/defense pair, records:
     - Attack effectiveness without defense (baseline)
     - Attack effectiveness with defense (mitigated)
     - Pass/fail: defense reduces attack effectiveness below threshold
   - Output: formatted report (text or JSON)
   ```
   === IronNet Attack-Defense Report ===
   Attack              | No Defense      | With Defense    | Result
   --------------------|-----------------|-----------------|-------
   SYN Flood           | Table full 256  | Table usage: 0  | PASS
   ARP Spoof           | Table poisoned  | Blocked (3/3)   | PASS
   VLAN Hop            | Frame delivered  | Dropped         | PASS
   IP Spoof            | Packet accepted | Dropped (uRPF)  | PASS
   RST Inject          | Conn killed     | RST rejected    | PASS
   ICMP Redirect       | Route changed   | Ignored         | PASS
   Slowloris           | Table full      | Timeout cleanup | PASS
   Frag Overlap        | Reassembled     | Dropped         | PASS
   ```

5. **Validation**
   - ICMP redirect WITHOUT defense: `show routes` shows new host route
   - ICMP redirect WITH defense: routing table unchanged
   - ironprobe-ext detects all 5 open ports (7, 53, 6379, 8080, 9000)
   - ironprobe-ext detects port 22 as filtered (ACL deny)
   - Full report generated with all 8 attack/defense pairs passing

---

### Phase 13 Sub-phase Summary

| Sub-phase | Component | Week | New Binaries | Attacks | Defenses |
|-----------|-----------|------|--------------|---------|----------|
| 13a | Infrastructure + SYN Flood | Week 35–36 | `ironattack` (skeleton + syn-flood) | SYN flood | SYN cookies, rate limit |
| 13b | ARP Spoofing + VLAN Hopping | Week 36–37 | — (adds subcommands) | ARP spoof, VLAN hop | ARP inspection, VLAN strict |
| 13c | TCP RST Injection + IP Spoofing | Week 37–38 | — | RST inject, IP spoof | RST validation, uRPF |
| 13d | Slowloris + Fragmentation | Week 38–39 | — | Slowloris, frag attack | Conn timeout, frag strict |
| 13e | ICMP Redirect + Scanner + Report | Week 39–40 | `ironprobe-ext` | ICMP redirect | Redirect disable, full report |

---

## Phase 14: Network Emulator — ironsim (Week 41–42)

This phase is split into 3 sub-phases.

### Goals
- Run multiple ironstack instances as network nodes on a single WSL machine
- Simulate topologies with configurable link properties (delay, drop, reorder)
- Provide scripted multi-node setups for end-to-end testing

### Architecture

```
ironsim (orchestrator)
  |
  +-- fork/exec --> ironstack-A (iron-a0: 10.0.1.1/24)
  |                     |
  |                 [veth pair]
  |                     |
  +-- fork/exec --> ironstack-B (iron-b0: 10.0.1.254/24, iron-b1: 10.0.2.254/24)
  |                     |
  |                 [veth pair]
  |                     |
  +-- fork/exec --> ironstack-C (iron-c0: 10.0.2.1/24)
  |
  +-- relay threads (apply delay/drop/reorder between nodes)
```

Each ironstack instance runs as a separate process with its own TAP interfaces and config file. ironsim orchestrates startup, link creation, impairments, and shutdown.

**Feasibility on single WSL machine:**
- WSL supports multiple TAP devices with unique names
- Each ironstack uses ~1-2 MB RAM, minimal CPU
- 3-5 simultaneous instances is trivial
- All instances need sudo (TAP creation)
- Each TAP name must be unique system-wide

### Design decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Node isolation | Separate processes (fork+exec) | Realistic, no shared state corruption |
| Link mechanism | TAP + veth pairs | Linux-native, no custom IPC needed |
| Link impairments | User-space relay thread | Portable, no tc/netem dependency |
| Topology format | Simple config file | Flexible, easy to modify |
| Traffic generation | Built-in ping/TCP test | Validates end-to-end connectivity |

---

### Phase 14a: Basic 2-Node Topology (Week 41)

#### Goals
- ironsim spawns 2 ironstack instances connected by a virtual link
- Validate: ping from node A reaches node B through the link

#### Tasks

1. **ironsim binary skeleton (`ironsim/main.c`)**
   - Parse topology config file
   - Create TAP interfaces for each node
   - Generate per-node router.conf files (temp files)
   - Fork+exec ironstack child processes
   - Wait for children, handle Ctrl+C for graceful shutdown

2. **Link creation using veth pairs**
   - For each link: create veth pair (e.g., `sim-a0` ↔ `sim-b0`)
   - Assign IPs on the Linux side to bridge traffic between TAPs
   - Or: use Linux bridge to connect node TAPs

3. **Topology config format**
   ```
   # 2-node linear topology
   node A ip 10.0.1.1/24
   node B ip 10.0.1.254/24
   link A B
   ```

4. **Validation**
   - Start ironsim with 2-node config
   - From Linux: `ping 10.0.1.1` via node A's TAP
   - Verify: node A responds, traffic visible in both nodes
   - ironsim prints: "Topology up: 2 nodes, 1 link"

---

### Phase 14b: Link Impairments + 3-Node Topology (Week 41–42)

#### Goals
- Add configurable delay, packet drop, and reorder to links
- Support 3-node linear topology (A → B → C)

#### Tasks

1. **Relay thread per link**
   - Reads packets from one end of the link
   - Applies impairments before forwarding to the other end:
     - **Delay**: sleep N ms before write
     - **Drop**: skip write with probability P
     - **Reorder**: buffer packets and deliver out of order occasionally
   - One thread per direction (bidirectional relay)

2. **Extended topology config**
   ```
   node A ip 10.0.1.1/24
   node B ip 10.0.1.254/24 ip 10.0.2.254/24
   node C ip 10.0.2.1/24
   link A B delay 5ms loss 0.1%
   link B C delay 10ms loss 0.5% reorder
   ```

3. **3-node routing**
   - Node B acts as router between A and C
   - Node A has route: 10.0.2.0/24 via 10.0.1.254
   - Node C has route: 10.0.1.0/24 via 10.0.2.254
   - End-to-end: A can reach C through B

4. **Validation**
   - Ping from A to C (through B): verify replies arrive
   - With 50% drop rate: verify ~50% packet loss
   - With 100ms delay: verify RTT increases by ~200ms

---

### Phase 14c: Traffic Generation + Reporting (Week 42)

#### Goals
- Built-in traffic generator for automated testing
- Report: latency, loss, throughput per link

#### Tasks

1. **Traffic generator**
   - ICMP ping flood: send N pings from A to C, measure RTT and loss
   - TCP throughput: connect to echo server on C, send data, measure rate
   - Configurable: `traffic A C icmp count 100` or `traffic A C tcp port 7 bytes 10000`

2. **Statistics collection**
   - Per-link: packets forwarded, dropped, delayed
   - Per-node: stats from each ironstack instance (via `show stats` piped)
   - End-to-end: latency distribution, loss percentage

3. **Report output**
   ```
   === ironsim Topology Report ===
   Nodes: 3 (A, B, C)
   Links: 2 (A-B: 5ms/0.1%, B-C: 10ms/0.5%)

   Traffic: A → C (ICMP ping × 100)
     Sent: 100  Received: 95  Loss: 5%
     RTT min/avg/max: 15/18/45 ms

   Per-node stats:
     A: tx=100 rx=95
     B: forwarded=195 drops_acl=0
     C: rx=100 tx=95
   ```

4. **Security testing through topology**
   - Run ironprobe-ext from A scanning C through B
   - Verify B's ACL blocks port 22 but permits port 7
   - Run ironattack from A through B to C

5. **Validation**
   - 3-node topology with impairments: report matches expected loss/delay
   - ACL on B blocks traffic: ping from A to C on blocked port fails
   - End-to-end echo: data sent from A arrives at C and returns

---

### Phase 14 Sub-phase Summary

| Sub-phase | Component | Week | Output |
|-----------|-----------|------|--------|
| 14a | 2-node topology + link creation | Week 41 | ironsim binary, basic connectivity |
| 14b | Link impairments + 3-node | Week 41–42 | Delay/drop/reorder, multi-hop routing |
| 14c | Traffic generation + report | Week 42 | Automated test report, security testing through topology |

---

## Phase 15: Packet Tools — irontrace (Week 43–44)

This phase is split into 3 sub-phases.

### Goals
- Capture packets at any pipeline stage (L2/L3/L4)
- Write captures in pcap format (compatible with Wireshark)
- Replay captured traces for regression testing
- Provide CLI commands for runtime capture control

### Two modes of operation

| Mode | How it works | Use case |
|------|-------------|----------|
| **Internal hooks** | Callbacks inside ironstack pipeline at L2/L3/L4 boundaries | See packets at each processing stage (before/after ACL, routing, etc.) |
| **External capture** | irontrace-replay binary reads/writes via TAP raw socket | Like tcpdump — observe and replay traffic from outside |

Internal hooks capture packets as they flow through the pipeline — you can see what happens at each layer. External replay injects real packets into the TAP device for realistic regression testing.

### Architecture

```
ironstack pipeline
  |
  +-- eth_parse() ──→ trace hook (L2 RX)
  +-- eth_build() ──→ trace hook (L2 TX)
  +-- ip_input()  ──→ trace hook (L3 RX)
  +-- ip_output() ──→ trace hook (L3 TX)
  +-- tcp_input() ──→ trace hook (L4 RX)
  |
  v
irontrace module
  |
  +-- trace_capture(layer, direction, data, len)
  +-- writes to pcap file: /tmp/irontrace.pcap

irontrace-replay (separate binary)
  |
  +-- reads pcap file
  +-- injects packets via raw socket or vnic_inject()
```

### Design decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Capture format | pcap (libpcap-compatible) | Opens in Wireshark, industry standard |
| Hook mechanism | Runtime enable/disable via CLI | No recompile needed, selective capture |
| Replay injection | Raw socket (external) + vnic_inject (internal) | Both realistic and fast modes |
| Storage | File-based (/tmp/irontrace.pcap) | Persistent, can be large, no memory limit |
| Filtering | Per-layer enable (L2/L3/L4/all) | Simple, covers common use cases |

---

### Phase 15a: Capture — Pipeline Hooks + pcap Writer (Week 43)

#### Goals
- Add trace hooks at L2/L3/L4 boundaries in the pipeline
- Write captured packets to pcap file format
- CLI commands to start/stop capture

#### Tasks

1. **Trace module (`irontrace/trace.h`, `trace.c`)**
   - `trace_init()` — initialize trace subsystem
   - `trace_start(filename, layers)` — begin capture to file
   - `trace_stop()` — stop capture, close file
   - `trace_capture(layer, direction, data, len)` — called from hooks
   - `trace_status()` — print current state (enabled, file, packet count)
   - Layer flags: `TRACE_L2`, `TRACE_L3`, `TRACE_L4`, `TRACE_ALL`

2. **pcap file format writer**
   - Global header (24 bytes): magic=0xA1B2C3D4, version=2.4, snaplen=65535, linktype=1 (Ethernet)
   - Per-packet header (16 bytes): timestamp_sec, timestamp_usec, captured_len, original_len
   - Packet data: raw bytes as seen at the hook point

3. **Pipeline hooks**
   - `eth.c` — after `eth_parse()` succeeds: `trace_capture(TRACE_L2, DIR_RX, raw, len)`
   - `eth.c` — in `eth_build()` output: `trace_capture(TRACE_L2, DIR_TX, out_buf, total)`
   - `ip.c` — in `ip_input()` after validation: `trace_capture(TRACE_L3, DIR_RX, data, len)`
   - `ip.c` — in `ip_output()` before send: `trace_capture(TRACE_L3, DIR_TX, pkt, total)`
   - `tcp.c` — in `tcp_input()`: `trace_capture(TRACE_L4, DIR_RX, data, len)`

4. **CLI commands**
   ```
   ironctl> trace start /tmp/capture.pcap all
   ironctl> trace start /tmp/l3only.pcap l3
   ironctl> trace stop
   ironctl> trace status
   ```

5. **Validation**
   - Start capture, ping router, stop capture
   - Open pcap file in Wireshark — verify ICMP packets visible
   - Verify packet count matches expected

---

### Phase 15b: Replay — pcap Reader + Packet Injection (Week 43–44)

#### Goals
- Read pcap files and inject packets back into the stack
- Support both internal (fast) and external (realistic) replay modes

#### Tasks

1. **irontrace-replay binary (`irontrace/replay.c`)**
   ```bash
   sudo ./irontrace-replay --file /tmp/capture.pcap --iface iron0
   sudo ./irontrace-replay --file /tmp/capture.pcap --fast
   ```
   - Read pcap global header, validate magic number
   - Read packet headers + data sequentially
   - External mode: send via raw socket to TAP interface
   - Fast mode: inject as quickly as possible (no timing)
   - Timed mode: preserve original inter-packet delays

2. **Internal replay via CLI**
   ```
   ironctl> trace replay /tmp/capture.pcap
   ```
   - Reads pcap file, calls `vnic_inject()` for each packet
   - Useful for regression testing without external binary

3. **Replay statistics**
   - Packets replayed, bytes sent, duration
   - Errors (injection failures)

4. **Validation**
   - Capture traffic → replay → verify same counters/behavior
   - Replay at max speed → verify no crashes (stress test)

---

### Phase 15c: CLI Integration + Regression Workflow (Week 44)

#### Goals
- Complete CLI integration for capture/replay
- Document the regression testing workflow

#### Tasks

1. **Full CLI command set**
   ```
   ironctl> trace start <file> [l2|l3|l4|all]  — begin capture
   ironctl> trace stop                          — stop capture
   ironctl> trace status                        — show state
   ironctl> trace replay <file>                 — replay internally
   ```

2. **Regression workflow**
   ```
   # Step 1: Capture the failing scenario
   ironctl> trace start /tmp/bug123.pcap all
   # ... reproduce the bug ...
   ironctl> trace stop

   # Step 2: Fix the bug in source code
   # ... edit code, rebuild ...

   # Step 3: Replay and verify fix
   ironctl> trace replay /tmp/bug123.pcap
   ironctl> show stats
   # Verify: no crashes, correct counters
   ```

3. **Integration with ironsim**
   - Capture traffic in a multi-node topology
   - Replay against a single node for isolated debugging

4. **Validation**
   - Full regression cycle: capture → fix → replay → verify
   - pcap file opens correctly in Wireshark
   - Replay produces identical stats as original capture

---

### Phase 15 Sub-phase Summary

| Sub-phase | Component | Week | Output |
|-----------|-----------|------|--------|
| 15a | Capture (hooks + pcap writer) | Week 43 | trace_capture() hooks, pcap file output |
| 15b | Replay (pcap reader + injection) | Week 43–44 | irontrace-replay binary, CLI replay |
| 15c | CLI + regression workflow | Week 44 | Full trace CLI, documented workflow |

---

## Phase 16: Man-in-the-Middle (MITM) (Week 45–47)

This phase is split into 3 sub-phases.

### Goals
- Demonstrate full MITM attack: intercept, inspect, modify, and forward traffic
- Show why encryption is essential for network security
- Build detection mechanisms for MITM attacks

### Architecture

```
Victim A (10.0.1.1)  ←→  Attacker (MITM relay)  ←→  Victim B / Server (10.0.2.1)
                          ↓
                     Logs all traffic
                     Can modify in transit
```

---

### Phase 16a: MITM Relay Engine (Week 45)

#### Goals
- Build a relay mode in ironattack that intercepts traffic between two hosts
- Combine ARP spoofing + packet forwarding

#### Tasks

1. **ARP poisoning both directions**
   - Tell A: "B is at attacker MAC"
   - Tell B: "A is at attacker MAC"
   - Both victims send traffic to attacker

2. **Relay engine (`ironattack/mitm_relay.c`)**
   - Receive packets from A destined for B
   - Log packet contents (src, dst, protocol, payload preview)
   - Forward to real B (rewrite MAC, keep IP intact)
   - Same in reverse direction
   - Transparent to both endpoints

3. **CLI command**
   ```bash
   sudo ./ironattack mitm --victim-a 10.0.1.1 --victim-b 10.0.2.1 --iface iron0
   ```

4. **Validation**
   - A pings B → attacker sees and forwards ping → B responds → attacker sees reply
   - A connects to B's echo server → attacker logs all data in transit
   - Neither A nor B detects the interception

---

### Phase 16b: Traffic Modification (Week 46)

#### Goals
- Modify packets in transit (inject, alter, drop selectively)
- Demonstrate data integrity attacks

#### Tasks

1. **Modification rules**
   - Replace: swap specific bytes in payload (e.g., change "OK" to "NO")
   - Inject: add extra data to HTTP responses
   - Drop: selectively drop packets matching criteria
   - Delay: hold packets to cause timeouts

2. **Rule configuration**
   ```bash
   sudo ./ironattack mitm --victim-a 10.0.1.1 --victim-b 10.0.2.1 \
       --modify "replace:OK:FAIL" --log /tmp/mitm.log
   ```

3. **Validation**
   - KV store: `SET foo bar` → attacker changes to `SET foo HACKED`
   - HTTP: inject JavaScript into response body
   - Echo: modify echoed data (client sends "hello", receives "XXXXX")

---

### Phase 16c: MITM Detection (Week 47)

#### Goals
- Build detection mechanisms into ironstack
- Alert when MITM indicators are present

#### Tasks

1. **ARP anomaly detection (enhanced)**
   - Detect rapid ARP changes (MAC flapping)
   - Detect duplicate IP with different MACs
   - Alert: "Possible MITM: IP 10.0.1.1 MAC changed 3 times in 10 seconds"

2. **Traffic analysis**
   - Detect unexpected latency increase (relay adds delay)
   - Detect TTL anomalies (relay may not decrement TTL correctly)
   - Detect duplicate packets (relay forwarding artifacts)

3. **Defense: encrypted channels**
   - Demonstrate that IPsec-protected traffic is opaque to MITM
   - Attacker sees encrypted bytes, cannot modify without detection

4. **Validation**
   - MITM active → detection alerts fire
   - MITM active + IPsec → attacker sees only encrypted data

---

### Phase 16 Sub-phase Summary

| Sub-phase | Component | Week | Output |
|-----------|-----------|------|--------|
| 16a | MITM relay engine | Week 45 | Transparent interception + logging |
| 16b | Traffic modification | Week 46 | In-transit data alteration |
| 16c | MITM detection | Week 47 | Anomaly alerts + encryption defense |

---

## Phase 17: DNS Poisoning & Hijacking (Week 48–50)

This phase is split into 4 sub-phases.

### Goals
- Demonstrate DNS cache poisoning and response spoofing
- Redirect victims to attacker-controlled IPs
- Build DNS security mechanisms (validation, DNSSEC-lite)

### Architecture

```
Client → DNS query → ironstack DNS server (port 53)
                          ↑
              Attacker races to respond first
              with forged DNS reply (wrong IP)
```

---

### Phase 17a: DNS Response Spoofing (Week 48)

#### Goals
- Attacker sends forged DNS responses to redirect domains to attacker IP

#### Tasks

1. **DNS spoof attack (`ironattack/attack_dns_spoof.c`)**
   ```bash
   sudo ./ironattack dns-spoof --domain ironnet.local --fake-ip 10.0.99.1 \
       --target 10.0.1.1 --iface iron0
   ```
   - Listen for DNS queries on the wire
   - Race to respond before the real DNS server
   - Forge response with attacker's IP for the queried domain

2. **Standalone DNS poisoner**
   - Continuously send unsolicited DNS responses
   - Target: any client that queries `ironnet.local`
   - Response: `ironnet.local → 10.0.99.1` (attacker IP)

3. **Validation**
   - Client queries `ironnet.local` → receives attacker's IP instead of real IP
   - Client connects to the fake IP → traffic goes to attacker

---

### Phase 17b: DNS Cache Poisoning (Week 49)

#### Goals
- Poison the DNS server's cache (if caching is added)
- Persistent redirection without continuous spoofing

#### Tasks

1. **Add DNS caching to dns_server.c**
   - Cache resolved queries with TTL
   - Subsequent queries served from cache

2. **Cache poisoning attack**
   - Send forged response with high TTL before real response arrives
   - Poisoned entry persists in cache for TTL duration
   - All subsequent clients get the poisoned answer

3. **Transaction ID guessing**
   - DNS uses 16-bit transaction ID for matching queries to responses
   - Attacker brute-forces transaction IDs (65536 possibilities)
   - Demonstrate: with weak randomization, poisoning succeeds quickly

4. **Validation**
   - Poison cache → all clients get wrong IP for N seconds (TTL)
   - After TTL expires → correct answer returns

---

### Phase 17c: DNS Security (Week 50)

#### Goals
- Implement defenses against DNS poisoning

#### Tasks

1. **Source port randomization**
   - Use random source port for outbound queries (not fixed port 53)
   - Attacker must guess both transaction ID AND source port
   - Reduces success probability from 1/65536 to 1/4 billion

2. **Response validation**
   - Verify response comes from expected server IP
   - Verify transaction ID matches outstanding query
   - Reject unsolicited responses

3. **DNSSEC-lite (signature verification)**
   - Add simple HMAC to DNS responses (shared secret between server and resolver)
   - Forged responses without valid HMAC are rejected
   - Demonstrates the principle of DNSSEC without full PKI

4. **Validation**
   - DNS spoof WITHOUT defenses: poisoning succeeds
   - DNS spoof WITH source port randomization: poisoning fails (can't guess port)
   - DNS spoof WITH HMAC: forged responses rejected

---

### Phase 17d: External DNS Cache Poisoning (Week 50)

#### Goals
- Implement a realistic external DNS cache poisoning tool (Kaminsky-style)
- Demonstrate that UDP-based attacks traverse the TAP device successfully
- Validate that `dns-validate` defense blocks external poisoning

#### Tasks

1. **External DNS spoof tool (`ironattack/dns_spoof_ext.c`)**
   ```bash
   sudo ./ironattack dns-spoof-ext --domain ironnet.local --fake-ip 10.0.99.1 \
       --target 10.0.1.1 --iface iron0 [--count <n>]
   ```
   - Floods forged DNS responses with random transaction IDs (Kaminsky-style brute-force)
   - Source IP spoofed as upstream DNS server (8.8.8.8) to look legitimate
   - Sends via IPPROTO_RAW socket bound to TAP interface
   - ironstack's DNS server accepts responses (QR=1) and caches the answer

2. **DNS server response acceptance**
   - DNS server checks QR flag: QR=0 → normal query, QR=1 → treat as upstream response
   - Responses are parsed for answer section (A record IP)
   - Answer is cached via `dns_cache_add_secure()` (defense-aware)
   - Simulates a recursive resolver accepting upstream responses

3. **Integration with existing defenses**
   - Without `dns-validate`: forged response accepted, cache poisoned
   - With `dns-validate`: `dns_cache_add_secure()` rejects mismatched IP, audit logged
   - Demonstrates full attack→defense cycle via external tool

4. **Validation**
   - Send 50 forged responses → cache poisoned to fake IP (without defense)
   - Enable `dns-validate` → repeat attack → cache NOT poisoned
   - Audit log shows blocked attempts
   - `dig` confirms poisoned/clean cache from external client

---

### Phase 17 Sub-phase Summary

| Sub-phase | Component | Week | Output |
|-----------|-----------|------|--------|
| 17a | DNS response spoofing | Week 48 | Forged DNS replies redirect domains |
| 17b | DNS cache poisoning | Week 49 | Persistent cache corruption |
| 17c | DNS security defenses | Week 50 | Source port randomization + HMAC validation |
| 17d | External DNS cache poisoning | Week 50 | Kaminsky-style attack via raw socket |

---

## Phase 18: Buffer Overflow Exploitation (Week 51–53)

This phase is split into 3 sub-phases.

### Goals
- Demonstrate memory corruption vulnerabilities and exploitation
- Show how ASAN detects these issues
- Build exploit mitigations (stack canaries, bounds checking)

### Architecture

```
Attacker → oversized input → vulnerable app server → stack overflow
                                                      ↓
                                              Control flow hijacked
                                              (or ASAN catches it)
```

---

### Phase 18a: Vulnerable Application (Week 51)

#### Goals
- Create an intentionally vulnerable app server for exploitation practice

#### Tasks

1. **Vulnerable server (`ironapps/vuln_server.c`, port 9999)**
   - Uses `strcpy()` without bounds checking
   - Fixed-size stack buffer (64 bytes)
   - Reads user input directly into buffer
   - Classic stack buffer overflow vulnerability

2. **Vulnerability types**
   - Stack buffer overflow: input > 64 bytes overwrites return address
   - Format string: `printf(user_input)` without format specifier
   - Integer overflow: length field wraps around, causes small allocation + large copy

3. **Normal operation**
   - Send < 64 bytes → server processes normally
   - Send > 64 bytes → ASAN detects stack-buffer-overflow

4. **Validation**
   - Normal input: server responds correctly
   - Oversized input: ASAN report printed, server crashes (detected)
   - Without ASAN (Release build): undefined behavior / segfault

---

### Phase 18b: Exploit Development (Week 52)

#### Goals
- Write exploit payloads that trigger the vulnerability
- Demonstrate control flow hijacking concepts

#### Tasks

1. **Crash PoC (proof of concept)**
   ```bash
   # Send 128 'A's to overflow the 64-byte buffer
   python3 -c "print('A'*128)" | nc 10.0.1.1 9999
   ```
   - ASAN catches: `stack-buffer-overflow`
   - Without ASAN: segfault at address 0x41414141

2. **Pattern-based offset finding**
   - Send cyclic pattern (e.g., "Aa0Aa1Aa2...")
   - Identify exact offset where return address is overwritten
   - Tool: `ironattack exploit --target 10.0.1.1 --port 9999 --pattern 128`

3. **Payload crafting**
   - Overwrite return address with known value
   - Demonstrate: redirect execution to a different function
   - In IronNet context: call `iron_request_shutdown()` to prove code execution

4. **Validation**
   - Pattern identifies offset = 72 (64 buffer + 8 saved RBP)
   - Crafted payload overwrites return address → controlled crash
   - ASAN always catches it in Debug builds (safety net)

---

### Phase 18c: Exploit Mitigations (Week 53)

#### Goals
- Implement and demonstrate common exploit mitigations

#### Tasks

1. **Stack canary**
   - Place random value between buffer and return address
   - Check canary before function returns
   - If modified → abort (overflow detected)
   - `defense stack-canary enable`

2. **Bounds checking**
   - Replace `strcpy` with `strncpy` (safe version)
   - Validate input length before copy
   - Reject inputs exceeding buffer size

3. **ASLR simulation**
   - Randomize buffer addresses between connections
   - Attacker can't predict where to jump
   - Demonstrate: same exploit fails with randomization

4. **Comparison: with and without mitigations**
   | Mitigation | Exploit result |
   |-----------|----------------|
   | None (Release build) | Segfault / code execution |
   | ASAN (Debug build) | Detected + abort |
   | Stack canary | Detected + abort |
   | Bounds checking | Input rejected (no overflow) |
   | ASLR | Exploit fails (wrong address) |

5. **Validation**
   - Same exploit payload tested against each mitigation
   - Report: which mitigations prevent exploitation

---

### Phase 18 Sub-phase Summary

| Sub-phase | Component | Week | Output |
|-----------|-----------|------|--------|
| 18a | Vulnerable application | Week 51 | Intentionally buggy server for practice |
| 18b | Exploit development | Week 52 | Crash PoC, offset finding, payload crafting |
| 18c | Exploit mitigations | Week 53 | Stack canary, bounds check, ASLR simulation |

---

## Phase 19: Covert Channels & Traffic Analysis (Week 54–56)

This phase is split into 3 sub-phases.

### Goals
- Hide data within normal-looking network traffic
- Demonstrate steganographic communication techniques
- Build detection mechanisms for covert channels

### Architecture

```
Sender (covert)  ──hidden data──→  Receiver (covert)
       ↓                                    ↑
  Encodes data in:                    Decodes from:
  - ICMP payload                      - ICMP payload
  - TCP sequence numbers              - TCP sequence numbers
  - DNS TXT records                   - DNS TXT records
  - Packet timing                     - Packet timing
```

---

### Phase 19a: Data Hiding in Protocol Fields (Week 54)

#### Goals
- Encode secret messages in protocol fields that are normally ignored

#### Tasks

1. **ICMP covert channel**
   - Encode data in ICMP echo request payload (normally random/zero)
   - Sender: `ironattack covert-icmp --target 10.0.1.1 --message "secret"`
   - Receiver: extract message from ICMP payload
   - Looks like normal ping traffic to observers

2. **TCP ISN (Initial Sequence Number) channel**
   - Encode 32 bits of data per connection in the ISN
   - Sender opens connections with crafted sequence numbers
   - Receiver decodes ISN values to reconstruct message
   - Each SYN carries 4 bytes of hidden data

3. **DNS TXT record channel**
   - Encode data as base64 in DNS TXT queries
   - Query: `c2VjcmV0.covert.ironnet.local` (base64 of "secret")
   - DNS server decodes and stores the message
   - Looks like normal DNS traffic

4. **Validation**
   - Send hidden message via each channel
   - Receiver correctly decodes the message
   - Normal traffic inspection (tcpdump) doesn't reveal the secret

---

### Phase 19b: Timing-Based Covert Channels (Week 55)

#### Goals
- Encode data in packet timing (inter-packet delays)

#### Tasks

1. **Timing channel encoder**
   - Bit 1: send packet after 100ms delay
   - Bit 0: send packet after 10ms delay
   - Receiver measures inter-packet gaps to decode bits
   - Bandwidth: ~10 bits/second (slow but stealthy)

2. **Packet counting channel**
   - Encode data in the number of packets per time window
   - 1-5 packets = bit 0, 6-10 packets = bit 1
   - Even harder to detect than timing

3. **Storage channel (IP ID field)**
   - IP identification field is 16 bits, often sequential
   - Encode data by manipulating the ID increment pattern
   - Receiver observes ID values to extract hidden bits

4. **Validation**
   - Timing channel: message transmitted at ~10 bps
   - Packet counting: message transmitted at ~1 bps
   - Both channels invisible to simple packet inspection

---

### Phase 19c: Covert Channel Detection (Week 56)

#### Goals
- Build anomaly detectors that identify covert channel usage

#### Tasks

1. **ICMP payload analysis**
   - Normal ping: payload is pattern (0x00-0xFF repeating)
   - Covert: payload has high entropy (random-looking data)
   - Detector: flag ICMP packets with entropy > threshold

2. **Timing analysis**
   - Normal traffic: variable inter-packet gaps
   - Covert timing: bimodal distribution (10ms or 100ms)
   - Detector: statistical test for bimodal timing patterns

3. **TCP ISN analysis**
   - Normal: ISN is random (high entropy, no pattern)
   - Covert: ISN encodes data (may have structure)
   - Detector: check ISN randomness quality

4. **DNS query analysis**
   - Normal: queries for known domains
   - Covert: queries contain base64 data in subdomains
   - Detector: flag queries with high-entropy labels

5. **Defense integration**
   ```
   ironctl> defense covert-detect enable
   ```
   - Monitors all traffic for covert channel indicators
   - Audit log: `AUDIT_COVERT_CHANNEL` events

6. **Validation**
   - Covert channel active → detector fires alert
   - Normal traffic → no false positives
   - Report: detection rate vs false positive rate

---

### Phase 19 Sub-phase Summary

| Sub-phase | Component | Week | Output |
|-----------|-----------|------|--------|
| 19a | Data hiding (ICMP, TCP ISN, DNS) | Week 54 | 3 covert channel implementations |
| 19b | Timing-based channels | Week 55 | Timing + packet counting channels |
| 19c | Covert channel detection | Week 56 | Anomaly detectors + defense integration |

---

## Phase 20: Advanced L2 Attacks (Week 57–58)

This phase is split into 2 sub-phases.

### Goals
- Demonstrate L2 attacks that exploit switch/bridge behavior
- Show how MAC table overflow forces a bridge into hub mode
- Implement defenses (MAC limit, port security)

### Architecture

```
Attacker → floods random src MACs → Bridge MAC table overflows
                                     ↓
                              Bridge falls back to flooding
                                     ↓
                              Attacker sees ALL traffic (hub mode)
```

---

### Phase 20a: MAC Flooding Attack (Week 57)

#### Goals
- Overflow the bridge's MAC address table with random source MACs
- Force the bridge into hub mode (flood all frames to all ports)
- Demonstrate that the attacker can now see traffic between other hosts

#### Tasks

1. **MAC flood attack (`ironattack mac-flood`)**
   ```bash
   sudo ./ironattack mac-flood --target 10.0.1.1 --iface iron0 --count 1000 --rate 500
   ```
   - Generate Ethernet frames with random source MAC addresses
   - Each frame has a unique random src MAC (exhausts MAC table)
   - Send at high rate to fill the table before entries age out
   - Report: frames sent, estimated table fill percentage

2. **Bridge behavior under flood**
   - Before flood: bridge forwards unicast to learned port only
   - During flood: MAC table full → new MACs evict old entries
   - After table corrupted: legitimate traffic flooded to all ports
   - Attacker on any port now sees all traffic (like a hub)

3. **Validation**
   - Before flood: unicast frame A→B only reaches port with B
   - After flood: unicast frame A→B reaches ALL ports (including attacker)
   - Bridge stats show: `frames_flooded` increases dramatically

---

### Phase 20b: MAC Flood Defense — Port Security (Week 58)

#### Goals
- Implement port security: limit number of MACs learned per port
- Block MAC flooding by refusing to learn beyond the limit

#### Tasks

1. **Port security defense (`defense port-security enable`)**
   - Configurable max MACs per port (default: 32)
   - When limit reached: new source MACs on that port are dropped
   - Audit log: `AUDIT_MAC_FLOOD` event when limit exceeded
   - `defense port-security <max-macs>` CLI command

2. **MAC flood with defense enabled**
   - Attacker sends 1000 random MACs
   - Only first 32 are learned; remaining 968 frames dropped
   - Bridge continues forwarding unicast correctly (table not corrupted)
   - Legitimate traffic unaffected

3. **Validation**
   - Without defense: MAC table overflows, bridge floods everything
   - With defense: table stays at 32 entries, excess frames dropped
   - Audit log shows MAC flood attempts blocked

---

### Phase 20 Sub-phase Summary

| Sub-phase | Component | Week | Output |
|-----------|-----------|------|--------|
| 20a | MAC flooding attack | Week 57 | Bridge table overflow, hub mode |
| 20b | Port security defense | Week 58 | MAC limit per port, flood blocked |

---

## Phase 21: Stealth Port Scanning (Week 59–60)

This phase is split into 2 sub-phases.

### Goals
- Implement advanced port scanning techniques that evade detection
- Demonstrate how different TCP flag combinations reveal port state
- Show how decoy scanning hides the attacker's real IP

### Background

Standard SYN scanning (ironprobe-ext) is easily detected because SYN packets to closed ports generate RST responses, and firewalls log SYN attempts. Stealth scans use unusual TCP flag combinations that behave differently:

| Scan type | Flags sent | Open port response | Closed port response |
|-----------|-----------|-------------------|---------------------|
| SYN scan | SYN | SYN+ACK | RST |
| FIN scan | FIN | No response (silence) | RST |
| XMAS scan | FIN+PSH+URG | No response (silence) | RST |
| NULL scan | (none) | No response (silence) | RST |

**Key insight:** Open ports silently drop unexpected FIN/XMAS/NULL packets (no response). Closed ports respond with RST. So "no response" = open, "RST" = closed. This is the inverse of SYN scanning.

**Why stealth:** Many firewalls only log SYN packets (connection attempts). FIN/XMAS/NULL packets don't trigger connection tracking and may pass through stateless firewalls undetected.

---

### Phase 21a: FIN, XMAS, and NULL Scans (Week 59)

#### Goals
- Implement three stealth scan types in ironattack
- Demonstrate different responses from open vs closed ports

#### Tasks

1. **Stealth scan tool (`ironattack stealth-scan`)**
   ```bash
   sudo ./ironattack stealth-scan --target 10.0.1.1 --ports 1-100 --mode fin|xmas|null [--iface <name>]
   ```
   - FIN scan: send TCP packet with only FIN flag set
   - XMAS scan: send TCP packet with FIN+PSH+URG flags ("Christmas tree")
   - NULL scan: send TCP packet with no flags set
   - Listen for RST responses (closed) vs silence (open|filtered)
   - Report: open/closed/filtered per port

2. **Scan result interpretation**
   - RST received → port is CLOSED
   - No response (timeout) → port is OPEN or FILTERED
   - ICMP unreachable → port is FILTERED

3. **Comparison with SYN scan**
   - Run SYN scan and stealth scan against same target
   - Show that both identify the same open ports
   - Show that stealth scan generates fewer log entries

4. **Validation**
   - FIN scan: ports 7,53,6379,8080,9000,9999 show as open (no RST)
   - FIN scan: port 22 shows as closed (RST received) or filtered
   - XMAS and NULL scans produce same results as FIN scan

---

### Phase 21b: Decoy Scanning (Week 60)

#### Goals
- Hide the attacker's real IP among multiple fake source IPs
- Make it difficult for the target to identify the real scanner

#### Tasks

1. **Decoy scan tool (`ironattack stealth-scan --decoys`)**
   ```bash
   sudo ./ironattack stealth-scan --target 10.0.1.1 --ports 7,80,22 --mode syn \
       --decoys 10.0.1.50,10.0.1.51,10.0.1.52 [--iface <name>]
   ```
   - For each port: send SYN from real IP AND from each decoy IP
   - All SYNs sent in random order (real IP mixed among decoys)
   - Target sees SYN from 4 different IPs — can't tell which is real
   - Only the real IP receives the SYN+ACK (decoys don't respond)

2. **Decoy effectiveness**
   - Target's audit log shows SYN from 4 IPs for each port
   - Without additional analysis, defender can't identify the real scanner
   - Defense: rate limiting per-source helps but doesn't eliminate the problem

3. **Validation**
   - Scan with 3 decoys: target logs show 4 source IPs per port
   - Real scanner correctly identifies open/closed ports
   - Decoy IPs appear in audit log alongside real IP

---

### Phase 21 Sub-phase Summary

| Sub-phase | Component | Week | Output |
|-----------|-----------|------|--------|
| 21a | FIN/XMAS/NULL stealth scans | Week 59 | Stealth port discovery |
| 21b | Decoy scanning | Week 60 | Scanner IP obfuscation |

---

## Phase 22: TCP Session Hijacking (Week 61–62)

This phase is split into 2 sub-phases.

### Goals
- Demonstrate taking over an established TCP session
- Inject data into an active connection as if from the legitimate client
- Show how sequence number prediction enables session hijacking
- Implement defense: TCP timestamps and challenge ACKs

### Architecture

```
Client (10.0.1.2) ←→ Server (10.0.1.1:7 echo)
         ↑
    Attacker observes traffic (via MITM or sniffing)
    Learns: src_port, seq number, ack number
         ↓
    Attacker injects data packet:
      src_ip = client IP (spoofed)
      seq = predicted next sequence number
      payload = attacker's data
         ↓
    Server accepts data as if from client!
```

### Key difference from RST injection

- **RST injection** (Phase 13c): kills the connection (destructive)
- **Session hijacking** (Phase 22): injects data into the connection (constructive — attacker takes control)

---

### Phase 22a: TCP Session Hijacking Attack (Week 61)

#### Goals
- Inject data into an established TCP connection
- Demonstrate that the server processes attacker's data as legitimate

#### Tasks

1. **Session hijack tool (`ironattack session-hijack`)**
   ```bash
   sudo ./ironattack session-hijack --target 10.0.1.1 --port 7 \
       --client 10.0.1.2 --sport <port> --seq <n> --ack <n> \
       --inject "HIJACKED DATA" [--iface <name>]
   ```
   - Craft TCP data packet with:
     - Source IP = client's IP (spoofed)
     - Source port = client's port
     - Sequence number = next expected by server
     - ACK number = server's current seq
     - Payload = attacker's injected data
   - Server accepts the packet as part of the legitimate session
   - Echo server echoes back the injected data (proving acceptance)

2. **Sequence number prediction**
   - In IronNet, the server's initial seq is predictable (starts at 1000)
   - After handshake: client seq = 1001, server seq = 1001
   - After client sends N bytes: client seq = 1001 + N
   - Attacker who knows N can predict the next seq number
   - Tool accepts `--seq` and `--ack` for manual specification

3. **Attack workflow**
   ```
   Step 1: Client connects to echo server (port 7)
   Step 2: Client sends "hello" (5 bytes) → client seq advances to 1006
   Step 3: Attacker injects with seq=1006, ack=1006
   Step 4: Server accepts injected data, echoes it back
   Step 5: Client's next packet has wrong seq → connection desynchronized
   ```

4. **Validation**
   - Inject "HIJACKED" into echo session → server echoes "HIJACKED"
   - Server's TCP state shows advanced seq (accepted the data)
   - Original client is now desynchronized (its packets rejected)

---

### Phase 22b: Session Hijacking Defense (Week 62)

#### Goals
- Implement defenses that make session hijacking difficult or detectable

#### Tasks

1. **Challenge ACK defense**
   - When a data packet arrives with unexpected seq (out of window):
     - Don't silently drop — send a challenge ACK back
     - Challenge ACK contains the server's current seq/ack
     - Legitimate client responds correctly; attacker can't (doesn't see the ACK)
   - `defense challenge-ack enable`

2. **TCP window strictness**
   - Tighten the acceptable sequence number window
   - Only accept data within a narrow range of `rcv_nxt`
   - Reduces the attacker's guessing space
   - `defense tcp-strict-window enable`

3. **Connection anomaly detection**
   - Detect sequence number jumps (sudden large advance)
   - Detect duplicate data from different source (desynchronization indicator)
   - Audit log: `AUDIT_SESSION_HIJACK` event

4. **Validation**
   - Without defense: hijack succeeds, data injected
   - With challenge-ack: server sends challenge, attacker can't respond
   - With strict window: injected packet outside window → dropped
   - Audit log shows hijack attempt detected

---

### Phase 22 Sub-phase Summary

| Sub-phase | Component | Week | Output |
|-----------|-----------|------|--------|
| 22a | TCP session hijacking attack | Week 61 | Data injection into active session |
| 22b | Session hijacking defense | Week 62 | Challenge ACK + strict window |

---

## Summary Timeline (Updated)

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
| 11 | ironapps (socket API + target apps) | Week 25–28 |
| 12 | ironfuzz / ironprobe / ironload | Week 29–34 |
| 13 | Attack Simulation & Defense | Week 35–40 |
| 14 | ironsim (network emulator) | Week 41–42 |
| 15 | irontrace (capture/replay) | Week 43–44 |
| 16 | Man-in-the-Middle (MITM) | Week 45–47 |
| 17 | DNS Poisoning & Hijacking | Week 48–50 |
| 18 | Buffer Overflow Exploitation | Week 51–53 |
| 19 | Covert Channels & Traffic Analysis | Week 54–56 |
| 20 | Advanced L2 Attacks (MAC flooding) | Week 57–58 |
| 21 | Stealth Port Scanning | Week 59–60 |
| 22 | TCP Session Hijacking | Week 61–62 |

**Total estimated duration: ~16 months (part-time development)**

---

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

## Next Steps

1. ~~Set up WSL Ubuntu development environment~~ ✅
2. ~~Create Git repository with initial CMake skeleton~~ ✅
3. ~~Implement `common/` utilities and IRON_ASSERT framework~~ ✅
4. ~~Phase 2: TUN/TAP integration and L2 parsing~~ ✅
5. ~~Phase 3: L3 IP layer, routing table, ICMP~~ ✅
6. ~~Phase 4: ACL & PBR engines~~ ✅
7. ~~Phase 5: L4 UDP & TCP~~ ✅
8. ~~Phase 6: IPsec (simulated)~~ ✅
9. ~~Phase 7-22: All phases complete~~ ✅

**Project complete.** All 22 phases implemented, 32 tests passing, 42 demos, 16 attack subcommands, 15 defenses.

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
