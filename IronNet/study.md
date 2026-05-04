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
  sudo ./ironattack --syn-flood 10.0.1.1 --rate 1000
  sudo ./ironattack --arp-spoof 10.0.1.1 --gateway 10.0.1.254
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

### Tasks

1. **Attack tools — ironattack (separate binary)**

   Each attack is a subcommand:
   ```bash
   sudo ./ironattack syn-flood --target 10.0.1.1 --port 7 --rate 1000
   sudo ./ironattack arp-spoof --target 10.0.1.1 --impersonate 10.0.1.254
   sudo ./ironattack vlan-hop --target-vlan 20 --iface iron0
   sudo ./ironattack ip-spoof --src 10.0.99.1 --dst 10.0.1.1 --port 7
   sudo ./ironattack rst-inject --target 10.0.1.1 --port 7
   sudo ./ironattack icmp-redirect --target 10.0.1.1 --new-gw 10.0.1.99
   sudo ./ironattack slowloris --target 10.0.1.1 --port 8080 --conns 200
   sudo ./ironattack frag-attack --target 10.0.1.1 --overlap
   ```

   Attacks implemented:
   - **SYN flood**: send thousands of SYNs from random source IPs to exhaust connection table
   - **ARP spoofing**: inject fake ARP replies to poison the router's ARP table
   - **VLAN hopping**: craft double-tagged 802.1Q frames to escape VLAN isolation
   - **IP spoofing**: forge source IP to bypass source-based ACLs
   - **TCP RST injection**: send forged RST to tear down established connections
   - **ICMP redirect**: send fake ICMP redirect to manipulate routing
   - **Slowloris**: open many connections, send data slowly to exhaust resources
   - **Fragmentation attacks**: overlapping fragments, tiny fragments

2. **Defense mechanisms — irondefense (built into ironstack)**

   Defenses are enabled/disabled via CLI:
   ```
   ironctl> defense syn-cookies enable
   ironctl> defense rate-limit 100/s per-source
   ironctl> defense arp-inspection enable
   ironctl> defense vlan-strict enable
   ```

   Defenses implemented:
   - **SYN cookies**: stateless SYN handling under flood (no connection table entry until ACK)
   - **Rate limiting**: per-source connection rate caps (drop excess SYNs)
   - **Connection tracking**: stateful inspection (already in Phase 8d)
   - **Anomaly detection**: flag unusual patterns (invalid flags, unusual sizes)
   - **Blackhole routing**: drop traffic to known-bad destinations
   - **ARP inspection**: validate ARP against known IP-MAC bindings
   - **VLAN strict mode**: reject double-tagged frames on access ports

3. **External scanner — ironprobe-ext (separate binary)**

   Real network scanning (sends actual SYN packets):
   ```bash
   sudo ./ironprobe-ext --target 10.0.1.1 --ports 1-65535 --iface iron0
   sudo ./ironprobe-ext --target 10.0.1.1 --udp --ports 53,67,123
   ```

4. **Penetration testing workflow**
   - **Reconnaissance**: `ironprobe-ext` scans to discover services and ACL gaps
   - **Enumeration**: identify open ports, protocol versions, service fingerprints
   - **Exploitation**: `ironattack` tests specific vulnerabilities
   - **Post-exploitation**: verify what access was gained, lateral movement
   - **Reporting**: automated test results with pass/fail per defense

5. **Attack-defense matrix**

   | Attack | Defense | Metric |
   |--------|---------|--------|
   | SYN flood | SYN cookies + rate limit | Connection table usage under attack |
   | ARP spoofing | ARP inspection | Poisoned entries detected/blocked |
   | VLAN hopping | VLAN strict mode | Double-tagged frames dropped |
   | IP spoofing | Source IP validation (uRPF) | Spoofed packets dropped |
   | TCP RST injection | Connection tracking | Forged RSTs rejected |
   | ICMP redirect | ICMP redirect disable | Routing table unchanged |
   | Slowloris | Connection timeout + rate limit | Resources recovered |
   | Fragmentation | Fragment validation | Overlapping/tiny frags dropped |

6. **Validation**
   - SYN flood with/without SYN cookies: measure connection table behavior
   - VLAN hopping attempt with/without strict trunk mode
   - ARP spoofing with/without ARP inspection
   - TCP RST injection with/without connection tracking
   - Full penetration test report generated automatically
   - Each attack/defense pair tested independently

### Summarization

1. Key difference table — Phase 12 (internal, generic) vs Phase 13 (external, specific attacks, real packets)
2. Architecture diagram — 3 terminals: router, attacker, monitor
3. External attack tools (ironattack separate binary) with 8 subcommands:
   * syn-flood, arp-spoof, vlan-hop, ip-spoof, rst-inject, icmp-redirect, slowloris, frag-attack
4. Defense mechanisms (irondefense built into ironstack) with CLI commands:
   * defense syn-cookies enable, defense rate-limit 100/s, defense arp-inspection enable, etc.
5. External scanner (ironprobe-ext separate binary) — real SYN packets via TAP
6. Attack-defense matrix — maps each attack to its defense with measurable metrics
7. Penetration testing workflow — reconnaissance → enumeration → exploitation → post-exploitation → reporting

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
| 11 | ironapps (socket API + target apps) | Week 25–28 |
| 12 | ironfuzz / ironprobe / ironload | Week 29–34 |
| 13 | Attack Simulation & Defense | Week 35–40 |
| 14 | ironsim (emulator) | Week 41–42 |
| 15 | irontrace (capture/replay) | Week 43–44 |

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
