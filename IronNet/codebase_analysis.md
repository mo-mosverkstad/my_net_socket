# IronNet — Codebase Analysis & Security Education Guide

A comprehensive guide for beginners covering networking fundamentals, hacking techniques, cybersecurity concepts, and a complete walkthrough of the IronNet source code, architecture, and deployment.

---

## Table of Contents

### Part I: Networking Fundamentals

**1. The OSI Model and TCP/IP Stack**
- 1.1 Seven layers explained (Physical → Application)
- 1.2 TCP/IP four-layer model (Link → Application)
- 1.3 How data flows through layers (encapsulation/decapsulation)
- 1.4 Where IronNet fits in the model

**2. Layer 2: Ethernet and Switching**
- 2.1 Ethernet frame format (MAC addresses, EtherType, payload)
- 2.2 MAC address learning and forwarding
- 2.3 VLANs (802.1Q tagging, access/trunk ports)
- 2.4 ARP (Address Resolution Protocol)
- 2.5 Bridging vs routing

**3. Layer 3: IP and Routing**
- 3.1 IPv4 header format (every field explained)
- 3.2 IP addressing and subnets (CIDR notation)
- 3.3 Routing tables and longest-prefix match
- 3.4 TTL and packet lifetime
- 3.5 IP fragmentation and reassembly
- 3.6 ICMP (ping, traceroute, error messages)

**4. Layer 4: Transport Protocols**
- 4.1 UDP (connectionless, header format, use cases)
- 4.2 TCP (connection-oriented, header format, flags)
- 4.3 TCP 3-way handshake (SYN, SYN+ACK, ACK)
- 4.4 TCP state machine (CLOSED → ESTABLISHED → TIME_WAIT)
- 4.5 TCP sequence numbers and acknowledgments
- 4.6 TCP window and flow control

**5. Network Security Fundamentals**
- 5.1 ACLs (Access Control Lists) and firewalls
- 5.2 NAT (Network Address Translation)
- 5.3 Connection tracking (stateful filtering)
- 5.4 IPsec (authentication and encryption)
- 5.5 Defense in depth principle

**6. DNS (Domain Name System)**
- 6.1 DNS query/response format
- 6.2 Record types (A, AAAA, CNAME, TXT)
- 6.3 Recursive vs authoritative resolution
- 6.4 DNS caching and TTL
- 6.5 DNSSEC overview

### Part II: Hacking Techniques and Cybersecurity

**7. Reconnaissance and Scanning**
- 7.1 Port scanning (SYN scan, connect scan)
- 7.2 Stealth scanning (FIN, XMAS, NULL scans)
- 7.3 Decoy scanning and IP obfuscation
- 7.4 Service fingerprinting
- 7.5 OS fingerprinting (TTL/window analysis)

**8. Layer 2 Attacks**
- 8.1 ARP spoofing (cache poisoning, MITM setup)
- 8.2 MAC flooding (CAM table overflow → hub mode)
- 8.3 VLAN hopping (double-tagging attack)
- 8.4 DHCP starvation and rogue DHCP (concept)

**9. Layer 3/4 Attacks**
- 9.1 SYN flood (resource exhaustion DoS)
- 9.2 IP spoofing (source authentication bypass)
- 9.3 TCP RST injection (connection killing)
- 9.4 TCP session hijacking (data injection)
- 9.5 ICMP redirect (routing manipulation)
- 9.6 IP fragmentation attacks (overlapping, tiny fragments)
- 9.7 Slowloris (application-layer connection exhaustion)

**10. DNS Attacks**
- 10.1 DNS response spoofing (forged replies)
- 10.2 DNS cache poisoning (Kaminsky attack)
- 10.3 DNS tunneling (data exfiltration via queries)

**11. Man-in-the-Middle (MITM)**
- 11.1 ARP-based MITM setup
- 11.2 Traffic interception and logging
- 11.3 In-transit data modification
- 11.4 MITM detection (MAC flapping, latency anomalies)

**12. Memory Exploitation**
- 12.1 Stack buffer overflow (strcpy vulnerability)
- 12.2 Format string attacks (%x, %p, %n)
- 12.3 Integer overflow/truncation
- 12.4 Return address overwrite (RIP control)
- 12.5 Exploit development workflow (crash → pattern → payload)
- 12.6 Mitigations (stack canary, ASLR, bounds checking, ASAN)

**13. Covert Channels and Evasion**
- 13.1 Storage channels (ICMP payload, TCP ISN, DNS subdomain, IP ID)
- 13.2 Timing channels (inter-packet delay, packet counting)
- 13.3 Covert channel detection (entropy analysis, timing bimodality, ASCII ratio)
- 13.4 Firewall evasion techniques (fragmentation, protocol tunneling)

**14. Defense Mechanisms**
- 14.1 SYN cookies (stateless SYN handling)
- 14.2 Rate limiting (per-source throttling)
- 14.3 ARP inspection (trusted bindings)
- 14.4 uRPF (source IP validation)
- 14.5 RST validation (sequence number check)
- 14.6 Connection idle timeout (slowloris defense)
- 14.7 Fragment strict mode (overlap/tiny rejection)
- 14.8 ICMP redirect disable
- 14.9 DNS validation (zone-based cache protection)
- 14.10 Port security (MAC limit per port)
- 14.11 Covert channel detection (anomaly-based)
- 14.12 Challenge ACK (session hijacking defense)

### Part III: IronNet Architecture and Design

**15. System Architecture Overview**
- 15.1 Component diagram (ironstack, ironctl, ironmon, ironapps, ironattack, ironsim, irontrace)
- 15.2 Data plane vs control plane separation
- 15.3 Packet processing pipeline (L2 → L3 → L4 → App)
- 15.4 Event-driven main loop (non-blocking I/O)
- 15.5 Thread model (main loop + CLI thread)

**16. Virtual Network I/O (TUN/TAP)**
- 16.1 What is TUN vs TAP
- 16.2 How /dev/net/tun works on Linux
- 16.3 IFF_TAP | IFF_NO_PI flags
- 16.4 Non-blocking read/write
- 16.5 Multiple TAP interfaces (iron0, iron1)
- 16.6 Linux-side configuration (ip addr, ip link)

**17. Build System and Project Structure**
- 17.1 CMake configuration (Debug/Release, ASAN)
- 17.2 Directory layout (src/, build/, demos/, configs/)
- 17.3 Library targets (iron_common, iron_cli, iron_mon, iron_apps, etc.)
- 17.4 Binary targets (ironstack, ironattack, ironmitm, ironsim, etc.)
- 17.5 Test infrastructure (unit tests, module tests, CTest)
- 17.6 WSL path spaces workaround (symlink)

**18. Configuration System**
- 18.1 router.conf format (interface, route, acl lines)
- 18.2 Config parser implementation
- 18.3 Runtime CLI configuration (ironctl commands)
- 18.4 Defense enable/disable at runtime

### Part IV: Source Code Walkthrough

**19. Common Utilities (`src/common/`)**
- 19.1 `types.h` — network types, enums, drop reasons
- 19.2 `log.h/c` — timestamped leveled logging
- 19.3 `stats.h/c` — global counter infrastructure
- 19.4 `utils.h/c` — byte-order, checksum, IP string conversion
- 19.5 `assert.h` — IRON_ASSERT invariant enforcement

**20. Protocol Stack Core (`src/ironstack/`)**
- 20.1 `main.c` — daemon entry point, signal handling, main loop
- 20.2 `core/pipeline.c` — packet processing loop, timer ticks
- 20.3 `core/iface.c` — interface configuration model
- 20.4 `core/router_conf.c` — config file parser
- 20.5 `io/vnic.c` — TAP device abstraction

**21. Layer 2 Implementation (`src/ironstack/l2/`)**
- 21.1 `eth.c` — Ethernet frame parse/build/dispatch
- 21.2 `arp.c` — ARP table, request/reply, inspection
- 21.3 `vlan.c` — 802.1Q tag insert/strip, access/trunk ports
- 21.4 `bridge.c` — MAC learning, unicast forwarding, flooding

**22. Layer 3 Implementation (`src/ironstack/l3/`)**
- 22.1 `ip.c` — IP input/output, validation, forwarding
- 22.2 `route.c` — routing table, longest-prefix match
- 22.3 `route_table.c` — multiple named routing tables (VRF-lite)
- 22.4 `acl.c` — access control list, first-match evaluation
- 22.5 `pbr.c` — policy-based routing, loop detection
- 22.6 `icmp.c` — echo request/reply, redirect handling
- 22.7 `ip_frag.c` — fragmentation and reassembly
- 22.8 `conntrack.c` — connection tracking (NEW/ESTABLISHED/INVALID)
- 22.9 `nat.c` — SNAT/DNAT, port allocation, return-path translation

**23. Layer 4 Implementation (`src/ironstack/l4/`)**
- 23.1 `tcp.c` — TCP state machine, connection table, SYN cookies, output
- 23.2 `udp.c` — stateless UDP dispatch

**24. Security Module (`src/ironstack/security/`)**
- 24.1 `defense.c` — defense registry, SYN cookies, rate limiting
- 24.2 `ipsec.c` — SA lifecycle, policy enforcement, XOR transform
- 24.3 `covert_detect.c` — entropy analysis, timing bimodality, ISN/DNS detection

**25. Application Servers (`src/ironapps/`)**
- 25.1 `app_socket.c` — socket API, listener registry, TCP/UDP output
- 25.2 `echo_server.c` — TCP/UDP echo (port 7)
- 25.3 `dns_server.c` — DNS server with zone table, cache, response builder
- 25.4 `kv_server.c` — key-value store (port 6379)
- 25.5 `http_server.c` — HTTP-like server (port 8080)
- 25.6 `rpc_server.c` — binary RPC protocol (port 9000)
- 25.7 `vuln_server.c` — intentionally vulnerable server (port 9999)

**26. Attack Tools (`src/ironattack/`)**
- 26.1 `main.c` — subcommand dispatch (12 commands)
- 26.2 `craft.c` — raw packet construction (TCP, ARP, ICMP, IP fragments)
- 26.3 `dns_spoof_ext.c` — external DNS cache poisoning (Kaminsky-style)
- 26.4 `exploit.c` — buffer overflow exploitation (crash, pattern, payload, fmtstr)
- 26.5 `covert.c` — 6 covert channel implementations
- 26.6 `mitm.c` — MITM relay engine (ARP poison + sniff + modify + forward)

**27. Supporting Tools**
- 27.1 `ironctl/cli.c` — embedded CLI (commands, thread, dispatch)
- 27.2 `ironmon/audit.c` — audit ring buffer, file output, JSON export
- 27.3 `ironmon/stats_json.c` — JSON stats export
- 27.4 `ironprobe/probe.c` — internal port scanner
- 27.5 `ironfuzz/fuzz.c` — mutation engine, corpus, seed generators
- 27.6 `ironload/load.c` — stress tester (TCP flood, route/ACL stress)
- 27.7 `irontrace/trace.c` — pcap capture with pipeline hooks
- 27.8 `irontrace/replay.c` — pcap replay via raw socket
- 27.9 `ironsim/main.c` — network emulator (multi-node topology)
- 27.10 `ironsim/test_traffic.c` — traffic generator and report
- 27.11 `ironprobe_ext/main.c` — external SYN scanner
- 27.12 `ironprobe_ext/report.c` — automated attack-defense report

**28. Test Infrastructure (`src/tests/`)**
- 28.1 Test philosophy (unit vs module vs interactive)
- 28.2 Stub pattern (defense_stub, audit_stub, trace_stub, covert_stub, etc.)
- 28.3 Module test framework (`module_test.h`)
- 28.4 Unit test listing (21 tests, what each validates)
- 28.5 Module test listing (11 tests, what each demonstrates)

### Part V: Deployment and Usage

**29. Building IronNet**
- 29.1 Prerequisites (WSL2, Ubuntu, GCC, CMake)
- 29.2 Debug build (with ASAN)
- 29.3 Release build (optimized)
- 29.4 Running tests (ctest)
- 29.5 Troubleshooting common build issues

**30. Running the Virtual Router**
- 30.1 Starting ironstack with config file
- 30.2 Linux-side TAP setup (ip addr, ip link)
- 30.3 CLI usage (ironctl prompt)
- 30.4 Verifying connectivity (ping, dig, nc)

**31. Running Attack Tools**
- 31.1 ironattack subcommands overview
- 31.2 Attack workflow (reconnaissance → exploitation → post-exploitation)
- 31.3 Defense enable/disable workflow
- 31.4 Attack-defense report (ironreport)

**32. Network Emulation (ironsim)**
- 32.1 Topology configuration format
- 32.2 2-node and 3-node topologies
- 32.3 Link impairments (delay, loss, reorder)
- 32.4 Traffic testing (ironsim-test)

**33. Packet Capture and Replay (irontrace)**
- 33.1 Starting/stopping capture
- 33.2 pcap format and Wireshark compatibility
- 33.3 Replay modes (timed vs fast, internal vs external)
- 33.4 Regression testing workflow

**34. Demo Guide**
- 34.1 Demo file organization (36 self-contained demos)
- 34.2 Quick reference: which demo for which topic
- 34.3 Recommended learning path for beginners

### Part VI: Appendices

**35. Glossary of Terms**
- Network terminology (MTU, TTL, CIDR, NAT, etc.)
- Security terminology (CVE, CWE, ASLR, ROP, etc.)
- IronNet-specific terminology (ironstack, ironctl, etc.)

**36. Protocol Reference Tables**
- Ethernet frame format (byte offsets)
- IPv4 header format (byte offsets)
- TCP header format (byte offsets)
- UDP header format (byte offsets)
- ICMP header format (byte offsets)
- DNS message format (byte offsets)
- ARP packet format (byte offsets)

**37. Attack-Defense Matrix**
- Complete table: all attacks, their defenses, and effectiveness metrics

**38. Port and Service Map**
- All IronNet services with ports, protocols, and purpose

**39. References and Further Reading**
- RFCs (791, 793, 826, 1035, etc.)
- Security resources (OWASP, MITRE ATT&CK, CWE)
- Books (TCP/IP Illustrated, Hacking: Art of Exploitation, etc.)

---


## 1. The OSI Model and TCP/IP Stack

### 1.1 Seven Layers Explained (Physical → Application)

The OSI (Open Systems Interconnection) model divides network communication into 7 layers. Each layer has a specific responsibility and communicates only with the layers directly above and below it.

```
Layer 7: Application    — HTTP, DNS, FTP, SMTP (user-facing protocols)
Layer 6: Presentation   — Encryption, compression, data format translation
Layer 5: Session        — Session management, authentication
Layer 4: Transport      — TCP, UDP (end-to-end delivery, ports)
Layer 3: Network        — IP, ICMP, routing (logical addressing, forwarding)
Layer 2: Data Link      — Ethernet, ARP, VLANs (physical addressing, frames)
Layer 1: Physical       — Cables, radio waves, electrical signals
```

**Why layers matter:** Each layer solves one problem. Layer 3 doesn't care whether the physical medium is copper, fiber, or wireless — it just hands a packet to Layer 2 and trusts it to deliver. This separation allows independent evolution (e.g., switching from Ethernet to WiFi doesn't require changing TCP).

### 1.2 TCP/IP Four-Layer Model (Link → Application)

In practice, the Internet uses a simplified 4-layer model:

```
┌─────────────────────────────────────────────────────────┐
│ Application Layer (HTTP, DNS, SSH, FTP)                  │  ← OSI 5-7
├─────────────────────────────────────────────────────────┤
│ Transport Layer (TCP, UDP)                               │  ← OSI 4
├─────────────────────────────────────────────────────────┤
│ Internet Layer (IP, ICMP, ARP)                           │  ← OSI 3
├─────────────────────────────────────────────────────────┤
│ Link Layer (Ethernet, WiFi, PPP)                         │  ← OSI 1-2
└─────────────────────────────────────────────────────────┘
```

The TCP/IP model merges OSI layers 5-7 into "Application" and layers 1-2 into "Link" because the distinctions between them are rarely important in practice.

### 1.3 How Data Flows Through Layers (Encapsulation/Decapsulation)

When you send data (e.g., an HTTP request), each layer wraps it with its own header:

```
Sending (encapsulation — top to bottom):

Application:  [HTTP GET /index.html]
Transport:    [TCP header][HTTP GET /index.html]
Network:      [IP header][TCP header][HTTP GET /index.html]
Link:         [Eth header][IP header][TCP header][HTTP GET /index.html][Eth trailer]
```

```
Receiving (decapsulation — bottom to top):

Link:         strips Ethernet header → passes IP packet up
Network:      strips IP header → passes TCP segment up
Transport:    strips TCP header → passes HTTP data up
Application:  processes HTTP request
```

Each layer only reads its own header and passes the rest upward. This is why a router (Layer 3 device) doesn't need to understand HTTP — it only looks at the IP header to make forwarding decisions.

**Terminology by layer:**
- Layer 2: **Frame** (Ethernet frame)
- Layer 3: **Packet** (IP packet)
- Layer 4: **Segment** (TCP segment) or **Datagram** (UDP datagram)
- Layer 7: **Message** (application data)

### 1.4 Where IronNet Fits in the Model

IronNet implements a complete protocol stack from Layer 2 through Layer 7:

```
┌─────────────────────────────────────────────────────────┐
│ Application: echo, DNS, KV, HTTP, RPC, vuln servers     │  ironapps/
├─────────────────────────────────────────────────────────┤
│ Transport: TCP state machine, UDP dispatch               │  ironstack/l4/
├─────────────────────────────────────────────────────────┤
│ Network: IP, ICMP, routing, ACL, PBR, NAT, conntrack    │  ironstack/l3/
├─────────────────────────────────────────────────────────┤
│ Data Link: Ethernet, ARP, VLAN, Bridge                   │  ironstack/l2/
├─────────────────────────────────────────────────────────┤
│ Physical: Linux TUN/TAP virtual interface                │  ironstack/io/
└─────────────────────────────────────────────────────────┘
```

IronNet replaces the kernel's network stack with its own userspace implementation. Packets enter via a TAP device (virtual Ethernet interface), flow through IronNet's L2→L3→L4→App pipeline, and responses exit back through the TAP device to the kernel.

This architecture allows us to:
- Instrument every layer (trace hooks, counters, audit logs)
- Inject attacks at any point in the pipeline
- Study protocol behavior without affecting the host system
- Run multiple instances (ironsim) for topology emulation

---


## 2. Layer 2: Ethernet and Switching

### 2.1 Ethernet Frame Format

Every piece of data on a local network is wrapped in an Ethernet frame:

```
┌──────────┬──────────┬───────────┬─────────────────────┬─────────┐
│ Dst MAC  │ Src MAC  │ EtherType │ Payload (46-1500 B) │ FCS     │
│ 6 bytes  │ 6 bytes  │ 2 bytes   │                     │ 4 bytes │
└──────────┴──────────┴───────────┴─────────────────────┴─────────┘
 Offset: 0      6         12          14                    end
```

- **Destination MAC** (6 bytes): who should receive this frame (FF:FF:FF:FF:FF:FF = broadcast)
- **Source MAC** (6 bytes): who sent this frame
- **EtherType** (2 bytes): what's inside the payload
  - `0x0800` = IPv4
  - `0x0806` = ARP
  - `0x8100` = VLAN-tagged frame (802.1Q)
  - `0x86DD` = IPv6
- **Payload** (46-1500 bytes): the actual data (IP packet, ARP request, etc.)
- **FCS** (4 bytes): Frame Check Sequence (CRC32 for error detection, handled by hardware)

**MAC address format:** `02:00:00:00:00:01` — 6 bytes written as hex pairs separated by colons. The first byte's least significant bit indicates unicast (0) vs multicast (1).

**In IronNet:** `eth.c` parses and builds Ethernet frames. The FCS is not used (TAP devices handle it transparently).

### 2.2 MAC Address Learning and Forwarding

A **switch** (or bridge) learns which MAC addresses are reachable on which port:

```
1. Frame arrives on Port 1 with src MAC = AA:BB:CC:DD:EE:01
   → Switch learns: "AA:BB:CC:DD:EE:01 is on Port 1"

2. Frame arrives on Port 2 with src MAC = AA:BB:CC:DD:EE:02
   → Switch learns: "AA:BB:CC:DD:EE:02 is on Port 2"

3. Frame arrives on Port 1 destined for AA:BB:CC:DD:EE:02
   → Switch looks up table: "AA:BB:CC:DD:EE:02 is on Port 2"
   → Forward ONLY to Port 2 (not flooded to all ports)
```

**Forwarding decisions:**
- **Known unicast:** destination MAC in table → forward to learned port only
- **Unknown unicast:** destination MAC NOT in table → flood to all ports (except ingress)
- **Broadcast** (FF:FF:FF:FF:FF:FF): flood to all ports (except ingress)

**Aging:** Entries expire after a timeout (typically 300 seconds). If a device moves to a different port, the old entry ages out and a new one is learned.

**In IronNet:** `bridge.c` implements MAC learning with a 256-entry table, aging, and VLAN-aware forwarding.

### 2.3 VLANs (802.1Q Tagging)

A **VLAN** (Virtual LAN) divides one physical network into multiple isolated broadcast domains. Devices in VLAN 10 cannot communicate at Layer 2 with devices in VLAN 20.

**802.1Q tag format** (4 bytes inserted between src MAC and EtherType):

```
Normal frame:  [Dst MAC][Src MAC][EtherType][Payload]
Tagged frame:  [Dst MAC][Src MAC][0x8100][TCI][EtherType][Payload]
                                   TPID   ↑
                                          └── PCP(3 bits) + DEI(1 bit) + VID(12 bits)
```

- **TPID** = 0x8100 (identifies this as a VLAN-tagged frame)
- **VID** = VLAN Identifier (0-4095, 12 bits → 4094 usable VLANs)

**Port modes:**
- **Access port:** connects to end devices. Frames are untagged on the wire. The switch assigns a VLAN internally.
- **Trunk port:** connects switches together. Frames carry VLAN tags so multiple VLANs share one link.

**In IronNet:** `vlan.c` handles tag insertion (egress on trunk), tag stripping (ingress from trunk), and VLAN-based isolation.

### 2.4 ARP (Address Resolution Protocol)

ARP maps IP addresses to MAC addresses. When a device wants to send an IP packet to 10.0.1.5, it needs to know the MAC address of 10.0.1.5 to build the Ethernet frame.

**ARP request/reply flow:**
```
1. Host A wants to reach 10.0.1.5 but doesn't know its MAC
2. Host A broadcasts: "Who has 10.0.1.5? Tell 10.0.1.1" (ARP Request)
3. Host B (10.0.1.5) responds: "10.0.1.5 is at 02:00:00:00:00:05" (ARP Reply)
4. Host A caches: 10.0.1.5 → 02:00:00:00:00:05
5. Host A can now build the Ethernet frame with correct dst MAC
```

**ARP packet format (28 bytes after Ethernet header):**
```
[HW Type: 2B][Proto Type: 2B][HW Len: 1B][Proto Len: 1B][Operation: 2B]
[Sender MAC: 6B][Sender IP: 4B][Target MAC: 6B][Target IP: 4B]
```

**Security issue:** ARP has no authentication. Anyone can send a fake ARP reply claiming any IP belongs to their MAC. This is the basis of ARP spoofing attacks.

**In IronNet:** `arp.c` implements the ARP table (128 entries, 300s timeout), request/reply handling, and ARP inspection defense.

### 2.5 Bridging vs Routing

| Aspect | Bridge (L2) | Router (L3) |
|--------|-------------|-------------|
| Operates on | MAC addresses | IP addresses |
| Forwards based on | MAC table lookup | Routing table lookup |
| Broadcast domain | Same (bridges don't block broadcasts) | Separate (routers block broadcasts) |
| Connects | Devices in same subnet | Different subnets |
| Example | Switch connecting PCs | Gateway connecting LAN to Internet |

**In IronNet:** The virtual router operates at L3 (routing between iron0 and iron1 subnets). The bridge module operates at L2 (forwarding within a VLAN).

---


## 3. Layer 3: IP and Routing

### 3.1 IPv4 Header Format (Every Field Explained)

The IPv4 header is 20 bytes minimum (up to 60 bytes with options):

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│Version│  IHL  │    TOS        │         Total Length              │ Byte 0-3
├───────┼───────┼───────────────┼───────────────────────────────────┤
│         Identification        │Flags│    Fragment Offset          │ Byte 4-7
├───────────────────────────────┼─────┼─────────────────────────────┤
│      TTL      │   Protocol    │       Header Checksum             │ Byte 8-11
├───────────────┼───────────────┼───────────────────────────────────┤
│                       Source IP Address                            │ Byte 12-15
├───────────────────────────────────────────────────────────────────┤
│                    Destination IP Address                          │ Byte 16-19
└───────────────────────────────────────────────────────────────────┘
```

| Field | Size | Purpose |
|-------|------|---------|
| Version | 4 bits | Always 4 for IPv4 |
| IHL | 4 bits | Header length in 32-bit words (min 5 = 20 bytes) |
| TOS | 8 bits | Type of Service / DSCP (QoS marking) |
| Total Length | 16 bits | Entire packet size (header + payload) in bytes |
| Identification | 16 bits | Unique ID for fragment reassembly |
| Flags | 3 bits | DF (Don't Fragment), MF (More Fragments) |
| Fragment Offset | 13 bits | Position of this fragment (in 8-byte units) |
| TTL | 8 bits | Time To Live — decremented at each hop, dropped at 0 |
| Protocol | 8 bits | What's inside: 1=ICMP, 6=TCP, 17=UDP |
| Checksum | 16 bits | Header integrity check (recomputed after TTL change) |
| Source IP | 32 bits | Sender's IP address |
| Destination IP | 32 bits | Receiver's IP address |

**In IronNet:** `ip.c` validates all these fields on input and constructs them on output. The checksum is computed using RFC 1071 one's complement sum.

### 3.2 IP Addressing and Subnets (CIDR Notation)

An IPv4 address is 32 bits, written as four decimal octets: `10.0.1.1`

**CIDR (Classless Inter-Domain Routing):** `10.0.1.0/24` means:
- First 24 bits = network portion (10.0.1)
- Last 8 bits = host portion (0-255)
- Subnet mask: 255.255.255.0

**Common prefixes:**
| CIDR | Subnet Mask | Hosts | Use |
|------|-------------|-------|-----|
| /32 | 255.255.255.255 | 1 | Single host route |
| /24 | 255.255.255.0 | 254 | Typical LAN |
| /16 | 255.255.0.0 | 65534 | Large network |
| /0 | 0.0.0.0 | All | Default route |

**In IronNet:** `ip_prefix_t` stores address + prefix length. `iron_ip_matches()` checks if an IP belongs to a prefix using bitwise AND with the computed mask.

### 3.3 Routing Tables and Longest-Prefix Match

A routing table maps destination prefixes to next-hop addresses and output interfaces:

```
Destination      Next-Hop       Interface
10.0.1.0/24      0.0.0.0        iron0      (connected — direct delivery)
10.0.2.0/24      0.0.0.0        iron1      (connected)
0.0.0.0/0        10.0.1.254     iron0      (default route — catch-all)
```

**Longest-prefix match:** When multiple routes match, the most specific one wins:
- Packet to `10.0.1.5`: matches `/24` (specific) AND `/0` (default) → uses `/24`
- Packet to `8.8.8.8`: only matches `/0` → uses default route

**In IronNet:** `route.c` implements a linear-scan FIB with longest-prefix match. `route_table.c` extends this to multiple named tables (VRF-lite).

### 3.4 TTL and Packet Lifetime

**TTL (Time To Live)** prevents packets from looping forever:
1. Sender sets TTL (typically 64 or 128)
2. Each router decrements TTL by 1
3. If TTL reaches 0 → packet is dropped, ICMP "Time Exceeded" sent back
4. This is how `traceroute` works: send packets with TTL=1, 2, 3... and collect the "Time Exceeded" replies from each hop

**In IronNet:** `ip_input()` checks TTL > 0 on arrival, decrements before forwarding, and drops if it reaches 0.

### 3.5 IP Fragmentation and Reassembly

When a packet is larger than the link's MTU (Maximum Transmission Unit, typically 1500 bytes), it must be fragmented:

```
Original packet (3000 bytes):
  [IP header][3000 bytes payload]

After fragmentation (MTU=1500):
  Fragment 1: [IP header, MF=1, offset=0   ][1480 bytes]
  Fragment 2: [IP header, MF=1, offset=1480][1480 bytes]
  Fragment 3: [IP header, MF=0, offset=2960][40 bytes]
```

- **MF flag** (More Fragments): set on all fragments except the last
- **Fragment Offset**: position in the original packet (in 8-byte units)
- **Identification**: same value for all fragments of one packet

**Reassembly:** The destination collects all fragments with the same ID, orders them by offset, and reconstructs the original packet.

**Security issues:**
- Overlapping fragments can confuse reassembly (teardrop attack)
- Tiny fragments can evade IDS inspection (fragment too small to contain TCP header)

**In IronNet:** `ip_frag.c` implements both fragmentation and reassembly with security checks (reject overlapping, reject tiny, timeout incomplete).

### 3.6 ICMP (Ping, Traceroute, Error Messages)

ICMP (Internet Control Message Protocol) carries diagnostic and error messages:

| Type | Code | Name | Purpose |
|------|------|------|---------|
| 0 | 0 | Echo Reply | Response to ping |
| 3 | 0-15 | Destination Unreachable | No route, port closed, etc. |
| 5 | 0-3 | Redirect | "Use a different gateway" |
| 8 | 0 | Echo Request | Ping |
| 11 | 0 | Time Exceeded | TTL expired (traceroute) |

**Ping:** Send Echo Request (type=8), receive Echo Reply (type=0). Measures round-trip time.

**In IronNet:** `icmp.c` handles Echo Request→Reply and ICMP Redirect (with defense to ignore redirects).

---


## 4. Layer 4: Transport Protocols

### 4.1 UDP (Connectionless, Header Format, Use Cases)

UDP (User Datagram Protocol) is the simplest transport protocol — it adds only 8 bytes of overhead:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─────────────────────────────────┼─────────────────────────────────┤
│         Source Port             │       Destination Port          │ Byte 0-3
├─────────────────────────────────┼─────────────────────────────────┤
│           Length                │          Checksum               │ Byte 4-7
└─────────────────────────────────┴─────────────────────────────────┘
```

**Properties:**
- No connection setup (no handshake)
- No delivery guarantee (packets can be lost, duplicated, reordered)
- No flow control (sender can overwhelm receiver)
- Very fast (minimal overhead)

**Use cases:** DNS (port 53), streaming video, gaming, VoIP — where speed matters more than reliability.

**In IronNet:** `udp.c` parses the header and dispatches to registered applications by destination port.

### 4.2 TCP (Connection-Oriented, Header Format, Flags)

TCP (Transmission Control Protocol) provides reliable, ordered delivery:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─────────────────────────────────┼─────────────────────────────────┤
│         Source Port             │       Destination Port          │ Byte 0-3
├─────────────────────────────────────────────────────────────────────┤
│                        Sequence Number                             │ Byte 4-7
├─────────────────────────────────────────────────────────────────────┤
│                     Acknowledgment Number                          │ Byte 8-11
├───────────┼───────┼─┼─┼─┼─┼─┼─┼─────────────────────────────────┤
│Data Offset│Reserved│U│A│P│R│S│F│          Window Size             │ Byte 12-15
├───────────┴───────┴─┴─┴─┴─┴─┴─┼─────────────────────────────────┤
│          Checksum               │       Urgent Pointer            │ Byte 16-19
└─────────────────────────────────┴─────────────────────────────────┘
```

**TCP Flags (6 bits):**
| Flag | Bit | Name | Purpose |
|------|-----|------|---------|
| U | URG | Urgent | Urgent pointer field is valid |
| A | ACK | Acknowledgment | Ack number field is valid |
| P | PSH | Push | Deliver data to application immediately |
| R | RST | Reset | Abort connection immediately |
| S | SYN | Synchronize | Initiate connection (set initial seq number) |
| F | FIN | Finish | No more data to send (graceful close) |

**Invalid combinations:** SYN+FIN and SYN+RST are invalid — a packet can't simultaneously start and end a connection. IronNet rejects these without creating state.

### 4.3 TCP 3-Way Handshake

Connection establishment requires three packets:

```
Client                          Server
  │                               │
  │──── SYN (seq=X) ────────────→│  "I want to connect, my seq starts at X"
  │                               │
  │←─── SYN+ACK (seq=Y, ack=X+1)│  "OK, my seq starts at Y, I got your X"
  │                               │
  │──── ACK (seq=X+1, ack=Y+1) ─→│  "Got your Y, connection established"
  │                               │
  │         ESTABLISHED           │
```

After the handshake, both sides know each other's sequence numbers and can exchange data.

**In IronNet:** `tcp.c` tracks the server side: SYN → SYN_RECV, ACK → ESTABLISHED. It sends SYN+ACK when a SYN arrives on a port with a registered application.

### 4.4 TCP State Machine

```
                    ┌──────────┐
                    │  CLOSED  │
                    └────┬─────┘
                         │ SYN received
                         ▼
                    ┌──────────┐
                    │ SYN_RECV │ (half-open)
                    └────┬─────┘
                         │ ACK received
                         ▼
                    ┌──────────────┐
                    │ ESTABLISHED  │ (data flows)
                    └────┬─────────┘
                         │ FIN received
                         ▼
                    ┌──────────────┐
                    │ FIN_WAIT_1   │
                    └────┬─────────┘
                         │ ACK received
                         ▼
                    ┌──────────────┐
                    │ FIN_WAIT_2   │
                    └────┬─────────┘
                         │ FIN received
                         ▼
                    ┌──────────────┐
                    │  TIME_WAIT   │ (wait 60s before cleanup)
                    └────┬─────────┘
                         │ timeout
                         ▼
                    ┌──────────┐
                    │  CLOSED  │
                    └──────────┘
```

**TIME_WAIT:** After both sides close, the connection stays in TIME_WAIT for 60 seconds. This prevents old delayed packets from being confused with a new connection on the same port.

**In IronNet:** `tcp.c` enforces legal state transitions. `tcp_timer_tick()` cleans up TIME_WAIT entries.

### 4.5 TCP Sequence Numbers and Acknowledgments

Every byte of data has a sequence number. The receiver acknowledges by sending the next expected sequence number:

```
Client sends: seq=1000, data="Hello" (5 bytes)
  → Server knows: bytes 1000-1004 received
  → Server ACKs: ack=1005 ("I expect byte 1005 next")

Client sends: seq=1005, data="World" (5 bytes)
  → Server ACKs: ack=1010
```

**Why this matters for attacks:**
- RST injection: attacker must guess the correct seq number to kill a connection
- Session hijacking: attacker must predict the next seq to inject data
- SYN cookies: encode connection info in the ISN to avoid state allocation

### 4.6 TCP Window and Flow Control

The **window size** (16 bits) tells the sender how much data the receiver can accept:

```
Receiver says: window=65535
  → Sender can send up to 65535 bytes before waiting for ACK

Receiver says: window=0
  → Sender must stop (receiver's buffer is full)
```

This prevents a fast sender from overwhelming a slow receiver.

**In IronNet:** Window is set to 0xFFFF (maximum) in all segments — flow control is simplified for the research stack.

---


## 5. Network Security Fundamentals

### 5.1 ACLs (Access Control Lists) and Firewalls

An ACL is an ordered list of rules that permit or deny traffic based on packet attributes:

```
Rule 1: PERMIT TCP dst-port 80     ← HTTP allowed
Rule 2: PERMIT TCP dst-port 443    ← HTTPS allowed
Rule 3: PERMIT ICMP                ← Ping allowed
Rule 4: DENY   TCP dst-port 22     ← SSH blocked
Rule 5: DENY   any                 ← Everything else blocked (implicit deny)
```

**Evaluation:** Top-down, first-match-wins. The first rule that matches determines the action. Order matters — if Rule 5 were first, nothing would be permitted.

**Match criteria:** Source IP, destination IP, protocol (TCP/UDP/ICMP), source port, destination port.

**Stateless vs stateful:**
- **Stateless ACL:** evaluates each packet independently. Return traffic needs explicit permit rules.
- **Stateful firewall:** tracks connections. If outbound is permitted, return traffic is automatically allowed.

**In IronNet:** `acl.c` implements stateless first-match ACL. `conntrack.c` adds stateful tracking (NEW/ESTABLISHED/INVALID states).

### 5.2 NAT (Network Address Translation)

NAT rewrites IP addresses as packets cross a router boundary:

**SNAT (Source NAT / Masquerade):**
```
Internal: 10.0.1.5:5000 → 8.8.8.8:80
After NAT: 203.0.113.1:10000 → 8.8.8.8:80
                ↑ public IP      ↑ allocated port

Return: 8.8.8.8:80 → 203.0.113.1:10000
After reverse NAT: 8.8.8.8:80 → 10.0.1.5:5000
```

Multiple internal hosts share one public IP using different port numbers.

**DNAT (Destination NAT / Port Forwarding):**
```
External: 1.2.3.4:54321 → 203.0.113.1:80
After DNAT: 1.2.3.4:54321 → 10.0.1.100:8080
                              ↑ internal server
```

Exposes an internal service on a public IP.

**In IronNet:** `nat.c` implements SNAT/DNAT with port allocation pool (10000-65000) and automatic return-path translation via mapping table.

### 5.3 Connection Tracking (Stateful Filtering)

Connection tracking remembers the state of every network flow:

| State | Meaning | Example |
|-------|---------|---------|
| NEW | First packet seen | TCP SYN, first UDP packet |
| ESTABLISHED | Reply seen (bidirectional) | TCP SYN+ACK received |
| RELATED | Related to existing connection | ICMP error for a TCP flow |
| INVALID | No matching connection | Unsolicited packet |

**Stateful ACL rule:** `permit state established` — allows return traffic without explicit rules for every possible response.

**Timeouts:** TCP established = 300s, UDP = 30s, ICMP = 10s. Expired entries are removed.

**In IronNet:** `conntrack.c` tracks flows bidirectionally with per-protocol timeouts.

### 5.4 IPsec (Authentication and Encryption)

IPsec secures IP communications by encrypting and/or authenticating packets:

**Key concepts:**
- **SA (Security Association):** agreement between two endpoints about how to protect traffic (algorithm, key, lifetime)
- **SPI (Security Parameter Index):** identifies which SA to use
- **Policy:** rules determining which traffic requires protection

**Modes:**
- **Transport mode:** encrypts only the payload (IP header visible)
- **Tunnel mode:** encrypts the entire original packet (new IP header added)

**Fail-closed:** If policy says "protect" but no SA exists → drop the packet (don't send unprotected).

**In IronNet:** `ipsec.c` implements SA lifecycle and policy enforcement with a dummy XOR transform (demonstrates control flow without real crypto complexity).

### 5.5 Defense in Depth Principle

No single defense is perfect. Defense in depth layers multiple protections:

```
Layer 1: Network perimeter (ACL/firewall)
Layer 2: Rate limiting (prevent floods)
Layer 3: Source validation (uRPF, ARP inspection)
Layer 4: Protocol validation (RST validation, frag-strict)
Layer 5: Application security (bounds checking, input validation)
Layer 6: Detection (audit logging, anomaly detection)
Layer 7: Recovery (connection timeout, cache flush)
```

If one layer fails, the next catches the attack. IronNet demonstrates this with 12 independent defense mechanisms that can be enabled in any combination.

---


## 6. DNS (Domain Name System)

### 6.1 DNS Query/Response Format

DNS translates human-readable names (ironnet.local) to IP addresses (10.0.1.1). It uses UDP port 53.

**DNS message format:**
```
┌─────────────────────────────────────────────────────────┐
│ Header (12 bytes)                                       │
│   Transaction ID (2B), Flags (2B), Counts (8B)          │
├─────────────────────────────────────────────────────────┤
│ Question Section                                        │
│   Query name + type + class                             │
├─────────────────────────────────────────────────────────┤
│ Answer Section (in responses)                           │
│   Name + type + class + TTL + data                      │
├─────────────────────────────────────────────────────────┤
│ Authority Section (optional)                            │
├─────────────────────────────────────────────────────────┤
│ Additional Section (optional, EDNS0 OPT record)         │
└─────────────────────────────────────────────────────────┘
```

**Flags field (16 bits):**
- QR (1 bit): 0=query, 1=response
- AA (1 bit): Authoritative Answer
- RD (1 bit): Recursion Desired
- RA (1 bit): Recursion Available
- RCODE (4 bits): 0=no error, 3=NXDOMAIN (name doesn't exist)

**Name encoding:** Labels are length-prefixed: `\x07ironnet\x05local\x00` = "ironnet.local"

**In IronNet:** `dns_server.c` parses queries, looks up the zone table, and builds responses with proper header flags and answer sections.

### 6.2 Record Types

| Type | Value | Purpose | Example |
|------|-------|---------|---------|
| A | 1 | IPv4 address | ironnet.local → 10.0.1.1 |
| AAAA | 28 | IPv6 address | ironnet.local → ::1 |
| CNAME | 5 | Alias | www.ironnet.local → ironnet.local |
| TXT | 16 | Text data | Used for SPF, DKIM, verification |
| MX | 15 | Mail server | ironnet.local → mail.ironnet.local |
| NS | 2 | Name server | ironnet.local → ns1.ironnet.local |

**In IronNet:** Only A records are implemented (sufficient for demonstrating DNS attacks).

### 6.3 Recursive vs Authoritative Resolution

**Authoritative server:** Holds the definitive records for a domain. When asked about "ironnet.local", it answers from its zone file.

**Recursive resolver:** Doesn't hold records itself. It queries other servers on behalf of the client, following the delegation chain (root → TLD → authoritative).

```
Client → Recursive Resolver → Root Server → .local TLD → Authoritative Server
                                                              ↓
Client ← Recursive Resolver ← ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ Answer
```

**Security implication:** The recursive resolver caches responses. If an attacker can inject a forged response before the real one arrives, the cache is poisoned.

**In IronNet:** The DNS server is authoritative (answers from zone table) but also accepts incoming responses (QR=1) to simulate a recursive resolver's cache — enabling the Kaminsky-style poisoning attack.

### 6.4 DNS Caching and TTL

DNS responses include a TTL (Time To Live) value:
- `ironnet.local. 60 IN A 10.0.1.1` → cache for 60 seconds
- After 60 seconds, the entry expires and must be re-queried

**Cache poisoning:** If an attacker injects a forged response with a high TTL (e.g., 300s), all clients get the wrong answer for 5 minutes.

**In IronNet:** `dns_server.c` implements a 32-entry cache with TTL expiry. `dns_cache_add_secure()` validates entries against the zone table when `dns-validate` defense is enabled.

### 6.5 DNSSEC Overview

DNSSEC adds cryptographic signatures to DNS responses:
- Each zone signs its records with a private key
- Resolvers verify signatures using the public key
- Forged responses without valid signatures are rejected

**Chain of trust:** Root zone → TLD → domain. Each level signs the next level's public key.

**In IronNet:** The `dns-validate` defense simulates DNSSEC by checking responses against the authoritative zone table (same principle — validate against a trusted source).

---


## 7. Reconnaissance and Scanning

### 7.1 Port Scanning (SYN Scan, Connect Scan)

Port scanning discovers which services are running on a target by probing ports:

**TCP Connect Scan:** Complete the full 3-way handshake. If connection succeeds → port is open. Simple but easily detected (full connection logged).

**TCP SYN Scan (half-open):** Send only SYN. If SYN+ACK received → port is open. Send RST to close without completing handshake. Faster and slightly stealthier than connect scan.

```
SYN scan results:
  SYN → SYN+ACK    = OPEN (service listening)
  SYN → RST        = CLOSED (no service)
  SYN → (nothing)  = FILTERED (firewall dropped it)
```

**In IronNet:**
- `ironprobe/probe.c` — internal scanner (checks listener table directly)
- `ironprobe_ext/main.c` — external SYN scanner via raw socket (sends real SYN packets through TAP)

### 7.2 Stealth Scanning (FIN, XMAS, NULL Scans)

These scans use unusual TCP flag combinations to evade detection:

| Scan | Flags | Open port | Closed port | Why stealthy |
|------|-------|-----------|-------------|--------------|
| FIN | FIN only | Silence | RST | No SYN = no connection log |
| XMAS | FIN+PSH+URG | Silence | RST | "Christmas tree" — all flags lit |
| NULL | No flags | Silence | RST | Empty packet — unusual |

**Key insight:** RFC 793 says: "If the port is closed, send RST. If open, silently drop unexpected segments." So silence = open, RST = closed (inverse of SYN scan).

**Limitation:** Only works against RFC-compliant stacks. Windows sends RST regardless of port state (making these scans useless against Windows).

**In IronNet:** Phase 21a implements FIN/XMAS/NULL scans in `ironattack stealth-scan`.

### 7.3 Decoy Scanning and IP Obfuscation

**Decoy scanning:** Send scan packets from multiple source IPs (real + fake). The target sees probes from many IPs and can't identify the real attacker.

```
Attacker (10.0.1.2) scans port 80 with decoys 10.0.1.50, 10.0.1.51:
  → Target sees SYN from 10.0.1.2  (real)
  → Target sees SYN from 10.0.1.50 (decoy)
  → Target sees SYN from 10.0.1.51 (decoy)
  → All sent in random order — which is real?
```

**In IronNet:** Phase 21b implements decoy scanning in `ironattack stealth-scan --decoys`.

### 7.4 Service Fingerprinting

After finding open ports, identify what service is running:
- Port 7: send data, check if echoed back → Echo server
- Port 53: send DNS query, check for valid response → DNS server
- Port 80: send HTTP GET, check for HTTP response → Web server
- Port 9000: send magic bytes, check for protocol response → Custom RPC

**In IronNet:** `ironprobe/probe.c` identifies services by known port assignments and response patterns.

### 7.5 OS Fingerprinting (TTL/Window Analysis)

Different operating systems use different default values:

| OS | Default TTL | TCP Window | IP ID behavior |
|----|-------------|------------|----------------|
| Linux | 64 | 29200 | Incremental |
| Windows | 128 | 65535 | Incremental |
| macOS | 64 | 65535 | Random |
| Cisco IOS | 255 | 4128 | Incremental |

By observing TTL and window size in responses, you can guess the target OS without any authentication.

**In IronNet:** IronNet uses TTL=64 and window=65535, which would fingerprint as Linux/macOS.

---


## 8. Layer 2 Attacks

### 8.1 ARP Spoofing (Cache Poisoning, MITM Setup)

**The attack:** Send fake ARP replies to poison a victim's ARP cache, redirecting their traffic through the attacker.

```
Normal:  Victim → Gateway (10.0.1.254 at MAC:GW)
Attack:  Attacker sends: "10.0.1.254 is at MAC:ATTACKER"
After:   Victim → Attacker (thinking it's the gateway) → Gateway
```

**Steps:**
1. Attacker sends unsolicited ARP reply: "10.0.1.254 is at AA:BB:CC:DD:EE:FF"
2. Victim updates ARP cache: 10.0.1.254 → AA:BB:CC:DD:EE:FF (attacker's MAC)
3. Victim sends all gateway-bound traffic to attacker
4. Attacker forwards to real gateway (transparent MITM)

**Why it works:** ARP has no authentication. Any device can claim any IP-to-MAC mapping.

**Defense:** ARP inspection — maintain trusted IP-MAC bindings, reject ARP replies that contradict them.

**In IronNet:**
- Attack: `ironattack arp-spoof --target 10.0.1.1 --impersonate 10.0.1.254`
- Defense: `defense arp-inspection enable` + `arp_trust_add()` in `arp.c`

### 8.2 MAC Flooding (CAM Table Overflow → Hub Mode)

**The attack:** Flood the switch with thousands of frames from random source MACs, filling its MAC address table.

```
Normal:  Switch learns MAC A on port 1, MAC B on port 2
         Frame A→B: forwarded only to port 2 (unicast)

After flood: MAC table full (all 256 entries = random MACs)
         Frame A→B: MAC B not in table → FLOODED to ALL ports
         Attacker on port 3 now sees A→B traffic!
```

**Why it works:** Switches have finite MAC tables (256-8192 entries). When full, they fall back to flooding (hub behavior) for unknown destinations.

**Defense:** Port security — limit the number of MACs that can be learned per port.

**In IronNet:**
- Attack: Phase 20a `ironattack mac-flood`
- Defense: Phase 20b `defense port-security enable`
- Bridge: `bridge.c` has 256-entry MAC table that can be overflowed

### 8.3 VLAN Hopping (Double-Tagging Attack)

**The attack:** Craft a frame with two VLAN tags. The first switch strips the outer tag (native VLAN), leaving the inner tag. The frame enters the target VLAN.

```
Attacker's frame: [Outer VLAN=1 (native)][Inner VLAN=20 (target)][Payload]

Switch 1: strips outer tag (native VLAN processing)
           → Frame now has: [VLAN=20][Payload]

Switch 2: sees VLAN 20 tag → forwards to VLAN 20 ports
           → Attacker's frame reaches VLAN 20 (escaped VLAN 1!)
```

**Requirements:**
- Attacker must be on the native VLAN (untagged)
- Target VLAN must be different from native VLAN
- Trunk port between switches must carry both VLANs

**Defense:** VLAN strict mode — reject any frame with a VLAN tag (0x8100) on access ports.

**In IronNet:**
- Attack: `ironattack vlan-hop --target-vlan 20 --outer-vlan 1`
- Defense: `defense vlan-strict enable` in `eth.c`

### 8.4 DHCP Starvation and Rogue DHCP (Concept)

**DHCP Starvation:** Attacker sends thousands of DHCP Discover messages with random MAC addresses, exhausting the DHCP server's IP pool. Legitimate clients can't get an IP address.

**Rogue DHCP:** After starving the legitimate server, attacker runs their own DHCP server that assigns:
- Attacker's IP as the default gateway → all traffic routed through attacker (MITM)
- Attacker's IP as DNS server → DNS responses can be forged

**Note:** IronNet does not implement DHCP, but the concept is documented here for completeness. The ARP spoofing attack achieves a similar MITM result.

---


## 9. Layer 3/4 Attacks

### 9.1 SYN Flood (Resource Exhaustion DoS)

**The attack:** Send thousands of TCP SYN packets from spoofed source IPs. The server allocates a connection table entry for each SYN (SYN_RECV state) and waits for the ACK that never comes.

```
Attacker → SYN (src=random IP #1) → Server: allocates entry #1
Attacker → SYN (src=random IP #2) → Server: allocates entry #2
...
Attacker → SYN (src=random IP #256) → Server: TABLE FULL
Legitimate client → SYN → Server: REJECTED (no room)
```

**Why it works:** TCP requires state allocation on SYN. With a fixed-size connection table (256 in IronNet), the attacker fills it with half-open connections that never complete.

**Defense: SYN cookies** — Don't allocate state on SYN. Instead, encode connection info in the SYN+ACK sequence number (cookie). Only allocate state when a valid ACK returns with the correct cookie.

**In IronNet:**
- Attack: `ironattack syn-flood --target 10.0.1.1 --port 7 --rate 1000 --count 5000`
- Defense: `defense syn-cookies enable` — table stays empty during flood
- Defense: `defense rate-limit 100/s` — per-source SYN rate cap

### 9.2 IP Spoofing (Source Authentication Bypass)

**The attack:** Forge the source IP address in packets to bypass source-based ACL rules or hide the attacker's identity.

```
ACL rule: PERMIT traffic from 10.0.1.0/24
Attacker (real IP: 192.168.1.5) sends packet with src=10.0.1.100
→ ACL sees source 10.0.1.100 → PERMIT (attacker bypasses the rule)
```

**Why it works:** IP has no built-in source authentication. Any device can put any source IP in the header.

**Defense: uRPF (unicast Reverse Path Forwarding)** — Check if the source IP is reachable via the interface the packet arrived on. If not → drop (the source is spoofed).

```
Packet arrives on iron0 with src=10.0.2.5
Route table says: 10.0.2.0/24 is via iron1 (not iron0)
→ Source is spoofed → DROP
```

**In IronNet:**
- Attack: `ironattack ip-spoof --src 10.0.99.1 --dst 10.0.1.1 --port 7`
- Defense: `defense urpf enable` — strict mode drops packets with no route or wrong interface for source

### 9.3 TCP RST Injection (Connection Killing)

**The attack:** Send a forged TCP RST packet to one side of an established connection. If the sequence number falls within the receive window, the connection is torn down.

```
Client (10.0.1.2:5000) ←→ Server (10.0.1.1:7) [ESTABLISHED]

Attacker sends: RST, src=10.0.1.2:5000, dst=10.0.1.1:7, seq=<guessed>
→ If seq is within server's receive window → connection KILLED
```

**Why it works:** TCP accepts RST from any source that matches the 4-tuple and has a valid sequence number. No authentication.

**Challenge:** The attacker must guess the correct sequence number. With a 32-bit seq space and typical window of 65535, the probability per guess is ~1/65536. Sending many RSTs with different seq values increases success.

**Defense: RST validation** — Only accept RST if seq exactly equals `rcv_nxt` (not just within window).

**In IronNet:**
- Attack: `ironattack rst-inject --target 10.0.1.1 --port 7 --src 10.0.1.2 --sport 54321 --seq 1000`
- Defense: `defense rst-validation enable`

### 9.4 TCP Session Hijacking (Data Injection)

**The attack:** Instead of killing a connection (RST), inject data into it. The attacker sends a data packet that appears to come from the legitimate client.

```
Client (seq=1005) ←→ Server (ack expects 1005)

Attacker sends: src=client, seq=1005, payload="HIJACKED"
→ Server accepts data (seq matches expected)
→ Server processes "HIJACKED" as if client sent it
→ Client's next packet (seq=1005) is now a duplicate → rejected
→ Connection desynchronized — attacker has taken over
```

**Requirements:**
- Know the client's IP and port (sniff or guess)
- Know the current sequence number (sniff via MITM, or predict)
- Be able to send spoofed packets (raw socket)

**Defense: Challenge ACK** — When unexpected data arrives, send a challenge ACK. Only the real client can respond correctly.

**In IronNet:** Phase 22a implements `ironattack session-hijack`.

### 9.5 ICMP Redirect (Routing Manipulation)

**The attack:** Send a fake ICMP Redirect message telling the router to use a different gateway for a specific destination.

```
Attacker sends ICMP Redirect (type=5, code=1):
  "For destination 8.8.8.8, use gateway 10.0.1.99 instead"

Router updates routing table:
  8.8.8.8/32 via 10.0.1.99 (attacker-controlled!)

All traffic to 8.8.8.8 now goes through attacker
```

**Why it works:** ICMP Redirect is a legitimate protocol feature (routers use it to optimize paths). But there's no authentication — anyone can send one.

**Defense:** Simply ignore all ICMP Redirect messages.

**In IronNet:**
- Attack: `ironattack icmp-redirect --target 10.0.1.1 --new-gw 10.0.1.99 --orig-dst 8.8.8.8`
- Defense: `defense icmp-redirect-disable enable`

### 9.6 IP Fragmentation Attacks

**Overlapping fragments:** Send fragments where byte ranges overlap. Different reassembly implementations handle overlaps differently — some use the first fragment's data, others use the last. This can bypass IDS/firewall inspection.

```
Fragment 1: offset=0, length=32, MF=1  [bytes 0-31]
Fragment 2: offset=16, length=32, MF=0 [bytes 16-47]  ← overlaps bytes 16-31!
```

**Tiny fragments:** Send fragments smaller than the minimum (68 bytes). The first fragment may be too small to contain the TCP header, so firewalls can't inspect ports.

**Defense: frag-strict** — Reject overlapping fragments and fragments below minimum size.

**In IronNet:**
- Attack: `ironattack frag-attack --target 10.0.1.1 --overlap` or `--tiny`
- Defense: `defense frag-strict enable`

### 9.7 Slowloris (Application-Layer Connection Exhaustion)

**The attack:** Open many TCP connections to a server, then send data very slowly (1 byte every few seconds). The connections stay open indefinitely, consuming connection table slots.

```
Attacker opens 200 connections to HTTP server (port 8080)
Each connection sends: "GET / HTTP/1.0\r\n" then... one byte every 2 seconds
Server waits for complete request (never arrives)
Connection table: 200/256 slots used by attacker
Legitimate clients: REJECTED (only 56 slots left)
```

**Why it works:** Servers typically wait for a complete request before timing out. Slowloris exploits this patience by sending just enough data to keep the connection alive.

**Defense: Connection idle timeout** — Close connections that haven't sent meaningful data within N seconds.

**In IronNet:**
- Attack: `ironattack slowloris --target 10.0.1.1 --port 8080 --conns 200`
- Defense: `defense conn-timeout 30` — idle connections closed after 30 seconds

---


## 10. DNS Attacks

### 10.1 DNS Response Spoofing (Forged Replies)

**The attack:** Send a forged DNS response to a client before the legitimate server responds. The client accepts the first valid response it receives.

```
Client → DNS query: "What is ironnet.local?" → Legitimate DNS server
                                                    ↓ (takes 50ms)
Attacker → Forged response: "ironnet.local = 10.0.99.1" → Client (arrives in 5ms)

Client accepts attacker's response (arrived first)
Client connects to 10.0.99.1 (attacker) instead of 10.0.1.1 (real server)
```

**Requirements:**
- Attacker must be on the network path (or able to send to the client)
- Forged response must match the transaction ID of the query
- Forged response must arrive before the legitimate response

**In IronNet:**
- `dns spoof-test` CLI command directly poisons the zone table (simulates successful spoof)
- `ironattack dns-spoof` sends forged DNS response packets via raw socket

### 10.2 DNS Cache Poisoning (Kaminsky Attack)

**The attack:** Poison the DNS server's cache so ALL clients get the wrong answer, not just one.

**Classic Kaminsky attack (2008):**
1. Attacker triggers the DNS server to query for `random123.ironnet.local` (non-existent)
2. DNS server sends query to upstream (transaction ID = X)
3. Attacker floods the DNS server with forged responses:
   - Random transaction IDs (brute-force guessing)
   - Answer: "ironnet.local NS = attacker's server" (delegation poisoning)
4. If one forged response matches transaction ID X → cache poisoned
5. All subsequent queries for `*.ironnet.local` go to attacker's server

**Why it's devastating:** One successful poisoning affects ALL clients using that DNS server, for the duration of the TTL.

**Defense:**
- Source port randomization (attacker must guess port AND transaction ID)
- DNSSEC (cryptographic signature verification)
- Response validation against authoritative zone

**In IronNet:**
- Attack: `ironattack dns-spoof-ext --domain ironnet.local --fake-ip 10.0.99.1 --target 10.0.1.1 --count 50`
- Defense: `defense dns-validate enable` — checks cache entries against zone table

### 10.3 DNS Tunneling (Data Exfiltration via Queries)

**The attack:** Encode stolen data as DNS query labels and send to an attacker-controlled DNS server. DNS traffic is rarely blocked by firewalls.

```
Stolen data: "password123"
Base64 encoded: "cGFzc3dvcmQxMjM="
DNS query: cGFzc3dvcmQxMjM=.exfil.attacker.com

Attacker's DNS server receives the query → decodes base64 → gets "password123"
```

**Why it works:**
- DNS (UDP port 53) is almost never blocked by firewalls
- DNS queries to external servers are normal traffic
- Base64 in subdomains looks like CDN hashes or tracking parameters
- Up to 63 bytes per label, 253 bytes per domain name

**Real-world tools:** iodine, dnscat2, dns2tcp

**In IronNet:**
- Attack: `ironattack covert --mode dns --message "secret" --target 10.0.1.1`
- Detection: `defense covert-detect enable` — flags high-entropy DNS labels

---


## 11. Man-in-the-Middle (MITM)

### 11.1 ARP-Based MITM Setup

A full MITM attack combines ARP spoofing with packet forwarding:

```
Step 1: Poison both victims' ARP caches
  Tell Victim A: "Victim B is at ATTACKER_MAC"
  Tell Victim B: "Victim A is at ATTACKER_MAC"

Step 2: Both victims send traffic to attacker (thinking it's the other)
  A → Attacker (dst MAC = attacker) → B
  B → Attacker (dst MAC = attacker) → A

Step 3: Attacker forwards packets (rewriting MACs) to maintain connectivity
  Neither victim notices the interception
```

**Result:** Attacker sees ALL traffic between A and B in plaintext. Can read passwords, session tokens, private messages.

**In IronNet:** `ironmitm --victim-a 10.0.1.1 --victim-b 10.0.1.2 --iface iron0`

### 11.2 Traffic Interception and Logging

Once MITM is established, the attacker logs all intercepted packets:

```
[A→B] 10.0.1.1:7 → 10.0.1.2:49700 TCP (47 bytes)
[B→A] 10.0.1.2:49700 → 10.0.1.1:7 TCP (47 bytes)
```

**What can be captured:**
- HTTP requests/responses (URLs, cookies, form data)
- DNS queries (what sites the victim visits)
- Email content (if unencrypted)
- Login credentials (HTTP basic auth, FTP, telnet)
- File transfers

**In IronNet:** `ironmitm --log /tmp/mitm.log` saves all intercepted traffic.

### 11.3 In-Transit Data Modification

Beyond passive sniffing, the attacker can modify data in transit:

```
Client sends to echo server: "SET password secret123"
Attacker modifies: "SET password HACKED!!!"
Server receives: "SET password HACKED!!!"
Server stores: password = "HACKED!!!"
```

**Modification types:**
- **Replace:** swap specific bytes (e.g., change "OK" to "NO")
- **Inject:** add extra data (e.g., inject JavaScript into HTTP response)
- **Drop:** selectively discard packets (cause timeouts)
- **Delay:** hold packets to cause application-level issues

**In IronNet:** `ironmitm --modify "secret:XXXXXX"` replaces matching patterns in transit.

### 11.4 MITM Detection (MAC Flapping, Latency Anomalies)

**MAC flap detection:** When an IP's MAC address changes rapidly (e.g., 3 times in 10 seconds), it indicates ARP spoofing.

```
Normal: 10.0.1.254 → 02:00:00:00:00:FE (stable for hours)
Attack: 10.0.1.254 → 02:AA:BB:CC:DD:EE (changes every 2 seconds!)
         → ALERT: MAC flap detected — possible MITM
```

**Other indicators:**
- Increased latency (relay adds processing time)
- TTL anomalies (relay may not decrement correctly)
- Duplicate packets (forwarding artifacts)

**Defense:** Encrypted channels (IPsec, TLS) make intercepted traffic unreadable. Attacker sees only ciphertext.

**In IronNet:**
- Detection: `defense mitm-detect enable` — alerts on MAC flapping
- Audit: `AUDIT_ARP_ANOMALY` events logged

---


## 12. Memory Exploitation

### 12.1 Stack Buffer Overflow (strcpy Vulnerability)

**The vulnerability:** A fixed-size buffer on the stack is written to without bounds checking. If input exceeds the buffer size, it overwrites adjacent stack data (saved registers, return address).

```c
void vulnerable_function(const char *input) {
    char buffer[64];    // 64 bytes on stack
    strcpy(buffer, input);  // NO bounds check — copies ALL of input
}
```

**Stack layout (x86_64):**
```
High addresses
┌─────────────────────┐
│ Return address (8B)  │ ← function returns here after execution
├─────────────────────┤
│ Saved RBP (8B)      │ ← previous frame pointer
├─────────────────────┤
│ buffer[63]          │
│ ...                 │ ← strcpy writes here (and beyond!)
│ buffer[0]           │
└─────────────────────┘
Low addresses
```

If input is 80 bytes: first 64 fill the buffer, next 8 overwrite saved RBP, next 8 overwrite the return address. When the function returns, execution jumps to the attacker-controlled address.

**In IronNet:** `vuln_server.c` ECHO command uses `strcpy(local_buf, input)` with a 64-byte buffer.

### 12.2 Format String Attacks (%x, %p, %n)

**The vulnerability:** User input is passed directly as a format string to printf/snprintf:

```c
// VULNERABLE:
snprintf(buf, sizeof(buf), user_input);  // user controls the format!

// SAFE:
snprintf(buf, sizeof(buf), "%s", user_input);  // format is fixed
```

**Exploitation:**
- `%x` — reads 4 bytes from the stack (leaks memory)
- `%p` — reads pointer-sized values (leaks addresses, defeats ASLR)
- `%s` — dereferences a stack value as a pointer (reads arbitrary memory)
- `%n` — writes the number of bytes printed so far to a stack address (arbitrary write!)

**Example:** Input `"%x.%x.%x.%x"` prints 4 stack values as hex, revealing:
- Stack addresses (bypass ASLR)
- Canary values (bypass stack protection)
- Return addresses (find code locations)

**In IronNet:** `vuln_server.c` FMT command passes user input directly to `snprintf()`.

### 12.3 Integer Overflow/Truncation

**The vulnerability:** A length value is cast to a smaller type, causing truncation:

```c
int requested = atoi(user_input);     // e.g., 257
uint8_t alloc_size = (uint8_t)requested;  // 257 → 1 (truncated!)
char *buf = malloc(alloc_size);       // allocates 1 byte
memcpy(buf, data, requested);         // copies 257 bytes into 1-byte buffer!
```

**Result:** The allocation is tiny but the copy is large → heap buffer overflow.

**Common patterns:**
- `uint16_t` wraps at 65536 (e.g., 65537 → 1)
- `uint8_t` wraps at 256 (e.g., 256 → 0)
- Signed/unsigned mismatch: negative value becomes huge positive when cast to unsigned

**In IronNet:** `vuln_server.c` READ command casts `int` to `uint8_t` for allocation size.

### 12.4 Return Address Overwrite (RIP Control)

**The goal:** Overwrite the return address with a value the attacker controls. When the function returns, execution jumps to the attacker's chosen address.

```
Payload: [64 bytes 'A'][8 bytes 'A' (RBP)][0xDEADBEEFCAFEBABE (return addr)]

After strcpy:
  buffer = "AAAA...A" (64 bytes)
  saved RBP = 0x4141414141414141
  return address = 0xDEADBEEFCAFEBABE

Function returns → RIP = 0xDEADBEEFCAFEBABE → crash (or code execution!)
```

**In a real exploit:** The return address would point to:
- Shellcode (attacker's machine code in the buffer)
- A ROP gadget (existing code snippet that does something useful)
- A libc function (e.g., `system("/bin/sh")`)

**In IronNet:** `ironattack exploit --mode payload` overwrites the return address with 0xDEADBEEFCAFEBABE.

### 12.5 Exploit Development Workflow

```
Step 1: CRASH — Confirm the vulnerability exists
  Send oversized input → observe crash (ASAN report or segfault)

Step 2: PATTERN — Find the exact offset to the return address
  Send cyclic pattern (Aa0Aa1Aa2...) → identify which bytes land on RIP
  Result: "Return address is at offset 72"

Step 3: CONTROL — Overwrite return address with chosen value
  Send: [72 bytes padding][controlled 8-byte address]
  Verify: crash at the controlled address (proves RIP control)

Step 4: EXPLOIT — Point return address to useful code
  Option A: Shellcode in the buffer (if executable stack)
  Option B: ROP chain (chain existing code gadgets)
  Option C: ret2libc (call system() with "/bin/sh")
```

**In IronNet:** `ironattack exploit` implements steps 1-3 with modes `crash`, `pattern`, `payload`.

### 12.6 Mitigations (Stack Canary, ASLR, Bounds Checking, ASAN)

| Mitigation | How it works | Prevents overflow? | Detects overflow? |
|-----------|-------------|-------------------|-------------------|
| **Stack canary** | Random value between buffer and return address; checked before return | ❌ | ✅ |
| **ASLR** | Randomize stack/heap/library addresses each run | ❌ | ❌ (makes exploitation unreliable) |
| **Bounds checking** | Validate input length before copy; reject oversized | ✅ | N/A |
| **ASAN** | Compiler instrumentation; detects out-of-bounds access at runtime | ❌ | ✅ (aborts immediately) |
| **NX/DEP** | Mark stack as non-executable; shellcode can't run | ❌ | ❌ (prevents shellcode only) |

**Defense in depth:** Use ALL mitigations together:
- Bounds checking prevents the overflow entirely (best)
- If overflow happens: canary detects it before return
- If canary is bypassed: ASLR makes the target address unpredictable
- If ASLR is defeated: NX prevents shellcode execution
- During development: ASAN catches everything immediately

**In IronNet:** `vuln_server.c` implements CANARY, BOUNDS, and ASLR commands for comparison.

---


## 13. Covert Channels and Evasion

### 13.1 Storage Channels (ICMP Payload, TCP ISN, DNS Subdomain, IP ID)

Storage channels hide data in protocol fields that are normally ignored or appear random:

| Channel | Where data hides | Bandwidth | Stealth |
|---------|-----------------|-----------|---------|
| ICMP payload | Ping packet data (normally zeros/pattern) | High (full message/pkt) | Medium |
| TCP ISN | Initial Sequence Number (normally random) | 4 bytes/SYN | High |
| DNS subdomain | Query label (base64 encoded) | 63 bytes/query | Medium |
| IP ID | Identification field (normally sequential) | 2 bytes/packet | High |

**ICMP example:** Normal ping payload is zeros. Covert ping carries "secret message" as payload. To an observer, it looks like a normal ping with unusual (but not invalid) payload.

**TCP ISN example:** Each SYN packet carries 4 bytes of hidden data in its sequence number. ISNs are supposed to be random, so encoded data is indistinguishable from normal.

**In IronNet:** `ironattack covert --mode icmp|isn|dns|ipid`

### 13.2 Timing Channels (Inter-Packet Delay, Packet Counting)

Timing channels encode data in the behavior of traffic, not its content:

**Inter-packet delay:**
- Bit 1 = send packet after 100ms delay
- Bit 0 = send packet after 10ms delay
- Receiver measures gaps between packets to decode
- Bandwidth: ~18 bits/second

**Packet counting:**
- Bit 1 = send 7 packets in a 200ms window
- Bit 0 = send 2 packets in a 200ms window
- Receiver counts packets per window to decode
- Bandwidth: ~5 bits/second

**Why timing channels are stealthy:** No payload modification. Content inspection reveals nothing. You must analyze traffic patterns statistically to detect them.

**In IronNet:** `ironattack covert --mode timing|counting`

### 13.3 Covert Channel Detection

Detection uses statistical analysis to identify anomalies:

| Detector | What it measures | Normal | Covert | Threshold |
|----------|-----------------|--------|--------|-----------|
| ICMP entropy | Shannon entropy of payload | ~5.3 (pattern) | >5.7 (random) | 5.7 |
| ICMP ASCII | % printable bytes in payload | ~50% | >70% (text) | 70% |
| Timing bimodal | % of gaps in two clusters | ~30% | >70% | 70% |
| TCP ISN ASCII | % printable bytes in ISNs | ~37% (random) | >65% (text) | 65% |
| DNS label entropy | Shannon entropy of first label | 2-3 (words) | >3.5 (base64) | 3.5 |

**Shannon entropy:** Measures information density. 0 = all same byte, 8.0 = perfectly random. English text ≈ 4.0, base64 ≈ 4.5, random binary ≈ 7.5.

**In IronNet:** `defense covert-detect enable` activates all detectors. Alerts logged as `AUDIT_COVERT_CHANNEL`.

### 13.4 Firewall Evasion Techniques

**Fragmentation evasion:** Split a packet so the TCP header is in the second fragment. Stateless firewalls that only inspect the first fragment miss the port information.

**Protocol tunneling:** Encapsulate blocked traffic inside allowed protocols:
- HTTP tunneling: wrap SSH inside HTTP CONNECT
- DNS tunneling: encode data in DNS queries (port 53 rarely blocked)
- ICMP tunneling: hide TCP data inside ping packets

**TTL-based evasion:** Set TTL so packets expire after passing the firewall but before reaching the IDS behind it. The firewall permits the packet, but the IDS never sees it.

**In IronNet:** Fragmentation attacks (`ironattack frag-attack`) and DNS covert channel demonstrate evasion concepts.

---

## 14. Defense Mechanisms

### 14.1 SYN Cookies (Stateless SYN Handling)

**Problem:** SYN flood fills the connection table.
**Solution:** Don't allocate state on SYN. Encode connection info in the SYN+ACK sequence number.

```
SYN arrives → compute cookie = hash(src_ip, dst_ip, src_port, dst_port, secret)
Send SYN+ACK with seq = cookie (no table entry created)
ACK arrives → validate: ack-1 == hash(...)? → only then create entry
```

**Effect:** Connection table stays empty during flood. Legitimate clients complete the handshake and get served.

### 14.2 Rate Limiting (Per-Source Throttling)

**Problem:** Attacker sends too many packets from one source.
**Solution:** Track SYN count per source IP per second. Drop excess.

```
Source 10.0.1.50: 150 SYNs this second (limit: 100)
→ First 100 accepted, remaining 50 dropped
→ Resets every second (rate_limit_tick())
```

### 14.3 ARP Inspection (Trusted Bindings)

**Problem:** ARP spoofing poisons the ARP table.
**Solution:** Maintain a trusted IP→MAC binding table. Reject ARP replies that contradict it.

```
Trusted: 10.0.1.254 → 02:00:00:00:00:FE
ARP reply arrives: "10.0.1.254 is at AA:BB:CC:DD:EE:FF"
→ Mismatch! DROP and log audit event.
```

### 14.4 uRPF (Source IP Validation)

**Problem:** IP spoofing bypasses source-based ACLs.
**Solution:** Check if source IP is reachable via the ingress interface.

```
Packet on iron0 with src=10.0.2.5
Route table: 10.0.2.0/24 via iron1
→ Source should arrive on iron1, not iron0 → SPOOFED → DROP
```

### 14.5 RST Validation (Sequence Number Check)

**Problem:** Forged RST kills connections.
**Solution:** Only accept RST if sequence number exactly equals expected `rcv_nxt`.

```
Connection expects rcv_nxt = 5000
RST arrives with seq = 4999 → REJECTED (off by one)
RST arrives with seq = 5000 → ACCEPTED (legitimate)
```

### 14.6 Connection Idle Timeout (Slowloris Defense)

**Problem:** Slowloris holds connections open indefinitely with minimal data.
**Solution:** Close ESTABLISHED connections with no data activity for N seconds.

```
Connection idle for 30 seconds → send RST → free table entry
Slowloris connections cleaned up → legitimate clients can connect
```

### 14.7 Fragment Strict Mode

**Problem:** Overlapping/tiny fragments evade inspection or crash reassembly.
**Solution:** Reject fragments that overlap or are below minimum size.

```
Fragment with offset overlapping previous fragment → DROP
Fragment smaller than 68 bytes (not last) → DROP
```

### 14.8 ICMP Redirect Disable

**Problem:** Fake ICMP Redirect manipulates routing table.
**Solution:** Ignore all incoming ICMP Redirect messages.

### 14.9 DNS Validation (Zone-Based Cache Protection)

**Problem:** Forged DNS responses poison the cache.
**Solution:** Before caching a response, check if the answer matches the authoritative zone table.

```
Forged response: ironnet.local → 10.0.99.1
Zone table says: ironnet.local → 10.0.1.1
→ Mismatch! BLOCK cache entry. Log audit event.
```

### 14.10 Port Security (MAC Limit Per Port)

**Problem:** MAC flooding overflows the bridge table.
**Solution:** Limit the number of MACs that can be learned per port.

```
Port 1: max 32 MACs
Attacker sends frame #33 with new random MAC → DROPPED
Bridge table stays intact, unicast forwarding continues normally
```

### 14.11 Covert Channel Detection (Anomaly-Based)

**Problem:** Hidden data in protocol fields/timing.
**Solution:** Statistical analysis of traffic patterns.

- ICMP: flag high-entropy or high-ASCII payloads
- Timing: detect bimodal inter-packet delay distribution
- TCP ISN: flag high ASCII ratio in sequence numbers
- DNS: flag high-entropy query labels

### 14.12 Challenge ACK (Session Hijacking Defense)

**Problem:** Attacker injects data with predicted sequence number.
**Solution:** When unexpected data arrives, send a challenge ACK. Only the real client can respond correctly (attacker doesn't see the challenge).

---


## 15. System Architecture Overview

### 15.1 Component Diagram

IronNet consists of multiple components, each with a specific role:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        IronNet Platform                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    ironstack (daemon)                          │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────────────────┐   │   │
│  │  │ L2: eth │ │ L3: ip  │ │ L4: tcp │ │ security: defense│   │   │
│  │  │ arp,vlan│ │ route   │ │ udp     │ │ ipsec, covert    │   │   │
│  │  │ bridge  │ │ acl,pbr │ │         │ │ detect           │   │   │
│  │  └─────────┘ │ icmp    │ └─────────┘ └──────────────────┘   │   │
│  │               │ nat,conn│                                     │   │
│  │               │ frag    │                                     │   │
│  │               └─────────┘                                     │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐    │   │
│  │  │ ironctl  │ │ ironmon  │ │ ironapps │ │ irontrace    │    │   │
│  │  │ (CLI)    │ │ (audit)  │ │ (servers)│ │ (capture)    │    │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────────┘    │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────────┐    │
│  │ ironattack   │ │ ironsim      │ │ ironprobe-ext / report   │    │
│  │ (12 attacks) │ │ (emulator)   │ │ (external scanner)       │    │
│  └──────────────┘ └──────────────┘ └──────────────────────────┘    │
│                                                                      │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────────┐    │
│  │ ironprobe    │ │ ironfuzz     │ │ ironload                 │    │
│  │ (scanner)    │ │ (fuzzer)     │ │ (stress tester)          │    │
│  └──────────────┘ └──────────────┘ └──────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

**Component roles:**
| Component | Type | Role |
|-----------|------|------|
| ironstack | Daemon (main binary) | Protocol stack + packet processing |
| ironctl | Library (embedded) | CLI for runtime configuration |
| ironmon | Library (embedded) | Audit logging + telemetry |
| ironapps | Library (embedded) | Application servers (echo, DNS, KV, HTTP, RPC, vuln) |
| irontrace | Library (embedded) | Packet capture to pcap |
| ironprobe | Library (embedded) | Internal port scanner |
| ironfuzz | Library (embedded) | Protocol fuzzer |
| ironload | Library (embedded) | Stress tester |
| ironattack | Separate binary | External attack tool (12 subcommands) |
| ironmitm | Separate binary | MITM relay engine |
| ironsim | Separate binary | Network emulator (multi-node) |
| ironsim-test | Separate binary | Traffic generator |
| ironprobe-ext | Separate binary | External SYN scanner |
| ironreport | Separate binary | Attack-defense report |
| irontrace-replay | Separate binary | pcap replay |

### 15.2 Data Plane vs Control Plane Separation

**Data plane:** Processes packets at wire speed. The main loop reads frames from TAP, parses headers, makes forwarding decisions, and writes frames out.

**Control plane:** Configures the data plane. The CLI thread reads commands from stdin and modifies routing tables, ACL rules, defense states.

```
┌─────────────────────────────────────────────┐
│ Control Plane (CLI thread)                   │
│   route add, acl add, defense enable         │
│   Modifies: route table, ACL rules, etc.     │
├─────────────────────────────────────────────┤
│ Data Plane (main loop)                       │
│   Read TAP → parse → route → forward → write │
│   Uses: route table, ACL rules (read-only)   │
└─────────────────────────────────────────────┘
```

Both run in the same process but on different threads. The data plane never blocks waiting for CLI input.

### 15.3 Packet Processing Pipeline (L2 → L3 → L4 → App)

Every packet follows this path through ironstack:

```
TAP device (vnic_read)
     │
     ▼
L2: eth_parse() → eth_dispatch()
     │                    │
     │ EtherType=0x0806   │ EtherType=0x0800
     ▼                    ▼
ARP: arp_input()    L3: ip_input()
                         │
                         ├── Validate (version, IHL, checksum, TTL)
                         ├── uRPF check (if enabled)
                         ├── ACL check
                         │
                         ├── Local delivery?
                         │   ├── ICMP → icmp_input()
                         │   ├── TCP  → tcp_input() → app dispatch
                         │   └── UDP  → udp_input() → app dispatch
                         │
                         └── Forward?
                             ├── TTL decrement
                             ├── PBR lookup
                             ├── FIB lookup
                             ├── ARP resolve
                             └── eth_build() → vnic_write()
```

### 15.4 Event-Driven Main Loop (Non-Blocking I/O)

The main loop polls all TAP interfaces in a tight loop:

```c
while (!shutdown_requested) {
    for (int i = 0; i < interface_count; i++) {
        int n = vnic_read(i, buf, size);  // non-blocking (O_NONBLOCK)
        if (n > 0) {
            eth_parse(buf, n, i, &frame);
            eth_dispatch(&frame);
        }
    }
    // Timer tick (1 second): TCP timeout, ARP aging, rate limit reset
    if (now != last_tick) {
        tcp_timer_tick();
        arp_timer_tick();
        ip_frag_timer_tick();
        rate_limit_tick();
    }
    usleep(1000);  // 1ms poll interval
}
```

**Non-blocking I/O:** `vnic_read()` returns immediately if no packet is available (errno=EAGAIN). This prevents the main loop from stalling.

### 15.5 Thread Model (Main Loop + CLI Thread)

```
Process: ironstack
  │
  ├── Main thread: packet processing loop (iron_pipeline_run_once)
  │     - Reads TAP devices
  │     - Processes packets
  │     - Runs timer ticks
  │
  └── CLI thread: reads stdin (cli_thread_func)
        - Parses commands
        - Modifies shared state (routes, ACLs, defenses)
        - Runs until "exit" or shutdown signal
```

**Thread safety:** For this research project, shared data structures (routes, ACLs) are simple enough that race conditions are unlikely in practice. A production system would need mutexes.

---


## 16. Virtual Network I/O (TUN/TAP)

### 16.1 What is TUN vs TAP

TUN and TAP are Linux kernel features that create virtual network interfaces accessible from userspace:

| | TUN | TAP |
|---|---|---|
| Layer | L3 (IP packets) | L2 (Ethernet frames) |
| Data format | Raw IP packets (no MAC header) | Full Ethernet frames (with MAC header) |
| Use case | VPN tunnels (OpenVPN, WireGuard) | Virtual switches, full stack simulation |
| ARP handling | Kernel handles ARP | Your program handles ARP |

**IronNet uses TAP** because it implements its own L2 layer (Ethernet parsing, ARP, VLANs). TUN would skip L2 entirely.

### 16.2 How /dev/net/tun Works on Linux

Both TUN and TAP devices are created through the same file:

```c
int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);

struct ifreq ifr;
memset(&ifr, 0, sizeof(ifr));
strncpy(ifr.ifr_name, "iron0", IFNAMSIZ);
ifr.ifr_flags = IFF_TAP | IFF_NO_PI;  // TAP mode, no packet info header

ioctl(fd, TUNSETIFF, &ifr);  // Create the interface
```

After this call:
- A new network interface `iron0` appears in `ip link show`
- Writing to `fd` sends an Ethernet frame "out" of iron0 (kernel receives it)
- Reading from `fd` receives frames that the kernel sent "into" iron0

### 16.3 IFF_TAP | IFF_NO_PI Flags

- `IFF_TAP` — create a TAP device (Layer 2, Ethernet frames)
- `IFF_TUN` — create a TUN device (Layer 3, IP packets)
- `IFF_NO_PI` — don't prepend a 4-byte "packet info" header to each frame

Without `IFF_NO_PI`, each read/write would have an extra 4-byte header containing flags and protocol. With `IFF_NO_PI`, you get raw Ethernet frames directly.

### 16.4 Non-Blocking Read/Write

The TAP fd is opened with `O_NONBLOCK`:
- `read()` returns immediately if no frame is available (returns -1, errno=EAGAIN)
- `write()` returns immediately after queuing the frame

This is essential for the main loop — it must poll multiple interfaces without blocking on any one.

```c
int n = read(fd, buf, buf_size);
if (n < 0 && errno == EAGAIN) {
    // No packet available — try next interface
}
```

### 16.5 Multiple TAP Interfaces (iron0, iron1)

IronNet creates multiple TAP interfaces for multi-subnet routing:

```
iron0: 10.0.1.1/24 (subnet 1)
iron1: 10.0.2.1/24 (subnet 2)
```

Each interface has:
- A unique name and file descriptor
- A MAC address (02:00:00:00:00:01, 02:00:00:00:00:02)
- An IP address and prefix length
- RX/TX/drop counters

The main loop reads from ALL interfaces each iteration:
```c
for (int i = 0; i < vnic_count; i++) {
    int n = vnic_read(i, buf, size);
    if (n > 0) process_frame(buf, n, i);
}
```

### 16.6 Linux-Side Configuration (ip addr, ip link)

After ironstack creates the TAP interfaces, the Linux side needs configuration to send traffic into them:

```bash
# Assign an IP to the Linux side of the TAP (acts as a "client" on the subnet)
sudo ip addr add 10.0.1.2/24 dev iron0

# Bring the interface up
sudo ip link set iron0 up

# Now Linux can send packets to 10.0.1.1 (ironstack) via iron0
ping 10.0.1.1        # ICMP goes through TAP to ironstack
dig @10.0.1.1 ...   # DNS query goes through TAP to ironstack
nc 10.0.1.1 7       # TCP connection goes through TAP to ironstack
```

**Important:** Only ironstack can open the TAP fd (one process per TAP). External tools (ironattack, dig, nc) send packets through the kernel's routing, which delivers them into the TAP.

---


## 17. Build System and Project Structure

### 17.1 CMake Configuration (Debug/Release, ASAN)

The project uses CMake with two build modes:

**Debug (default):** AddressSanitizer enabled, no optimization
```cmake
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif()
```

**Release:** Optimized, no ASAN
```bash
cmake ../src -DCMAKE_BUILD_TYPE=Release
```

ASAN detects memory errors at runtime: buffer overflows, use-after-free, double-free, memory leaks. Essential for the vulnerable server demos.

### 17.2 Directory Layout

```
IronNet/
├── src/                          # All source code
│   ├── CMakeLists.txt            # Top-level build config
│   ├── common/                   # Shared utilities (log, stats, utils, types)
│   ├── ironstack/                # Core protocol stack daemon
│   │   ├── main.c               # Entry point
│   │   ├── core/                # Pipeline, config, interfaces
│   │   ├── io/                  # TAP device abstraction
│   │   ├── l2/                  # Ethernet, ARP, VLAN, Bridge
│   │   ├── l3/                  # IP, routing, ACL, PBR, NAT, conntrack, ICMP, frag
│   │   ├── l4/                  # TCP, UDP
│   │   └── security/           # Defense, IPsec, covert detection
│   ├── ironctl/                  # Embedded CLI
│   ├── ironmon/                  # Audit logging, JSON stats
│   ├── ironapps/                 # Application servers (6 servers)
│   ├── ironattack/               # External attack tool (12 subcommands)
│   ├── ironprobe/                # Internal scanner
│   ├── ironprobe_ext/            # External scanner + report
│   ├── ironfuzz/                 # Protocol fuzzer
│   ├── ironload/                 # Stress tester
│   ├── ironsim/                  # Network emulator
│   ├── irontrace/                # Packet capture/replay
│   ├── configs/                  # Router configuration files
│   └── tests/                    # Unit + module tests + stubs
├── build/                        # Build output (out-of-source)
├── demos/                        # 36 self-contained demo files
├── study.md                      # Implementation plan (22 phases)
├── history.md                    # Development history
├── build.md                      # Build & test guide
├── test.md                       # Test case documentation
├── DEMO.md                       # Demo index
└── codebase_analysis.md          # This document
```

### 17.3 Library Targets

Libraries are linked into the ironstack daemon:

| Library | Source | Contains |
|---------|--------|----------|
| `iron_common` | `common/` | log, stats, utils, types |
| `iron_cli` | `ironctl/` | CLI parser, command dispatch |
| `iron_mon` | `ironmon/` | Audit ring buffer, JSON export |
| `iron_apps` | `ironapps/` | 6 application servers |
| `iron_probe` | `ironprobe/` | Internal port scanner |
| `iron_fuzz` | `ironfuzz/` | Mutation engine, corpus |
| `iron_load` | `ironload/` | Stress test functions |
| `iron_trace` | `irontrace/` | pcap writer, trace hooks |

### 17.4 Binary Targets

| Binary | Source | Purpose |
|--------|--------|---------|
| `ironstack` | `ironstack/` | Main daemon (protocol stack + all libraries) |
| `ironattack` | `ironattack/` | External attack tool |
| `ironmitm` | `ironattack/mitm.c` | MITM relay engine |
| `ironsim` | `ironsim/main.c` | Network emulator |
| `ironsim-test` | `ironsim/test_traffic.c` | Traffic generator |
| `ironprobe-ext` | `ironprobe_ext/main.c` | External SYN scanner |
| `ironreport` | `ironprobe_ext/report.c` | Attack-defense report |
| `irontrace-replay` | `irontrace/replay.c` | pcap replay |

### 17.5 Test Infrastructure (Unit Tests, Module Tests, CTest)

**Unit tests (21):** Fast, minimal output. Test one module in isolation with stubs for dependencies. Output: PASS/FAIL.

**Module tests (11):** Verbose, visible output. Test integration between modules with hex dumps and decoded fields. Output: formatted report.

**CTest:** CMake's test runner. `ctest --output-on-failure` runs all 32 tests.

**Stubs:** Tests that include source files directly need stubs for dependencies:
- `defense_stub.c` — no-op defense functions
- `audit_stub.c` — no-op audit functions
- `trace_stub.c` — no-op trace functions
- `covert_stub.c` — no-op covert detection functions
- `app_stub.c` — no-op app socket functions
- `ip_output_stub.c` — no-op IP output

### 17.6 WSL Path Spaces Workaround

WSL paths with spaces (e.g., `OneDrive - Ericsson`) cause issues with `getcwd()` in some tools. Workaround: create a symlink:

```bash
ln -s "/mnt/c/Users/USERNAME/OneDrive - Ericsson/misc/backup2/Sanders.Wang/github/my_net_socket/IronNet" ~/ironnet
cd ~/ironnet/build
```

---

## 18. Configuration System

### 18.1 router.conf Format

The router configuration file uses a simple line-based format:

```
# Comments start with #
interface iron0 mac 02:00:00:00:00:01 ip 10.0.1.1/24
interface iron1 mac 02:00:00:00:00:02 ip 10.0.2.1/24

route 10.0.1.0/24 dev iron0
route 10.0.2.0/24 dev iron1
route 0.0.0.0/0 via 10.0.1.254 dev iron0

acl permit tcp any any port 80
acl permit icmp any any port 0
acl deny tcp any any port 22
acl permit tcp any any port 9999
```

**Line types:**
- `interface <name> mac <mac> ip <ip>/<prefix>` — create TAP interface with IP
- `route <prefix>/<len> dev <name>` — connected route (direct delivery)
- `route <prefix>/<len> via <next-hop> dev <name>` — static route with gateway
- `acl <permit|deny> <tcp|udp|icmp|any> any any port <port>` — ACL rule

### 18.2 Config Parser Implementation

`router_conf.c` reads the file line by line:
1. Skip empty lines and comments (`#`)
2. Match prefix: `interface`, `route`, or `acl`
3. Parse fields with `sscanf()`
4. Call the appropriate API: `iface_add()`, `route_add()`, `acl_add_rule()`

The parser is intentionally simple — no complex grammar, no nested structures.

### 18.3 Runtime CLI Configuration (ironctl Commands)

After startup, the CLI allows live modification:

```
ironctl> route add 192.168.0.0/16 via 10.0.1.254 iface 0
ironctl> acl add deny tcp port 443
ironctl> defense syn-cookies enable
ironctl> dns cache-flush
ironctl> show routes
ironctl> show stats
```

Changes take effect immediately — the next packet processed uses the updated configuration.

### 18.4 Defense Enable/Disable at Runtime

All 12 defenses start disabled and can be toggled at runtime:

```
ironctl> defense show
  syn-cookies:           disabled
  rate-limit:            disabled
  arp-inspection:        disabled
  vlan-strict:           disabled
  rst-validation:        disabled
  urpf:                  disabled
  conn-timeout:          disabled
  frag-strict:           disabled
  icmp-redirect-disable: disabled
  mitm-detect:           disabled
  dns-validate:          disabled
  covert-detect:         disabled

ironctl> defense syn-cookies enable
ironctl> defense rate-limit 100/s
ironctl> defense conn-timeout 30
```

This allows testing attacks with and without defenses to compare effectiveness.

---


## 19. Common Utilities (`src/common/`)

### 19.1 `types.h` — Network Types, Enums, Drop Reasons

Defines the vocabulary used across all modules:

```c
typedef struct { uint32_t addr; uint8_t prefix_len; } ip_prefix_t;  // e.g., 10.0.1.0/24
typedef struct { uint16_t min; uint16_t max; } port_range_t;        // e.g., 80-80

typedef enum { PROTO_ICMP=1, PROTO_TCP=6, PROTO_UDP=17, PROTO_ANY=0 } ip_protocol_t;
typedef enum { ACL_PERMIT, ACL_DENY } acl_action_t;
typedef enum { TCP_CLOSED, TCP_SYN_RECV, TCP_ESTABLISHED, ... } tcp_state_t;
```

### 19.2 `log.h/c` — Timestamped Leveled Logging

```c
LOG_DBG("MODULE", "debug message %d", value);   // only shown with -d flag
LOG_INF("MODULE", "info message");              // always shown
LOG_WRN("MODULE", "warning");                   // highlighted
LOG_ERR("MODULE", "error");                     // critical
```

Output: `[26506.088852] [INFO ] [MAIN] IronNet v0.1.0 starting...`

Timestamp uses `CLOCK_MONOTONIC` (seconds since boot, not wall clock).

### 19.3 `stats.h/c` — Global Counter Infrastructure

64 named counters tracking every important event:

```c
iron_stats_increment(STAT_L3_RX_PACKETS);
iron_stats_increment(STAT_L3_DROPS_ACL);
iron_stats_dump();  // prints all non-zero counters
```

Categories: L2 (rx/tx/drops), L3 (rx/tx/forward/drops by reason), TCP (created/closed/half-open/drops), UDP (rx).

### 19.4 `utils.h/c` — Byte-Order, Checksum, IP String Conversion

**Byte-order:** Network protocols use big-endian. x86 CPUs use little-endian.
```c
uint16_t iron_htons(uint16_t h);  // host → network (16-bit)
uint32_t iron_htonl(uint32_t h);  // host → network (32-bit)
```

**Checksum:** RFC 1071 one's complement sum (used by IP, ICMP, TCP, UDP):
```c
uint16_t iron_checksum(const uint8_t *data, int len);
```

**IP conversion:**
```c
char *iron_ip_to_str(uint32_t ip, char *buf, int len);  // 0x0100000A → "10.0.0.1"
uint32_t iron_str_to_ip(const char *str);               // "10.0.1.1" → 0x0101000A
```

### 19.5 `assert.h` — IRON_ASSERT Invariant Enforcement

```c
IRON_ASSERT(condition, "CATEGORY", "message %d", value);
```

On failure: prints category/file/line/message, increments failure counter, calls `abort()`. Used to enforce protocol invariants (e.g., TCP state must be valid, no routing loops).

---

## 20. Protocol Stack Core (`src/ironstack/`)

### 20.1 `main.c` — Daemon Entry Point

```c
int main(int argc, char **argv) {
    // Parse args: -d (debug), config file path
    // Register signal handlers (SIGINT, SIGTERM → graceful shutdown)
    // Initialize pipeline
    // Start CLI thread
    // Main loop: iron_pipeline_run_once() until shutdown
    // Cleanup: dump stats, shutdown pipeline
}
```

### 20.2 `core/pipeline.c` — Packet Processing Loop

The heart of the system:
```c
void iron_pipeline_run_once(void) {
    for (int i = 0; i < vnic_count; i++) {
        int n = vnic_read(i, rx_buf, RX_BUF_SIZE);
        if (n > 0) {
            eth_parse(rx_buf, n, i, &frame);
            eth_dispatch(&frame);
        }
    }
    // 1-second timer tick
    if (now != last_tick) {
        tcp_timer_tick();      // TIME_WAIT cleanup, idle timeout
        arp_timer_tick();      // ARP entry aging
        ip_frag_timer_tick();  // Fragment reassembly timeout
        rate_limit_tick();     // Reset per-source counters
    }
    usleep(1000);  // 1ms poll
}
```

Also initializes all subsystems at startup and loads the config file.

### 20.3 `core/iface.c` — Interface Configuration Model

Each interface has: name, MAC, IP, prefix length, vnic index.

```c
int iface_add(const char *name, uint8_t *mac, uint32_t ip, uint8_t prefix_len);
iface_config_t *iface_get(int idx);
iface_config_t *iface_find_by_name(const char *name);
iface_config_t *iface_find_by_ip(uint32_t ip);
bool iface_is_local_ip(uint32_t ip);  // checks all interfaces
```

### 20.4 `core/router_conf.c` — Config File Parser

Reads `router.conf` line by line, dispatches to handlers:
- `handle_interface()` → `iface_add()`
- `handle_route()` → `route_add()`
- `handle_acl()` → `acl_add_rule()`

### 20.5 `io/vnic.c` — TAP Device Abstraction

```c
int vnic_create(const char *name, uint8_t mac[6]);  // opens /dev/net/tun, creates TAP
int vnic_read(int idx, uint8_t *buf, int len);      // non-blocking read from TAP fd
int vnic_write(int idx, const uint8_t *buf, int len); // write frame to TAP fd
int vnic_inject(int idx, const uint8_t *buf, int len); // same as write (for testing)
```

---

## 21. Layer 2 Implementation (`src/ironstack/l2/`)

### 21.1 `eth.c` — Ethernet Frame Parse/Build/Dispatch

**eth_parse():** Validates frame (≥14 bytes), extracts dst/src MAC, EtherType, payload pointer.

**eth_build():** Constructs frame: `[dst_mac][src_mac][ethertype][payload]`. Returns total length.

**eth_dispatch():** Routes by EtherType:
- `0x0800` → `ip_input()` (L3)
- `0x0806` → `arp_input()` (ARP)
- `0x8100` → VLAN strict check (if enabled, drop tagged frames)
- Other → drop, increment counter

### 21.2 `arp.c` — ARP Table, Request/Reply, Inspection

**ARP table:** 128 entries, each: IP → MAC + timestamp. Entries age out after 300 seconds.

**arp_input():** On ARP request for our IP → send reply. Always learn sender's MAC (unless ARP inspection blocks it).

**arp_resolve():** Look up MAC for an IP. If not found → send ARP request, return broadcast MAC as fallback.

**ARP inspection:** If `arp-inspection` enabled and sender IP has a trusted binding → reject if MAC doesn't match.

**MITM detection:** If `mitm-detect` enabled and an existing entry's MAC changes → log warning.

### 21.3 `vlan.c` — 802.1Q Tag Insert/Strip

**vlan_ingress():** On trunk port: strip 4-byte tag, extract VID. On access port: assign port's VLAN.

**vlan_egress():** On trunk port: insert 4-byte tag (TPID + TCI). On access port: send untagged.

**Port config:** Each port has mode (access/trunk), access VLAN, trunk allowed bitmap (4096 bits).

### 21.4 `bridge.c` — MAC Learning, Unicast Forwarding, Flooding

**MAC table:** 256 entries: MAC → port + VLAN + timestamp.

**bridge_forward():**
1. Learn src MAC → ingress port
2. Lookup dst MAC in table
3. If found → forward to learned port (unicast)
4. If not found or broadcast → flood to all ports in same VLAN (except ingress)

**Aging:** `bridge_timer_tick()` removes entries older than 300 seconds.

---


## 22. Layer 3 Implementation (`src/ironstack/l3/`)

### 22.1 `ip.c` — IP Input/Output, Validation, Forwarding

**ip_input() flow:**
1. Validate: version=4, IHL≥5, checksum correct, TTL>0
2. Fragment reassembly (if MF flag or offset>0)
3. uRPF check (if enabled): verify source IP reachable via ingress interface
4. ACL check: permit or deny
5. Local delivery (dst is our IP) → dispatch to ICMP/TCP/UDP
6. Forward (dst is not ours) → TTL--, recompute checksum, PBR→FIB→ARP→L2 TX

**ip_output():** Build IP header (version, TTL=64, protocol, src/dst), compute checksum, route lookup, ARP resolve, build Ethernet frame, write to TAP.

### 22.2 `route.c` — Routing Table, Longest-Prefix Match

128-entry FIB. Each entry: prefix (IP + prefix_len), next_hop, out_iface, hit_count.

```c
int route_lookup(uint32_t dst_ip, uint32_t *next_hop, int *out_iface);
```
Scans all entries, finds the one with longest matching prefix. Returns next_hop and output interface.

### 22.3 `route_table.c` — Multiple Named Routing Tables (VRF-lite)

Up to 8 named tables ("main", "mgmt", custom). Each has independent FIB. PBR can select which table to use.

### 22.4 `acl.c` — Access Control List, First-Match Evaluation

Ordered rule list (max 64 rules). Each rule: match criteria + action (PERMIT/DENY).

```c
acl_action_t acl_evaluate(src_ip, dst_ip, protocol, src_port, dst_port);
```
Top-down scan, first match wins. Default policy (PERMIT or DENY) if no rule matches.

### 22.5 `pbr.c` — Policy-Based Routing, Loop Detection

PBR overrides normal routing based on source IP, destination IP, protocol. Evaluated before FIB lookup.

**Loop detection:** Tracks visited hops in `pkt_context_t`. If PBR would send to an already-visited hop → return -2 (loop).

### 22.6 `icmp.c` — Echo Request/Reply, Redirect Handling

- Echo Request (type=8) → swap src/dst, change type to 0, recompute checksum, send reply
- ICMP Redirect (type=5) → if `icmp-redirect-disable` enabled, ignore; otherwise add host route
- Covert detection hook: check payload entropy and timing when `covert-detect` enabled

### 22.7 `ip_frag.c` — Fragmentation and Reassembly

**Fragmentation:** Split oversized packets into MTU-sized fragments with correct MF flag and offset.

**Reassembly:** Collect fragments by ID, order by offset, reconstruct when last fragment (MF=0) received. Timeout: 30 seconds.

**Security:** Reject overlapping fragments, reject tiny fragments (<68 bytes), limit fragments per ID (max 64).

### 22.8 `conntrack.c` — Connection Tracking

Tracks flows by 5-tuple (src_ip, dst_ip, proto, src_port, dst_port). Bidirectional matching.

States: NEW → ESTABLISHED (on reply) → expired (timeout). Per-protocol timeouts: TCP=300s, UDP=30s, ICMP=10s.

### 22.9 `nat.c` — SNAT/DNAT, Port Allocation

**SNAT:** Match source prefix → rewrite src IP to public IP, allocate port from pool (10000-65000). Create mapping for return-path translation.

**DNAT:** Match dst IP+port → rewrite to internal server IP+port.

**Mappings:** Bidirectional. Return traffic automatically reverse-translated.

---

## 23. Layer 4 Implementation (`src/ironstack/l4/`)

### 23.1 `tcp.c` — TCP State Machine, Connection Table, SYN Cookies, Output

**Connection table:** 256 entries. Each: 4-tuple, state, seq/ack numbers, last_activity timestamp.

**State machine:** CLOSED → SYN_RECV → ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED.

**SYN handling:**
1. Check rate limit (if enabled)
2. If SYN cookies enabled → send cookie in SYN+ACK, no state allocated
3. Otherwise → allocate entry, set SYN_RECV, send SYN+ACK
4. Covert detection: analyze ISN for encoded data (if enabled)

**Data delivery:** When data arrives for ESTABLISHED connection → find registered app listener → call `on_data` callback.

**TCP output:** `tcp_send_segment()` builds TCP header with proper checksum (including pseudo-header) and calls `ip_output()`.

**Timers:** `tcp_timer_tick()` cleans up TIME_WAIT (60s) and idle connections (configurable timeout).

### 23.2 `udp.c` — Stateless UDP Dispatch

Simple: parse header (8 bytes), extract ports, find registered listener, call `on_data` callback. No state, no connection tracking at L4 level.

---

## 24. Security Module (`src/ironstack/security/`)

### 24.1 `defense.c` — Defense Registry, SYN Cookies, Rate Limiting

**Registry:** 16 named defenses, each with enable/disable state. `defense_is_enabled("name")` checked inline in the data path.

**SYN cookies:**
```c
uint32_t syncookie_generate(src_ip, dst_ip, src_port, dst_port, client_seq);
bool syncookie_validate(src_ip, dst_ip, src_port, dst_port, cookie, ack);
```
Cookie = hash of 4-tuple + secret. Validated when ACK arrives.

**Rate limiting:** 64 per-source buckets. `rate_limit_check(src_ip)` returns false if source exceeded threshold. `rate_limit_tick()` resets all counters every second.

### 24.2 `ipsec.c` — SA Lifecycle, Policy Enforcement, XOR Transform

**SA database:** 32 entries. Each: SPI, src/dst IP, direction, transform, key, timestamps, counters.

**Policy database:** 16 entries. Each: match criteria + action (PROTECT/BYPASS/DISCARD) + SA reference.

**Transform:** XOR each payload byte with key byte (dummy crypto — demonstrates control flow without real crypto complexity). XOR is its own inverse, so same function encrypts and decrypts.

**Fail-closed:** If policy says PROTECT but SA is missing/expired → drop (never send unprotected).

### 24.3 `covert_detect.c` — Entropy Analysis, Timing Bimodality, ISN/DNS Detection

**Shannon entropy:** `calc_entropy(data, len)` — measures information density (0=uniform, 8=max random).

**ICMP detection:** Flag payloads with entropy > 5.7 OR ASCII ratio > 70% (normal ping is non-printable pattern).

**Timing detection:** Maintain 32-sample history of inter-packet gaps. If >70% fall in two clusters (10ms and 100ms) → bimodal timing channel detected.

**ISN detection:** Maintain 4-sample history of TCP sequence numbers. If >65% of bytes are printable ASCII → encoded text in ISNs.

**DNS detection:** Calculate entropy of first query label. If >3.5 and label length ≥8 → possible base64 exfiltration.

---


## 25. Application Servers (`src/ironapps/`)

### 25.1 `app_socket.c` — Socket API, Listener Registry, TCP/UDP Output

The application-facing API:
```c
int app_socket_listen(protocol, port, on_data_cb, on_accept_cb, on_close_cb);
int app_socket_send(dst_ip, dst_port, src_ip, src_port, protocol, data, len);
```

**Listener registry:** Up to 32 listeners. When TCP/UDP delivers data, `app_find_listener(proto, port)` finds the registered callback.

**TCP output:** Builds TCP segment with proper checksum (pseudo-header included), calls `ip_output()`.

**UDP output:** Builds UDP packet (8-byte header + payload), calls `ip_output()`.

### 25.2 `echo_server.c` — TCP/UDP Echo (Port 7)

Simplest possible server: receives data, sends it back unchanged. Registered on both TCP and UDP port 7.

### 25.3 `dns_server.c` — DNS Server with Zone Table, Cache, Response Builder

**Zone table:** 16 static entries (example.com, ironnet.local, etc.).

**Cache:** 32 entries with TTL. First lookup caches result for 60s. Expired entries removed on next access.

**Response builder:** Copies query header+question, sets QR=1/AA=1/RD=1/RA=1, appends A record answer. Handles EDNS0 by only copying the question section (not additional records).

**Response acceptance:** Incoming DNS responses (QR=1) are parsed and cached via `dns_cache_add_secure()` — simulates recursive resolver behavior for Kaminsky attack demonstration.

### 25.4 `kv_server.c` — Key-Value Store (Port 6379)

Text protocol: `SET key value`, `GET key`, `DEL key`. 256-entry in-memory hash table. Responses: `+OK`, `$value`, `$nil`, `-ERR`.

### 25.5 `http_server.c` — HTTP-Like Server (Port 8080)

Parses `GET /path HTTP/1.0`. Returns 200 OK for `/` and `/index`, 404 for other paths, 400 for non-GET methods.

### 25.6 `rpc_server.c` — Binary RPC Protocol (Port 9000)

Fixed-size header: `[MAGIC "IRON" 4B][CMD 2B][LENGTH 2B][PAYLOAD...]`

Commands: PING→PONG, ECHO→ECHO_REPLY, STATUS→STATUS_REPLY. Invalid magic or unknown command → ERROR response.

### 25.7 `vuln_server.c` — Intentionally Vulnerable Server (Port 9999)

**Commands and vulnerabilities:**
| Command | Vulnerability | CWE |
|---------|--------------|-----|
| `ECHO <text>` | Stack buffer overflow (strcpy, 64B buffer) | CWE-121 |
| `FMT <text>` | Format string (user input as format) | CWE-134 |
| `READ <len>` | Integer overflow (uint8_t truncation) | CWE-190 |
| `CANARY <text>` | Mitigation: stack canary detection | — |
| `BOUNDS <text>` | Mitigation: input length validation | — |
| `ASLR <text>` | Mitigation: randomized buffer address | — |
| `SAFE <text>` | Safe comparison (strncpy) | — |

---

## 26. Attack Tools (`src/ironattack/`)

### 26.1 `main.c` — Subcommand Dispatch (12 Commands)

```
ironattack <subcommand> [options]

Subcommands:
  syn-flood, arp-spoof, vlan-hop, rst-inject, ip-spoof,
  slowloris, frag-attack, icmp-redirect, dns-spoof,
  dns-spoof-ext, exploit, covert
```

Each subcommand parses its own options and executes independently.

### 26.2 `craft.c` — Raw Packet Construction

Builds complete Ethernet+IP+TCP/ARP/ICMP frames from scratch:
- `craft_tcp_syn()` — SYN packet with checksums
- `craft_tcp_rst()` — RST packet
- `craft_tcp_ack()` — ACK+PSH with payload (for slowloris)
- `craft_arp_reply()` — ARP reply (for spoofing)
- `craft_double_tagged()` — Q-in-Q VLAN hopping frame
- `craft_ip_fragment()` — IP fragment with controlled offset/MF
- `craft_icmp_redirect()` — ICMP redirect message

**tap_open():** Opens IPPROTO_RAW socket with IP_HDRINCL + SO_BINDTODEVICE. Packets route through kernel into the TAP device.

**tap_write():** Strips Ethernet header (raw socket sends IP-level), sends via `sendto()`.

### 26.3 `dns_spoof_ext.c` — External DNS Cache Poisoning

Floods forged DNS responses with random transaction IDs. Source IP spoofed as upstream DNS (8.8.8.8). Targets ironstack's DNS server which accepts responses (QR=1) and caches them.

### 26.4 `exploit.c` — Buffer Overflow Exploitation

Four modes targeting the vulnerable server (port 9999):
- `crash` — send oversized input, trigger ASAN abort
- `pattern` — send cyclic pattern, identify return address offset
- `payload` — overwrite return address with 0xDEADBEEFCAFEBABE
- `fmtstr` — leak stack memory via %p/%x format specifiers

Connects via normal TCP socket (no raw socket needed).

### 26.5 `covert.c` — 6 Covert Channel Implementations

| Mode | Channel type | Technique |
|------|-------------|-----------|
| `icmp` | Storage | Message in ICMP echo payload |
| `isn` | Storage | 4 bytes per SYN in sequence number |
| `dns` | Storage | Base64 in DNS query subdomain |
| `timing` | Timing | Bit encoded as inter-packet delay |
| `counting` | Timing | Bit encoded as burst size per window |
| `ipid` | Storage | 2 bytes per packet in IP ID field |

### 26.6 `mitm.c` — MITM Relay Engine

Standalone binary (`ironmitm`):
1. ARP-poisons both victims bidirectionally
2. Opens AF_PACKET in promiscuous mode
3. Sniffs all intercepted traffic, logs to file
4. Optionally modifies payloads (`--modify "find:replace"`)
5. Forwards packets to real destination (MAC rewrite)

---

## 27. Supporting Tools

### 27.1 `ironctl/cli.c` — Embedded CLI

Spawns a pthread that reads stdin. Tokenizes input into argc/argv, dispatches to command handlers. Commands: show, route, acl, arp, defense, scan, ping, fuzz, load, trace, dns, tcp flush, audit, help, exit.

### 27.2 `ironmon/audit.c` — Audit Ring Buffer, File Output

256-event ring buffer. Each event: timestamp, type, src/dst IP, protocol, ports, detail string. Written to `/tmp/ironnet_audit.log` (append mode). JSON export via `audit_dump_json()`.

### 27.3 `ironmon/stats_json.c` — JSON Stats Export

Outputs all non-zero counters as JSON: `{"l2.rx_frames": 47, "l3.drops.acl": 3, ...}`

### 27.4 `ironprobe/probe.c` — Internal Port Scanner

Checks listener registry and ACL to determine port state (OPEN/FILTERED/CLOSED) without sending real packets. Fast, no sudo needed.

### 27.5 `ironfuzz/fuzz.c` — Mutation Engine, Corpus, Seed Generators

8 mutation strategies: bit-flip, byte-flip, truncate, extend, boundary values, insert, delete, field-aware. Pre-built seeds for TCP SYN, DNS query, HTTP GET, RPC PING.

### 27.6 `ironload/load.c` — Stress Tester

4 test types: TCP flood (fill connection table), route stress (fill FIB), ACL stress (many rules), bandwidth (max packet rate). Reports: attempted/succeeded/rejected/elapsed/avg per op.

### 27.7 `irontrace/trace.c` — pcap Capture with Pipeline Hooks

Hooks at L2 RX/TX, L3 RX/TX, L4 RX. Writes pcap format (global header + per-packet header + data). CLI: `trace start/stop/status`.

### 27.8 `irontrace/replay.c` — pcap Replay via Raw Socket

Reads pcap file, injects packets via IPPROTO_RAW + SO_BINDTODEVICE. Supports timed mode (preserve original delays) and fast mode (max speed).

### 27.9 `ironsim/main.c` — Network Emulator

Spawns multiple ironstack instances (fork+exec) with generated configs. Creates TAP interfaces, assigns IPs, adds host routes, applies tc netem impairments (delay, loss, reorder). Clean shutdown via SIGTERM.

### 27.10 `ironsim/test_traffic.c` — Traffic Generator

Sends ICMP pings and TCP connections to all topology nodes. Reports: sent/received/loss/min/avg/max RTT per target.

### 27.11 `ironprobe_ext/main.c` — External SYN Scanner

Sends real TCP SYN packets via raw socket, listens for SYN+ACK (open) or RST (closed) or timeout (filtered). Reports per-port state.

### 27.12 `ironprobe_ext/report.c` — Automated Attack-Defense Report

Runs 5 attack/defense pairs programmatically, measures effectiveness with and without defenses, outputs formatted pass/fail report.

---

## 28. Test Infrastructure (`src/tests/`)

### 28.1 Test Philosophy

| Type | Purpose | Output | Speed |
|------|---------|--------|-------|
| Unit test | Correctness of one module | PASS/FAIL | Fast (<1ms) |
| Module test | Integration between modules | Hex dumps, decoded fields | Fast (<10ms) |
| Interactive | Full system behavior | Terminal output | Manual |

Unit tests use stubs to isolate the module under test. Module tests include multiple source files directly.

### 28.2 Stub Pattern

Tests that include `tcp.c` need stubs for functions tcp.c calls but that aren't part of the test:

```c
// stubs/defense_stub.c
bool defense_is_enabled(const char *n) { (void)n; return false; }
int defense_init(void) { return 0; }
// ... all defense functions return no-op values
```

Stubs used: `defense_stub.c`, `audit_stub.c`, `trace_stub.c`, `covert_stub.c`, `app_stub.c`, `ip_output_stub.c`.

### 28.3 Module Test Framework (`module_test.h`)

Provides test registration and execution:
```c
mt_suite_init(&suite, "L2 Module Test");
mt_suite_add(&suite, "Text Payload Frame", test_text_payload);
mt_suite_add(&suite, "IPv4+TCP SYN Frame", test_ipv4_tcp);
mt_suite_run(&suite);  // runs all, prints summary
```

Helpers: `mt_hex_dump()`, `mt_print_mac()`, `mt_print_ip()`.

### 28.4 Unit Test Listing (21 Tests)

| Test | Module | Assertions |
|------|--------|------------|
| test_stats | stats.c | 5 (init, increment, add, decrement, name) |
| test_eth | eth.c | 5 (parse valid, too short, unknown ethertype, build, too large) |
| test_route | route.c | 4 (add/lookup, no match, longest prefix, delete) |
| test_acl | acl.c | 5 (default deny/permit, permit rule, deny rule, first match) |
| test_tcp | tcp.c | 5 (SYN creates, ACK establishes, FIN closes, invalid flags, table full) |
| test_ipsec | ipsec.c | 5 (SA CRUD, outbound protect, inbound decrypt, discard, fail closed) |
| test_vlan | vlan.c | 7 (access untagged, wrong VLAN, trunk tagged, not allowed, untagged drop, egress trunk, egress access) |
| test_arp | arp.c | 4 (add/resolve, unknown sends request, reply handling, entry update) |
| test_ip_frag | ip_frag.c | 4 (no frag needed, fragmentation, DF flag, reassembly) |
| test_iface | iface.c | 4 (add/get, find by IP, find by name, is_local_ip) |
| test_pbr | pbr.c | 4 (match, no match, loop detection, delete) |
| test_route_table | route_table.c | 6 (default main, create/find, independent, longest prefix, delete, duplicate) |
| test_conntrack | conntrack.c | 6 (new, reply establishes, UDP, bidirectional, unknown invalid, counters) |
| test_nat | nat.c | 6 (SNAT outbound, return traffic, DNAT, no rule, reuse mapping, different ports) |
| test_defense | defense.c | 5 (init disabled, enable/disable, syncookie, rate limit, unknown) |
| test_audit | audit.c | 5 (log/retrieve, ring wraps, disable suppresses, enable resumes, multiple types) |
| test_app_socket | app_socket.c | 4 (listen/find, wrong port, wrong protocol, multiple) |
| test_dns | dns_server.c | 3 (lookup found, not found, multiple entries) |
| test_covert_detect | covert_detect.c | 7 (ICMP low entropy, ICMP high ASCII, ISN random, ISN ASCII, DNS normal, DNS base64, DNS short) |
| test_apps | kv/http/rpc | 11 (KV set/get/del/unknown, HTTP get/404/400, RPC ping/echo/bad magic/short) |
| test_router_conf | router_conf.c | 5 (load config, interface parsed, routes parsed, ACL parsed, missing file) |

### 28.5 Module Test Listing (11 Tests)

| Test | What it demonstrates |
|------|---------------------|
| test_l2_module | Frame build/parse, hex dump, ASCII payload, invalid frame handling |
| test_l3_module | IP forwarding with TTL, TTL expiry drop, ICMP echo→reply |
| test_pbr_acl_module | PBR redirect, PBR loop, ACL deny SSH, ACL permit HTTP |
| test_l4_module | TCP handshake, graceful close, invalid flags, UDP receive |
| test_ipsec_module | Encrypt/decrypt roundtrip, DISCARD policy, fail closed, SA expiry |
| test_vlan_module | Trunk tag insert/strip, access VLAN assign, VLAN isolation |
| test_bridge_module | MAC learning, broadcast flood, VLAN isolation, no hairpin |
| test_route_table_module | Independent routing, PBR table selection, table isolation |
| test_conntrack_module | TCP lifecycle, UDP stateful, stateful ACL, timeout expiry |
| test_nat_module | SNAT roundtrip, DNAT port forward, multiple hosts, no rule passthrough |
| test_security_module | Fuzz no crash, mutation changes data, route stress |

---


## 29. Building IronNet

### 29.1 Prerequisites (WSL2, Ubuntu, GCC, CMake)

```bash
# Windows: Install WSL2 with Ubuntu 22.04+
wsl --install -d Ubuntu

# Inside WSL:
sudo apt update
sudo apt install -y build-essential cmake dnsutils
```

Required: GCC 12+, CMake 3.20+, Make.

### 29.2 Debug Build (with ASAN)

```bash
cd IronNet
mkdir -p build && cd build
cmake ../src -DCMAKE_BUILD_TYPE=Debug
make
```

Debug build enables AddressSanitizer — detects buffer overflows, use-after-free, and other memory errors at runtime.

### 29.3 Release Build (Optimized)

```bash
mkdir -p build-release && cd build-release
cmake ../src -DCMAKE_BUILD_TYPE=Release
make
```

No ASAN, full optimization. Buffer overflows cause real undefined behavior instead of clean ASAN reports.

### 29.4 Running Tests (ctest)

```bash
cd IronNet/build
ctest --output-on-failure
# Expected: 32 tests (21 unit + 11 module), all passing
```

### 29.5 Troubleshooting Common Build Issues

| Issue | Solution |
|-------|----------|
| `cmake: command not found` | `sudo apt install cmake` |
| `cc: command not found` | `sudo apt install build-essential` |
| ASAN errors at runtime | Expected in Debug — indicates real bugs |
| Path with spaces fails | Use symlink: `ln -s "/mnt/c/.../IronNet" ~/ironnet` |
| TAP creation fails | Need `sudo` for ironstack |

---

## 30. Running the Virtual Router

### 30.1 Starting ironstack with Config File

```bash
cd IronNet/build
sudo ./ironstack/ironstack ../src/configs/router.conf      # normal
sudo ./ironstack/ironstack -d ../src/configs/router.conf   # debug logging
```

### 30.2 Linux-Side TAP Setup

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up
```

### 30.3 CLI Usage (ironctl Prompt)

```
ironctl> help                    # list all commands
ironctl> show routes             # display routing table
ironctl> defense show            # show defense states
ironctl> exit                    # graceful shutdown
```

### 30.4 Verifying Connectivity

```bash
ping -c 3 10.0.1.1              # ICMP
dig @10.0.1.1 ironnet.local     # DNS
echo "hello" | nc -w2 10.0.1.1 7  # TCP echo
```

---

## 31. Running Attack Tools

### 31.1 ironattack Subcommands Overview

All attack commands require `sudo` (raw socket) except `exploit` (normal TCP).

```bash
sudo ./ironattack/ironattack --help
```

### 31.2 Attack Workflow (Reconnaissance → Exploitation → Post-Exploitation)

```
1. RECONNAISSANCE: scan 10.0.1.1 1 10000 → find open ports
2. EXPLOITATION: ironattack syn-flood/arp-spoof/exploit/etc.
3. VERIFICATION: show tcp / show arp / dns cache → confirm impact
4. DEFENSE: defense <name> enable → enable mitigation
5. RE-TEST: repeat attack → confirm defense works
```

### 31.3 Defense Enable/Disable Workflow

Test attack without defense (baseline), enable defense, repeat attack, compare results.

### 31.4 Attack-Defense Report (ironreport)

```bash
sudo ./ironprobe_ext/ironreport
# Runs 5 attack/defense pairs, outputs pass/fail table
```

---

## 32. Network Emulation (ironsim)

### 32.1 Topology Configuration Format

```
node a ip 10.0.1.1/24
node b ip 10.0.1.254/24 ip 10.0.2.254/24
node c ip 10.0.2.1/24
link a b delay 5ms
link b c delay 10ms loss 1%
```

### 32.2 2-Node and 3-Node Topologies

```bash
sudo ./ironsim/ironsim                              # 2-node default
sudo ./ironsim/ironsim ../src/configs/topo_3node.conf  # 3-node
```

### 32.3 Link Impairments (Delay, Loss, Reorder)

Applied via Linux `tc netem`. Configurable per-link in topology file.

### 32.4 Traffic Testing (ironsim-test)

```bash
sudo ./ironsim/ironsim-test --all --count 10 --tcp 7
```

---

## 33. Packet Capture and Replay (irontrace)

### 33.1 Starting/Stopping Capture

```
ironctl> trace start /tmp/capture.pcap all
ironctl> trace stop
ironctl> trace status
```

### 33.2 pcap Format and Wireshark Compatibility

Standard pcap format. Open with: `wireshark /tmp/capture.pcap` or `tcpdump -r /tmp/capture.pcap -XX`

### 33.3 Replay Modes (Timed vs Fast, Internal vs External)

```bash
# External (realistic, via raw socket)
sudo ./irontrace/irontrace-replay --file /tmp/capture.pcap --iface iron0

# Internal (full bidirectional, via CLI)
ironctl> trace replay /tmp/capture.pcap
```

### 33.4 Regression Testing Workflow

Capture → fix bug → replay → verify correct behavior.

---

## 34. Demo Guide

### 34.1 Demo File Organization (36 Self-Contained Demos)

Each demo in `demos/` includes prerequisites, build steps, terminal instructions, and expected output.

### 34.2 Quick Reference: Which Demo for Which Topic

| Topic | Demos |
|-------|-------|
| Basic router + ping | demo.01-03 |
| Application servers | demo.04 |
| Scanning & testing | demo.05-07 |
| Network attacks | demo.08-17 |
| Network emulation | demo.18-20 |
| Packet capture | demo.21-23 |
| MITM | demo.24-26 |
| DNS attacks | demo.27-30 |
| Buffer overflow | demo.31-33 |
| Covert channels | demo.34-36 |

### 34.3 Recommended Learning Path for Beginners

```
Week 1: demo.01 → demo.02 → demo.04 (fundamentals)
Week 2: demo.05 → demo.06 → demo.07 (testing tools)
Week 3: demo.08 → demo.09 → demo.12 (network attacks)
Week 4: demo.24 → demo.27 → demo.30 (MITM + DNS)
Week 5: demo.31 → demo.32 → demo.33 (exploitation)
Week 6: demo.34 → demo.35 → demo.36 (covert channels)
```

---


## 35. Glossary of Terms

### Network Terminology

| Term | Definition |
|------|-----------|
| **MTU** | Maximum Transmission Unit — largest packet size a link can carry (typically 1500 bytes) |
| **TTL** | Time To Live — decremented at each hop, packet dropped at 0 |
| **CIDR** | Classless Inter-Domain Routing — notation like 10.0.1.0/24 |
| **NAT** | Network Address Translation — rewrites IP addresses at router boundary |
| **SNAT** | Source NAT — rewrites source IP (masquerade) |
| **DNAT** | Destination NAT — rewrites destination IP (port forwarding) |
| **FIB** | Forwarding Information Base — the routing table |
| **ARP** | Address Resolution Protocol — maps IP to MAC address |
| **VLAN** | Virtual LAN — logical network segmentation at Layer 2 |
| **VRF** | Virtual Routing and Forwarding — multiple independent routing tables |
| **PBR** | Policy-Based Routing — route based on source/protocol, not just destination |
| **ACL** | Access Control List — ordered rules to permit/deny traffic |
| **SPI** | Security Parameter Index — identifies an IPsec Security Association |
| **SA** | Security Association — IPsec agreement (algorithm, key, lifetime) |
| **ISN** | Initial Sequence Number — first seq number in TCP handshake |
| **MSS** | Maximum Segment Size — largest TCP payload per segment |
| **RTT** | Round-Trip Time — time for packet to reach destination and return |
| **TAP** | Network TAP — virtual Layer 2 interface (Ethernet frames) |
| **TUN** | Network TUNnel — virtual Layer 3 interface (IP packets) |
| **pcap** | Packet Capture format — standard file format for captured packets |

### Security Terminology

| Term | Definition |
|------|-----------|
| **CVE** | Common Vulnerabilities and Exposures — unique ID for known vulnerabilities |
| **CWE** | Common Weakness Enumeration — classification of vulnerability types |
| **ASLR** | Address Space Layout Randomization — randomize memory addresses |
| **DEP/NX** | Data Execution Prevention / No-Execute — mark memory as non-executable |
| **ROP** | Return-Oriented Programming — chain existing code gadgets for exploitation |
| **ASAN** | AddressSanitizer — compiler tool detecting memory errors at runtime |
| **DoS** | Denial of Service — make a service unavailable |
| **DDoS** | Distributed Denial of Service — DoS from many sources |
| **MITM** | Man-in-the-Middle — attacker intercepts communication between two parties |
| **uRPF** | unicast Reverse Path Forwarding — source IP validation |
| **IDS** | Intrusion Detection System — monitors for malicious activity |
| **IPS** | Intrusion Prevention System — blocks malicious activity |
| **DNSSEC** | DNS Security Extensions — cryptographic DNS response validation |

### IronNet-Specific Terminology

| Term | Definition |
|------|-----------|
| **ironstack** | Main daemon — the protocol stack that processes packets |
| **ironctl** | Embedded CLI for runtime configuration |
| **ironmon** | Telemetry and audit logging subsystem |
| **ironapps** | Application servers running on top of the stack |
| **ironattack** | External attack tool with 12 subcommands |
| **ironmitm** | MITM relay engine (separate binary) |
| **ironsim** | Network emulator (spawns multiple ironstack instances) |
| **irontrace** | Packet capture and replay subsystem |
| **ironprobe** | Internal port scanner |
| **ironprobe-ext** | External SYN scanner via raw socket |
| **ironreport** | Automated attack-defense test report |
| **ironfuzz** | Protocol fuzzer with 8 mutation strategies |
| **ironload** | Stress tester (TCP flood, route/ACL stress) |

---

## 36. Protocol Reference Tables

### Ethernet Frame Format

```
Offset  Size    Field
0       6       Destination MAC address
6       6       Source MAC address
12      2       EtherType (0x0800=IPv4, 0x0806=ARP, 0x8100=VLAN)
14      46-1500 Payload
```
Total: 60-1514 bytes (excluding preamble and FCS).

### IPv4 Header Format

```
Offset  Size    Field
0       1       Version (4 bits) + IHL (4 bits)
1       1       Type of Service (DSCP + ECN)
2       2       Total Length
4       2       Identification
6       2       Flags (3 bits) + Fragment Offset (13 bits)
8       1       TTL
9       1       Protocol (1=ICMP, 6=TCP, 17=UDP)
10      2       Header Checksum
12      4       Source IP Address
16      4       Destination IP Address
20      0-40    Options (if IHL > 5)
```
Minimum: 20 bytes. Maximum: 60 bytes.

### TCP Header Format

```
Offset  Size    Field
0       2       Source Port
2       2       Destination Port
4       4       Sequence Number
8       4       Acknowledgment Number
12      1       Data Offset (4 bits) + Reserved (4 bits)
13      1       Flags: URG|ACK|PSH|RST|SYN|FIN
14      2       Window Size
16      2       Checksum
18      2       Urgent Pointer
20      0-40    Options (if Data Offset > 5)
```
Minimum: 20 bytes.

### UDP Header Format

```
Offset  Size    Field
0       2       Source Port
2       2       Destination Port
4       2       Length (header + payload)
6       2       Checksum (optional in IPv4)
8       ...     Payload
```
Fixed: 8 bytes header.

### ICMP Header Format

```
Offset  Size    Field
0       1       Type (8=echo request, 0=echo reply, 5=redirect, 11=time exceeded)
1       1       Code
2       2       Checksum
4       4       Type-specific data (ID+Seq for echo, Gateway for redirect)
8       ...     Payload (original IP header for error messages)
```
Minimum: 8 bytes.

### DNS Message Format

```
Offset  Size    Field
0       2       Transaction ID
2       2       Flags (QR, Opcode, AA, TC, RD, RA, RCODE)
4       2       Question Count (QDCOUNT)
6       2       Answer Count (ANCOUNT)
8       2       Authority Count (NSCOUNT)
10      2       Additional Count (ARCOUNT)
12      ...     Question Section (name + type + class)
...     ...     Answer Section (name + type + class + TTL + rdlength + rdata)
```
Header: 12 bytes. Name encoding: length-prefixed labels (`\x07ironnet\x05local\x00`).

### ARP Packet Format

```
Offset  Size    Field
0       2       Hardware Type (1 = Ethernet)
2       2       Protocol Type (0x0800 = IPv4)
4       1       Hardware Address Length (6 for Ethernet)
5       1       Protocol Address Length (4 for IPv4)
6       2       Operation (1=Request, 2=Reply)
8       6       Sender Hardware Address (MAC)
14      4       Sender Protocol Address (IP)
18      6       Target Hardware Address (MAC)
24      4       Target Protocol Address (IP)
```
Fixed: 28 bytes (after Ethernet header).

---

## 37. Attack-Defense Matrix

| Attack | Tool Command | Defense | Defense Command | Effectiveness |
|--------|-------------|---------|-----------------|---------------|
| SYN Flood | `ironattack syn-flood` | SYN Cookies | `defense syn-cookies enable` | Table stays empty under flood |
| SYN Flood | `ironattack syn-flood` | Rate Limit | `defense rate-limit 100/s` | Excess SYNs dropped |
| ARP Spoofing | `ironattack arp-spoof` | ARP Inspection | `defense arp-inspection enable` | Fake ARP replies blocked |
| VLAN Hopping | `ironattack vlan-hop` | VLAN Strict | `defense vlan-strict enable` | Double-tagged frames dropped |
| TCP RST Injection | `ironattack rst-inject` | RST Validation | `defense rst-validation enable` | Forged RSTs rejected |
| IP Spoofing | `ironattack ip-spoof` | uRPF | `defense urpf enable` | Spoofed packets dropped |
| Slowloris | `ironattack slowloris` | Conn Timeout | `defense conn-timeout 30` | Idle connections closed |
| Fragmentation | `ironattack frag-attack` | Frag Strict | `defense frag-strict enable` | Overlap/tiny fragments dropped |
| ICMP Redirect | `ironattack icmp-redirect` | Redirect Disable | `defense icmp-redirect-disable enable` | Redirects ignored |
| DNS Poisoning | `ironattack dns-spoof-ext` | DNS Validate | `defense dns-validate enable` | Forged responses blocked |
| MITM (ARP) | `ironmitm` | MITM Detect | `defense mitm-detect enable` | MAC flap alerts |
| Covert Channels | `ironattack covert` | Covert Detect | `defense covert-detect enable` | Anomaly alerts |
| Buffer Overflow | `ironattack exploit` | ASAN / Canary / Bounds | (compile-time / CANARY / BOUNDS cmd) | Overflow detected/prevented |
| MAC Flooding | Phase 20 `ironattack mac-flood` | Port Security | Phase 20 `defense port-security` | MAC limit per port |
| Stealth Scan | Phase 21 `ironattack stealth-scan` | Stateful ACL | conntrack + ACL | Unusual flags logged |
| Session Hijack | Phase 22 `ironattack session-hijack` | Challenge ACK | Phase 22 `defense challenge-ack` | Hijack attempt rejected |

---

## 38. Port and Service Map

| Port | Protocol | Service | Binary | Purpose |
|------|----------|---------|--------|---------|
| 7 | TCP | Echo | ironstack (ironapps) | Echoes received data back |
| 7 | UDP | Echo | ironstack (ironapps) | Echoes received data back |
| 53 | UDP | DNS | ironstack (ironapps) | Resolves domain names from zone table |
| 6379 | TCP | KV Store | ironstack (ironapps) | SET/GET/DEL key-value operations |
| 8080 | TCP | HTTP | ironstack (ironapps) | Simple GET request handling |
| 9000 | TCP | Binary RPC | ironstack (ironapps) | PING/ECHO/STATUS with binary protocol |
| 9999 | TCP | Vulnerable | ironstack (ironapps) | Intentionally insecure (overflow, format string) |

**External tools (no listening port — they send packets):**
| Tool | Socket Type | Purpose |
|------|-------------|---------|
| ironattack | IPPROTO_RAW | Send crafted attack packets |
| ironmitm | AF_PACKET | Sniff + forward (promiscuous) |
| ironprobe-ext | IPPROTO_RAW | SYN scan via raw socket |
| irontrace-replay | IPPROTO_RAW | Replay pcap captures |
| ironsim | fork+exec | Spawn multiple ironstack instances |

---

## 39. References and Further Reading

### RFCs (Protocol Specifications)

| RFC | Title | Relevance |
|-----|-------|-----------|
| RFC 791 | Internet Protocol (IPv4) | IP header format, fragmentation |
| RFC 793 | Transmission Control Protocol | TCP state machine, flags, handshake |
| RFC 826 | Address Resolution Protocol | ARP request/reply format |
| RFC 768 | User Datagram Protocol | UDP header format |
| RFC 792 | Internet Control Message Protocol | ICMP types, ping, redirect |
| RFC 1035 | Domain Names - Implementation | DNS message format, name encoding |
| RFC 1071 | Computing the Internet Checksum | Checksum algorithm used by IP/TCP/UDP |
| RFC 2827 | Network Ingress Filtering (BCP 38) | uRPF / source IP validation |
| RFC 4987 | TCP SYN Flooding Attacks | SYN cookies defense |
| RFC 3704 | Ingress Filtering for Multihomed Networks | uRPF strict/loose mode |

### Security Resources

| Resource | URL | Content |
|----------|-----|---------|
| MITRE ATT&CK | attack.mitre.org | Adversary tactics and techniques |
| MITRE CWE | cwe.mitre.org | Common Weakness Enumeration |
| OWASP | owasp.org | Web application security |
| CVE Database | cve.mitre.org | Known vulnerability database |
| Exploit Database | exploit-db.com | Public exploits and PoCs |

### Books

| Title | Author | Topic |
|-------|--------|-------|
| TCP/IP Illustrated, Vol. 1 | W. Richard Stevens | Protocol internals (the bible) |
| Hacking: The Art of Exploitation | Jon Erickson | Buffer overflows, shellcode, networking |
| The Web Application Hacker's Handbook | Stuttard & Pinto | Web security |
| Network Security Assessment | Chris McNab | Penetration testing methodology |
| Computer Networking: A Top-Down Approach | Kurose & Ross | Networking fundamentals |
| Practical Packet Analysis | Chris Sanders | Wireshark and packet inspection |
| Metasploit: The Penetration Tester's Guide | Kennedy et al. | Exploitation framework |

### Tools (Real-World Equivalents)

| IronNet Tool | Real-World Equivalent | Purpose |
|-------------|----------------------|---------|
| ironattack syn-flood | hping3, Scapy | Packet crafting |
| ironattack arp-spoof | arpspoof, ettercap | ARP poisoning |
| ironmitm | mitmproxy, ettercap | Traffic interception |
| ironprobe-ext | nmap | Port scanning |
| ironattack dns-spoof-ext | dnsspoof, Scapy | DNS poisoning |
| ironattack exploit | Metasploit, pwntools | Exploitation |
| ironattack covert (dns) | iodine, dnscat2 | DNS tunneling |
| ironattack covert (icmp) | ptunnel, icmpsh | ICMP tunneling |
| irontrace | tcpdump, Wireshark | Packet capture |
| ironfuzz | AFL++, libFuzzer | Fuzzing |
| ironsim | GNS3, Mininet | Network emulation |

---

*End of document.*
