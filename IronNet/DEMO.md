# IronNet — Virtual Router Demo

This guide shows how to run the IronNet virtual router with real TAP interfaces on WSL Ubuntu.

---

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built (see `build.md`)
- Two terminal windows (both in WSL)

---

## Quick Start

### Terminal 1: Start the router

```bash
cd IronNet/build
make
sudo ./ironstack/ironstack ../src/configs/router.conf
```

You should see:
```
[INFO ] [MAIN] IronNet v0.1.0 starting...
[INFO ] [VNIC] Created TAP interface: iron0 (fd=4)
[INFO ] [IFACE] Interface iron0 added: 10.0.1.1/24 (vnic=0)
[INFO ] [VNIC] Created TAP interface: iron1 (fd=5)
[INFO ] [IFACE] Interface iron1 added: 10.0.2.1/24 (vnic=1)
[INFO ] [ROUTE] Route added: 10.0.1.0/24 via 10.0.1.0 iface 0
[INFO ] [ROUTE] Route added: 10.0.2.0/24 via 10.0.2.0 iface 1
[INFO ] [ROUTE] Route added: 0.0.0.0/0 via 0.0.0.0 iface 0
[INFO ] [ACL] Rule 1 added (PERMIT)
[INFO ] [ACL] Rule 2 added (PERMIT)
[INFO ] [ACL] Rule 3 added (DENY)
[INFO ] [MAIN] IronNet running. Press Ctrl+C to stop.
```

### Terminal 2: Configure Linux side and test

```bash
# Assign peer IPs to the TAP interfaces
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip addr add 10.0.2.2/24 dev iron1
sudo ip link set iron0 up
sudo ip link set iron1 up

# Ping the router
ping -c 3 10.0.1.1
ping -c 3 10.0.2.1
```

---

## Enable Debug Logging

To see all packet processing (ARP, IP forwarding, ACL decisions):

```bash
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

The `-d` flag enables DEBUG level logging. You'll see every packet received, parsed, and forwarded.

---

## Network Topology

```
Linux (Terminal 2)              IronNet Router (Terminal 1)
                                
  10.0.1.2/24  ←── iron0 ──→  10.0.1.1/24
                                10.0.2.1/24  ←── iron1 ──→  10.0.2.2/24
```

Both iron0 and iron1 are TAP interfaces. Linux sees them as normal network interfaces. IronNet reads/writes raw Ethernet frames through them.

---

## Test Cases

### 1. ICMP Ping (should work)

```bash
ping -c 3 10.0.1.1
ping -c 3 10.0.2.1
```

Expected: 3 replies from each. In Terminal 1 (with `-d`), you'll see:
```
[DEBUG] [L2] Dispatching IPv4 packet
[DEBUG] [ICMP] Echo request from ..., id=... seq=...
[DEBUG] [ICMP] Echo reply sent
```

### 2. ACL Deny (SSH port 22)

The config has: `acl deny tcp any any port 22`

```bash
nc -zv 10.0.1.1 22
```

Expected: `nc` hangs (no response). In Terminal 1, you'll see:
```
[INFO ] [ACL] DENY rule 3: 10.0.1.2 -> 10.0.1.1 proto=6 sport=xxxxx dport=22
```

### 3. ACL Permit (HTTP port 80)

The config has: `acl permit tcp any any port 80`

```bash
nc -zv 10.0.1.1 80
```

Expected: `nc` also hangs (no application listening on port 80 yet — that's Phase 11). But in Terminal 1, you will NOT see an ACL DENY message — the packet is permitted through ACL. The TCP SYN is accepted into the state machine but no SYN+ACK is sent back because there's no application.

### 4. View statistics on shutdown

Press `Ctrl+C` in Terminal 1. You'll see:
```
[INFO ] [STATS] --- IronNet Statistics ---
[INFO ] [STATS]   l2.rx_frames                   XX
[INFO ] [STATS]   l3.rx_packets                  XX
[INFO ] [STATS]   l3.local_deliver               XX
[INFO ] [STATS]   l3.drops.acl                   XX
[INFO ] [STATS]   tcp.conn_created               XX
[INFO ] [STATS] --- End ---
```

---

## Config File Format

`src/configs/router.conf`:
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
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ioctl TUNSETIFF failed` | Run with `sudo` |
| `/dev/net/tun` not found | `sudo mkdir -p /dev/net && sudo mknod /dev/net/tun c 10 200` |
| `RTNETLINK answers: File exists` | Route already exists (safe to ignore) |
| No output in Terminal 1 | Use `-d` flag for debug logging |
| `nc` hangs on permitted port | Check TCP checksum, use tcpdump to verify SYN+ACK sent |
| Ping works but nc doesn't | Likely TCP checksum issue — capture with tcpdump |

---

## Packet Capture for Debugging

Use `tcpdump` in a **third terminal** to see raw packets on the TAP interface:

### Capture all traffic with hex dump

```bash
sudo tcpdump -i iron0 -XX -n
```

This shows every frame entering/leaving iron0 in full hex + ASCII, including:
- Ethernet header (MACs, EtherType)
- IP header (src/dst, TTL, protocol)
- TCP/UDP header (ports, flags, checksum)
- Payload

### Capture only TCP traffic

```bash
sudo tcpdump -i iron0 -XX -n tcp
```

### Capture only traffic to/from a specific port

```bash
sudo tcpdump -i iron0 -XX -n port 7
sudo tcpdump -i iron0 -XX -n port 53
```

### Save to file for Wireshark analysis

```bash
sudo tcpdump -i iron0 -w /tmp/iron0.pcap
# Then open /tmp/iron0.pcap in Wireshark
```

### Example: debugging echo server

**Terminal 1:** Start router
```bash
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

**Terminal 2:** Capture packets
```bash
sudo tcpdump -i iron0 -XX -n port 7
```

**Terminal 3:** Send test traffic
```bash
echo "hello" | nc -w2 10.0.1.1 7
```

In Terminal 2 you'll see:
```
# SYN from client
10.0.1.2.54321 > 10.0.1.1.7: Flags [S], seq 12345...

# SYN+ACK from ironstack
10.0.1.1.7 > 10.0.1.2.54321: Flags [S.], seq 1000, ack 12346...

# ACK from client
10.0.1.2.54321 > 10.0.1.1.7: Flags [.], ack 1001...

# Data from client ("hello")
10.0.1.2.54321 > 10.0.1.1.7: Flags [P.], "hello"

# Echo reply from ironstack
10.0.1.1.7 > 10.0.1.2.54321: Flags [P.], "hello"
```

### What to look for when debugging

| Symptom | Check in tcpdump |
|---------|------------------|
| nc hangs (no response) | Is SYN+ACK being sent? Check flags and checksum |
| Connection reset | Is RST being sent? By whom? |
| Data not echoed | Is the data segment arriving? Is the echo reply sent? |
| ACL deny not working | Is the packet reaching ironstack at all? |
| ARP issues | Look for ARP requests/replies (EtherType 0x0806) |

Note: A built-in packet trace tool (irontrace) is planned for Phase 15.

---

## What's Happening Under the Hood

When you `ping 10.0.1.1`:

1. Linux sends ICMP echo request as an Ethernet frame into TAP `iron0`
2. IronNet reads the frame via `vnic_read()`
3. `eth_parse()` extracts the IPv4 packet
4. `ip_input()` validates the IP header
5. ACL check: **PERMIT rule 2 matches** (ICMP)
6. Destination 10.0.1.1 is local → `icmp_input()` called
7. ICMP echo reply built and sent via `ip_output()` → `eth_build()` → `vnic_write()`
8. Linux receives the reply on `iron0`

When you `nc 10.0.1.1 22`:

1. Linux sends TCP SYN to port 22 via `iron0`
2. IronNet receives it, `eth_parse()` extracts IPv4 packet
3. `ip_input()` validates IP header
4. ACL check: **DENY rule 3 matches** (TCP dst-port 22)
5. Packet dropped, counter incremented, log message printed:
   ```
   [INFO ] [ACL] DENY rule 3: 10.0.1.2 -> 10.0.1.1 proto=6 sport=xxxxx dport=22
   ```
6. `nc` never gets a response (no RST sent back)

---

## Cleanup

After stopping ironstack (Ctrl+C or `exit` command), the TAP interfaces are automatically removed. If they persist:

```bash
sudo ip link delete iron0
sudo ip link delete iron1
```

---

## CLI Demo (ironctl)

The router includes an embedded CLI. After startup, you'll see the `ironctl>` prompt where you can type commands interactively.

### Start the router with CLI

```bash
cd IronNet/build
sudo ./ironstack/ironstack ../src/configs/router.conf
```

You'll see startup logs followed by:
```
ironctl>
```

### Show commands

```
ironctl> help
Available commands:
  show stats              - Display counters
  show routes             - Display routing table
  show route-tables       - Display all routing tables
  show arp                - Display ARP table
  show tcp                - Display TCP connections
  show conntrack          - Display connection tracking
  show nat                - Display NAT mappings
  show interfaces         - Display interfaces
  show ipsec              - Display IPsec SA/policies
  route add <prefix>/<len> via <next_hop> iface <idx>
  route delete <prefix>/<len>
  acl add <permit|deny> <tcp|udp|icmp|any> port <port>
  acl delete <rule_id>
  arp add <ip> <mac>
  help                    - Show this help
  exit                    - Stop the router
```

### View interfaces loaded from config

```
ironctl> show interfaces
Interfaces (2):
  iron0  10.0.1.1/24  MAC 02:00:00:00:00:01  UP
  iron1  10.0.2.1/24  MAC 02:00:00:00:00:02  UP
```

### View routes loaded from config

```
ironctl> show routes
[INFO ] [ROUTE] --- Routing Table ---
[INFO ] [ROUTE]   10.0.1.0/24 via 10.0.1.0 iface 0 (hits: 0)
[INFO ] [ROUTE]   10.0.2.0/24 via 10.0.2.0 iface 1 (hits: 0)
[INFO ] [ROUTE]   0.0.0.0/0 via 0.0.0.0 iface 0 (hits: 0)
```

### Add a route at runtime

```
ironctl> route add 192.168.0.0/16 via 10.0.1.254 iface 0
[INFO ] [ROUTE] Route added: 192.168.0.0/16 via 10.0.1.254 iface 0

ironctl> show routes
[INFO ] [ROUTE] --- Routing Table ---
[INFO ] [ROUTE]   10.0.1.0/24 via 10.0.1.0 iface 0 (hits: 0)
[INFO ] [ROUTE]   10.0.2.0/24 via 10.0.2.0 iface 1 (hits: 0)
[INFO ] [ROUTE]   0.0.0.0/0 via 0.0.0.0 iface 0 (hits: 0)
[INFO ] [ROUTE]   192.168.0.0/16 via 10.0.1.254 iface 0 (hits: 0)
```

### Add ACL rules at runtime

```
ironctl> acl add deny tcp port 443
[INFO ] [ACL] Rule 100 added (DENY)

ironctl> acl show
[INFO ] [ACL] --- ACL Rules ---
[INFO ] [ACL]   Rule 1: PERMIT (hits: 5)
[INFO ] [ACL]   Rule 2: PERMIT (hits: 12)
[INFO ] [ACL]   Rule 3: DENY (hits: 3)
[INFO ] [ACL]   Rule 100: DENY (hits: 0)
[INFO ] [ACL]   Default: PERMIT
```

### Add static ARP entry

```
ironctl> arp add 10.0.1.5 02:00:00:00:00:05
ARP entry added.

ironctl> show arp
[INFO ] [ARP] --- ARP Table ---
[INFO ] [ARP]   10.0.1.5 -> 02:00:00:00:00:05
```

### View live statistics (after some traffic)

```
ironctl> show stats
[INFO ] [STATS] --- IronNet Statistics ---
[INFO ] [STATS]   l2.rx_frames                   47
[INFO ] [STATS]   l3.rx_packets                  35
[INFO ] [STATS]   l3.local_deliver               20
[INFO ] [STATS]   l3.drops.acl                   3
[INFO ] [STATS]   tcp.conn_created               2
[INFO ] [STATS] --- End ---
```

### View TCP connections

```
ironctl> show tcp
[INFO ] [TCP] --- TCP Connections (2 active) ---
[INFO ] [TCP]   10.0.1.2:54321 -> 10.0.1.1:80  state=SYN_RECV
[INFO ] [TCP]   10.0.1.2:54322 -> 10.0.1.1:80  state=SYN_RECV
```

### Delete a route

```
ironctl> route delete 192.168.0.0/16
Route deleted.
```

### Delete an ACL rule

```
ironctl> acl delete 100
ACL rule 100 deleted.
```

### Graceful shutdown

```
ironctl> exit
[INFO ] [MAIN] Shutting down...
[INFO ] [STATS] --- IronNet Statistics ---
...
[INFO ] [MAIN] IronNet stopped.
```

### CLI + Traffic Demo (two terminals)

**Terminal 1: Start router with CLI**
```bash
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

**Terminal 2: Generate traffic**
```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up
ping -c 3 10.0.1.1
nc -zv 10.0.1.1 22
```

**Terminal 1: Observe and interact**
```
# You'll see debug logs for each packet, then at the prompt:
ironctl> show stats
# See counters updated with the traffic

ironctl> show arp
# See 10.0.1.2 learned from ping

ironctl> acl add deny icmp port 0
# Now ping will be blocked

ironctl> show stats
# See l3.drops.acl increasing
```

---

## Audit Log Demo

The audit log captures all security-relevant events automatically.

### View audit log after ACL denies

```
ironctl> show audit-log
--- Audit Log (last 3 events) ---
  [17045] ACL_DENY             10.0.1.2:54321 -> 10.0.1.1:22 proto=6 rule 3
  [17046] ACL_DENY             10.0.1.2:54322 -> 10.0.1.1:22 proto=6 rule 3
  [17047] ACL_DENY             10.0.1.2:54323 -> 10.0.1.1:22 proto=6 rule 3
```

### JSON export for scripting

```
ironctl> show audit-log json
[
  {"ts":17045,"type":"ACL_DENY","src":"10.0.1.2","dst":"10.0.1.1","proto":6,"sport":54321,"dport":22,"detail":"rule 3"},
  {"ts":17046,"type":"ACL_DENY","src":"10.0.1.2","dst":"10.0.1.1","proto":6,"sport":54322,"dport":22,"detail":"rule 3"}
]

ironctl> show stats json
{
  "l2.rx_frames": 47,
  "l3.rx_packets": 35,
  "l3.local_deliver": 20,
  "l3.drops.acl": 3
}
```

### Toggle audit logging

```
ironctl> audit disable
[INFO ] [AUDIT] Audit logging disabled

ironctl> audit enable
[INFO ] [AUDIT] Audit logging enabled
```

### Audit log file

Events are also written to `/tmp/ironnet_audit.log` in structured format:
```
17045|ACL_DENY|10.0.1.2|10.0.1.1|6|54321|22|rule 3
17046|ACL_DENY|10.0.1.2|10.0.1.1|6|54322|22|rule 3
```

This file can be parsed by external tools for automated security analysis.

---

## Test Documentation

For a complete list of all unit tests and module tests, see `test.md`.

Key module tests with visible output:
- `./tests/test_l2_module` — Ethernet frame hex dumps
- `./tests/test_l3_module` — IP forwarding and ICMP
- `./tests/test_pbr_acl_module` — PBR redirect and ACL deny
- `./tests/test_l4_module` — TCP handshake and UDP
- `./tests/test_ipsec_module` — Encrypt/decrypt roundtrip
- `./tests/test_vlan_module` — VLAN tag insert/strip
- `./tests/test_bridge_module` — MAC learning and flooding
- `./tests/test_route_table_module` — Multiple routing tables with PBR selection
- `./tests/test_conntrack_module` — Connection tracking state transitions
- `./tests/test_nat_module` — SNAT/DNAT translation and return-path
- `./tests/test_conntrack_module` and `test_nat_module` also validate audit integration indirectly

After Phase 11a, the router can complete TCP handshakes with clients. Register an app on a port and `nc` will get a SYN+ACK response. See Phase 11b for echo/DNS server implementations.

After Phase 11b, the router runs:
- **Echo server** on TCP/UDP port 7 — echoes back any data
- **DNS server** on UDP port 53 — responds to A record queries from static zone
- **KV server** on TCP port 6379 — SET/GET/DEL key-value store
- **HTTP server** on TCP port 8080 — responds to GET requests
- **RPC server** on TCP port 9000 — binary protocol (PING/ECHO/STATUS)

Test in terminal 2 with:
```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up

# TCP echo
echo "hello" | nc 10.0.1.1 7

# UDP echo
echo "hello" | nc -u 10.0.1.1 7

# This installs dig, nslookup, and host commands.
sudo apt install dnsutils

# DNS query
dig @10.0.1.1 ironnet.local

# KV Store
echo "SET foo bar" | nc -w2 10.0.1.1 6379
echo "GET foo" | nc -w2 10.0.1.1 6379

# HTTP
echo -e "GET / HTTP/1.0\r\n\r\n" | nc -w2 10.0.1.1 8080

# Binary RPC (PING command: magic=IRON, cmd=0001, len=0000)
printf '\x49\x52\x4f\x4e\x00\x01\x00\x00' | nc -w2 10.0.1.1 9000 | xxd

```

To run all tests:
```bash
cd IronNet/build
ctest --output-on-failure
```

To run module tests with verbose output:
```bash
../src/tests/run_module_tests.sh .
```
