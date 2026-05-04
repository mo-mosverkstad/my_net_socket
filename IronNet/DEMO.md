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
| `nc` hangs on permitted port | Expected — no application listening yet (Phase 11) |
| Ping works but nc doesn't | ICMP is handled by ironstack; TCP needs an app to respond |

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

After stopping ironstack (Ctrl+C), the TAP interfaces are automatically removed. If they persist:

```bash
sudo ip link delete iron0
sudo ip link delete iron1
```

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

To run all tests:
```bash
cd IronNet/build
ctest --output-on-failure
```

To run module tests with verbose output:
```bash
../src/tests/run_module_tests.sh .
```
