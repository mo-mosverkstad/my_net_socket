# Demo 24: Man-in-the-Middle Relay (ironmitm) — Traffic Interception

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Three terminal windows

## What this demo shows

- MITM attack intercepts all traffic between two hosts
- ARP poisoning redirects traffic through the attacker
- All intercepted packets are logged (direction, IPs, ports, protocol)
- Traffic is forwarded transparently — victims don't notice

## Network Topology

```
Terminal 2 (Victim/Client)     Terminal 3 (Attacker/MITM)     Terminal 1 (Router/Server)
  10.0.1.2                       ironmitm                       10.0.1.1
     |                              |                              |
     +--- "10.0.1.1 is at          |                              |
     |     DE:AD:BE:EF:01" ←-------+------→ "10.0.1.2 is at      |
     |                              |         DE:AD:BE:EF:01" ----+
     |                              |                              |
     +--------→ traffic --------→ [sniff + log + forward] ------→ +
     +←-------- traffic ←-------- [sniff + log + forward] ←------ +
```

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

## Terminal 2: Setup client

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up
```

## Terminal 3: Start MITM relay

```bash
cd IronNet/build
sudo ./ironattack/ironmitm --victim-a 10.0.1.1 --victim-b 10.0.1.2 --iface iron0 --log /tmp/mitm.log
```

Expected output:
```
╔══════════════════════════════════════════╗
║     ironmitm — MITM Relay Engine         ║
╚══════════════════════════════════════════╝

  Victim A: 10.0.1.1
  Victim B: 10.0.1.2
  Iface:    iron0
  Log:      /tmp/mitm.log

  [mitm] Starting ARP poisoning + relay...
  [mitm] Press Ctrl+C to stop.
```

## Terminal 2: Generate traffic (victim doesn't know it's intercepted)

```bash
# Ping the router — MITM sees it
ping -c 3 10.0.1.1

# TCP echo — MITM sees the data
echo "secret message" | nc -w2 10.0.1.1 7

# HTTP request — MITM sees the request
echo -e "GET / HTTP/1.0\r\n\r\n" | nc -w2 10.0.1.1 8080
```

## Terminal 3: MITM output (intercepted traffic)

```
  [A->B] 10.0.1.2:0 -> 10.0.1.1:0 OTHER (84 bytes)
  [B->A] 10.0.1.1:0 -> 10.0.1.2:0 OTHER (84 bytes)
  [A->B] 10.0.1.2:54321 -> 10.0.1.1:7 TCP (68 bytes)
  [B->A] 10.0.1.1:7 -> 10.0.1.2:54321 TCP (68 bytes)
  [A->B] 10.0.1.2:54321 -> 10.0.1.1:7 TCP (82 bytes)
  [B->A] 10.0.1.1:7 -> 10.0.1.2:54321 TCP (82 bytes)
  ...
```

## Terminal 3: Stop MITM (Ctrl+C)

```
^C
  [mitm] Stopped.
  [mitm] Intercepted: 24 packets
  [mitm] Forwarded:   24 packets
  [mitm] Log saved.
```

## View the log file

```bash
cat /tmp/mitm.log
```

Format: `direction|src_ip|src_port|dst_ip|dst_port|protocol|size`
```
A->B|10.0.1.2|54321|10.0.1.1|7|TCP|68
B->A|10.0.1.1|7|10.0.1.2|54321|TCP|68
A->B|10.0.1.2|54321|10.0.1.1|7|TCP|82
B->A|10.0.1.1|7|10.0.1.2|54321|TCP|82
```

## How it works

1. **ARP Poisoning** (every 2 seconds):
   - Tells Victim A (router): "Victim B's IP is at my MAC (DE:AD:BE:EF:01)"
   - Tells Victim B (client): "Victim A's IP is at my MAC (DE:AD:BE:EF:01)"
   - Both victims send traffic to the attacker's MAC instead of each other

2. **Packet Sniffing**:
   - AF_PACKET socket in promiscuous mode
   - Only processes packets addressed to attacker's MAC (intercepted traffic)

3. **Logging**:
   - Prints each packet: direction, src:port → dst:port, protocol, size
   - Optionally writes to log file for later analysis

4. **Forwarding**:
   - Rewrites destination MAC to the real victim's MAC
   - Sends via sendto() — traffic reaches the intended recipient
   - Transparent to both victims

## Why this demonstrates the need for encryption

- The attacker sees ALL data in plaintext (echo data, HTTP requests, etc.)
- Without encryption (TLS/IPsec), any network intermediary can read traffic
- With IPsec enabled on ironstack, the attacker would only see encrypted bytes

## Command reference

```bash
sudo ./ironattack/ironmitm --victim-a <ip> --victim-b <ip> --iface <name> [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--victim-a <ip>` | First victim IP | (required) |
| `--victim-b <ip>` | Second victim IP | (required) |
| `--iface <name>` | Network interface | iron0 |
| `--log <file>` | Log file path | (none) |
| `--modify <find:replace>` | Modify payload in transit (same-length, can repeat) | (none) |

---

## Traffic Modification Demo (Phase 16b)

The `--modify` option replaces matching patterns in packet payloads as they pass through the MITM. This demonstrates data integrity attacks.

### Terminal 1: Start router

```bash
cd IronNet/build
sudo ./ironstack/ironstack ../src/configs/router.conf
```

### Terminal 2: Setup client

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up
```

### Terminal 3: Start MITM with modification rules

```bash
cd IronNet/build
sudo ./ironattack/ironmitm --victim-a 10.0.1.1 --victim-b 10.0.1.2 --iface iron0 \
    --modify "secret:XXXXXX" --modify "hello:PWNED" --log /tmp/mitm_modify.log
```

Expected startup:
```
╔══════════════════════════════════════════╗
║     ironmitm — MITM Relay Engine         ║
╚══════════════════════════════════════════╝

  Victim A: 10.0.1.1
  Victim B: 10.0.1.2
  Iface:    iron0
  Log:      /tmp/mitm_modify.log
  Modify:   2 rules
    [1] "secret" -> "XXXXXX"
    [2] "hello" -> "PWNED"

  [mitm] Resolving victim MACs...
  [mitm] Starting ARP poisoning + relay...
  [mitm] Press Ctrl+C to stop.
```

### Terminal 2: Send data containing the patterns

```bash
# Echo server echoes back data — MITM modifies the echo reply
echo "secret" | nc -w2 10.0.1.1 7
# Without MITM: receives "secret" back
# With MITM modify: the reply from router has "secret" replaced with "XXXXXX"

echo "hello world" | nc -w2 10.0.1.1 7
# Reply has "hello" replaced with "PWNED"

echo "normal data" | nc -w2 10.0.1.1 7
# No matching pattern — passes through unmodified
```

### Terminal 3: MITM shows modifications

```
  [A->B] 10.0.1.1:7 -> 10.0.1.2:49700 TCP (47 bytes)
  [MODIFY] Replaced "secret" with "XXXXXX" at offset 54
  [A->B] 10.0.1.1:7 -> 10.0.1.2:49701 TCP (51 bytes)
  [MODIFY] Replaced "hello" with "PWNED" at offset 54
  [A->B] 10.0.1.1:7 -> 10.0.1.2:49702 TCP (51 bytes)
```

### Terminal 3: Stop MITM (Ctrl+C)

```
^C
  [mitm] Stopped.
  [mitm] Intercepted: 30 packets
  [mitm] Forwarded:   30 packets
  [mitm] Modification rules:
    "secret" -> "XXXXXX": 1 hits
    "hello" -> "PWNED": 1 hits
  [mitm] Log saved.
```

### Modification rules

| Rule format | Example | Effect |
|-------------|---------|--------|
| `find:replace` | `"secret:XXXXXX"` | Replace "secret" with "XXXXXX" in payload |
| Multiple rules | `--modify "OK:NO" --modify "bar:XXX"` | Apply all rules to each packet |

**Constraints:**
- Find and replace must be the **same length** (in-place replacement)
- Only searches payload after headers (offset 54+, after eth+ip+tcp)
- Up to 8 rules maximum
- Does not recalculate TCP checksums (strict receivers may drop modified packets)

### What this demonstrates

- **Data integrity attack**: attacker can silently alter data in transit
- **Why encryption matters**: with TLS/IPsec, payload is encrypted — attacker can't find patterns
- **Why checksums matter**: TCP checksum mismatch would detect modification (if receiver validates)

---

## Notes

- Requires sudo (AF_PACKET + promiscuous mode)
- Both victims must be on the same subnet as the attacker
- ARP poisoning refreshes every 2 seconds to maintain interception
- Ctrl+C stops cleanly and prints statistics
- The attacker MAC is hardcoded as 02:DE:AD:BE:EF:01
- In a real scenario, the attacker would first ARP-resolve the victims' real MACs

## Known Limitation: Single-TAP Forwarding Loop

On a single-TAP setup (ironstack + Linux client + MITM all on `iron0`), forwarding intercepted packets creates an amplification loop:

```
ironstack sends reply → MITM intercepts → MITM forwards (back to iron0)
→ ironstack sees it again → sends another reply → MITM intercepts again → ...
```

This manifests as duplicate ping replies with decreasing TTL.

**This is an architectural limitation of single-TAP, not a code bug.** In a real network (or ironsim 3-node topology), each host has its own interface and forwarding works correctly.

## Recommended: Use ironsim 3-node topology

For a proper MITM demo without loops, use the ironsim topology where the attacker sits between two nodes on separate interfaces:

```
Node A (iron-a0) ←→ Attacker (iron-b0, iron-b1) ←→ Node C (iron-c0)
```

This is how real MITM attacks work — the attacker is a separate host on the network path.

---

## MITM Detection Demo (Phase 16c)

The router can detect MITM attacks by monitoring ARP table changes. When a MAC address for an existing IP changes rapidly ("MAC flapping"), it indicates ARP poisoning.

### Terminal 1: Start router with detection enabled

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

```
ironctl> defense mitm-detect enable
[INFO ] [DEFENSE] Defense 'mitm-detect' ENABLED
```

### Terminal 1: Simulate ARP spoofing (triggers detection)

First create a legitimate ARP entry, then simulate an attacker changing it:

```
ironctl> arp add 10.0.1.2 02:00:00:00:00:AA
ARP entry added.

ironctl> arp spoof-test 10.0.1.2
Simulating ARP spoof for 10.0.1.2 (fake MAC 02:DE:AD:BE:EF:99)
[WARN ] [ARP] MITM DETECT: MAC flap for 10.0.1.2 (02:00:00:00:00:AA -> 02:DE:AD:BE:EF:99)
```

The detection fires immediately — the MAC for 10.0.1.2 changed from the legitimate `02:00:00:00:00:AA` to the attacker's `02:DE:AD:BE:EF:99`.

### Terminal 1: Verify audit log

```
ironctl> show audit-log
  [XXXX] ARP_ANOMALY   10.0.1.2:0 -> 0.0.0.0:0 proto=0 MAC flap - possible MITM
```

### How detection works

1. `defense mitm-detect enable` activates MAC flap monitoring
2. When `arp_add_entry()` is called with a **different MAC** for an existing IP:
   - Logs: `[WARN] MITM DETECT: MAC flap for <ip> (old_mac -> new_mac)`
   - Audit event: `AUDIT_ARP_ANOMALY` with "MAC flap - possible MITM"
3. In a real network, this triggers when an attacker sends ARP replies claiming a victim's IP is at the attacker's MAC

### Note on external testing

The `arp spoof-test` CLI command simulates what happens when an attacker's ARP reply reaches the router. On a single-TAP setup, external `ironattack arp-spoof` packets cannot reach ironstack as valid ARP frames (architectural limitation — ARP is not IP and can't be sent via raw IP socket). In the ironsim multi-node topology, real ARP flows between nodes and detection works with actual attack traffic.

### External ARP spoof attempt (for reference)

You can also try the external attack tool. On a single-TAP setup, the ARP frames don't reach ironstack (no warning fires), but this demonstrates the attack command:

**Terminal 2:**
```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up
ping -c 1 10.0.1.1
```

**Terminal 3:**
```bash
cd IronNet/build
sudo ./ironattack/ironattack arp-spoof --target 10.0.1.1 --impersonate 10.0.1.2 --count 3
```

Expected output:
```
=== ARP Spoof Attack ===
  Target:      10.0.1.1
  Impersonate: 10.0.1.2
  Count:       3

  Sent: 3 ARP replies
```

**Terminal 1:** No warning appears — this is the known limitation. The ARP frames are sent via raw IP socket which cannot deliver non-IP (ethertype 0x0806) frames to the TAP device. In a real multi-host network or ironsim topology, these ARP replies would reach the router and trigger the MITM detection alert.
