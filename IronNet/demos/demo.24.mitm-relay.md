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
sudo ./ironattack/ironmitm --victim-a <ip> --victim-b <ip> --iface <name> [--log <file>]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--victim-a <ip>` | First victim IP | (required) |
| `--victim-b <ip>` | Second victim IP | (required) |
| `--iface <name>` | Network interface | iron0 |
| `--log <file>` | Log file path | (none) |

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
