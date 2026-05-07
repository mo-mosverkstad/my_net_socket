# Demo 37: MAC Flooding Attack (Phase 20a)

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Two terminal windows

## What this demo shows

- MAC flooding attack overflows the bridge/ARP table with random source addresses
- After overflow, legitimate entries are evicted → traffic flooded to all ports (hub mode)
- Attacker on any port can now see all traffic between other hosts

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

## Terminal 2: Setup network and launch attack

```bash
cd IronNet/build
sudo ip addr add 10.0.1.2/24 dev iron0 2>/dev/null
sudo ip link set iron0 up
```

## Part 1: Check ARP table before attack

```
# In Terminal 1:
ironctl> show arp
```

Should show few entries (or empty).

## Part 2: Launch MAC flood (internal simulation)

Since ARP is a Layer 2 protocol (ethertype 0x0806) that cannot be sent via raw IP sockets through the TAP device, we use the internal CLI command to simulate the MAC flood:

```
# In Terminal 1:
ironctl> arp flood-test 200
MAC flood simulation: injecting 200 random ARP entries...
Injected 200 random entries. ARP table should be full.
Legitimate entries (e.g., 10.0.1.2) may have been evicted.
Use 'show arp' to verify.
Use `arp flush` to clear the table after testing
```

This directly fills the ARP table with 200 random entries (192.168.10.x with random MACs), simulating what a real MAC flood would do on a physical switch.

## Part 2b: External MAC flood (IP-level)

The external tool sends packets from random source IPs. While this doesn't directly fill the ARP table (ARP learns from ARP replies, not IP sources), it demonstrates the attack concept and generates traffic from many sources:

```bash
# In Terminal 2:
sudo ./ironattack/ironattack mac-flood --target 10.0.1.1 --iface iron0 --count 500 --rate 1000
```

Expected output:
```
=== MAC Flooding Attack (Phase 20a) ===
  Target:  10.0.1.1
  Iface:   iron0
  Count:   500 frames (random src MACs)
  Rate:    1000 pps
  Goal:    Overflow bridge MAC table (256 entries)

  Sent:    500 frames with random source IPs
  Elapsed: 0.50 s
  Rate:    1000 pps

  Effect on bridge MAC table:
    - Each random src IP triggers ARP learning of a new MAC
    - Bridge table (256 entries) overflows after ~256 unique MACs
    - After overflow: legitimate MACs evicted → traffic flooded to all ports

  To verify:
    ironctl> show arp    (should show many random entries)
    ironctl> show stats  (check l2 flooded counter)

Use `arp flush` to clear the table after testing
```

## Part 3: Verify table overflow

```
# In Terminal 1:
ironctl> show arp
```

The ARP table should now be full of random entries (192.168.10.x addresses with random MACs). Legitimate entries (like 10.0.1.2) have been evicted.

Try pinging from Terminal 2:
```bash
ping -c 1 10.0.1.1
```

The ping should still work (ironstack responds to its own IP), but the ARP entry for 10.0.1.2 was evicted — ironstack will need to re-learn it via ARP request.

## How MAC flooding works

```
Normal operation:
  Bridge MAC table: [10.0.1.2 → port 0] [10.0.2.1 → port 1]
  Frame from 10.0.1.2 to 10.0.2.1 → forwarded ONLY to port 1

After MAC flood (table full of random entries):
  Bridge MAC table: [192.168.10.1 → port 0] [192.168.10.2 → port 0] ... (256 random)
  10.0.2.1 is NOT in table anymore (evicted!)
  Frame from 10.0.1.2 to 10.0.2.1 → FLOODED to ALL ports
  Attacker on port 2 now sees the frame!
```

## Real-world impact

In a real network with a physical switch:
1. Attacker connects to any switch port
2. Sends thousands of frames with random source MACs
3. Switch CAM table (8K-32K entries) fills up
4. Switch falls back to flooding for unknown destinations
5. Attacker's port receives ALL traffic (like a hub)
6. Attacker can now sniff passwords, session tokens, etc.

## Defense (Phase 20b)

Port security limits the number of MACs learned per port:
```
ironctl> defense port-security enable
```
With port security: only first N MACs are learned per port. Excess frames are dropped.

## Command reference

| Command | Description |
|---------|-------------|
| `ironattack mac-flood --target <ip> --count 500` | Send 500 frames with random src |
| `ironattack mac-flood --target <ip> --rate 2000` | Send at 2000 packets/second |
| `show arp` | View ARP/MAC table (verify overflow) |
| `show stats` | View packet counters |

## Notes

- The attack uses random source IPs (192.168.10.x) which cause ARP table entries
- IronNet's ARP table has 128 entries — overflow happens after ~128 unique sources
- In real switches, CAM tables are larger (8K-32K) but the principle is the same
- The attack must sustain high rate to keep the table full (entries age out after 300s)
- Use `arp flush` to clear the table after testing
