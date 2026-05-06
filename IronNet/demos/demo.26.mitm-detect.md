# Demo 26: MITM Detection — MAC Flap Monitoring

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- One terminal window (internal test) or three (external test)

## What this demo shows

- Router detects MITM attacks by monitoring ARP table for MAC flapping
- When a MAC address for an existing IP changes, it indicates ARP poisoning
- `defense mitm-detect enable` activates the detection

## Terminal 1: Start router with detection enabled

```bash
cd IronNet/build
sudo ./ironstack/ironstack ../src/configs/router.conf
```

```
ironctl> defense mitm-detect enable
[INFO ] [DEFENSE] Defense 'mitm-detect' ENABLED
```

## Terminal 1: Simulate ARP spoofing (triggers detection)

First create a legitimate ARP entry, then simulate an attacker changing it:

```
ironctl> arp add 10.0.1.2 02:00:00:00:00:AA
ARP entry added.

ironctl> arp spoof-test 10.0.1.2
Simulating ARP spoof for 10.0.1.2 (fake MAC 02:DE:AD:BE:EF:99)
[WARN ] [ARP] MITM DETECT: MAC flap for 10.0.1.2 (02:00:00:00:00:AA -> 02:DE:AD:BE:EF:99)
```

The detection fires immediately — the MAC for 10.0.1.2 changed from the legitimate `02:00:00:00:00:AA` to the attacker's `02:DE:AD:BE:EF:99`.

## Terminal 1: Verify audit log

```
ironctl> show audit-log
  [XXXX] ARP_ANOMALY   10.0.1.2:0 -> 0.0.0.0:0 proto=0 MAC flap - possible MITM
```

## How detection works

1. `defense mitm-detect enable` activates MAC flap monitoring
2. When `arp_add_entry()` is called with a **different MAC** for an existing IP:
   - Logs: `[WARN] MITM DETECT: MAC flap for <ip> (old_mac -> new_mac)`
   - Audit event: `AUDIT_ARP_ANOMALY` with "MAC flap - possible MITM"
3. In a real network, this triggers when an attacker sends ARP replies claiming a victim's IP is at the attacker's MAC

## External ARP spoof attempt (for reference)

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

**Terminal 1:** No warning appears — this is the known limitation. ARP frames can't be sent via raw IP socket to the TAP device. In a real multi-host network or ironsim topology, these ARP replies would reach the router and trigger the MITM detection alert.

## Note

The `arp spoof-test` CLI command simulates what happens when an attacker's ARP reply reaches the router. It directly calls `arp_add_entry()` with a fake MAC, which is exactly what would happen if a real ARP reply arrived via the TAP interface.
