# Demo 38: Port Security Defense (Phase 20b)

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- One terminal window

## What this demo shows

- Port security limits the number of MAC/ARP entries that can be learned
- MAC flood attack is blocked when port security is enabled
- Legitimate entries are preserved (table not corrupted)

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

## Part 1: MAC flood WITHOUT defense (table overflows)

```
ironctl> arp flood-test 200
MAC flood simulation: injecting 200 random ARP entries...
Injected 200 random entries. ARP table should be full.
Legitimate entries (e.g., 10.0.1.2) may have been evicted.
Use 'show arp' to verify. Use 'arp flush' to clear the table after testing.

ironctl> show arp
# Shows 128 entries (ARP_TABLE_MAX) — all random 192.168.10.x addresses
# Legitimate entry for 10.0.1.2 has been evicted!
```

Clean up:
```
ironctl> arp flush
ARP table flushed.
```

## Part 2: Enable port security

```
ironctl> defense port-security 32
[INFO ] [ARP] Port security max MACs set to 32
[INFO ] [DEFENSE] Defense 'port-security' ENABLED
```

This limits the ARP table to 32 entries. Any attempt to add beyond 32 is blocked.

## Part 3: MAC flood WITH defense (attack blocked)

```
ironctl> arp flood-test 200
MAC flood simulation: injecting 200 random ARP entries...
```

Terminal 1 shows warnings:
```
[WARN ] [ARP] Port security: ARP entry BLOCKED for 192.168.10.32 (table at limit 32)
[WARN ] [ARP] Port security: ARP entry BLOCKED for 192.168.10.33 (table at limit 32)
... (168 more blocked)
```

```
ironctl> show arp
# Shows only 32 entries — table did NOT overflow!
# First 32 random entries were learned, rest blocked
```

## Part 4: Verify legitimate traffic still works

```
ironctl> arp flush
ARP table flushed.

ironctl> defense port-security 32
```

Now from Terminal 2, ping the router:
```bash
cd IronNet/build
sudo ip addr add 10.0.1.2/24 dev iron0 2>/dev/null
sudo ip link set iron0 up

ping -c 1 10.0.1.1
```

```
ironctl> show arp
# Shows: 10.0.1.2 → <linux MAC> (legitimate entry learned, within limit)
```

The legitimate entry is learned because the table has room (1 < 32).

## Part 5: Check audit log

```
ironctl> show audit-log
  [XXXX] ARP_ANOMALY  192.168.10.32:0 -> 0.0.0.0:0 proto=0 Port security - MAC flood blocked
  [XXXX] ARP_ANOMALY  192.168.10.33:0 -> 0.0.0.0:0 proto=0 Port security - MAC flood blocked
  ...
```

## Comparison: with and without defense

| Scenario | ARP table after 200 entries | Legitimate entry preserved? |
|----------|---------------------------|----------------------------|
| No defense | 128 entries (all random, oldest evicted) | ❌ Evicted |
| Port security (max=32) | 32 entries (first 32 random, rest blocked) | ✅ If added before limit |

## How port security works

```
defense port-security 32:
  → g_port_security_max = 32

arp_add_entry() called:
  1. Is entry already in table? → update (always allowed)
  2. Is port-security enabled?
     → Is g_arp_count >= g_port_security_max?
        → YES: BLOCK entry, log audit event
        → NO: allow (proceed to add)
  3. Add new entry normally
```

## Command reference

| Command | Description |
|---------|-------------|
| `defense port-security 32` | Enable with max 32 MACs |
| `defense port-security enable` | Enable with current max (default 32) |
| `defense port-security disable` | Disable port security |
| `arp flood-test 200` | Simulate MAC flood (inject 200 random entries) |
| `arp flush` | Clear ARP table |
| `show arp` | View ARP table entries |

## Cleanup

```
ironctl> defense port-security disable
ironctl> arp flush
```
