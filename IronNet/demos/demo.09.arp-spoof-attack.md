# Demo 09: ARP Spoofing Attack + Defense (ARP Inspection)

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Two terminal windows

## What this demo shows

- ARP spoofing poisons the router's ARP table, making it believe a gateway IP belongs to the attacker's MAC
- ARP inspection defense validates ARP replies against trusted bindings before learning

## Network Topology

```
Linux (Terminal 2)              IronNet Router (Terminal 1)
  ironattack (attacker)  ──→   10.0.1.1/24 (iron0)
  claims: 10.0.1.254 is at attacker MAC
```

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

## Part 1: ARP Spoof WITHOUT defense

### Terminal 2: Run ARP spoof

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up
sudo ./ironattack/ironattack arp-spoof --target 10.0.1.1 --impersonate 10.0.1.254 --count 3
```

Output:
```
=== ARP Spoof Attack ===
  Target:      10.0.1.1
  Impersonate: 10.0.1.254
  Count:       3

  Sent: 3 ARP replies
```

### Terminal 1: ARP table is POISONED

```
ironctl> show arp
[INFO ] [ARP] --- ARP Table ---
[INFO ] [ARP]   10.0.1.254 -> 02:AA:BB:CC:DD:EE    ← attacker's MAC!
```

The router now thinks the gateway (10.0.1.254) is at the attacker's MAC. Traffic destined for the gateway would be sent to the attacker instead.

## Part 2: ARP Spoof WITH ARP inspection defense

### Terminal 1: Enable ARP inspection

```
ironctl> defense arp-inspection enable
[INFO ] [DEFENSE] Defense 'arp-inspection' ENABLED
```

### Terminal 2: Run ARP spoof again

```bash
sudo ./ironattack/ironattack arp-spoof --target 10.0.1.1 --impersonate 10.0.1.254 --count 3
```

### Terminal 1: Attack blocked

```
[WARN ] [ARP] ARP inspection BLOCKED: 10.0.1.254 untrusted MAC 02:AA:BB:CC:DD:EE
[WARN ] [ARP] ARP inspection BLOCKED: 10.0.1.254 untrusted MAC 02:AA:BB:CC:DD:EE
[WARN ] [ARP] ARP inspection BLOCKED: 10.0.1.254 untrusted MAC 02:AA:BB:CC:DD:EE

ironctl> show arp
# ARP table NOT updated — attack blocked

ironctl> show audit-log
# Shows AUDIT_ARP_ANOMALY events for each blocked attempt
```

## How ARP inspection works

1. Administrator adds trusted bindings (known IP-MAC pairs)
2. When ARP reply arrives, before learning the sender's MAC:
   - Check if sender IP has a trusted binding
   - If yes: compare MAC — if mismatch, DROP and log audit event
   - If no binding exists for that IP: allow (no restriction)
3. Attacker's fake ARP reply is blocked because the MAC doesn't match the trusted binding

## Cleanup

```
ironctl> defense arp-inspection disable
```
