# Demo 10: VLAN Hopping Attack + Defense (VLAN Strict Mode)

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Two terminal windows

## What this demo shows

- VLAN hopping uses double-tagged 802.1Q frames to escape VLAN isolation
- VLAN strict mode rejects any tagged frame at ingress, blocking the attack

## How VLAN hopping works

```
Normal frame:  [Dst MAC][Src MAC][EtherType 0x0800][IP...]
Double-tagged: [Dst MAC][Src MAC][TPID 0x8100][outer VID=1][TPID 0x8100][inner VID=20][EtherType 0x0800][IP...]
```

When the outer tag (native VLAN 1) is stripped by the first switch, the inner tag (VLAN 20) remains — the frame enters the target VLAN.

## Network Topology

```
Linux (Terminal 2)              IronNet Router (Terminal 1)
  ironattack (attacker)  ──→   iron0 (access port, VLAN 1)
  double-tagged frame           target: VLAN 20
```

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

## Part 1: VLAN Hop WITHOUT defense

### Terminal 2: Send double-tagged frames

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up
sudo ./ironattack/ironattack vlan-hop --target 10.0.1.1 --target-vlan 20 --outer-vlan 1 --count 5
```

Output:
```
=== VLAN Hopping Attack ===
  Target:      10.0.1.1
  Outer VLAN:  1 (native)
  Inner VLAN:  20 (target)
  Count:       5

  Sent: 5 double-tagged frames
```

### Terminal 1: Frames processed (no defense)

```
[DEBUG] [L2] Unknown ethertype: 0x8100, dropping
# Without strict mode, the frame is dropped due to unknown ethertype
# But in a real switch topology, the outer tag would be stripped first
```

## Part 2: VLAN Hop WITH VLAN strict mode

### Terminal 1: Enable VLAN strict mode

```
ironctl> defense vlan-strict enable
[INFO ] [DEFENSE] Defense 'vlan-strict' ENABLED
```

### Terminal 2: Send double-tagged frames again

```bash
sudo ./ironattack/ironattack vlan-hop --target 10.0.1.1 --target-vlan 20 --count 5
```

### Terminal 1: All frames dropped at ingress

```
[WARN ] [L2] VLAN strict: tagged frame dropped (TPID 0x8100)
[WARN ] [L2] VLAN strict: tagged frame dropped (TPID 0x8100)
[WARN ] [L2] VLAN strict: tagged frame dropped (TPID 0x8100)
[WARN ] [L2] VLAN strict: tagged frame dropped (TPID 0x8100)
[WARN ] [L2] VLAN strict: tagged frame dropped (TPID 0x8100)

ironctl> show audit-log
# Shows AUDIT_VLAN_MISMATCH events for each dropped frame

ironctl> show stats
# l2.rx_drops counter increased by 5
```

## How VLAN strict mode works

When enabled, `eth_parse()` checks bytes 12-13 of every incoming frame:
- If TPID = 0x8100 (VLAN tag present): DROP immediately
- This blocks double-tagged frames at the earliest possible point in the pipeline
- Audit event logged: AUDIT_VLAN_MISMATCH

## Cleanup

```
ironctl> defense vlan-strict disable
```
