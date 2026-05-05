# Demo 14: Fragmentation Attack + Defense (frag-strict)

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Two terminal windows

## What this demo shows

- Overlapping fragments confuse IP reassembly (can bypass ACL/IDS inspection)
- Tiny fragments (below minimum size) evade inspection by splitting headers across fragments
- frag-strict defense rejects both attack types with audit logging

## Fragment attack types

**Overlapping fragments:**
```
Fragment 1: offset=0,  len=32, MF=1  [bytes 0-31]
Fragment 2: offset=16, len=32, MF=0  [bytes 16-47] ← overlaps with frag 1!
```
The overlapping region (bytes 16-31) is ambiguous — different implementations handle it differently, potentially bypassing security checks.

**Tiny fragments:**
```
Fragment 1: offset=0, len=8, MF=1   ← only 8 bytes (below minimum 48)
```
Splits the TCP header across fragments, making it impossible to inspect ports/flags in the first fragment.

## Network Topology

```
Linux (Terminal 2)              IronNet Router (Terminal 1)
  ironattack (attacker)  ──→   10.0.1.1 (iron0)
  malformed fragments
```

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

## Part 1: Overlapping fragments WITHOUT defense

### Terminal 2: Send overlapping fragments

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up
sudo ./ironattack/ironattack frag-attack --target 10.0.1.1 --overlap --count 5
```

Output:
```
=== Fragmentation Attack ===
  Target:  10.0.1.1
  Mode:    overlap
  Count:   5

  Sent: 10 fragments
```

### Terminal 1: Fragments processed (no defense)

```
[DEBUG] [FRAG] Fragment too small or reassembly in progress
# Without frag-strict, overlapping fragments may be accepted
```

## Part 2: Tiny fragments WITHOUT defense

### Terminal 2: Send tiny fragments

```bash
sudo ./ironattack/ironattack frag-attack --target 10.0.1.1 --tiny --count 5
```

### Terminal 1: Tiny fragments dropped by existing check

```
[DEBUG] [FRAG] Fragment too small: 8 bytes
# Already rejected by minimum size check (FRAG_MIN_SIZE = 68)
```

## Part 3: Attacks WITH frag-strict defense

### Terminal 1: Enable frag-strict

```
ironctl> defense frag-strict enable
[INFO ] [DEFENSE] Defense 'frag-strict' ENABLED
```

### Terminal 2: Send overlapping fragments

```bash
sudo ./ironattack/ironattack frag-attack --target 10.0.1.1 --overlap --count 5
```

### Terminal 1: Overlapping fragments blocked with audit log

```
[WARN ] [FRAG] frag-strict: overlapping fragment dropped (offset=16, received=32)
[WARN ] [FRAG] frag-strict: overlapping fragment dropped (offset=16, received=32)
...

ironctl> show audit-log
# Shows AUDIT_FRAGMENT_DROP events with "overlapping fragment" detail
```

### Terminal 2: Send tiny fragments

```bash
sudo ./ironattack/ironattack frag-attack --target 10.0.1.1 --tiny --count 5
```

### Terminal 1: Tiny fragments blocked with audit log

```
[WARN ] [FRAG] frag-strict: tiny fragment dropped (8 bytes)
[WARN ] [FRAG] frag-strict: tiny fragment dropped (8 bytes)
...

ironctl> show audit-log
# Shows AUDIT_FRAGMENT_DROP events with "tiny fragment" detail
```

## How frag-strict works

Without defense: tiny fragments are already rejected (minimum size check). Overlapping fragments may be accepted and cause ambiguous reassembly.

With `defense frag-strict enable`:
1. **Tiny fragments**: rejected with WARN log + AUDIT_FRAGMENT_DROP event
2. **Overlapping fragments**: detected when new fragment's offset < already received length → rejected + audit event
3. Both cases: reassembly entry is invalidated (entire packet discarded)

## Cleanup

```
ironctl> defense frag-strict disable
```
