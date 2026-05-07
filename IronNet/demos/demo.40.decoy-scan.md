# Demo 40: Decoy Scanning (Phase 21b)

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Two terminal windows

## What this demo shows

- Decoy scanning hides the real scanner's IP among multiple fake source IPs
- Target sees SYN from many IPs per port — can't identify the real attacker
- All decoy SYNs and the real SYN are sent in random order

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

## Terminal 2: Setup network and launch decoy scan

```bash
cd IronNet/build
sudo ip addr add 10.0.1.2/24 dev iron0 2>/dev/null
sudo ip link set iron0 up
```

## Launch decoy scan

```bash
sudo ./ironattack/ironattack decoy-scan --target 10.0.1.1 \
    --decoys 10.0.1.50,10.0.1.51,10.0.1.52 --ports 7,22,80,9999
```

Expected output:
```
=== Decoy Scanning (Phase 21b) ===
  Target:   10.0.1.1
  Real IP:  10.0.1.2
  Decoys:   10.0.1.50, 10.0.1.51, 10.0.1.52
  Iface:    iron0
  Strategy: For each port, send SYN from real IP + all decoys (random order)
            Target sees 4 source IPs per port — can't identify the real scanner

  Port 7: SYN from 10.0.1.51, 10.0.1.2*, 10.0.1.50, 10.0.1.52
  Port 22: SYN from 10.0.1.52, 10.0.1.50, 10.0.1.51, 10.0.1.2*
  Port 80: SYN from 10.0.1.2*, 10.0.1.52, 10.0.1.51, 10.0.1.50
  Port 9999: SYN from 10.0.1.50, 10.0.1.51, 10.0.1.2*, 10.0.1.52

  Total SYN packets sent: 16
  (* = real scanner IP mixed among decoys)

  Target's audit log will show SYN from 4 different IPs per port.
  Without additional analysis, defender cannot identify the real scanner.
```

Note: The order is randomized each run — the real IP (*) appears at different positions.

## Terminal 1: Verify from defender's perspective

```
ironctl> show tcp
```

Shows connections from ALL 4 IPs — the defender sees:
- 10.0.1.2 (real scanner — but defender doesn't know this)
- 10.0.1.50 (decoy)
- 10.0.1.51 (decoy)
- 10.0.1.52 (decoy)

All look equally suspicious. The defender can't tell which is the real attacker.

## How decoy scanning works

```
Normal SYN scan:
  Attacker (10.0.1.2) → SYN → Target
  Target logs: "SYN from 10.0.1.2" → attacker identified!

Decoy scan:
  10.0.1.51 → SYN → Target    (decoy)
  10.0.1.2  → SYN → Target    (real — mixed in random position)
  10.0.1.50 → SYN → Target    (decoy)
  10.0.1.52 → SYN → Target    (decoy)
  Target logs: "SYN from 10.0.1.51, 10.0.1.2, 10.0.1.50, 10.0.1.52"
  → Which one is real? Can't tell!
```

## Why it works

- All SYN packets look identical (same flags, similar timing)
- Decoy IPs are spoofed (attacker sends with fake source)
- Only the real IP receives the SYN+ACK response (decoys don't)
- But the target can't observe who receives the SYN+ACK (it just sends to all)

## Limitations

- Decoy IPs must be reachable (otherwise target knows they're fake — no ARP entry)
- If decoy IPs are real machines, they'll send RST (unexpected SYN+ACK) — may alert defender
- Rate limiting per-source helps but doesn't eliminate the problem
- uRPF can block decoys if they're from wrong subnet

## Defense considerations

| Defense | Effectiveness against decoys |
|---------|------------------------------|
| Rate limiting | Partial — limits each source equally (real + decoys) |
| uRPF | Blocks decoys from wrong subnet (but same-subnet decoys pass) |
| SYN cookies | Doesn't help identify attacker (just handles the SYNs statelessly) |
| Traffic analysis | Compare which IP completes handshake (only real scanner does) |

## Command reference

| Command | Description |
|---------|-------------|
| `decoy-scan --target <ip> --decoys <ip1,ip2,ip3>` | Scan with 3 decoys |
| `decoy-scan --target <ip> --decoys <ip1,...> --ports 7,80,443` | Specific ports |

## Phase 21 complete

| Sub-phase | Component | Status |
|-----------|-----------|--------|
| 21a | FIN/XMAS/NULL stealth scans | ✅ |
| 21b | Decoy scanning | ✅ |
