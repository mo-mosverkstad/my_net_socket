# Demo 39: Stealth Port Scanning — FIN, XMAS, NULL (Phase 21a)

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Two terminal windows

## What this demo shows

- Three stealth scan types that evade stateless firewalls
- FIN scan: sends TCP FIN flag only
- XMAS scan: sends FIN+PSH+URG ("Christmas tree" — all flags lit)
- NULL scan: sends TCP packet with no flags
- Interpretation: RST = closed, silence = open|filtered (inverse of SYN scan)

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

## Terminal 2: Setup network

```bash
cd IronNet/build
sudo ip addr add 10.0.1.2/24 dev iron0 2>/dev/null
sudo ip link set iron0 up
```

## Part 1: FIN scan

```bash
sudo ./ironattack/ironattack stealth-scan --target 10.0.1.1 --mode fin --ports 7,22,53,80,9999
```

Expected output:
```
=== Stealth Port Scan (Phase 21a) ===
  Target: 10.0.1.1
  Mode:   FIN scan (FIN flag only)
  Flags:  0x01
  Iface:  iron0
  Logic:  RST = CLOSED, silence = OPEN|FILTERED

  PORT     STATE
  ----     -----
  7        OPEN|FILTERED
  22       OPEN|FILTERED
  53       OPEN|FILTERED
  80       OPEN|FILTERED
  9999     OPEN|FILTERED

  Results: 5 open|filtered, 0 closed
```

## Part 2: XMAS scan

```bash
sudo ./ironattack/ironattack stealth-scan --target 10.0.1.1 --mode xmas --ports 7,22,53,80,9999
```

Expected output:
```
=== Stealth Port Scan (Phase 21a) ===
  Target: 10.0.1.1
  Mode:   XMAS scan (FIN+PSH+URG)
  Flags:  0x29
  ...
```

## Part 3: NULL scan

```bash
sudo ./ironattack/ironattack stealth-scan --target 10.0.1.1 --mode null --ports 7,22,53,80,9999
```

Expected output:
```
=== Stealth Port Scan (Phase 21a) ===
  Target: 10.0.1.1
  Mode:   NULL scan (no flags)
  Flags:  0x00
  ...
```

## How stealth scans work

```
RFC 793 behavior:
  Port OPEN:   unexpected FIN/XMAS/NULL → silently DROP (no response)
  Port CLOSED: unexpected segment → send RST

Therefore:
  RST received    → port is CLOSED (something responded)
  No response     → port is OPEN or FILTERED (nothing responded)
```

This is the **inverse** of SYN scanning:
| Scan type | Open port | Closed port |
|-----------|-----------|-------------|
| SYN scan | SYN+ACK | RST |
| Stealth scan | Silence | RST |

## Why stealth scans evade detection

1. **No SYN flag** → stateless firewalls that only log SYN packets miss these
2. **No connection created** → no entry in connection tracking tables
3. **Looks like garbage** → many IDS only alert on SYN to closed ports
4. **No half-open state** → no SYN_RECV entry in target's TCP table

## Limitations

- Only works against RFC-compliant TCP stacks
- Windows sends RST regardless of port state (scans useless against Windows)
- Stateful firewalls (conntrack) may drop packets with no matching connection
- Cannot distinguish OPEN from FILTERED (both produce silence)

## Comparison with SYN scan (ironprobe-ext)

```bash
# SYN scan (for comparison)
sudo ./ironprobe_ext/ironprobe-ext --target 10.0.1.1 --ports 7,22,53,80,9999
```

SYN scan gives definitive OPEN/CLOSED/FILTERED. Stealth scan only gives CLOSED vs OPEN|FILTERED.

## Command reference

| Command | Description |
|---------|-------------|
| `stealth-scan --mode fin --ports 7,22,80` | FIN scan on specific ports |
| `stealth-scan --mode xmas --ports 1-100` | XMAS scan on port range |
| `stealth-scan --mode null --ports 7,53,9999` | NULL scan |

## Notes

- All stealth scans require `sudo` (raw socket access)
- Timeout per port: 500ms (configurable in source)
- IronNet's TCP stack silently drops unexpected FIN/XMAS/NULL on open ports (RFC-compliant)
- Port 22 may show as OPEN|FILTERED (ACL denies but no RST sent — packet just dropped)

## Why all ports show OPEN|FILTERED in IronNet

In the demo results, all ports show OPEN|FILTERED because:

1. **Open ports (7, 53, 80, 9999):** IronNet's TCP receives the FIN/XMAS/NULL packet but finds no matching established connection. Per RFC 793, it silently drops the unexpected segment — no RST sent. This is correct behavior for open ports.

2. **Filtered port (22):** The ACL denies the packet (you can see `ACL DENY rule 3` in Terminal 1). The packet is dropped by the ACL before reaching TCP — no RST sent either.

3. **No truly "closed" ports exist:** A CLOSED result requires a port with no listener AND no firewall rule AND the TCP stack actively sends RST for unexpected segments to closed ports. IronNet drops silently in all cases.

**This is realistic:** Most modern systems behind firewalls show all ports as OPEN|FILTERED in stealth scans because firewalls drop packets silently rather than sending RST. Only unfiltered hosts with no firewall send RST from closed ports.

**What the scan DOES prove:**
- ✅ Stealth scans don't trigger connection logs (no "New connection: SYN_RECV" messages)
- ✅ No half-open connections created in the TCP table
- ✅ Only ACL deny for port 22 is logged (ACL evaluates before TCP)
- ✅ The scan is stealthier than SYN scan — no state created on the target

**To see CLOSED (RST) results**, you would need to scan a host that:
- Has no firewall (packets reach TCP directly)
- Has no service on the port
- Actively sends RST for segments to closed ports (like a bare Linux kernel without iptables)
