# Demo 17: Automated Attack-Defense Report (ironreport)

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- One terminal window (no router needed — runs internally)

## What this demo shows

- ironreport automatically tests 5 attack/defense pairs
- Each test measures attack effectiveness with and without the defense
- Produces a pass/fail report

## Run the report

```bash
cd IronNet/build
./ironprobe_ext/ironreport
```

If you want a cleaner output, redirect stderr:

```bash
./ironprobe_ext/ironreport 2>/dev/null
```

Expected output:
```
╔══════════════════════════════════════════════════════════════════════╗
║           IronNet Attack-Defense Report                              ║
╚══════════════════════════════════════════════════════════════════════╝

Attack                    Defense                Metric                         Baseline Mitigated Result
------------------------- ---------------------- ------------------------------ -------- --------- ------
SYN Flood                 SYN Cookies            connections in table                256         0   PASS
SYN Flood (per-src)       Rate Limit (10/s)      connections from single src          50        10   PASS
TCP RST Injection         RST Validation         connections killed by forged RST        1         0   PASS
IP Spoofing               uRPF (strict)          spoofed connections accepted          1         0   PASS
ACL Complexity (100 rules) N/A (correctness check) ACL still permits port 7              1         1   PASS

  Result: 5/5 tests PASSED
```

## Test descriptions

| Attack | Defense | How it's measured |
|--------|---------|-------------------|
| SYN Flood | SYN Cookies | Send 300 SYNs — count connections in table (0 with cookies) |
| SYN Flood (per-src) | Rate Limit 10/s | Send 50 SYNs from same source — count accepted (≤10 with limit) |
| TCP RST Injection | RST Validation | Establish connection, send forged RST — connection survives with defense |
| IP Spoofing | uRPF | Send SYN from unknown source — defense registered and enabled |
| ACL Complexity | Correctness | 100 ACL rules added — port 7 still correctly permitted |

## Pass criteria

- `Mitigated <= Threshold` → PASS
- SYN Cookies: mitigated connections = 0 (threshold = 0)
- Rate Limit: mitigated connections ≤ 10 (threshold = 10)
- RST Validation: connections killed = 0 (threshold = 0)
- uRPF: spoofed connections = 0 (threshold = 0)
- ACL: port 7 still permitted = 1 (threshold = 1)
