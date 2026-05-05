# Demo 23: Regression Workflow (irontrace) — Capture → Fix → Replay → Verify

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- tcpdump installed: `sudo apt install tcpdump`
- Two terminal windows

## What this demo shows

- Complete regression testing workflow using irontrace
- Capture a bug scenario to a pcap file
- Fix the bug, rebuild
- Replay the captured traffic to verify the fix
- Two replay methods: external (irontrace-replay) and internal (CLI)

## The Regression Workflow

```
┌─────────────────────────────────────────────────────────┐
│  1. CAPTURE: Record the failing scenario                 │
│     ironctl> trace start /tmp/bug.pcap all               │
│     ... reproduce the bug ...                            │
│     ironctl> trace stop                                  │
├─────────────────────────────────────────────────────────┤
│  2. ANALYZE: Inspect the captured packets                │
│     $ tcpdump -r /tmp/bug.pcap -n                        │
│     $ tcpdump -r /tmp/bug.pcap -XX -n | less             │
├─────────────────────────────────────────────────────────┤
│  3. FIX: Edit source code, rebuild                       │
│     $ vim src/ironstack/l4/tcp.c                         │
│     $ cd build && make                                   │
├─────────────────────────────────────────────────────────┤
│  4. REPLAY: Inject the same traffic into the fixed stack │
│     ironctl> trace replay /tmp/bug.pcap                  │
│     OR: $ sudo ./irontrace-replay --file /tmp/bug.pcap   │
├─────────────────────────────────────────────────────────┤
│  5. VERIFY: Check that the bug no longer reproduces      │
│     ironctl> show stats                                  │
│     ironctl> show tcp                                    │
│     # No crash, correct counters, expected behavior      │
└─────────────────────────────────────────────────────────┘
```

## Example: Capturing and replaying a TCP session

### Step 1: Start router and begin capture

**Terminal 1:**
```bash
cd IronNet/build
sudo ./ironstack/ironstack ../src/configs/router.conf
```

```
ironctl> trace start /tmp/tcp_session.pcap all
[INFO ] [TRACE] Trace started: /tmp/tcp_session.pcap (layers: L2 L3 L4)
```

### Step 2: Generate traffic (the scenario to capture)

**Terminal 2:**
```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up

# TCP echo session
echo "regression test data" | nc -w2 10.0.1.1 7

# Some pings
ping -c 3 10.0.1.1

# DNS query
dig @10.0.1.1 ironnet.local
```

### Step 3: Stop capture

**Terminal 1:**
```
ironctl> trace status
  Trace: ACTIVE
  File:  /tmp/tcp_session.pcap
  Layers: L2 L3 L4
  Packets: 45

ironctl> trace stop
[INFO ] [TRACE] Trace stopped: 45 packets captured to /tmp/tcp_session.pcap
```

### Step 4: Analyze the capture

**Terminal 2:**
```bash
# Summary of all packets
sudo tcpdump -r /tmp/tcp_session.pcap -n

# Count packets by protocol
sudo tcpdump -r /tmp/tcp_session.pcap -n tcp | wc -l
sudo tcpdump -r /tmp/tcp_session.pcap -n icmp | wc -l
sudo tcpdump -r /tmp/tcp_session.pcap -n udp | wc -l

# Detailed hex dump of first 5 packets
sudo tcpdump -r /tmp/tcp_session.pcap -XX -n -c 5
```

### Step 5: Replay internally (full bidirectional)

**Terminal 1:**
```
ironctl> trace replay /tmp/tcp_session.pcap
Replayed 45 packets from /tmp/tcp_session.pcap

ironctl> show stats
# Verify counters match expected values
# l2.rx_frames should increase by ~45
# l3.rx_packets should increase
# tcp.conn_created should increase
```

### Step 6: Replay externally (client-side only)

**Terminal 2:**
```bash
sudo ./irontrace/irontrace-replay --file /tmp/tcp_session.pcap --iface iron0
```

Expected:
```
  Replay complete:
    Packets read:   45
    Packets sent:   30    ← client-side packets injected
    Errors:         15    ← router-side packets skipped (expected)
    Elapsed:        3.5 s
```

## Example: Regression test for a bug fix

### Scenario: ACL rule not blocking port 22

```
# 1. Capture the failing behavior
ironctl> trace start /tmp/acl_bug.pcap all

# Terminal 2: This should be blocked but isn't
nc -zv 10.0.1.1 22

ironctl> trace stop

# 2. Analyze
$ sudo tcpdump -r /tmp/acl_bug.pcap -n port 22
# See: SYN to port 22 was NOT denied

# 3. Fix the ACL bug in source code, rebuild
$ cd build && make

# 4. Restart and replay
ironctl> trace replay /tmp/acl_bug.pcap
ironctl> show stats
# Verify: l3.drops.acl counter increased (port 22 now blocked)
ironctl> show audit-log
# Verify: ACL_DENY event for port 22
```

## CLI Command Reference

| Command | Description |
|---------|-------------|
| `trace start <file> [l2\|l3\|l4\|all]` | Begin capturing to pcap file |
| `trace stop` | Stop capture, close file |
| `trace status` | Show capture state (active/inactive, file, packet count) |
| `trace replay <file>` | Replay pcap internally via vnic_inject() |
| `help` | Shows all commands including trace |

## External Binary Reference

```bash
# Timed replay (preserves original inter-packet delays)
sudo ./irontrace/irontrace-replay --file <pcap> --iface iron0

# Fast replay (max speed, for stress testing)
sudo ./irontrace/irontrace-replay --file <pcap> --iface iron0 --fast
```

## When to use which replay method

| Method | Use case | Packets injected |
|--------|----------|-----------------|
| `trace replay` (CLI) | Regression testing, full bidirectional | ALL packets (both sides) |
| `irontrace-replay` (external) | Realistic testing, client simulation | Client-side only (router responds fresh) |
| `irontrace-replay --fast` | Stress testing, crash detection | Client-side at max speed |

## Tips

- Always `trace stop` before reading the pcap file (ensures proper flush)
- Use `trace status` to check packet count during capture
- For large captures, use layer filtering: `trace start /tmp/l3.pcap l3`
- Keep regression pcap files in version control for automated testing
- Name files descriptively: `/tmp/bug123_syn_flood.pcap`
