# Demo 22: Packet Replay (irontrace-replay) — Regression Testing

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- tcpdump installed: `sudo apt install tcpdump`
- A pcap capture file (see demo.21 to create one)
- Two terminal windows

## What this demo shows

- Replay previously captured pcap files back into the network
- Two modes: timed (original delays) and fast (max speed)
- Internal CLI replay for regression testing without external binary
- Full regression workflow: capture → fix → replay → verify

## Step 1: Create a capture file

### Terminal 1: Start router and begin capture

```bash
cd IronNet/build
sudo ./ironstack/ironstack ../src/configs/router.conf
```

```
ironctl> trace start /tmp/regression.pcap all
```

### Terminal 2: Generate traffic

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up
ping -c 5 10.0.1.1
echo "test data" | nc -w2 10.0.1.1 7
```

### Terminal 1: Stop capture

```
ironctl> trace stop
[INFO ] [TRACE] Trace stopped: 20 packets captured to /tmp/regression.pcap

ironctl> exit
```

## Step 2: External replay (irontrace-replay binary)

### Terminal 1: Restart router

```bash
sudo ./ironstack/ironstack ../src/configs/router.conf
```

### Terminal 2: Replay with original timing

```bash
sudo ./irontrace/irontrace-replay --file /tmp/regression.pcap --iface iron0
```

Expected output:
```
╔══════════════════════════════════════════╗
║     irontrace-replay — Packet Replay     ║
╚══════════════════════════════════════════╝

  File:      /tmp/regression.pcap
  Interface: iron0
  Mode:      timed (original delays)
  Linktype:  1

  Replay complete:
    Packets read:   53
    Packets sent:   39
    Errors:         14
    Elapsed:        5.32 s
    Rate:           7 pps
```

Note: The 14 errors are **expected** — these are packets with source IP `10.0.1.1` (ironstack's IP). The kernel rejects sending from an IP that belongs to another process's TAP interface. Only client-side packets (source `10.0.1.2`) are successfully injected. ironstack generates fresh responses when it processes the replayed client packets.

### Terminal 2: Replay at max speed (stress test)

```bash
sudo ./irontrace/irontrace-replay --file /tmp/regression.pcap --iface iron0 --fast
```

Expected output:
```
  File:      /tmp/regression.pcap
  Interface: iron0
  Mode:      fast (max speed)

  Replay complete:
    Packets read:   20
    Packets sent:   20
    Errors:         0
    Elapsed:        0.01 s
    Rate:           2000 pps
```

## Step 3: Internal replay (CLI command)

### Terminal 1: Replay from within the router

```
ironctl> trace replay /tmp/regression.pcap
Replayed 20 packets from /tmp/regression.pcap

ironctl> show stats
# Verify counters match expected values
```

## Full regression workflow

```bash
# === Step 1: Capture the bug ===
# Start router, enable trace, reproduce the issue
ironctl> trace start /tmp/bug123.pcap all
# ... trigger the bug (e.g., specific packet sequence) ...
ironctl> trace stop
# Save the pcap — this is your regression test input

# === Step 2: Fix the bug ===
# Edit source code, rebuild
cd IronNet/build && make

# === Step 3: Verify the fix ===
# Restart router with the fix
sudo ./ironstack/ironstack ../src/configs/router.conf

# Replay the captured traffic
ironctl> trace replay /tmp/bug123.pcap
ironctl> show stats
# Verify: no crashes, counters correct, bug no longer reproduces

# Or use external replay:
sudo ./irontrace/irontrace-replay --file /tmp/bug123.pcap --iface iron0
```

## Verify capture contents before replay

```bash
# Check what's in the pcap file
sudo tcpdump -r /tmp/regression.pcap -n | head -10

# Count packets
sudo tcpdump -r /tmp/regression.pcap -n | wc -l

# Show hex dump of first packet
sudo tcpdump -r /tmp/regression.pcap -XX -n -c 1
```

## Command reference

### External binary (irontrace-replay)

```bash
sudo ./irontrace/irontrace-replay --file <pcap> [--iface <name>] [--fast]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--file <path>` | pcap file to replay | (required) |
| `--iface <name>` | Interface to inject on | iron0 |
| `--fast` | Replay at max speed | timed |

### Internal CLI command

```
ironctl> trace replay <file>
```

Reads pcap and injects each packet via `vnic_inject()` into the pipeline.

## Notes

- External replay sends IP packets via `IPPROTO_RAW` socket bound to the interface
- Only **client-side packets** (source IP = Linux's IP) are injected successfully
- Packets with ironstack's source IP (e.g., 10.0.1.1) are rejected by the kernel — this is expected
- ironstack generates fresh responses to replayed client packets
- For **full bidirectional replay**, use the internal CLI command: `trace replay <file>`
- Internal replay uses `vnic_inject()` which bypasses the kernel entirely
- Timed mode preserves original inter-packet delays (capped at 10s max)
- Fast mode is useful for stress testing (replay thousands of packets instantly)
- ARP frames in the pcap are skipped (not IPv4)
- The pcap file must have been captured with `trace start` (standard pcap format)
