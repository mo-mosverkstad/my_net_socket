# Demo 16: External Scanner (ironprobe-ext) — Real SYN Scan

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Two terminal windows

## What this demo shows

- ironprobe-ext sends real TCP SYN packets via raw socket and listens for SYN+ACK responses
- Unlike the internal `scan` CLI command, this is a real external network scan

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack ../src/configs/router.conf
```

## Terminal 2: Setup and run external scan

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up

# Scan ports 1-10000
sudo ./ironprobe_ext/ironprobe-ext --target 10.0.1.1 --ports 1-10000 --iface iron0
```

Expected output:
```
=== ironprobe-ext: Scanning 10.0.1.1 ports 1-10000 ===

  Open: 5  Filtered: 0  Closed: 9995

  7      OPEN       echo
  53     OPEN       dns
  6379   OPEN       kv-store
  8080   OPEN       http
  9000   OPEN       rpc
```

## Scan specific ports

```bash
# Scan only known service ports
sudo ./ironprobe_ext/ironprobe-ext --target 10.0.1.1 --ports 7-7 --iface iron0
sudo ./ironprobe_ext/ironprobe-ext --target 10.0.1.1 --ports 22-22 --iface iron0
```

## How it works

1. Opens `IPPROTO_RAW` socket bound to `iron0`
2. Gets source IP from the interface (`10.0.1.2`)
3. Sends TCP SYN to each port with unique source port
4. Listens for responses for 1 second:
   - SYN+ACK received → OPEN
   - RST received → CLOSED
   - No response → FILTERED (or CLOSED)
5. Prints results sorted by state

## Difference from internal scanner

| | Internal `scan` CLI | ironprobe-ext |
|---|---|---|
| Method | Checks internal state | Sends real packets |
| Network | No packets sent | Real SYN packets via TAP |
| Requires sudo | No | Yes |
| Detects ACL | Yes (checks ACL table) | Yes (no SYN+ACK = filtered) |
