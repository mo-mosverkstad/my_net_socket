# Demo 13: Slowloris Attack + Defense (Connection Idle Timeout)

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Two terminal windows

## What this demo shows

- Slowloris opens many TCP connections and sends data very slowly, exhausting the connection table without completing requests
- Connection idle timeout defense closes ESTABLISHED connections that have been idle for too long, recovering resources

## How Slowloris works

```
Normal HTTP client:  SYN → SYN+ACK → ACK → "GET / HTTP/1.0\r\n\r\n" → response → FIN
Slowloris:           SYN → SYN+ACK → ACK → "X" (1 byte every 2s, never completes)
```

By holding connections open indefinitely, the attacker fills the connection table (max 256) so legitimate clients cannot connect.

## Network Topology

```
Linux (Terminal 2)              IronNet Router (Terminal 1)
  ironattack (attacker)  ──→   10.0.1.1:8080 (HTTP server)
  50 slow connections
```

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

## Part 1: Slowloris WITHOUT defense

### Terminal 2: Run Slowloris attack

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up
sudo ./ironattack/ironattack slowloris --target 10.0.1.1 --port 8080 --conns 50
```

Output:
```
=== Slowloris Attack ===
  Target:  10.0.1.1:8080
  Conns:   50

  Phase 1: Opening 50 connections...
  Phase 2: Sending partial headers (1 byte every 2s)...
  Done: 50 connections held open for ~10s
```

### Terminal 1: Connection table filling up

```
ironctl> show tcp
# 50 connections in ESTABLISHED state from 192.168.10.1
# All holding open without completing requests

ironctl> show stats
# tcp.conn_created = 50
```

## Part 2: Slowloris WITH connection idle timeout defense

### Terminal 1: Flush old connections and enable defense

```
ironctl> tcp flush
TCP connections flushed.

ironctl> defense conn-timeout 5
[INFO ] [DEFENSE] Defense 'conn-timeout' ENABLED
```

This sets a 5-second idle timeout — any ESTABLISHED connection with no data for 5 seconds is closed.

### Terminal 2: Run Slowloris again

```bash
sudo ./ironattack/ironattack slowloris --target 10.0.1.1 --port 8080 --conns 50
```

### Terminal 1: Connections cleaned up automatically

```
# After ~5 seconds of inactivity:
[INFO ] [TCP] Idle timeout: closing connection (port 20000 -> 8080)
[INFO ] [TCP] Idle timeout: closing connection (port 20001 -> 8080)
...

ironctl> show tcp
[INFO ] [TCP] --- TCP Connections (0 active) ---
# Resources recovered!

ironctl> show stats
# tcp.conn_closed counter increased
```

## How connection idle timeout works

1. `tcp_timer_tick()` runs periodically checking all ESTABLISHED connections
2. If `defense conn-timeout` is enabled and `now - last_activity >= timeout_secs`: close connection
3. Slowloris connections that only send 1 byte every 2 seconds will be closed after the timeout
4. Legitimate clients that send complete requests are not affected (they complete quickly)

## Cleanup

```
ironctl> tcp flush
ironctl> defense conn-timeout disable
```
