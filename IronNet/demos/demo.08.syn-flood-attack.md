# Demo 08: SYN Flood Attack + Defense (SYN Cookies & Rate Limiting)

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Two terminal windows

## What this demo shows

- SYN flood fills the TCP connection table (max 256) causing legitimate clients to be rejected
- SYN cookies defense handles SYNs statelessly — table stays empty during flood
- Rate limiting defense drops excess SYNs per source

## Network Topology

```
Linux (Terminal 2)              IronNet Router (Terminal 1)
  ironattack (attacker)  ──→   10.0.1.1/24 (iron0)
```

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack ../src/configs/router.conf
```

## Part 1: SYN Flood WITHOUT defense

### Terminal 2: Run SYN flood

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up
sudo ./ironattack/ironattack syn-flood --target 10.0.1.1 --port 7 --rate 1000 --count 5000
```

Output:
```
=== SYN Flood Attack ===
  Target:  10.0.1.1:7
  Rate:    1000 pps
  Count:   5000

  Sent:    5000 packets
  Elapsed: 5.01 s
  Rate:    998 pps
```

### Terminal 1: Connection table fills up

```
ironctl> show tcp
# Many SYN_RECV connections from random IPs

ironctl> show stats
# tcp.drops.resource counter increasing (table full)
```

## Part 2: SYN Flood WITH SYN cookies defense

### Terminal 1: Flush old connections and enable defense

```
ironctl> tcp flush
TCP connections flushed.

ironctl> defense syn-cookies enable
[INFO ] [DEFENSE] Defense 'syn-cookies' ENABLED
```

### Terminal 2: Run SYN flood again

```bash
sudo ./ironattack/ironattack syn-flood --target 10.0.1.1 --port 7 --rate 1000 --count 5000
```

### Terminal 1: Table stays empty

```
ironctl> show tcp
[INFO ] [TCP] --- TCP Connections (0 active) ---
# No state allocated — SYNs handled statelessly via cookies
```

## Part 3: Rate limiting defense

### Terminal 1: Enable rate limiting

```
ironctl> defense syn-cookies disable
ironctl> tcp flush

ironctl> defense rate-limit 100/s
[INFO ] [DEFENSE] Rate limit set to 100/s per source
[INFO ] [DEFENSE] Defense 'rate-limit' ENABLED
```

### Terminal 2: Run SYN flood

```bash
sudo ./ironattack/ironattack syn-flood --target 10.0.1.1 --port 7 --rate 1000 --count 1000
```

### Terminal 1: Excess SYNs dropped per source

```
ironctl> show stats
# tcp.drops.resource counter shows rate-limited drops
```

## How SYN cookies work

Without defense:
1. SYN arrives → allocate connection table entry (SYN_RECV)
2. 256 SYNs → table full → legitimate clients rejected

With SYN cookies:
1. SYN arrives → NO table entry allocated
2. Compute cookie = hash(src_ip, dst_ip, src_port, dst_port)
3. Send SYN+ACK with cookie as sequence number
4. ACK arrives → validate cookie → ONLY THEN create connection
5. Table stays empty during flood

## Cleanup

```
ironctl> tcp flush
ironctl> defense syn-cookies disable
ironctl> defense rate-limit disable
```
