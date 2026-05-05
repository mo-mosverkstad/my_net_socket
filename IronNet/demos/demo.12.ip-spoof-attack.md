# Demo 12: IP Spoofing Attack + Defense (uRPF)

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Two terminal windows

## What this demo shows

- IP spoofing sends SYN packets with a forged source IP to bypass source-based ACL rules
- uRPF (unicast Reverse Path Forwarding) defense drops packets whose source IP has no route or is reachable via a different interface

## Network Topology

```
Linux (Terminal 2)              IronNet Router (Terminal 1)
  ironattack (attacker)  ──→   10.0.1.1/24 (iron0)
  claims src: 10.0.99.1        (no route for 10.0.99.0/24)
```

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

## Part 1: IP Spoof WITHOUT defense

### Terminal 2: Send spoofed SYN packets

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up
sudo ./ironattack/ironattack ip-spoof --src 10.0.99.1 --dst 10.0.1.1 --port 7 --count 5
```

Output:
```
=== IP Spoofing Attack ===
  Spoofed src: 10.0.99.1
  Target:      10.0.1.1:7
  Count:       5

  Sent: 5 spoofed SYN packets
```

### Terminal 1: Spoofed packets accepted

```
ironctl> show tcp
[INFO ] [TCP] --- TCP Connections (5 active) ---
[INFO ] [TCP]   10.0.99.1:47303 -> 10.0.1.1:7  state=SYN_RECV
[INFO ] [TCP]   10.0.99.1:41973 -> 10.0.1.1:7  state=SYN_RECV
...
# Connections created from fake source 10.0.99.1
```

## Part 2: IP Spoof WITH uRPF defense

### Terminal 1: Flush old connections and enable uRPF

```
ironctl> tcp flush
TCP connections flushed.

ironctl> defense urpf enable
[INFO ] [DEFENSE] Defense 'urpf' ENABLED
```

### Terminal 2: Send spoofed packets again

```bash
sudo ./ironattack/ironattack ip-spoof --src 10.0.99.1 --dst 10.0.1.1 --port 7 --count 5
```

### Terminal 1: Spoofed packets dropped

```
[WARN ] [IP] uRPF: no route for src 0A006301, dropping
[WARN ] [IP] uRPF: no route for src 0A006301, dropping
[WARN ] [IP] uRPF: no route for src 0A006301, dropping
[WARN ] [IP] uRPF: no route for src 0A006301, dropping
[WARN ] [IP] uRPF: no route for src 0A006301, dropping

ironctl> show tcp
[INFO ] [TCP] --- TCP Connections (0 active) ---
# No connections created — spoofed source rejected

ironctl> show stats
# l3.drops.invalid counter increased by 5
```

## How uRPF works (strict mode)

1. Packet arrives on interface X with source IP S
2. Look up route for S in the routing table
3. **If no route exists for S: DROP** — source is unknown/spoofed
4. **If route for S points to interface Y ≠ X: DROP** — source is spoofed
5. Only if route for S points to interface X: ALLOW

Since there's no route for `10.0.99.0/24` in the routing table, all packets from that source are dropped.

## Verify legitimate traffic still works

```bash
# Terminal 2: legitimate traffic from 10.0.1.2 (has a route via iron0)
ping -c 3 10.0.1.1
# Should still work — 10.0.1.0/24 route points to iron0
```

## Cleanup

```
ironctl> tcp flush
ironctl> defense urpf disable
```
