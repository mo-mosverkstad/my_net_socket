# Demo 18: Network Emulator (ironsim) — 2-Node Topology

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Two terminal windows

## What this demo shows

- ironsim spawns multiple ironstack instances on a single WSL machine
- Each node gets its own TAP interface and IP address
- Linux routes between the nodes, enabling ping from the host to each node

## Network Topology

```
Linux Host (Terminal 2)
  |
  +-- 10.0.1.2/24 on iron-a ──→ ironstack Node A (10.0.1.1/24)
  |
  +-- 10.0.2.2/24 on iron-b ──→ ironstack Node B (10.0.2.1/24)
```

## Topology Config File

`src/configs/topo_2node.conf`:
```
# ironsim topology: 2-node linear
node a ip 10.0.1.1/24
node b ip 10.0.2.1/24
link a b
```

## Terminal 1: Start ironsim

```bash
cd IronNet/build
make
sudo ./ironsim/ironsim ../src/configs/topo_2node.conf
```

Expected output:
```
╔══════════════════════════════════════════╗
║       ironsim — Network Emulator         ║
╚══════════════════════════════════════════╝

  [ironsim] Loaded topology: ../src/configs/topo_2node.conf
  [ironsim] Nodes: 2, Links: 1

  [ironsim] Generated config: /tmp/ironsim_a.conf
  [ironsim] Generated config: /tmp/ironsim_b.conf
  [ironsim] Node a started (pid=XXXX, tap=iron-a, ip=10.0.1.1/24)
  [ironsim] Node b started (pid=XXXX, tap=iron-b, ip=10.0.2.1/24)
  [ironsim] Linux: 10.0.1.2/24 on iron-a
  [ironsim] Linux: 10.0.2.2/24 on iron-b

  [ironsim] Topology is UP. Press Ctrl+C to stop.
  [ironsim] Test with: ping 10.0.1.1 or ping 10.0.2.1
```

## Terminal 2: Test connectivity

```bash
# Ping Node A
ping -c 3 10.0.1.1

# Expected:
# 64 bytes from 10.0.1.1: icmp_seq=1 ttl=64 time=1.58 ms
# 64 bytes from 10.0.1.1: icmp_seq=2 ttl=64 time=0.60 ms
# 64 bytes from 10.0.1.1: icmp_seq=3 ttl=64 time=0.55 ms

# Ping Node B
ping -c 3 10.0.2.1

# Expected:
# 64 bytes from 10.0.2.1: icmp_seq=1 ttl=64 time=1.76 ms
# 64 bytes from 10.0.2.1: icmp_seq=2 ttl=64 time=0.55 ms
# 64 bytes from 10.0.2.1: icmp_seq=3 ttl=64 time=0.50 ms
```

## Terminal 1: Stop ironsim

Press **Ctrl+C** (not `exit` — that only stops one child process):

```
^C
  [ironsim] Shutting down...
  [ironsim] Node a stopped (pid=XXXX)
  [ironsim] Node b stopped (pid=XXXX)
  [ironsim] Done.
```

## How it works

1. ironsim reads the topology config file
2. For each node: generates a temporary `router.conf` in `/tmp/`
3. Fork+exec: spawns an ironstack process for each node
4. Waits 2 seconds for TAP interfaces to be created
5. Assigns peer IPs on the Linux side (`.2` on each TAP)
6. Enables IP forwarding in the kernel
7. Linux can now ping each node through its TAP interface

## Default topology (no config file)

If no config file is provided, ironsim uses a built-in 2-node topology:

```bash
sudo ./ironsim/ironsim
```

## Notes

- Each ironstack instance runs as a separate process (full isolation)
- Each node uses ~1-2 MB RAM
- TAP names are unique per node: `iron-a`, `iron-b`, etc.
- Does not conflict with standalone `ironstack` using `iron0`/`iron1`
- Use Ctrl+C to stop (sends SIGTERM to all children)
- The `exit` CLI command only stops one child — use Ctrl+C instead

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "cannot find ironstack binary" | Run from `IronNet/build` directory |
| Ping fails | Wait a few seconds after "Topology is UP" for ARP to resolve |
| `exit` doesn't stop everything | Use Ctrl+C instead |
| TAP already exists | Previous ironsim didn't clean up — `sudo ip link delete iron-a` |
