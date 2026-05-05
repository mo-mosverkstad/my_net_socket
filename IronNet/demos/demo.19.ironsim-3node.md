# Demo 19: Network Emulator (ironsim) — 3-Node Topology with Link Impairments

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Two terminal windows

## What this demo shows

- 3-node linear topology: A ←→ B (router) ←→ C
- Node B has 2 interfaces (acts as router between subnets)
- Link impairments: configurable delay and packet loss via tc netem
- All nodes reachable from the Linux host

## Network Topology

```
Linux Host (Terminal 2)
  |
  +-- iron-a0 ──[5ms delay]──→ Node A (10.0.1.1/24)
  |
  +-- iron-b0 ──[5ms delay]──→ Node B (10.0.1.254/24, 10.0.2.254/24)
  |
  +-- iron-b1 ──[10ms, 1% loss]──→ Node B (second interface)
  |
  +-- iron-c0 ──[10ms, 1% loss]──→ Node C (10.0.2.1/24)
```

## Topology Config File

`src/configs/topo_3node.conf`:
```
# ironsim topology: 3-node linear with impairments
#
#   Node A (10.0.1.1) <--5ms--> Node B (10.0.1.254, 10.0.2.254) <--10ms/1% loss--> Node C (10.0.2.1)

node a ip 10.0.1.1/24
node b ip 10.0.1.254/24 ip 10.0.2.254/24
node c ip 10.0.2.1/24

link a b delay 5ms
link b c delay 10ms loss 1%
```

## Terminal 1: Start ironsim

```bash
cd IronNet/build
make
sudo ./ironsim/ironsim ../src/configs/topo_3node.conf
```

Expected output:
```
╔══════════════════════════════════════════╗
║       ironsim — Network Emulator         ║
╚══════════════════════════════════════════╝

  [ironsim] Loaded topology: ../src/configs/topo_3node.conf
  [ironsim] Nodes: 3, Links: 2

  [ironsim] Config: /tmp/ironsim_a.conf (1 interfaces)
  [ironsim] Config: /tmp/ironsim_b.conf (2 interfaces)
  [ironsim] Config: /tmp/ironsim_c.conf (1 interfaces)
  [ironsim] Node a started (pid=XXXX)
  [ironsim] Node b started (pid=XXXX)
  [ironsim] Node c started (pid=XXXX)
  [ironsim] Link a-b: netem delay 5ms
  [ironsim] Link b-c: netem delay 10ms loss 1%

  [ironsim] Network wiring complete:
    a: iron-a0 (10.0.1.1/24)
    b: iron-b0 (10.0.1.254/24)
    b: iron-b1 (10.0.2.254/24)
    c: iron-c0 (10.0.2.1/24)

  [ironsim] Topology is UP. Press Ctrl+C to stop.
```

## Terminal 2: Test connectivity

```bash
# Ping Node A (~5ms RTT — link A-B delay)
ping -c 3 10.0.1.1

# Ping Node B interface 1 (~5ms RTT)
ping -c 3 10.0.1.254

# Ping Node B interface 2 (~10ms RTT — link B-C delay)
ping -c 3 10.0.2.254

# Ping Node C (~10ms RTT — link B-C delay)
ping -c 3 10.0.2.1
```

Expected results:
```
10.0.1.1:   RTT ~5-6ms   (link A-B: 5ms delay)
10.0.1.254: RTT ~5-6ms   (link A-B: 5ms delay)
10.0.2.254: RTT ~10-11ms (link B-C: 10ms delay)
10.0.2.1:   RTT ~10-11ms (link B-C: 10ms delay)
```

Note: First ping may be higher (~20ms) due to ARP resolution.

## Terminal 1: Stop ironsim

Press **Ctrl+C**:
```
^C
  [ironsim] Shutting down...
  [ironsim] Node a stopped
  [ironsim] Node b stopped
  [ironsim] Node c stopped
  [ironsim] Done.
```

## Link impairment options

| Option | Format | Example | Effect |
|--------|--------|---------|--------|
| delay | `delay <N>ms` | `delay 50ms` | Add N milliseconds latency each direction |
| loss | `loss <N>%` | `loss 5%` | Drop N% of packets randomly |
| reorder | `reorder` | `reorder` | Deliver 25% of packets out of order |

Combine multiple options per link:
```
link a b delay 100ms loss 10% reorder
```

## How it works

1. ironsim parses the topology config
2. Spawns ironstack processes (one per node, each with unique TAP interfaces)
3. Assigns Linux-side peer IPs and host routes
4. Applies `tc netem` on TAP interfaces for link impairments
5. Linux kernel handles routing between subnets via the TAP interfaces
6. On shutdown: removes netem qdiscs, stops all children

## Notes

- No manual `ip addr add` needed — ironsim handles all Linux-side setup
- Node B with 2 interfaces acts as a router (has routes to both subnets)
- `tc netem` requires the `iproute2` package (usually pre-installed)
- The `ironctl>` prompts visible in Terminal 1 are from child processes sharing the terminal — ignore them

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Cannot find device iron0" | ironsim uses `iron-a0`, `iron-b0`, etc. — no manual setup needed |
| Ping to Node C fails | Wait a few seconds for ARP resolution after topology is UP |
| Shutdown stuck | Fixed — stdin redirected to /dev/null for children |
| High first-ping latency | Normal — ARP resolution on first packet |
