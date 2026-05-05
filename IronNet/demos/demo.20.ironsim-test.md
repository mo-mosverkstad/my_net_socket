# Demo 20: Traffic Generator & Report (ironsim-test)

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Two terminal windows
- A running ironsim topology (see demo.19)

## What this demo shows

- ironsim-test runs automated ping and TCP tests against all nodes in a topology
- Measures latency (min/avg/max), packet loss, and TCP port connectivity
- Produces a formatted report

## Terminal 1: Start the 3-node topology

```bash
cd IronNet/build
sudo ./ironsim/ironsim ../src/configs/topo_3node.conf
```

Wait until you see "Topology is UP".

## Terminal 2: Run traffic tests

### Test all standard 3-node IPs with ping + TCP port 7

```bash
cd IronNet/build
sudo ./ironsim/ironsim-test --all --count 10 --tcp 7
```

Expected output:
```
  [ironsim-test] Testing 4 targets, 10 pings each, TCP port 7

  Pinging 10.0.1.1...
  Pinging 10.0.1.254...
  Pinging 10.0.2.254...
  Pinging 10.0.2.1...
  Testing TCP/7...

╔══════════════════════════════════════════════════════════════╗
║            ironsim-test — Topology Test Report               ║
╚══════════════════════════════════════════════════════════════╝

  Target            Sent  Recv  Loss%  Min(ms)  Avg(ms)  Max(ms)  TCP/7
  ---------------- ----- ----- ------ -------- -------- --------  ------
  10.0.1.1            10    10   0.0%     5.3ms     6.5ms    12.6ms  OPEN
  10.0.1.254          10    10   0.0%     5.2ms     6.2ms    11.5ms  OPEN
  10.0.2.254          10    10   0.0%    10.2ms    11.6ms    20.9ms  OPEN
  10.0.2.1            10    10   0.0%    10.2ms    12.0ms    21.9ms  OPEN

  Summary: 4 targets, 40/40 packets received (0.0% overall loss)
```

### Test specific targets

```bash
# Test only Node C
sudo ./ironsim/ironsim-test --target 10.0.2.1 --count 20

# Test with TCP port 8080
sudo ./ironsim/ironsim-test --target 10.0.1.1 --target 10.0.2.1 --count 5 --tcp 8080
```

### Test with high-loss link

Edit `topo_3node.conf` to set `loss 50%` on link B-C, restart ironsim, then:
```bash
sudo ./ironsim/ironsim-test --all --count 50
```

Expected: ~50% loss on 10.0.2.254 and 10.0.2.1 targets.

## Command-line options

| Option | Description | Default |
|--------|-------------|---------|
| `--target <ip>` | Add a target IP to test | (none) |
| `--all` | Test 10.0.1.1, 10.0.1.254, 10.0.2.254, 10.0.2.1 | off |
| `--count <n>` | Number of pings per target | 10 |
| `--tcp <port>` | Also test TCP connectivity to this port | off |
| `--help` | Show usage | |

## How it works

1. For each target: runs `ping -c <count> -W 1 -q <ip>` and parses output
2. Extracts: packets sent/received, RTT min/avg/max
3. If `--tcp` specified: attempts non-blocking TCP connect with 2s timeout
4. Prints formatted report table

## Terminal 1: Stop ironsim

Press Ctrl+C when done testing.

## Notes

- ironsim-test does NOT require ironsim to be running — it just pings IPs
- But the IPs only respond when ironstack nodes are running
- TCP test requires the target node to have a listener on the specified port
- All nodes have echo server (port 7) and HTTP server (port 8080) by default
