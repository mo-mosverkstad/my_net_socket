# Demo 07: Stress Tester (ironload) — Resource Limits & Degradation

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- One terminal window

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack ../src/configs/router.conf
```

## Terminal 1: Run stress tests from CLI

### TCP connection flood (fills connection table)

```
ironctl> load tcp 300
=== Load Test: TCP Flood ===
  Attempted:  300
  Succeeded:  256
  Rejected:   44
  Elapsed:    2423 us
  Avg/op:     8076 ns
  Result:     PASS (graceful)
```

TCP_MAX_CONNECTIONS = 256. After 256 connections, new SYNs are gracefully rejected.

### Route table stress

```
ironctl> load route 128
=== Load Test: Route Stress ===
  Attempted:  128
  Succeeded:  128
  Rejected:   0
  Elapsed:    2626 us
  Avg/op:     2248 ns
  Result:     PASS (graceful)
```

Adds 128 routes, measures lookup latency. ROUTE_MAX_ENTRIES = 128.

### ACL complexity stress

```
ironctl> load acl 100
=== Load Test: ACL Stress ===
  Attempted:  100
  Succeeded:  100
  Rejected:   0
  Elapsed:    9031 us
  Avg/op:     8805 ns
  Result:     PASS (graceful)
```

Adds 100 ACL rules, measures per-packet evaluation time. Linear degradation.

### Bandwidth flood

```
ironctl> load bw 10000
=== Load Test: Bandwidth ===
  Attempted:  10000
  Succeeded:  0
  Rejected:   10000
  Elapsed:    21547 us
  Avg/op:     2154 ns
  Result:     PASS (graceful)
```

Sends 10000 packets at max rate (~464K pps). All rejected (no matching connection) — tests rejection path performance.

## Cleanup after TCP flood

```
ironctl> tcp flush
TCP connections flushed.

ironctl> show tcp
[INFO ] [TCP] --- TCP Connections (0 active) ---
```
