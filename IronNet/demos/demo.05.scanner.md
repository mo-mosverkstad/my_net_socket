# Demo 05: Network Scanner (ironprobe) — Port Scan & ACL Validation

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- One terminal window

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack ../src/configs/router.conf
```

## Terminal 1: Run scanner from CLI

### Port scan (local target)

```
ironctl> scan 10.0.1.1 1 10000
=== Scan Results for 10.0.1.1 ===
  Open: 5  Filtered: 1  Closed: 9994

  7      OPEN       echo
  22     FILTERED
  53     OPEN       dns
  6379   OPEN       kv-store
  8080   OPEN       http
  9000   OPEN       rpc
```

### Port scan (non-existent target)

```
ironctl> scan 10.0.1.3 1 100
=== Scan Results for 10.0.1.3 ===
  Open: 0  Filtered: 0  Closed: 100
```

### ICMP ping

```
ironctl> ping 10.0.1.1
10.0.1.1 is ALIVE

ironctl> ping 10.0.1.3
10.0.1.3 is UNREACHABLE
```

### ACL validation

Validates that expected-open ports are open and expected-filtered ports are filtered:

```
ironctl> acl-check 10.0.1.1
ACL validation: 0 mismatches
```

Expected open: 7, 53, 6379, 8080, 9000
Expected filtered: 22

## How it works

The scanner checks the stack's internal state directly:
1. Is the target IP a local interface IP? (If not → all CLOSED)
2. Would ACL deny traffic to this port? (If yes → FILTERED)
3. Is an app listener registered on this port? (If yes → OPEN, else → CLOSED)
