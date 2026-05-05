# Demo 01: Virtual Router — Ping & ACL

## Prerequisites

- WSL 2 with Ubuntu
- GCC, CMake, Make installed (`sudo apt install build-essential cmake`)
- Two terminal windows (both in WSL)

## Build

```bash
cd IronNet
mkdir -p build && cd build
cmake ../src -DCMAKE_BUILD_TYPE=Debug
make
```

## Network Topology

```
Linux (Terminal 2)              IronNet Router (Terminal 1)

  10.0.1.2/24  ←── iron0 ──→  10.0.1.1/24
                                10.0.2.1/24  ←── iron1 ──→  10.0.2.2/24
```

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

Expected output:
```
[INFO ] [MAIN] IronNet v0.1.0 starting...
[INFO ] [VNIC] Created TAP interface: iron0 (fd=4)
[INFO ] [IFACE] Interface iron0 added: 10.0.1.1/24 (vnic=0)
[INFO ] [VNIC] Created TAP interface: iron1 (fd=5)
[INFO ] [IFACE] Interface iron1 added: 10.0.2.1/24 (vnic=1)
[INFO ] [ROUTE] Route added: 10.0.1.0/24 via 10.0.1.0 iface 0
[INFO ] [ROUTE] Route added: 10.0.2.0/24 via 10.0.2.0 iface 1
[INFO ] [ROUTE] Route added: 0.0.0.0/0 via 0.0.0.0 iface 0
[INFO ] [ACL] Rule 1 added (PERMIT)
[INFO ] [ACL] Rule 2 added (PERMIT)
[INFO ] [ACL] Rule 3 added (DENY)
[INFO ] [MAIN] IronNet running. Press Ctrl+C to stop.
```

## Terminal 2: Configure Linux side and test

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up

# Test 1: ICMP Ping (should work — ACL permits ICMP)
ping -c 3 10.0.1.1

# Test 2: ACL Deny (SSH port 22 — ACL denies TCP port 22)
nc -zv 10.0.1.1 22
# nc will hang (no response)

# Test 3: ACL Permit (HTTP port 80 — ACL permits TCP port 80)
nc -zv 10.0.1.1 80
# nc will also hang (permitted but no app listening)
```

## Terminal 1: Observe

With `-d` flag you'll see:
```
[DEBUG] [L2] Dispatching IPv4 packet
[DEBUG] [ICMP] Echo request from 10.0.1.2
[DEBUG] [ICMP] Echo reply sent
...
[INFO ] [ACL] DENY rule 3: 10.0.1.2 -> 10.0.1.1 proto=6 sport=xxxxx dport=22
```

## Terminal 1: View statistics and shutdown

```
ironctl> show stats
ironctl> exit
```

## Cleanup

After stopping (Ctrl+C or `exit`), TAP interfaces are removed automatically. If they persist:
```bash
sudo ip link delete iron0
sudo ip link delete iron1
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ioctl TUNSETIFF failed` | Run with `sudo` |
| `/dev/net/tun` not found | `sudo mkdir -p /dev/net && sudo mknod /dev/net/tun c 10 200` |
| `RTNETLINK answers: File exists` | IP already assigned (safe to ignore) |
| No debug output | Use `-d` flag |
