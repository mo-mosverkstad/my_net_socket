# Demo 02: CLI (ironctl) — Runtime Configuration

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Two terminal windows

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

Wait for `ironctl>` prompt.

## Terminal 2: Setup network

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up
```

## Terminal 1: CLI commands

### Show interfaces, routes, ARP

```
ironctl> show interfaces
ironctl> show routes
ironctl> show arp
ironctl> show tcp
ironctl> show stats
```

### Add/delete routes at runtime

```
ironctl> route add 192.168.0.0/16 via 10.0.1.254 iface 0
ironctl> show routes
ironctl> route delete 192.168.0.0/16
```

### Add/delete ACL rules at runtime

```
ironctl> acl add deny tcp port 443
ironctl> acl show
ironctl> acl delete 100
```

### Add static ARP entry

```
ironctl> arp add 10.0.1.5 02:00:00:00:00:05
ironctl> show arp
```

### Flush TCP connections

```
ironctl> show tcp
ironctl> tcp flush
ironctl> show tcp
```

### Graceful shutdown

```
ironctl> exit
```

## Terminal 2: Generate traffic to observe

```bash
ping -c 3 10.0.1.1
nc -zv 10.0.1.1 22
```

Then in Terminal 1:
```
ironctl> show stats
ironctl> show arp
```
