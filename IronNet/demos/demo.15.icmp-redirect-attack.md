# Demo 15: ICMP Redirect Attack + Defense (icmp-redirect-disable)

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Two terminal windows

## What this demo shows

- ICMP redirect messages can manipulate the router's routing table by adding host routes
- icmp-redirect-disable defense ignores all ICMP redirect messages

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

## Part 1: ICMP Redirect WITHOUT defense

### Terminal 2: Send ICMP redirect

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up
sudo ./ironattack/ironattack icmp-redirect --target 10.0.1.1 --new-gw 10.0.1.99 --orig-dst 8.8.8.8 --count 3
```

### Terminal 1: Routing table modified

```
[WARN ] [ICMP] ICMP redirect: new gateway 10.0.1.99
[WARN ] [ICMP] ICMP redirect: added host route 08080808 via 0A000163

ironctl> show routes
# New host route for 8.8.8.8 via 10.0.1.99 (attacker-controlled!)
```

## Part 2: ICMP Redirect WITH defense

### Terminal 1: Enable defense

```
ironctl> defense icmp-redirect-disable enable
[INFO ] [DEFENSE] Defense 'icmp-redirect-disable' ENABLED
```

### Terminal 2: Send ICMP redirect again

```bash
sudo ./ironattack/ironattack icmp-redirect --target 10.0.1.1 --new-gw 10.0.1.99 --orig-dst 8.8.8.8 --count 3
```

### Terminal 1: Redirects ignored

```
[WARN ] [ICMP] ICMP redirect ignored (defense enabled) from C0A80A01

ironctl> show routes
# Routing table unchanged — attack blocked
```

## Cleanup

```
ironctl> defense icmp-redirect-disable disable
```
