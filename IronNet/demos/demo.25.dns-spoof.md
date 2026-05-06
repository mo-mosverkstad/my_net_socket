# Demo 25: DNS Response Spoofing — Zone Poisoning

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Two terminal windows
- Optional: `dnsutils` for dig command: `sudo apt install dnsutils`

## What this demo shows

- DNS zone table can be poisoned to redirect domains to attacker-controlled IPs
- After poisoning, all DNS queries for the domain return the fake IP
- Demonstrates why DNS security (DNSSEC, DoH) is important

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

## Terminal 1: Verify legitimate DNS resolution

```
ironctl> dns lookup ironnet.local
ironnet.local -> 10.0.1.1

ironctl> dns lookup example.com
example.com -> 93.184.216.34
```

## Terminal 1: Poison the DNS zone table

```
ironctl> dns spoof-test ironnet.local 10.0.99.1
DNS POISONED: ironnet.local -> 10.0.99.1

ironctl> dns lookup ironnet.local
ironnet.local -> 10.0.99.1
```

The domain `ironnet.local` now resolves to the attacker's IP `10.0.99.1` instead of the real `10.0.1.1`.

## Terminal 2: Verify poisoning from client side

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up

# DNS query returns the poisoned IP
dig @10.0.1.1 ironnet.local

# Expected: ironnet.local -> 10.0.99.1 (attacker's IP!)
# Instead of the real 10.0.1.1
```

## Terminal 1: Restore legitimate entry

```
ironctl> dns spoof-test ironnet.local 10.0.1.1
DNS POISONED: ironnet.local -> 10.0.1.1

ironctl> dns lookup ironnet.local
ironnet.local -> 10.0.1.1
```

## External attack tool

The `ironattack dns-spoof` command sends forged DNS response packets via raw IP socket:

```bash
sudo ./ironattack/ironattack dns-spoof --domain ironnet.local --fake-ip 10.0.99.1 --target 10.0.1.1 --count 10
```

Output:
```
=== DNS Spoof Attack ===
  Domain:  ironnet.local
  Fake IP: 10.0.99.1
  Target:  10.0.1.1
  Count:   10

  Sent: 10 forged DNS responses
  Payload: ironnet.local -> 10.0.99.1 (TTL=60s)
```

Note: On a single-TAP setup, the forged UDP packets may not reach ironstack's DNS server (same raw socket limitation as other attacks). The `dns spoof-test` CLI command demonstrates the concept reliably.

## How DNS spoofing works

1. **Normal flow:** Client queries DNS server → server looks up zone table → returns real IP
2. **After poisoning:** Client queries DNS server → server looks up zone table → returns **attacker's IP**
3. **Client connects to fake IP** → traffic goes to attacker instead of real server

In a real network, the attacker would:
- Sniff DNS queries on the wire
- Race to respond before the real DNS server
- Send a forged response with the attacker's IP and matching transaction ID

## What this demonstrates

- **DNS is inherently insecure** — responses are not authenticated
- **Any network intermediary can forge DNS responses**
- **DNSSEC** adds cryptographic signatures to prevent forgery
- **DNS over HTTPS (DoH)** encrypts queries to prevent interception

## Command reference

| Command | Description |
|---------|-------------|
| `dns lookup <domain>` | Query the DNS zone table |
| `dns spoof-test <domain> <ip>` | Poison a zone entry (simulate successful DNS spoof) |
| `ironattack dns-spoof --domain <name> --fake-ip <ip> --target <ip>` | External forged DNS response attack |
