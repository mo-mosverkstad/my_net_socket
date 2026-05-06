# Demo 27: DNS Response Spoofing — Zone Poisoning

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- `dnsutils` installed: `sudo apt install dnsutils`
- Two terminal windows

## What this demo shows

- External DNS queries (via `dig`) reach ironstack's DNS server over UDP
- DNS zone table can be poisoned to redirect domains to attacker-controlled IPs
- After poisoning, external clients receive the fake IP
- Demonstrates why DNS security (DNSSEC, DoH) is important

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

## Terminal 2: Verify external DNS queries work (UDP reaches ironstack)

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up

# Query ironstack's DNS server from external client
dig @10.0.1.1 ironnet.local
```

Expected output (answer section):
```
;; ANSWER SECTION:
ironnet.local.       60      IN      A       10.0.1.1
```

This proves: **external UDP packets reach ironstack's DNS server and get a response.** The full path is:
```
dig (Linux) → UDP port 53 → kernel routes to iron0 TAP → ironstack reads → DNS server responds → reply via TAP → dig receives
```

## Terminal 2: Query other domains

```bash
dig @10.0.1.1 example.com
# Expected: 93.184.216.34

dig @10.0.1.1 server.ironnet.local
# Expected: 10.0.2.1

dig @10.0.1.1 nonexistent.com
# Expected: NXDOMAIN (status: NXDOMAIN)
```

## Terminal 1: Poison the DNS zone table

```
ironctl> dns spoof-test ironnet.local 10.0.99.1
DNS POISONED: ironnet.local -> 10.0.99.1
```

## Terminal 2: Verify poisoning from external client

```bash
dig @10.0.1.1 ironnet.local
```

Expected output (answer section):
```
;; ANSWER SECTION:
ironnet.local.       60      IN      A       10.0.99.1
```

**The external client now receives the attacker's IP!** Any application that resolves `ironnet.local` via this DNS server will connect to `10.0.99.1` instead of the real `10.0.1.1`.

## Terminal 1: Restore legitimate entry

```
ironctl> dns spoof-test ironnet.local 10.0.1.1
DNS POISONED: ironnet.local -> 10.0.1.1
```

## Terminal 2: Verify restoration

```bash
dig @10.0.1.1 ironnet.local
# Expected: back to 10.0.1.1
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

Note: This sends forged DNS **responses** to the target. In a real attack scenario, the attacker races to respond before the legitimate server. The `dns spoof-test` CLI command demonstrates the poisoning result directly.

## How DNS spoofing works

1. **Normal flow:** Client queries DNS server → server looks up zone table → returns real IP
2. **After poisoning:** Client queries DNS server → server looks up zone table → returns **attacker's IP**
3. **Client connects to fake IP** → traffic goes to attacker instead of real server

In a real network, the attacker would:
- Sniff DNS queries on the wire
- Race to respond before the real DNS server
- Send a forged response with the attacker's IP and matching transaction ID

## What this demonstrates

- **External UDP reaches ironstack** — DNS queries/responses flow through the TAP
- **DNS is inherently insecure** — responses are not authenticated
- **Any network intermediary can forge DNS responses**
- **DNSSEC** adds cryptographic signatures to prevent forgery
- **DNS over HTTPS (DoH)** encrypts queries to prevent interception

## Command reference

| Command | Description |
|---------|-------------|
| `dig @10.0.1.1 <domain>` | External DNS query (proves UDP works) |
| `dns lookup <domain>` | Internal DNS zone table query |
| `dns spoof-test <domain> <ip>` | Poison a zone entry (simulate successful DNS spoof) |
| `ironattack dns-spoof --domain <name> --fake-ip <ip> --target <ip>` | External forged DNS response attack |
