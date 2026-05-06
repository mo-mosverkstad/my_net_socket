# Demo 30: External DNS Cache Poisoning (dns-spoof-ext)

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- `dnsutils` installed: `sudo apt install dnsutils`
- Two terminal windows

## What this demo shows

- External DNS cache poisoning via raw socket (Kaminsky-style attack)
- Forged DNS responses traverse the TAP and poison ironstack's cache
- The `dns-validate` defense blocks the external attack
- Full attack path: attacker → raw UDP → kernel → TAP → ironstack DNS server → cache poisoned

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

## Terminal 2: Setup network and verify DNS works

```bash
cd IronNet/build
sudo ip addr add 10.0.1.2/24 dev iron0 2>/dev/null
sudo ip link set iron0 up

# Verify DNS works
dig @10.0.1.1 ironnet.local +short
# Expected: 10.0.1.1
```

## Part 1: Attack WITHOUT defense (cache poisoned)

### Terminal 2: Launch external DNS poisoning attack

```bash
sudo ./ironattack/ironattack dns-spoof-ext \
    --domain ironnet.local --fake-ip 10.0.99.1 \
    --target 10.0.1.1 --iface iron0 --count 50
```

Expected output:
```
=== External DNS Cache Poisoning (Phase 17d) ===
  Domain:  ironnet.local
  Fake IP: 10.0.99.1
  Target:  10.0.1.1 (DNS server)
  Iface:   iron0
  Count:   50
  Method:  Flood forged DNS responses (Kaminsky-style)
           Spoofing source as upstream DNS (8.8.8.8)

  Sent: 50 forged DNS responses
  Payload: ironnet.local -> 10.0.99.1 (TTL=300s)
```

### Terminal 1: Verify cache is poisoned

```
ironctl> dns cache
=== DNS Cache ===
  ironnet.local -> 10.0.99.1 (TTL: 298s)
```

The cache is poisoned! Any client querying this DNS server will now get the attacker's IP.

### Terminal 2: Verify from external client

```bash
dig @10.0.1.1 ironnet.local +short
# Expected: 10.0.99.1 (poisoned!)
```

## Part 2: Enable defense and retry

### Terminal 1: Flush cache and enable dns-validate

```
ironctl> dns cache-flush
DNS cache flushed.

ironctl> defense dns-validate enable
[INFO ] [DEFENSE] Defense 'dns-validate' ENABLED
```

### Terminal 2: Repeat the attack

```bash
sudo ./ironattack/ironattack dns-spoof-ext \
    --domain ironnet.local --fake-ip 10.0.99.1 \
    --target 10.0.1.1 --iface iron0 --count 50
```

### Terminal 1: Verify cache is NOT poisoned

```
ironctl> dns cache
=== DNS Cache ===
  (empty)
```

The defense blocked all 50 poisoning attempts! Check the audit log:

```
ironctl> show audit-log
  [XXXX] ACL_DENY   10.0.99.1:0 -> 10.0.1.1:53 proto=17 DNS cache poison blocked
```

### Terminal 2: Verify legitimate queries still work

```bash
dig @10.0.1.1 ironnet.local +short
# Expected: 10.0.1.1 (correct, from zone table)
```

## How the attack works

```
Attacker (10.0.1.2)              ironstack DNS server (10.0.1.1)
   |                                     |
   |-- Forged UDP packet --------------->|
   |   IP src: 8.8.8.8 (spoofed)        |
   |   IP dst: 10.0.1.1                 |
   |   UDP src: 53, dst: 53             |
   |   DNS: QR=1 (response)             |
   |   Answer: ironnet.local -> 10.0.99.1|
   |                                     |
   |                                     |-- Checks QR=1 flag
   |                                     |-- Parses answer section
   |                                     |-- Calls dns_cache_add_secure()
   |                                     |-- WITHOUT defense: cached!
   |                                     |-- WITH defense: BLOCKED!
```

## How dns-validate blocks it

1. Forged response arrives with `ironnet.local -> 10.0.99.1`
2. `dns_cache_add_secure()` checks: is `dns-validate` enabled?
3. Looks up `ironnet.local` in the authoritative zone table → real IP is `10.0.1.1`
4. `10.0.99.1 != 10.0.1.1` → **BLOCKED**, audit event logged
5. Cache remains clean

## Real-world parallels

| IronNet concept | Real-world equivalent |
|-----------------|----------------------|
| Flood with random txn IDs | Kaminsky attack (2008) |
| Source spoofed as 8.8.8.8 | Attacker impersonates upstream resolver |
| `dns-validate` defense | DNSSEC signature verification |
| Zone table = trusted source | DNSSEC chain of trust |

## Command reference

| Command | Description |
|---------|-------------|
| `ironattack dns-spoof-ext --domain <d> --fake-ip <ip> --target <ip>` | External cache poisoning attack |
| `ironattack dns-spoof-ext ... --count <n>` | Number of forged responses |
| `defense dns-validate enable` | Block poisoning (validates against zone) |
| `dns cache-flush` | Clear DNS cache |
| `dns cache` | Show cached entries |

## Cleanup

```
ironctl> defense dns-validate disable
ironctl> dns cache-flush
```
