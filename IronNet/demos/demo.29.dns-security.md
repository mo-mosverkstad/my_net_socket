# Demo 27: DNS Security (dns-validate) — Blocking Cache Poisoning

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- One terminal window

## What this demo shows

- DNS cache poisoning succeeds without defense
- With `dns-validate` enabled, poisoning attempts are blocked
- The defense validates cache entries against the authoritative zone table

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

## Part 1: Poisoning WITHOUT defense (attack succeeds)

```
ironctl> dns lookup ironnet.local
ironnet.local -> 10.0.1.1

ironctl> dns cache-poison ironnet.local 10.0.99.1 60
DNS CACHE POISONED: ironnet.local -> 10.0.99.1 (TTL=60s)

ironctl> dns lookup ironnet.local
ironnet.local -> 10.0.99.1
```

The cache is poisoned — all lookups return the attacker's IP.

## Part 2: Enable DNS validation defense

```
ironctl> dns cache-flush
DNS cache flushed.

ironctl> defense dns-validate enable
[INFO ] [DEFENSE] Defense 'dns-validate' ENABLED
```

## Part 3: Poisoning WITH defense (attack blocked)

```
ironctl> dns cache-poison ironnet.local 10.0.99.1 60
[DNS SECURITY] Cache poison BLOCKED: ironnet.local -> 10.0.99.1 (real: 10.0.1.1)

ironctl> dns lookup ironnet.local
ironnet.local -> 10.0.1.1
```

The poisoning attempt is blocked! The defense checked the zone table and found that `ironnet.local` should resolve to `10.0.1.1`, not `10.0.99.1`.

## Part 4: Verify audit log

```
ironctl> show audit-log
  [XXXX] ACL_DENY   10.0.99.1:0 -> 10.0.1.1:53 proto=17 DNS cache poison blocked
```

## How dns-validate works

1. When `dns cache-poison` (or any external cache injection) is attempted:
2. `dns_cache_add_secure()` checks: does this domain exist in the zone table?
3. If yes: compare the attempted IP with the zone table's authoritative IP
4. If they **don't match** → BLOCK the cache entry, log audit event
5. If they **match** (or domain not in zone table) → allow

This simulates the principle of DNSSEC: responses are validated against a trusted source before being accepted.

## Real-world equivalents

| IronNet defense | Real-world equivalent |
|-----------------|----------------------|
| `dns-validate` | DNSSEC signature verification |
| Zone table = trusted source | DNSSEC chain of trust (root → TLD → domain) |
| Blocked = signature mismatch | DNSSEC SERVFAIL on invalid signature |

## Command reference

| Command | Description |
|---------|-------------|
| `defense dns-validate enable` | Enable DNS cache validation |
| `defense dns-validate disable` | Disable DNS cache validation |
| `dns cache-poison <domain> <ip> <ttl>` | Attempt cache poisoning (blocked if defense enabled) |
| `dns cache` | Show cached entries |
| `dns cache-flush` | Clear cache |
| `dns lookup <domain>` | Query DNS |

## Cleanup

```
ironctl> defense dns-validate disable
ironctl> dns cache-flush
```
