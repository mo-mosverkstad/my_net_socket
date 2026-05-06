# Demo 26: DNS Cache Poisoning — Persistent Redirection with TTL

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- One terminal window

## What this demo shows

- DNS server caches query results with TTL (Time To Live)
- Attacker can poison the cache with a fake IP and custom TTL
- All subsequent queries return the poisoned answer until TTL expires
- After expiry, the real answer returns automatically

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

## Step 1: Normal DNS lookup (populates cache)

```
ironctl> dns lookup ironnet.local
ironnet.local -> 10.0.1.1

ironctl> dns cache
=== DNS Cache ===
  ironnet.local -> 10.0.1.1 (TTL: 60s)
```

The first lookup hits the zone table and caches the result with a 60-second TTL.

## Step 2: Poison the cache

```
ironctl> dns cache-poison ironnet.local 10.0.99.1 120
DNS CACHE POISONED: ironnet.local -> 10.0.99.1 (TTL=120s)

ironctl> dns cache
=== DNS Cache ===
  ironnet.local -> 10.0.99.1 (TTL: 15s)
```

The cache entry is overwritten with the attacker's IP and a 15-second TTL.

## Step 3: Verify poisoning

```
ironctl> dns lookup ironnet.local
ironnet.local -> 10.0.99.1
```

All lookups now return the poisoned IP — served directly from cache.

## Step 4: Wait for TTL to expire

Wait 15+ seconds, then:

```
ironctl> dns lookup ironnet.local
ironnet.local -> 10.0.1.1
```

The cache entry expired. The lookup falls through to the zone table and returns the real IP.

## Step 5: Inspect and flush cache

```
ironctl> dns cache
=== DNS Cache ===
  ironnet.local -> 10.0.1.1 (TTL: 60s)

ironctl> dns cache-flush
DNS cache flushed.

ironctl> dns cache
=== DNS Cache ===
  (empty)
```

## How DNS cache poisoning works in the real world

1. **Normal operation:** DNS resolver caches responses to reduce latency
2. **Attack:** Attacker sends forged DNS response with:
   - Matching transaction ID (16-bit, guessable)
   - High TTL (e.g., 86400 = 24 hours)
   - Fake IP address
3. **Result:** All clients get the poisoned answer for the duration of the TTL
4. **Persistence:** Unlike zone poisoning (Phase 17a), cache poisoning is temporary — it expires after TTL

## Command reference

| Command | Description |
|---------|-------------|
| `dns lookup <domain>` | Query DNS (checks cache first, then zone table) |
| `dns cache` | Show all cached entries with remaining TTL |
| `dns cache-poison <domain> <ip> <ttl>` | Inject poisoned entry with custom TTL |
| `dns cache-flush` | Clear all cached entries |
| `dns spoof-test <domain> <ip>` | Poison zone table directly (permanent until overwritten) |

## Difference: Zone poisoning vs Cache poisoning

| Aspect | Zone poisoning (17a) | Cache poisoning (17b) |
|--------|---------------------|----------------------|
| Target | Zone table (permanent data) | Cache (temporary data) |
| Duration | Until manually fixed | Until TTL expires |
| Command | `dns spoof-test` | `dns cache-poison` |
| Real-world equivalent | Compromised DNS server | Forged DNS response |
