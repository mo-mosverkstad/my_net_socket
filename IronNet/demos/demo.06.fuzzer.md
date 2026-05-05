# Demo 06: Protocol Fuzzer (ironfuzz) — Mutation-Based Testing

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- One terminal window

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack ../src/configs/router.conf
```

## Terminal 1: Run fuzzer from CLI

### Fuzz TCP protocol

```
ironctl> fuzz tcp 1000
[INFO ] [FUZZ] Fuzzing started: 1000 iterations, 1 seeds
[INFO ] [FUZZ] Fuzzing complete: 1000 iterations, 0 crashes
=== Fuzzer Statistics ===
  Iterations:   1000
  Crashes:      0
  Mutations:    1000
  Corpus size:  1 seeds
```

### Fuzz DNS protocol

```
ironctl> fuzz dns 500
[INFO ] [FUZZ] Fuzzing complete: 500 iterations, 0 crashes
```

### Fuzz HTTP protocol

```
ironctl> fuzz http 500
[INFO ] [FUZZ] Fuzzing complete: 500 iterations, 0 crashes
```

### Fuzz RPC protocol

```
ironctl> fuzz rpc 500
[INFO ] [FUZZ] Fuzzing complete: 500 iterations, 0 crashes
```

## Mutation strategies (8 total)

| Strategy | What it does |
|----------|-------------|
| BIT_FLIP | Flip a random bit |
| BYTE_FLIP | Replace a random byte with random value |
| TRUNCATE | Shorten the packet |
| EXTEND | Append random bytes |
| BOUNDARY | Insert boundary values (0x0000, 0xFFFF, 0x7FFF, 0x8000) |
| INSERT | Insert 1-4 random bytes at random position |
| DELETE | Remove 1-4 bytes from random position |
| FIELD_AWARE | Mutate specific protocol fields (TTL, flags, length, ports) |

Each iteration applies 1-3 random mutations to a seed packet.

## Pre-built seeds

| Seed | Protocol | Content |
|------|----------|---------|
| tcp_syn | TCP | SYN to port 7, seq=1000 |
| dns_query | DNS/UDP | A record query for "ironnet.local" |
| http_get | HTTP/TCP | "GET / HTTP/1.0\r\n\r\n" |
| rpc_ping | RPC/TCP | Magic "IRON" + CMD PING + len 0 |

## What to look for

- `Crashes: 0` — no memory errors (ASAN would catch any)
- If crashes > 0 — ASAN report printed, crash input saved for reproduction
