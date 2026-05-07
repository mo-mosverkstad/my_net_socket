# Demo 41: TCP Session Hijacking (Phase 22a)

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Three terminal windows

## What this demo shows

- Inject data into an established TCP connection by spoofing the client's IP
- Server accepts injected data as if it came from the legitimate client
- Echo server echoes back the hijacked data (proving acceptance)
- Connection becomes desynchronized after injection

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

## Terminal 2: Setup network and establish a TCP connection

```bash
cd IronNet/build
sudo ip addr add 10.0.1.2/24 dev iron0 2>/dev/null
sudo ip link set iron0 up

# Connect to echo server INTERACTIVELY (keep connection open!)
nc 10.0.1.1 7
# Type "hello" and press Enter
# You should see "hello" echoed back
# DO NOT close nc — leave this terminal open!
```

> **Important:** Do NOT pipe input (`echo | nc`). That closes the connection immediately. You must keep `nc` running interactively so the connection stays in ESTABLISHED state.

## Terminal 1: Check connection is ESTABLISHED

```
ironctl> show tcp
  10.0.1.2:37704 -> 10.0.1.1:7  state=ESTABLISHED  snd_nxt=1007 rcv_nxt=1007
```

Note the client's source port (e.g., 37704) and the `rcv_nxt` value. The connection MUST show `state=ESTABLISHED` — if it shows `TIME_WAIT`, the connection already closed (too late to hijack).

**Understanding the sequence numbers:**
- `snd_nxt=1007` — server has sent 7 bytes (ISN 1000 + SYN+ACK + 6 echo bytes)
- `rcv_nxt=1007` — server expects byte 1007 next from client (client sent "hello\n" = 6 bytes, so 1001+6=1007)
- **To hijack: use `--seq 1007`** (must match server's `rcv_nxt`)

## Terminal 3: Inject data into the ESTABLISHED session

```bash
cd IronNet/build
sudo ./ironattack/ironattack session-hijack \
    --target 10.0.1.1 --port 7 \
    --client 10.0.1.2 --sport 37704 \
    --seq 1007 --ack 1001 \
    --inject "HIJACKED!"
```

> Replace `37704` with the actual source port shown by `show tcp`.

Expected output:
```
=== TCP Session Hijacking (Phase 22a) ===
  Target server: 10.0.1.1:7
  Spoofed as:    10.0.1.2:54321 (client)
  Sequence:      1007
  Ack:           1001
  Inject:        "HIJACKED!" (9 bytes)
  Iface:         iron0

  Attack: Craft TCP data packet that appears to come from the client.
  If seq matches server's rcv_nxt, data is accepted as legitimate.

  [SENT] Injected 9 bytes as 10.0.1.2:54321 → 10.0.1.1:7 (seq=1007)

  Expected server behavior:
    - If seq matches rcv_nxt: DATA ACCEPTED (hijack successful!)
    - Echo server will echo back "HIJACKED!"
    - Server advances rcv_nxt by 9
    - Client's next real packet (same seq) will be REJECTED (desync)
```

## Terminal 1: Verify injection was accepted

```
ironctl> show tcp
  10.0.1.2:37704 -> 10.0.1.1:7  state=ESTABLISHED  snd_nxt=1016 rcv_nxt=1016
```

**Before hijack:** `rcv_nxt=1007`
**After hijack:** `rcv_nxt=1016` (advanced by 9 = length of "HIJACKED!")

This proves the server accepted the injected data! The echo server also sent back "HIJACKED!" (9 bytes), so `snd_nxt` also advanced.

## How session hijacking works

```
Normal flow:
  Client (seq=1001) ←→ Server (ack expects 1001)
  Client sends "hello\n" (6 bytes) → seq advances to 1007
  Server's rcv_nxt = 1007

Hijack:
  Attacker sends: src=client, seq=1007, payload="HIJACKED!"
  Server checks: seq == rcv_nxt (1007 == 1007)? YES!
  Server accepts data → processes "HIJACKED!" → echoes it back
  Server advances rcv_nxt to 1016

Desynchronization:
  Client's next packet: seq=1007 (client doesn't know about injection)
  Server expects: seq=1016 (already received 1007-1015 from attacker)
  Server rejects client's packet → connection broken for real client
  Attacker has taken over the session!
```

## Simplified demo (without real client)

If you don't want to coordinate with a real `nc` client, you can inject into a half-open connection:

```bash
# Step 1: Create a SYN_RECV connection (single SYN from a fake IP)
sudo ./ironattack/ironattack syn-flood --target 10.0.1.1 --port 7 --count 1 --rate 1

# Step 2: Check the connection in Terminal 1
ironctl> show tcp
# Example output:
#   192.168.45.123:12345 -> 10.0.1.1:7  state=SYN_RECV  snd_nxt=1001 rcv_nxt=1001
#
# Write down: client IP (192.168.45.123), port (12345), rcv_nxt (1001)

# Step 3: Inject data — replace values with ACTUAL numbers from step 2!
# Example (using the values from step 2 above):
sudo ./ironattack/ironattack session-hijack \
    --target 10.0.1.1 --port 7 \
    --client 192.168.45.123 --sport 12345 \
    --seq 1001 --ack 1001 \
    --inject "HIJACKED!"
```

> **Important:** Replace `192.168.45.123`, `12345`, and `1001` with the ACTUAL values shown by `show tcp`. Do NOT type angle brackets like `<port>` — those are placeholders.

Note: Injection into SYN_RECV may not work (server expects ACK to complete handshake first). For best results, use an ESTABLISHED connection (interactive `nc` method above).

## Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| `show tcp` shows TIME_WAIT | Connection already closed | Use interactive `nc` (don't pipe input) |
| `show tcp` shows no connection | `nc` hasn't connected yet | Wait for `nc` to connect, then check |
| Injection not accepted | Wrong seq number | Use exact `rcv_nxt` value from `show tcp` |
| No echo response visible | Echo goes to client (nc), not attacker | Check Terminal 2 — `nc` may show the echoed hijacked data |

## Key differences from RST injection

| Aspect | RST Injection (Phase 13c) | Session Hijacking (Phase 22a) |
|--------|--------------------------|-------------------------------|
| Goal | Kill the connection | Take over the connection |
| Packet type | RST flag | ACK+PSH with data payload |
| Effect | Connection torn down | Attacker's data processed by server |
| Aftermath | Connection closed | Connection desynchronized (attacker controls) |
| Difficulty | Easier (just need seq in window) | Harder (need exact rcv_nxt) |

## Command reference

| Command | Description |
|---------|-------------|
| `session-hijack --target <ip> --port <port> --client <ip> --sport <port> --seq <n> --ack <n> --inject <text>` | Full hijack |
| `--seq 1001 --ack 1001` | Default values (right after handshake) |

## Notes

- IronNet uses predictable ISN (1000) — makes hijacking trivial for demonstration
- Real systems use random ISNs (32-bit) — attacker must sniff or predict
- The attacker needs to know: client IP, client port, current seq number
- In practice, MITM position (Phase 16) provides all needed information
- Phase 22b will implement defenses (challenge ACK, strict window)
