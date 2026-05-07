# Demo 42: Session Hijacking Defense (Phase 22b)

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Three terminal windows

## What this demo shows

- `tcp-strict-window` defense blocks data with wrong sequence number
- `challenge-ack` defense sends ACK back to challenge the sender
- Session hijacking attempt is detected and blocked
- Audit log records the blocked attempt

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

## Part 1: Hijack WITHOUT defense (succeeds — baseline)

### Terminal 2: Open connection

```bash
cd IronNet/build
sudo ip addr add 10.0.1.2/24 dev iron0 2>/dev/null
sudo ip link set iron0 up

nc 10.0.1.1 7
hello
```

### Terminal 1: Check connection and note rcv_nxt

```
ironctl> show tcp
  10.0.1.2:XXXXX -> 10.0.1.1:7  state=ESTABLISHED  snd_nxt=1007 rcv_nxt=1007
```

### Terminal 3: Inject data (use actual port and rcv_nxt from above)

```bash
sudo ./ironattack/ironattack session-hijack \
    --target 10.0.1.1 --port 7 \
    --client 10.0.1.2 --sport XXXXX \
    --seq 1007 --ack 1001 \
    --inject "HIJACKED!"
```

### Terminal 1: Verify — rcv_nxt advanced (hijack succeeded)

```
ironctl> show tcp
  10.0.1.2:XXXXX -> 10.0.1.1:7  state=ESTABLISHED  snd_nxt=1016 rcv_nxt=1016
```

`rcv_nxt` went from 1007 to 1016 (advanced by 9 = "HIJACKED!"). Attack succeeded.

## Part 2: Enable defenses

Close the old connection (Ctrl+C in Terminal 2), then:

```
ironctl> tcp flush
ironctl> defense tcp-strict-window enable
[INFO ] [DEFENSE] Defense 'tcp-strict-window' ENABLED

ironctl> defense challenge-ack enable
[INFO ] [DEFENSE] Defense 'challenge-ack' ENABLED
```

## Part 3: Hijack WITH defense (blocked)

### Terminal 2: Open new connection

```bash
nc 10.0.1.1 7
hello
```

### Terminal 1: Note rcv_nxt

```
ironctl> show tcp
  10.0.1.2:YYYYY -> 10.0.1.1:7  state=ESTABLISHED  snd_nxt=1007 rcv_nxt=1007
```

### Terminal 3: Try injection with WRONG seq (attacker guesses wrong)

```bash
sudo ./ironattack/ironattack session-hijack \
    --target 10.0.1.1 --port 7 \
    --client 10.0.1.2 --sport YYYYY \
    --seq 9999 --ack 1001 \
    --inject "HIJACKED!"
```

### Terminal 1: Defense blocks the injection

```
[WARN ] [TCP] TCP strict window: seq 9999 != rcv_nxt 1007 (possible hijack)
[WARN ] [TCP] Challenge ACK sent to 0A000102:YYYYY
```

```
ironctl> show tcp
  10.0.1.2:YYYYY -> 10.0.1.1:7  state=ESTABLISHED  snd_nxt=1007 rcv_nxt=1007
```

**rcv_nxt is UNCHANGED (still 1007)** — the injection was blocked! The data was not accepted.

### Terminal 3: Try injection with CORRECT seq (attacker knows exact value)

```bash
sudo ./ironattack/ironattack session-hijack \
    --target 10.0.1.1 --port 7 \
    --client 10.0.1.2 --sport YYYYY \
    --seq 1007 --ack 1001 \
    --inject "HIJACKED!"
```

### Terminal 1: Correct seq passes the defense

```
ironctl> show tcp
  10.0.1.2:YYYYY -> 10.0.1.1:7  state=ESTABLISHED  snd_nxt=1016 rcv_nxt=1016
```

With the exact correct seq, the injection still succeeds — `tcp-strict-window` only blocks WRONG seq values. If the attacker knows the exact `rcv_nxt`, the defense doesn't help.

## How the defenses work

**tcp-strict-window:**
```
Data arrives with seq=X for connection with rcv_nxt=Y:
  If X == Y: ACCEPT (legitimate or attacker with exact knowledge)
  If X != Y: DROP + log warning
```

**challenge-ack:**
```
When tcp-strict-window drops a packet:
  Send ACK back to the source with server's current seq/ack
  Legitimate client: receives ACK, adjusts (connection recovers)
  Attacker: doesn't see the ACK (spoofed IP), can't respond
```

## Defense effectiveness

| Scenario | Without defense | With tcp-strict-window |
|----------|----------------|----------------------|
| Attacker guesses wrong seq | Data dropped (wrong seq anyway) | Data dropped + logged + challenge ACK |
| Attacker knows exact seq | Data ACCEPTED | Data ACCEPTED (defense can't help) |
| Attacker guesses within window | Data ACCEPTED (normal TCP allows window) | Data DROPPED (strict = exact match only) |

**Key insight:** `tcp-strict-window` narrows the attack surface from a 65535-byte window to exactly 1 value. The attacker must know the EXACT `rcv_nxt` — guessing within a range no longer works.

## Check audit log

```
ironctl> show audit-log
  [XXXX] TCP_INVALID  10.0.1.2:YYYYY -> 10.0.1.1:7 proto=6 Session hijack blocked (strict window)
```

## Command reference

| Command | Description |
|---------|-------------|
| `defense tcp-strict-window enable` | Only accept data with seq == rcv_nxt |
| `defense tcp-strict-window disable` | Allow normal TCP window tolerance |
| `defense challenge-ack enable` | Send challenge ACK on rejected data |
| `defense challenge-ack disable` | Silently drop without challenge |

## Phase 22 complete

| Sub-phase | Component | Status |
|-----------|-----------|--------|
| 22a | TCP session hijacking attack | ✅ |
| 22b | Session hijacking defense (strict window + challenge ACK) | ✅ |

## Cleanup

```
ironctl> defense tcp-strict-window disable
ironctl> defense challenge-ack disable
ironctl> tcp flush
```
