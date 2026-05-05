# Demo 11: TCP RST Injection Attack + Defense (RST Validation)

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Three terminal windows

## What this demo shows

- TCP RST injection sends forged RST packets to tear down an established connection
- RST validation defense only accepts RST if the sequence number matches the expected value

## Network Topology

```
Terminal 3 (client)  ──nc──→  IronNet Router (Terminal 1)
Terminal 2 (attacker) ──RST──→  (forged RST to kill connection)
```

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

## Part 1: RST Injection WITHOUT defense

### Terminal 3: Establish a TCP connection to echo server

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up
nc 10.0.1.1 7
hello
# Connection is now ESTABLISHED — keep this terminal open
```

### Terminal 1: Note the source port

```
ironctl> show tcp
[INFO ] [TCP] --- TCP Connections (1 active) ---
[INFO ] [TCP]   10.0.1.2:40408 -> 10.0.1.1:7  state=ESTABLISHED
```

Note the source port (e.g., **40408**) — you need this for the RST injection.

### Terminal 2: Inject forged RST

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up

# Use the source port from 'show tcp' above
sudo ./ironattack/ironattack rst-inject --target 10.0.1.1 --port 7 --src 10.0.1.2 --sport 40408 --seq 1000 --count 10
```

Output:
```
=== TCP RST Injection ===
  Target:  10.0.1.1:7
  Spoof:   10.0.1.2:40408
  Seq:     1000
  Count:   10

  Sent: 10 RST packets
```

### Terminal 1: Connection killed

```
[DEBUG] [TCP] RST received, closing connection

ironctl> show tcp
[INFO ] [TCP] --- TCP Connections (0 active) ---
```

Terminal 3's `nc` connection is now dead.

## Part 2: RST Injection WITH RST validation defense

### Terminal 3: Re-establish connection

```bash
nc 10.0.1.1 7
hello
```

### Terminal 1: Note new source port, then enable defense

```
ironctl> show tcp
# Note the new source port (e.g., 52100)

ironctl> defense rst-validation enable
[INFO ] [DEFENSE] Defense 'rst-validation' ENABLED
```

### Terminal 2: Inject RST with wrong sequence number

```bash
# Use the new source port, but a wrong seq number
sudo ./ironattack/ironattack rst-inject --target 10.0.1.1 --port 7 --src 10.0.1.2 --sport 52100 --seq 9999 --count 10
```

### Terminal 1: RSTs rejected — connection survives

```
[DEBUG] [TCP] RST validation: rejected (seq=9999, expected=102)
[DEBUG] [TCP] RST validation: rejected (seq=10000, expected=102)
...

ironctl> show tcp
# Connection still ESTABLISHED!
```

Terminal 3's `nc` connection is still alive.

## How RST validation works

Without defense: any RST matching the 4-tuple closes the connection immediately.

With `defense rst-validation enable`:
1. RST arrives for an existing connection
2. Check: RST sequence number == connection's `rcv_nxt`?
3. If yes: legitimate RST, close connection
4. If no: forged RST (attacker guessed wrong seq), silently drop

This prevents blind RST injection where the attacker doesn't know the exact sequence number.

## Key point

The `--sport` must match the **actual source port** shown in `show tcp`. If the port doesn't match, the RST is ignored (no matching connection). Always check `show tcp` first.

## Cleanup

```
ironctl> tcp flush
ironctl> defense rst-validation disable
```
