# Demo 36: Covert Channel Detection (Phase 19c)

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Two terminal windows

## What this demo shows

- `defense covert-detect enable` activates anomaly detection for all covert channels
- ICMP payload entropy analysis flags hidden data
- Timing bimodality detection flags timing channels
- TCP ISN ASCII ratio analysis flags ISN-encoded data
- DNS label entropy analysis flags base64 exfiltration
- All detections logged to audit log

## Terminal 1: Start the router with detection enabled

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

Then enable detection:
```
ironctl> defense covert-detect enable
[INFO ] [DEFENSE] Defense 'covert-detect' ENABLED
```

## Terminal 2: Setup network

```bash
cd IronNet/build
sudo ip addr add 10.0.1.2/24 dev iron0 2>/dev/null
sudo ip link set iron0 up
```

## Detection 1: ICMP payload entropy

Normal pings have payload entropy ~5.3 (timestamp + incrementing pattern). Hidden binary/encrypted data has entropy > 6.0.

```bash
# Send covert ICMP with high-entropy binary data (random bytes as message)
sudo ./ironattack/ironattack covert --target 10.0.1.1 --mode icmp --message "$(head -c 32 /dev/urandom | base64)"
```

**Terminal 1 shows:**
```
[WARN ] [COVERT] ICMP payload entropy 6.15 (threshold 6.0) — possible covert channel
```

**Normal ping does NOT trigger (no false positive):**
```bash
ping -c 3 10.0.1.1
# → No detection alert (normal ping entropy ~5.3, below threshold 6.0)
```

## Detection 2: Timing bimodality

Normal traffic has variable timing. Timing channels show bimodal distribution (two distinct delay clusters).

```bash
# Send timing-encoded message (needs 32+ bits to trigger detection)
sudo ./ironattack/ironattack covert --target 10.0.1.1 --mode timing --message "ABCD"
```

**Terminal 1 shows (after 32 packets):**
```
[WARN ] [COVERT] Timing bimodal: 15 low + 12 high / 32 (ratio 0.84) — possible timing channel
```

## Detection 3: TCP ISN analysis

Normal ISNs are random (low ASCII ratio). ISN-encoded text has high ASCII byte ratio.

```bash
# Send ISN-encoded message (needs 16 SYNs to trigger)
sudo ./ironattack/ironattack covert --target 10.0.1.1 --mode isn --message "HELLO WORLD SECRET MESSAGE!!"
```

**Terminal 1 shows (after 16 SYNs):**
```
[WARN ] [COVERT] TCP ISN ASCII ratio 0.78 (50/64) — possible ISN covert channel
```

## Detection 4: DNS label entropy

Normal DNS queries have low-entropy labels (english words). Base64-encoded data has high entropy.

```bash
# Send DNS covert message
sudo ./ironattack/ironattack covert --target 10.0.1.1 --mode dns --message "top secret message"
```

**Terminal 1 shows:**
```
[WARN ] [COVERT] DNS label entropy 4.58 (len=24) for 'dG9wIHNlY3JldCBtZXNzYWdl.covert.ironnet.local' — possible DNS exfiltration
```

## Verify audit log

```
ironctl> show audit-log
  [XXXX] COVERT   10.0.1.2:0 -> 10.0.1.1:0 proto=1 ICMP high entropy payload
  [XXXX] COVERT   10.0.1.2:0 -> 10.0.1.1:0 proto=1 Bimodal timing pattern
  [XXXX] COVERT   10.0.1.2:0 -> 10.0.1.1:0 proto=6 TCP ISN high ASCII ratio
  [XXXX] COVERT   10.0.1.2:0 -> 10.0.1.1:53 proto=17 DNS high entropy label
```

## Detection thresholds

| Detector | Metric | Threshold | Normal value | Covert value |
|----------|--------|-----------|--------------|--------------|
| ICMP entropy | Shannon entropy of payload | > 6.0 bits | ~5.3 (timestamp+pattern) | 6.5-7.5 (random/binary) |
| Timing bimodal | % of gaps in two clusters | > 70% | ~30% (variable) | >80% (10ms/100ms) |
| TCP ISN ASCII | % of printable bytes in ISNs | > 65% | ~37% (random) | >70% (encoded text) |
| DNS label entropy | Shannon entropy of first label | > 3.5 bits | 2-3 (english words) | 4-5 (base64) |

## Normal traffic (no false positives)

```bash
# Normal ping (entropy ~5.3 — below threshold 6.0)
ping -c 5 10.0.1.1
# → No detection alert

# Normal DNS query (low entropy label "ironnet" ~2.8)
dig @10.0.1.1 ironnet.local
# → No detection alert
```

## Phase 19 complete

All 3 sub-phases of Phase 19 are now done:

| Sub-phase | Component | Status |
|-----------|-----------|--------|
| 19a | Data hiding (ICMP, ISN, DNS) | ✅ |
| 19b | Timing channels (delay, counting, IP ID) | ✅ |
| 19c | Covert channel detection (entropy, timing, ISN, DNS) | ✅ |

## Command reference

| Command | Description |
|---------|-------------|
| `defense covert-detect enable` | Enable all covert channel detectors |
| `defense covert-detect disable` | Disable detection |
| `show audit-log` | View detection alerts |

## Notes

- Detection requires `covert-detect` defense to be enabled
- ICMP detection triggers per-packet (immediate)
- Timing detection requires 32 packets to build history (delayed)
- ISN detection requires 16 SYN packets to build history (delayed)
- DNS detection triggers per-query (immediate)
- 12 defenses now registered (added covert-detect)
