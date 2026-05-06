# Demo 35: Timing-Based Covert Channels (Phase 19b)

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Two terminal windows

## What this demo shows

- Three timing/steganographic covert channels that hide data without modifying payload content
- Timing channel: bits encoded as inter-packet delays (100ms=1, 10ms=0)
- Packet counting channel: bits encoded as burst size per time window
- IP ID channel: 2 bytes per packet hidden in the IP Identification field
- All channels are invisible to payload inspection (no suspicious content)

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

## Terminal 2: Setup network

```bash
cd IronNet/build
sudo ip addr add 10.0.1.2/24 dev iron0 2>/dev/null
sudo ip link set iron0 up
```

## Channel 4: Timing (inter-packet delay encoding)

Each bit is encoded as a delay before sending a ping packet:
- Bit 1 = 100ms delay
- Bit 0 = 10ms delay

```bash
sudo ./ironattack/ironattack covert --target 10.0.1.1 --mode timing --message "Hi"
```

Expected output:
```
=== Covert Channel Tool (Phase 19a/19b) ===
  Target:  10.0.1.1
  Mode:    timing
  Message: "Hi" (2 bytes)
  Iface:   iron0

  [Timing Covert Channel]
  Encoding 2 bytes (16 bits) via inter-packet delays
  Bit 1 = 100ms delay, Bit 0 = 10ms delay
  Estimated time: 0.9 seconds
  Bandwidth: ~18 bits/second

  Byte 'H' (0x48): bits 01001000
  Byte 'i' (0x69): bits 01101001

  Sent: 16 packets (16 bits encoded)
  To decode: measure inter-packet gaps (>50ms = 1, <50ms = 0)
```

**Why it's covert:** An observer sees normal ping packets at irregular intervals. The timing pattern is the message — no payload inspection reveals anything.

## Channel 5: Packet counting (burst size encoding)

Each bit is encoded as the number of packets in a 200ms window:
- Bit 0 = 2 packets in window
- Bit 1 = 7 packets in window

```bash
sudo ./ironattack/ironattack covert --target 10.0.1.1 --mode counting --message "AB"
```

Expected output:
```
=== Covert Channel Tool (Phase 19a/19b) ===
  Target:  10.0.1.1
  Mode:    counting
  Message: "AB" (2 bytes)
  Iface:   iron0

  [Packet Counting Covert Channel]
  Encoding 2 bytes (16 bits) via packet count per window
  Bit 0 = 2 packets/window, Bit 1 = 7 packets/window
  Window: 200ms, Bandwidth: ~5 bits/second

  Byte 'A' (0x41): 0(2) 1(7) 0(2) 0(2) 0(2) 0(2) 0(2) 1(7)
  Byte 'B' (0x42): 0(2) 1(7) 0(2) 0(2) 0(2) 0(2) 1(7) 0(2)

  Sent: 72 total packets (16 bits encoded)
  To decode: count packets per 200ms window (<=4 = 0, >=5 = 1)
```

**Why it's covert:** An observer sees bursts of pings — some short, some long. Without knowing the encoding scheme, the pattern looks like normal variable-rate traffic.

## Channel 6: IP ID field (storage channel)

The IP Identification field (16 bits) is used for fragment reassembly but is often ignored. We encode 2 bytes of message per packet.

```bash
sudo ./ironattack/ironattack covert --target 10.0.1.1 --mode ipid --message "SECRET"
```

Expected output:
```
=== Covert Channel Tool (Phase 19a/19b) ===
  Target:  10.0.1.1
  Mode:    ipid
  Message: "SECRET" (6 bytes)
  Iface:   iron0

  [IP ID Covert Channel]
  Encoding 6 bytes across 3 packets (2 bytes/pkt in IP ID field)

  Pkt #1: IP_ID=0x4553 (bytes: "SE")
  Pkt #2: IP_ID=0x4543 (bytes: "CR")
  Pkt #3: IP_ID=0x5445 (bytes: "ET")

  Sent: 3 packets (6 bytes hidden in IP ID fields)
  To decode: capture packets, extract IP ID field (bytes 4-5), concatenate
```

**Why it's covert:** IP ID values are supposed to be unique per packet (for fragment reassembly) but their actual values are arbitrary. Encoded data looks like normal sequential or random IDs.

## Channel comparison (Phase 19a + 19b)

| Channel | Type | Bandwidth | Stealth | Detection |
|---------|------|-----------|---------|-----------|
| ICMP payload | Storage | High (msg/pkt) | Medium | Entropy analysis |
| TCP ISN | Storage | 4 bytes/pkt | High | Statistical ISN analysis |
| DNS subdomain | Storage | 63 bytes/query | Medium | Label entropy |
| **Timing** | **Timing** | **~18 bps** | **Very high** | **Timing analysis** |
| **Counting** | **Timing** | **~5 bps** | **Very high** | **Rate analysis** |
| **IP ID** | **Storage** | **2 bytes/pkt** | **High** | **ID pattern analysis** |

## Key differences: storage vs timing channels

| Aspect | Storage channels (19a) | Timing channels (19b) |
|--------|----------------------|---------------------|
| Where data hides | In packet fields/payload | In packet timing/count |
| Payload inspection | May reveal data | Reveals nothing |
| Bandwidth | Higher | Lower |
| Detection | Content analysis | Statistical analysis |
| Examples | ICMP payload, ISN, DNS, IP ID | Inter-packet delay, burst count |

## Command reference

| Command | Description |
|---------|-------------|
| `covert --mode timing --message <text>` | Encode via inter-packet delays |
| `covert --mode counting --message <text>` | Encode via packet burst count |
| `covert --mode ipid --message <text>` | Encode in IP Identification field |

## Notes

- Timing channel is slow (~18 bps) but extremely stealthy — no payload modification
- Counting channel is even slower (~5 bps) but harder to detect than timing
- IP ID channel is fast (2 bytes/pkt) but detectable via ID pattern analysis
- All channels require `sudo` (raw socket access)
- Phase 19c will add detection mechanisms for these channels
