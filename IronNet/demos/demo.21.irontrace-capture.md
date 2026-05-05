# Demo 21: Packet Capture (irontrace) — pcap File Output

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- tcpdump installed: `sudo apt install tcpdump`
- Two terminal windows
- Optional: Wireshark on Windows for GUI pcap viewing

## What this demo shows

- Capture packets at L2/L3/L4 pipeline boundaries to a pcap file
- View captured packets using tcpdump
- Open pcap files in Wireshark for detailed analysis
- Selective capture by layer (L2 only, L3 only, etc.)

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack ../src/configs/router.conf
```

## Terminal 1: Start packet capture

```
ironctl> trace start /tmp/capture.pcap all
[INFO ] [TRACE] Trace started: /tmp/capture.pcap (layers: L2 L3 L4)

ironctl> trace status
  Trace: ACTIVE
  File:  /tmp/capture.pcap
  Layers: L2 L3 L4
  Packets: 0
```

## Terminal 2: Generate traffic

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up

# ICMP ping (generates L2 + L3 packets)
ping -c 5 10.0.1.1

# TCP connection to echo server (generates L2 + L3 + L4 packets)
echo "hello trace" | nc -w2 10.0.1.1 7
```

## Terminal 1: Stop capture and check status

```
ironctl> trace status
  Trace: ACTIVE
  File:  /tmp/capture.pcap
  Layers: L2 L3 L4
  Packets: 25

ironctl> trace stop
[INFO ] [TRACE] Trace stopped: 25 packets captured to /tmp/capture.pcap
```

## Terminal 2: View captured packets with tcpdump

### Show all packets (summary)

```bash
sudo tcpdump -r /tmp/capture.pcap -n
```

Expected output:
```
reading from file /tmp/capture.pcap, link-type EN10MB (Ethernet)
12:34:56.789012 IP 10.0.1.2 > 10.0.1.1: ICMP echo request, id 1234, seq 1, length 64
12:34:56.789123 IP 10.0.1.1 > 10.0.1.2: ICMP echo reply, id 1234, seq 1, length 64
12:34:57.790012 IP 10.0.1.2 > 10.0.1.1: ICMP echo request, id 1234, seq 2, length 64
...
12:35:01.123456 IP 10.0.1.2.54321 > 10.0.1.1.7: Flags [S], seq 1000, win 65535
12:35:01.123567 IP 10.0.1.1.7 > 10.0.1.2.54321: Flags [S.], seq 1001, ack 1001
...
```

### Show packets with full hex dump

```bash
sudo tcpdump -r /tmp/capture.pcap -XX -n
```

### Show only ICMP packets

```bash
sudo tcpdump -r /tmp/capture.pcap -n icmp
```

### Show only TCP packets

```bash
sudo tcpdump -r /tmp/capture.pcap -n tcp
```

### Show only packets to/from a specific port

```bash
sudo tcpdump -r /tmp/capture.pcap -n port 7
```

### Show packet count and file info

```bash
sudo tcpdump -r /tmp/capture.pcap -n | wc -l
```

## Selective capture by layer

### Capture L3 only (IP packets without Ethernet header)

```
ironctl> trace start /tmp/l3only.pcap l3
```

Note: L3-only capture uses pcap linktype=101 (Raw IP). tcpdump handles this automatically.

### Capture L2 only (full Ethernet frames)

```
ironctl> trace start /tmp/l2only.pcap l2
```

### Capture L4 only (TCP/UDP segments)

```
ironctl> trace start /tmp/l4only.pcap l4
```

## Open in Wireshark (Windows)

The pcap file is in standard libpcap format. To view in Wireshark:

```bash
# Copy from WSL to Windows
cp /tmp/capture.pcap /mnt/c/Users/$USER/Desktop/capture.pcap
```

Then double-click `capture.pcap` on your Windows Desktop — Wireshark opens it automatically.

In Wireshark you can:
- Filter by protocol: `icmp`, `tcp`, `dns`
- Filter by IP: `ip.addr == 10.0.1.1`
- Filter by port: `tcp.port == 7`
- Follow TCP stream: right-click → Follow → TCP Stream
- See full packet decode with all protocol layers

## Capture during attack testing

### Capture while running SYN flood

```
ironctl> trace start /tmp/synflood.pcap l3
```

Terminal 2:
```bash
sudo ./ironattack/ironattack syn-flood --target 10.0.1.1 --port 7 --rate 100 --count 50
```

Terminal 1:
```
ironctl> trace stop
```

View the flood:
```bash
sudo tcpdump -r /tmp/synflood.pcap -n tcp | head -20
# Shows many SYN packets from random source IPs
```

## pcap file format

The captured file uses standard libpcap format:
- **Global header** (24 bytes): magic=0xA1B2C3D4, version=2.4, snaplen=65535
- **Linktype**: 1 (Ethernet) for L2 captures, 101 (Raw IP) for L3/L4 captures
- **Per-packet header** (16 bytes): timestamp (sec + usec), captured length, original length
- **Packet data**: raw bytes as seen at the hook point

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Trace: INACTIVE" after start | Check file path is writable (`/tmp/` always works) |
| 0 packets captured | Generate traffic AFTER starting trace |
| tcpdump shows "bad dump file format" | Ensure trace was stopped cleanly before reading |
| Wireshark can't open | Verify file was copied in binary mode |
| Only seeing RX, no TX | TX hooks capture outbound packets (ping replies, SYN+ACK) |

## Cleanup

```
ironctl> trace stop
rm /tmp/capture.pcap
```
