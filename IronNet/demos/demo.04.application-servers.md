# Demo 04: Application Servers (ironapps) — Echo, DNS, KV, HTTP, RPC

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- `dnsutils` for DNS test: `sudo apt install dnsutils`
- Two terminal windows

## Services running automatically

| Port | Protocol | Service |
|------|----------|---------|
| 7 | TCP/UDP | Echo server |
| 53 | UDP | DNS server |
| 6379 | TCP | KV store |
| 8080 | TCP | HTTP server |
| 9000 | TCP | Binary RPC |

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack ../src/configs/router.conf
```

## Terminal 2: Setup and test all services

```bash
sudo ip addr add 10.0.1.2/24 dev iron0
sudo ip link set iron0 up

# TCP Echo (port 7)
echo "hello ironnet" | nc -w2 10.0.1.1 7
# Expected: hello ironnet

# UDP Echo (port 7)
echo "hello udp" | nc -u -w1 10.0.1.1 7
# Expected: hello udp

# DNS query (port 53)
sudo apt install dnsutils -y
dig @10.0.1.1 ironnet.local
dig @10.0.1.1 server.ironnet.local
dig @10.0.1.1 nonexistent.com   # → NXDOMAIN

# KV Store (port 6379)
echo "SET foo bar" | nc -w2 10.0.1.1 6379
# Expected: +OK
echo "GET foo" | nc -w2 10.0.1.1 6379
# Expected: $bar
echo "DEL foo" | nc -w2 10.0.1.1 6379
# Expected: +OK
echo "GET foo" | nc -w2 10.0.1.1 6379
# Expected: $nil

# HTTP server (port 8080)
echo -e "GET / HTTP/1.0\r\n\r\n" | nc -w2 10.0.1.1 8080
# Expected: HTTP/1.0 200 OK ... Welcome to IronNet!
echo -e "GET /secret HTTP/1.0\r\n\r\n" | nc -w2 10.0.1.1 8080
# Expected: HTTP/1.0 404 Not Found

# Binary RPC (port 9000)
# PING command: magic=IRON(0x49524F4E), cmd=0x0001, len=0x0000
printf '\x49\x52\x4f\x4e\x00\x01\x00\x00' | nc -w2 10.0.1.1 9000 | xxd
# Expected: 49524f4e 8001 0000 (IRON + PONG + len=0)

# ECHO command with payload "hi"
printf '\x49\x52\x4f\x4e\x00\x02\x00\x02hi' | nc -w2 10.0.1.1 9000 | xxd
# Expected: 49524f4e 8002 0002 6869 (IRON + ECHO_REPLY + len=2 + "hi")
```

## Terminal 1: Verify with scanner

```
ironctl> scan 10.0.1.1 1 10000
=== Scan Results for 10.0.1.1 ===
  Open: 5  Filtered: 1  Closed: 9994

  7      OPEN       echo
  22     FILTERED
  53     OPEN       dns
  6379   OPEN       kv-store
  8080   OPEN       http
  9000   OPEN       rpc
```

## DNS zone table

The DNS server has these static entries:
- `example.com` → 93.184.216.34
- `ironnet.local` → 10.0.1.1
- `server.ironnet.local` → 10.0.2.1
- `www.ironnet.local` → 10.0.1.100
