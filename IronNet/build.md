# IronNet — Build & Test Guide

## Prerequisites

- **WSL 2** with Ubuntu 22.04+ installed
- **GCC 12+** or **Clang 15+**
- **CMake 3.20+**
- **Make**

### Install dependencies (Ubuntu)

```bash
sudo apt update
sudo apt install -y build-essential cmake
```

---

## Project Layout

```
IronNet/
├── src/           # Source code
├── build/         # Build output (out-of-source)
├── ideas.md
├── study.md
├── build.md       # This file
└── todo.md
```

---

## Build

### Debug Build (default, with AddressSanitizer)

```bash
cd IronNet
mkdir -p build && cd build
cmake ../src -DCMAKE_BUILD_TYPE=Debug
make
```

### Release Build (optimized, no ASAN)

```bash
cd IronNet
mkdir -p build-release && cd build-release
cmake ../src -DCMAKE_BUILD_TYPE=Release
make
```

---

## Run

### Start the ironstack daemon (no config)

```bash
cd IronNet/build
./ironstack/ironstack
```

### Start as virtual router (with config file)

```bash
cd IronNet/build
sudo ./ironstack/ironstack ../src/configs/router.conf
```

### Enable debug logging

```bash
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

The `-d` flag shows all packet processing (ARP, IP, ACL, ICMP) at DEBUG level.

Press `Ctrl+C` to stop. On shutdown it prints collected statistics.

See `DEMO.md` for a full walkthrough with two terminals.

---

## Run Tests

### Run all tests via CTest (unit + module)

```bash
cd IronNet/build
ctest --output-on-failure
```

### Run unit tests directly

Unit tests are fast, minimal-output correctness checks:

```bash
cd IronNet/build
./tests/test_stats
./tests/test_eth
```

### Run module tests directly

Module tests produce verbose, visible output (hex dumps, decoded fields, formatted results):

```bash
cd IronNet/build
./tests/test_l2_module
./tests/test_l3_module
./tests/test_pbr_acl_module
./tests/test_l4_module
./tests/test_ipsec_module
```

Example output:
```
=== IronNet L2 Module Test — Ethernet Frame Visibility ===

[1] Built frame with text payload:
  Raw frame hex:
    FF FF FF FF FF FF 02 00 00 00 00 01 08 00 48 65
    6C 6C 6F 20 49 72 6F 6E 4E 65 74 21
--- Ethernet Frame ---
  Dst MAC: FF:FF:FF:FF:FF:FF
  Src MAC: 02:00:00:00:00:01
  EtherType: 0x0800
  Total length: 28 bytes
  Payload length: 14 bytes
  Payload hex:
    48 65 6C 6C 6F 20 49 72 6F 6E 4E 65 74 21
  Payload ASCII: Hello IronNet!

[2] Built frame with simulated IPv4+TCP SYN:
  Raw frame hex:
    02 00 00 00 00 02 02 00 00 00 00 01 08 00 45 00
    00 28 00 01 00 00 40 06 00 00 0A 00 01 01 0A 00
    02 01 04 D2 00 50 00 00 00 01 00 00 00 00 50 02
    FF FF 00 00 00 00
--- Ethernet Frame ---
  Dst MAC: 02:00:00:00:00:02
  Src MAC: 02:00:00:00:00:01
  EtherType: 0x0800
  Total length: 54 bytes
  Payload length: 40 bytes
  Payload hex:
    45 00 00 28 00 01 00 00 40 06 00 00 0A 00 01 01
    0A 00 02 01 04 D2 00 50 00 00 00 01 00 00 00 00
    50 02 FF FF 00 00 00 00
  Payload ASCII: E..(....@..............P........P.......

  --- Decoded IP header ---
    Version: 4
    IHL: 5
    TTL: 64
    Protocol: 6 (TCP=6)
    Src IP: 10.0.1.1
    Dst IP: 10.0.2.1
    Src Port: 1234
    Dst Port: 80

[3] Parsing invalid frame (8 bytes, too short):
  Result: DROPPED (rc=-1)
  Drop counter: 1

=== Summary: 3 passed, 0 failed, 3 total ===
```

---

## Quick One-Liner (build + test)

```bash
cd IronNet && mkdir -p build && cd build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make && ctest --output-on-failure

../src/tests/run_module_tests.sh .

```

---

## Build Outputs

| Binary | Location | Type | Description |
|--------|----------|------|-------------|
| ironstack | `build/ironstack/ironstack` | Daemon | Protocol stack daemon |
| test_stats | `build/tests/test_stats` | Unit test | Stats module correctness |
| test_eth | `build/tests/test_eth` | Unit test | L2 Ethernet parsing correctness |
| test_route | `build/tests/test_route` | Unit test | L3 routing table correctness |
| test_acl | `build/tests/test_acl` | Unit test | ACL engine correctness |
| test_tcp | `build/tests/test_tcp` | Unit test | TCP state machine correctness |
| test_ipsec | `build/tests/test_ipsec` | Unit test | IPsec SA/policy correctness |
| test_l2_module | `build/tests/test_l2_module` | Module test | L2 visible integration test |
| test_l3_module | `build/tests/test_l3_module` | Module test | L3 IP/ICMP visible integration test |
| test_pbr_acl_module | `build/tests/test_pbr_acl_module` | Module test | PBR & ACL visible integration test |
| test_l4_module | `build/tests/test_l4_module` | Module test | L4 TCP/UDP visible integration test |
| test_ipsec_module | `build/tests/test_ipsec_module` | Module test | IPsec visible integration test |
| libiron_common.a | `build/common/libiron_common.a` | Library | Shared utility library |

---

## Test Types

| Type | Location | Purpose | Output |
|------|----------|---------|--------|
| Unit tests | `src/tests/unit/` | Fast correctness checks | Minimal (PASS/FAIL) |
| Module tests | `src/tests/module/` | Integration with visible payload inspection | Verbose (hex dumps, decoded fields, formatted report) |
| Regression tests | `src/tests/regression/` | Replay captured failures after fixes | (future) |
| Stress tests | `src/tests/stress/` | Load and resource exhaustion | (future) |

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `cmake: command not found` | `sudo apt install cmake` |
| `cc: command not found` | `sudo apt install build-essential` |
| ASAN errors at runtime | Expected in Debug builds — these indicate real bugs to fix |
| `No tests were found` | Ensure you ran `cmake ../src` from `IronNet/build/` |
