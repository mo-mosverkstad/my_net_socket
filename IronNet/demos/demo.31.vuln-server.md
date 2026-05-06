# Demo 31: Vulnerable Application (Phase 18a)

## Prerequisites

- WSL 2 with Ubuntu
- IronNet built: `cd IronNet/build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make`
- Two terminal windows

## What this demo shows

- An intentionally vulnerable TCP server (port 9999) with three exploit classes
- Stack buffer overflow via `strcpy` (ASAN catches in Debug build)
- Format string vulnerability via user-controlled format
- Integer overflow in length field (truncation mismatch)
- Safe version for comparison

## Terminal 1: Start the router

```bash
cd IronNet/build
sudo ./ironstack/ironstack -d ../src/configs/router.conf
```

You should see:
```
[INFO ] [VULN] Vulnerable server started on TCP port 9999 (INTENTIONALLY INSECURE)
```

## Terminal 2: Setup network

```bash
cd IronNet/build
sudo ip addr add 10.0.1.2/24 dev iron0 2>/dev/null
sudo ip link set iron0 up
```

## Part 1: Normal operation (safe inputs)

```bash
# HELP command
echo "HELP" | nc -w2 10.0.1.1 9999
# Expected: +COMMANDS: ECHO <text>, FMT <text>, READ <len>, SAFE <text>, HELP

# Safe echo (short input, within 64-byte buffer)
echo "ECHO hello" | nc -w2 10.0.1.1 9999
# Expected: +ECHO hello

# Safe version (always bounds-checked)
echo "SAFE hello world this is a test" | nc -w2 10.0.1.1 9999
# Expected: +SAFE hello world this is a test

# Normal READ
echo "READ 10" | nc -w2 10.0.1.1 9999
# Expected: +READ(10 alloc=10) AAAA_NORMA
```

## Part 2: Stack buffer overflow (Vulnerability 1)

The `ECHO` command uses `strcpy()` into a 64-byte stack buffer. Sending more than 63 bytes overflows it.

> **Note:** In Debug builds, the overflow will crash the router (ASAN abort). You must restart ironstack after this test to continue with Parts 3-4.

```bash
# Send exactly 64 bytes (safe, just fits)
echo "ECHO $(python3 -c "print('A'*63)")" | nc -w2 10.0.1.1 9999
# Expected: +ECHO AAAAAA...AAA (63 A's)

# Send 128 bytes (OVERFLOW!)
echo "ECHO $(python3 -c "print('A'*128)")" | nc -w2 10.0.1.1 9999
```

**In Debug build (ASAN enabled):** Terminal 1 will show:
```
==12345==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x...
WRITE of size 129 at 0x... thread T0
    #0 strcpy
    #1 vuln_echo_unsafe vuln_server.c:XX
```

The router process will abort — ASAN detected the overflow and stopped execution to prevent exploitation.

**Compare with SAFE command (no crash):**
```bash
echo "SAFE $(python3 -c "print('A'*128)")" | nc -w2 10.0.1.1 9999

echo "SAFE $(python3 -c "print('A'*128)")" | nc -q1 -w5 10.0.1.1 9999
# Expected: +SAFE AAAAAA...AAA (truncated to 63 chars, no crash)
```

## Part 3: Format string vulnerability (Vulnerability 2)

The `FMT` command passes user input directly as a format string to `snprintf()`.

```bash
# Normal text (no format specifiers)
echo "FMT hello world" | nc -w2 10.0.1.1 9999
# Expected: +FMT hello world

# Leak stack values with %x
echo "FMT %x.%x.%x.%x" | nc -w2 10.0.1.1 9999
# Expected: +FMT <hex values from stack> (e.g., "0.0.7fff1234.deadbeef")

# Leak more stack data
echo "FMT %p.%p.%p.%p.%p.%p" | nc -w2 10.0.1.1 9999
# Expected: +FMT (nil).(nil).0x7fff... (pointer values from stack)
```

**What this demonstrates:**
- `%x` reads 4 bytes from the stack (leaks memory contents)
- `%p` reads pointer-sized values (leaks addresses, defeats ASLR)
- In a real exploit, `%n` would write to memory (disabled in snprintf for safety)

## Part 4: Integer overflow (Vulnerability 3)

The `READ` command takes a length parameter. Internally, it's cast to `uint8_t` (0-255) for allocation size, but the original `int` value is used for the copy length.

```bash
# Normal read (length fits in uint8_t)
echo "READ 20" | nc -w2 10.0.1.1 9999
# Expected: +READ(20 alloc=20) AAAA_NORMAL_DATA_BBB

# Integer truncation: 256 → uint8_t = 0
echo "READ 256" | nc -w2 10.0.1.1 9999
# Expected: -ERR zero length (256 truncates to 0)

# Read 200 bytes (alloc=200, but reads from 256-byte pool)
echo "READ 200" | nc -w2 10.0.1.1 9999
# Expected: +READ(200 alloc=200) AAAA_NORMAL_DATA_BBBB_PADDING_CCCC_...

# Truncation mismatch: 257 → uint8_t = 1, but copies 257 bytes
echo "READ 257" | nc -w2 10.0.1.1 9999
# Expected: +READ(257 alloc=1) <reads 256 bytes from pool — alloc says 1 but copy uses 257>
```

**What this demonstrates:**
- The `alloc_size` (uint8_t) and `copy_len` (int) disagree
- An attacker could exploit this mismatch to read beyond intended boundaries
- In a real system with heap allocation, this would be a heap overflow

## Part 5: Comparison — safe vs unsafe

```bash
# Unsafe: crashes on overflow
echo "ECHO $(python3 -c "print('B'*100)")" | nc -w2 10.0.1.1 9999
# → ASAN crash (Debug) or undefined behavior (Release)

# Safe: truncates gracefully
echo "SAFE $(python3 -c "print('B'*100)")" | nc -w2 10.0.1.1 9999
# → +SAFE BBBB...BBB (63 chars max, no crash)
```

## Vulnerability summary

| Command | Vulnerability | CWE | ASAN catches? |
|---------|--------------|-----|---------------|
| `ECHO <128+ bytes>` | Stack buffer overflow | CWE-121 | ✅ Yes (stack-buffer-overflow) |
| `FMT %x.%x.%x` | Format string | CWE-134 | ❌ No (valid memory access) |
| `READ 257` | Integer overflow/truncation | CWE-190 | ❌ No (within bounds of static pool) |

## Real-world impact

| Vulnerability | What an attacker can do |
|---------------|------------------------|
| Buffer overflow | Overwrite return address → execute arbitrary code |
| Format string | Leak memory (bypass ASLR), write to memory (%n) |
| Integer overflow | Read/write beyond intended buffer boundaries |

## Command reference

| Command | Description |
|---------|-------------|
| `ECHO <text>` | Unsafe echo (strcpy, no bounds check) |
| `FMT <text>` | Format string (user input as format) |
| `READ <len>` | Read with integer truncation |
| `SAFE <text>` | Safe echo (strncpy, bounds checked) |
| `HELP` | Show commands |

## Notes

- The vulnerable server auto-starts with ironstack on port 9999
- In Debug builds, ASAN catches buffer overflows immediately (process aborts)
- In Release builds (`-DCMAKE_BUILD_TYPE=Release`), overflows cause undefined behavior
- Phase 18b will develop exploit payloads targeting these vulnerabilities
- Phase 18c will implement mitigations (stack canaries, bounds checking)
