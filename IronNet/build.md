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

### Start the ironstack daemon

```bash
cd IronNet/build
./ironstack/ironstack
```

Press `Ctrl+C` to stop. On shutdown it prints collected statistics.

---

## Run Tests

### Run all tests via CTest

```bash
cd IronNet/build
ctest --output-on-failure
```

### Run a specific test directly

```bash
cd IronNet/build
./tests/test_stats
```

---

## Quick One-Liner (build + test)

```bash
cd IronNet && mkdir -p build && cd build && cmake ../src -DCMAKE_BUILD_TYPE=Debug && make && ctest --output-on-failure
```

---

## Build Outputs

| Binary | Location | Description |
|--------|----------|-------------|
| ironstack | `build/ironstack/ironstack` | Protocol stack daemon |
| test_stats | `build/tests/test_stats` | Stats module unit test |
| libiron_common.a | `build/common/libiron_common.a` | Shared utility library |

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `cmake: command not found` | `sudo apt install cmake` |
| `cc: command not found` | `sudo apt install build-essential` |
| ASAN errors at runtime | Expected in Debug builds — these indicate real bugs to fix |
| `No tests were found` | Ensure you ran `cmake ../src` from `IronNet/build/` |
