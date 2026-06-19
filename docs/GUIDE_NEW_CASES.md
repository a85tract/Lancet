# Guide: Adding New OSS-Fuzz / CVE Cases to Lancet

## Overview

Most real-world cases in the Lancet paper come from OSS-Fuzz via the OSV database. The workflow is:

1. **Find a vulnerability** on osv.dev with a reproducer
2. **Build the vulnerable version** from source  
3. **Run Lancet** against it with the PoC input
4. **Verify** the detection matches the root cause

## Step 1: Find a Case on OSV

Browse https://osv.dev and filter by:
- **Ecosystem**: OSS-Fuzz
- **Type**: Use-after-free, Heap-buffer-overflow, Stack-buffer-overflow, Null-dereference
- **Has reproducer**: Look for entries with a "Reproducer testcase" link

Each OSV entry provides:
- **Affected commit range**: the vulnerable version
- **Fixed commit**: the patch (helps understand root cause)
- **Reproducer**: binary input that triggers the bug
- **Fuzz target**: which harness binary to use

Example: `OSV-2023-1276` (OpenSC)
```
Affected: OpenSC before commit 5def7eba
Fuzz target: fuzz_pkcs15init
Reproducer: downloadable from OSS-Fuzz
```

## Step 2: Build the Vulnerable Version

### Template Dockerfile

```dockerfile
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    gcc g++ make cmake git wget autoconf automake libtool pkg-config

# 1. Clone the project at the vulnerable commit
RUN git clone https://github.com/<project>.git /app/src && \
    cd /app/src && git checkout <vulnerable_commit>

# 2. Build with debug info (important for addr2line)
RUN cd /app/src && \
    ./configure --disable-optimization CFLAGS="-g -O0" && \
    make -j$(nproc)

# 3. If using OSS-Fuzz harness: build the fuzz target
# Check the project's oss-fuzz integration for the build script:
# https://github.com/google/oss-fuzz/tree/master/projects/<project>
RUN cd /app/src && \
    gcc -g -O0 -o /app/fuzz_target tests/fuzzing/fuzz_<target>.c \
    -I. -L. -l<project> -lpthread

# 4. Install PIN
RUN wget -q https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.28-98749-g6643ecee5-gcc-linux.tar.gz && \
    tar xzf pin-*.tar.gz && mv pin-3.28* /app/pin && rm pin-*.tar.gz

# 5. Copy Lancet tool and PoC
COPY lancet.so /app/pintools/lancet.so
COPY poc_input /app/@POC@
COPY run.sh /app/run.sh
RUN chmod +x /app/run.sh

ENTRYPOINT ["/app/run.sh"]
```

### Template run.sh

```bash
#!/bin/bash
TOOL=${1:-baseline}
cd /app/pintools && mkdir -p logs

if [ "$TOOL" == "lancet" ]; then
    # First run without PIN to verify PoC triggers the bug
    /app/fuzz_target /app/@POC@
    # Then run with Lancet
    time ../pin/pin -t lancet.so -nolog 0 -- /app/fuzz_target /app/@POC@
    echo "--------------------------------"
    echo "Ownership log:"
    echo "--------------------------------"
    cat logs/ownership.log
else
    time ../pin/pin -t lancet.so -nolog 1 -noreason 1 -- /app/fuzz_target /app/@POC@
fi
```

## Step 3: Determine Lancet Configuration

### Auto-detected allocators

Lancet auto-detects: PHP `_emalloc`, nginx `ngx_palloc`, jemalloc, tcmalloc, GLib, mimalloc. 
No configuration needed — it scans binary symbols at load time.

### Custom allocators not in the registry

If the project uses a custom allocator not in the auto-detect list:

```bash
# Find allocator symbols
nm -D /app/fuzz_target | grep -iE "alloc|malloc|free|realloc"

# Run with explicit hooks
./run.sh lancet -malloc my_alloc -free my_free
```

Or add to `registry.hpp`:
```cpp
{"my_alloc", "my_alloc", "my_free", "my_calloc", "my_realloc", "MyProject"},
```

### Target library

If the bug is in a shared library (not the main binary):

```bash
./run.sh lancet -targetlib libfoo.so
```

### Skip functions

If a hot function causes excessive analysis time but isn't the bug site:

```bash
./run.sh lancet -skip "hot_parser_loop,format_string_func"
```

## Step 4: Run and Analyze

```bash
# Build Docker image
docker build -t lancet:my_case .

# Run baseline (timing only)
docker run lancet:my_case baseline

# Run Lancet analysis
docker run lancet:my_case lancet
```

### Expected output types by vulnerability class

| Bug Type | Expected Lancet Detection |
|----------|--------------------------|
| Use-after-free | `[INCONSISTENCY mov read/write UAF]` + dangling/expired pointers |
| Double-free | `double free detected` (stdout) + dangling pointers in log |
| Heap buffer overflow | `[INCONSISTENCY arithmetic -> CROSSBOUNDARY]` or `[memset/memcpy CROSSBOUNDARY]` |
| Stack buffer overflow | `[INCONSISTENCY mov write reg] co: N vo: -1` or `[FORTIFY buffer overflow]` |
| Null pointer deref | `[MovRead nullptr deref] final_ea: 0x0` |
| Use-after-scope | `[INCONSISTENCY mov read UAF]` on stack address |
| Invalid free | `[INVALID FREE]` (stdout) |

### Verify root cause with addr2line

```bash
# Inside Docker:
addr2line -e /app/fuzz_target -f 0x<PC_from_lancet_output>
```

This should point to the vulnerable function/line matching the CVE description.

## Step 5: Add to Regression Suite

### Option A: Docker-based (for CI)

Add to `tests/run_docker_regression.sh`:
```bash
run_test "my_case" "lancet:my_case" "UAF|CROSSBOUNDARY|dangling" "" "" ""
```

### Option B: Native binary (lightweight)

If the binary uses system ld.so (not a custom glibc):
```bash
# Copy binary + PoC to tests/
cp /app/fuzz_target tests/
cp /app/@POC@ tests/

# Run directly
./run.sh -nolog 0 -- tests/fuzz_target tests/@POC@
```

## Recommended OSV Cases to Add Next

These are high-value targets from OSS-Fuzz with known memory corruption bugs:

### Easy (single binary, system malloc)
- **OSV-2024-xxx** (SQLite) — heap OOB in SQL parser
- **OSV-2023-xxx** (libxml2) — UAF in XML namespace handling
- **OSV-2024-xxx** (curl) — double-free in connection pooling

### Medium (needs custom allocator or target_lib)
- **Redis** — uses `zmalloc/zfree` → add to registry
- **nginx** — uses `ngx_palloc` → already in registry
- **Python CPython** — uses `PyMem_Malloc` → add to registry

### Complex (multi-process / network)
- **Apache httpd** — fork-based, needs multi-process support
- **PostgreSQL** — shared memory + custom allocator

## Checklist for Each New Case

- [ ] Vulnerable commit identified and built with `-g -O0`
- [ ] PoC input triggers the bug (crash/ASAN report without Lancet)
- [ ] Lancet detects the bug (ownership log has relevant findings)
- [ ] `addr2line` confirms the PC maps to the actual bug site
- [ ] Detection type matches the vulnerability class (UAF→UAF, OOB→CROSS, etc.)
- [ ] No false positives in the output (only real bug-related findings)
- [ ] Added to regression test suite
- [ ] Timing recorded (baseline vs lancet overhead)
