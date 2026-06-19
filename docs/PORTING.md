# Lancet Advanced — Server Porting Guide

## Overview

This document covers porting the Lancet Advanced tool and its Docker-based test suite to a new server. The original server is Ubuntu 22.04 x86-64, 4GB RAM.

## Prerequisites on Target Server

```
OS:      Ubuntu 20.04/22.04 x86-64 (other distros may work, untested)
RAM:     ≥4GB (tool uses ~50MB; Docker containers need more)
Disk:    ~500MB for source + PIN SDK (minimum)
         +~60GB if transferring Docker images for CVE experiments
gcc/g++: ≥9.0 (tested with 11.4)
Docker:  ≥20.10 (only needed for CVE experiments; how2heap/Juliet run natively)
```

**Minimal setup (no Docker):** PIN SDK + lancet source + how2heap source = ~212MB.
See `LIGHTWEIGHT_TESTING.md` for running 22 exploit techniques + Juliet without Docker.

## Components to Transfer

### 1. Lancet Advanced Source (required, ~200KB)

```bash
# On source server:
cd /home/seondst/Desktop/Code
tar czf lancet_advanced.tar.gz lancet_advanced/

# On target server:
tar xzf lancet_advanced.tar.gz
```

### 2. Intel PIN 3.28 SDK (required, ~211MB)

PIN is freely available from Intel's official download page. No account required.

**Download URL:**
```
https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html
```

**Exact version used:** PIN 3.28, build 98749 (2023), Linux x86-64.

```bash
# Option A: Download directly from Intel (recommended for new server)
# Go to the Intel PIN download page above, select:
#   - Pin 3.28 → Linux → x86-64
# The file is named: pin-3.28-98749-g6643ecee5-gcc-linux.tar.gz
# Direct link (may change):
wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.28-98749-g6643ecee5-gcc-linux.tar.gz
tar xzf pin-3.28-98749-g6643ecee5-gcc-linux.tar.gz
mv pin-3.28-98749-g6643ecee5-gcc-linux pin-3.28

# Option B: Copy from source server
cd /home/seondst/Desktop/Code
tar czf pin-3.28.tar.gz pin-3.28/
# Transfer and extract on target
```

After extracting, update `makefile` if the path differs:
```makefile
PIN_ROOT := /path/to/pin-3.28
```

**Note:** PIN 3.28 requires Linux kernel ≤6.x. Tested on Ubuntu 22.04 (kernel 6.8). Newer PIN versions (3.30+) may also work but are untested with this codebase.

### 3. Docker Images (required for full regression, ~53GB total, PRIVATE registry)

The Docker images are hosted on `ghcr.io/a85tract/lancet` and are **private** — they cannot be pulled without authentication. Transfer via `docker save/load`:

```bash
# On source server — export all images:
TAGS=(cpv15 cve_2024_41965 cve_2019_6977 juliet_how2heap osv_2024_204 \
      ffmpeg_11228 ffmpeg_10749 osv_2023_1276 cve_2024_43374 gpac_2701 \
      gpac_2583 php_16595 osv_2024_96 php_76041 cve_2004_1287 \
      cve_2007_1001 cve_2012_2386)

for tag in "${TAGS[@]}"; do
  echo "Saving $tag..."
  docker save "ghcr.io/a85tract/lancet:$tag" | gzip > "lancet_${tag}.tar.gz"
done

# On target server — import:
for f in lancet_*.tar.gz; do
  echo "Loading $f..."
  gunzip -c "$f" | docker load
done
```

Per-image sizes for selective transfer:

| Tag | Size | Experiment | Required for |
|-----|------|-----------|--------------|
| juliet_how2heap | 1.87GB | exp05 | house_of_einherjar, Juliet CWE tests |
| php_16595 | 2.85GB | exp13 | PHP UAF (Zend allocator) |
| ffmpeg_10749 | 2.84GB | exp08 | ffmpeg nullptr deref |
| ffmpeg_11228 | 2.86GB | exp07 | ffmpeg nullptr deref |
| cve_2024_41965 | 1.24GB | exp02 | vim UAF/double-free |
| osv_2024_204 | 993MB | exp06 | UAF detection |
| cve_2019_6977 | 2.04GB | exp03 | PHP OOB (imagecolormatch) |
| gpac_2701 | 1.87GB | exp11 | GPAC UAF/double-free |
| gpac_2583 | 1.87GB | exp12 | GPAC UAF |
| osv_2023_1276 | 1.97GB | exp09 | UAF detection |
| cve_2024_43374 | 1.94GB | exp10 | UAF detection |
| cpv15 | 1.59GB | exp01 | nginx untrusted deref |
| osv_2024_96 | 1.09GB | exp14 | mruby CROSSBOUNDARY |
| php_76041 | 2.05GB | exp15 | PHP nullptr deref |
| cve_2004_1287 | 928MB | exp16 | NASM stack OOB |
| cve_2007_1001 | 1.76GB | exp17 | PHP OOB |
| cve_2012_2386 | 1.86GB | exp18 | PHP CROSSBOUNDARY |

**Minimum set for quick validation**: `juliet_how2heap` + `php_16595` + `osv_2024_204` (~5.7GB)

### 4. Native Test Binaries (optional, for testing without Docker)

The Juliet test suite binaries use system ld.so and run natively:

```bash
# On source server:
tar czf juliet_tests.tar.gz \
  /home/seondst/Desktop/Code/heapkiller/testcases/juliet-test-suite-c/CWE41* \
  /home/seondst/Desktop/Code/heapkiller/testcases/juliet_how2heap/how2heap/house_of_einherjar
```

## Build on Target Server

```bash
cd lancet_advanced
export CC=gcc CXX=g++

# If PIN_ROOT path differs, edit makefile:
# PIN_ROOT := /your/path/to/pin-3.28

make clean && make -j$(nproc)
# Output: obj-intel64/lancet.so
```

## Quick Validation

```bash
# 1. Compile a simple test
cat > /tmp/test_uaf.c << 'EOF'
#include <stdlib.h>
#include <string.h>
int main() {
    char *p = (char *)malloc(64);
    free(p);
    p[16] = 'A';  // UAF write
    return 0;
}
EOF
gcc -o /tmp/test_uaf /tmp/test_uaf.c -g -no-pie

# 2. Run lancet
/path/to/pin-3.28/pin -t ./obj-intel64/lancet.so -nolog 0 -- /tmp/test_uaf

# 3. Check detection
cat logs/ownership.log
# Should contain: [INCONSISTENCY mov write reg UAF]
```

## Full Docker Regression

```bash
# Run all experiments:
bash tests/run_docker_regression.sh

# Or run individual experiments manually:
docker run --rm \
  -v $(pwd)/obj-intel64/lancet.so:/app/pintools/lancet.so:ro \
  --entrypoint /bin/bash \
  ghcr.io/a85tract/lancet:php_16595 \
  -c 'cd /app/pintools && mkdir -p logs && \
      time ../pin/pin -t lancet.so -nolog 0 -malloc _emalloc -free _efree \
        -- /app/php/sapi/cli/php /app/@POC@ 2>&1; \
      cat logs/ownership.log'
```

## KNOB Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-nolog` | 1 | Disable ownership logging (0=enable) |
| `-noreason` | 0 | Disable ownership reasoning rules |
| `-noheap` | 0 | Disable heap allocation tracking |
| `-debug` | 0 | Enable verbose debug output |
| `-targetlib` | "" | Target library name (e.g. `libgpac.so`) |
| `-skip` | "" | Comma-separated functions to skip |
| `-logdir` | `./logs` | Log output directory |
| `-malloc` | `malloc` | Allocation function name (e.g. `_emalloc`) |
| `-free` | `free` | Free function name (e.g. `_efree`) |
| `-calloc` | `calloc` | Calloc function name |
| `-realloc` | `realloc` | Realloc function name |

## Per-CVE Configurations

These are the tested KNOB combinations for each experiment:

```bash
# PHP cases (Zend allocator):
-malloc _emalloc -free _efree

# PHP CVE-2019-6977 (additional skip):
-malloc _emalloc -free _efree -skip "zend_str_tolower_copy,php_gd_gdImageColorMatch"

# GPAC cases:
-targetlib libgpac.so

# All others: default malloc/free hooks
```

## Known Limitations

1. **PIN signal 11 on exploits** (exp01, exp08): When the target dereferences a corrupted pointer, PIN itself may crash before our detection callback fires. The original tool's larger memory footprint (~2GB shadow) changes the heap layout enough to avoid the crash.

2. **Stack buffer overflow** (exp16): Requires per-stack-frame subject tracking, not yet implemented. The tool detects heap-based OOB only.

3. **4GB RAM constraint**: Range-based ownership uses ~50MB vs original's ~2GB. Docker containers need additional RAM for the target process.

4. **Pre-hook allocations**: Memory allocated by ld.so/libc before our malloc hook is installed is invisible. This causes benign "free error" messages (silently suppressed) but doesn't affect detection.
