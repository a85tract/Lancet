# Lancet Dataset — Structured Vulnerability Case Library

## Directory Structure

Each case is a self-contained directory under `dataset/`:

```
dataset/
├── CVE-2024-4323_fluentbit/     ← TEMPLATE (complete)
│   ├── metadata.json            # Machine-readable case info
│   ├── analysis.md              # Human-readable analysis with per-line Lancet explanation
│   ├── run_lancet.sh            # Reproducible: run Lancet on this case
│   ├── bin/                     # Target binary
│   │   └── fluent-bit
│   ├── src/                     # Source code (exploit source, vuln source if available)
│   ├── poc/                     # PoC input file (crash trigger, not full exploit)
│   ├── exp/                     # Exploit code (the attack, not just crash)
│   │   ├── exploit.py
│   │   └── exploit_trigger.sh
│   └── lancet/                  # Lancet output
│       └── raw.log              # Full ownership.log from Lancet run
├── CVE-YYYY-NNNNN_target/      ← TODO cases
│   └── ...
└── README.md                    # This file
```

## Case Template

### metadata.json
```json
{
  "cve": "CVE-YYYY-NNNNN",
  "name": "Human-readable name",
  "target": "Software name",
  "bug_type": "UAF / OOB / overflow / type confusion / ...",
  "exploit_type": "heap spray / ROP / stack pivot / ...",
  "binary": "bin/<binary_name>",
  "poc": "poc/<poc_file> or exp/<exploit_file>",
  "lancet_output": "lancet/raw.log",
  "analysis": "analysis.md",
  "run_script": "run_lancet.sh",
  "lancet_args": "-nolog 0 -noreason 0 [-targetlib X] [-struct_layout Y]",
  "detection_summary": {
    "total_lines": 0,
    "uaf_read": 0,
    "uaf_write": 0,
    "crossboundary": 0,
    "return_address_hijack": 0,
    "stack_pivot": 0,
    "dangling_expired": 0
  },
  "exploit_phases_captured": "N/M",
  "false_positives": 0,
  "false_negatives": 0
}
```

### analysis.md Structure
```markdown
# CVE-YYYY-NNNNN — Target Name

## Vulnerability
One paragraph describing the bug.

## Exploit Chain
Numbered steps of the actual exploit technique.

## Lancet Output Summary
Table of detection counts.

## Key Detection Lines Explained
For each exploit phase, show the relevant Lancet log line and explain:
- What instruction triggered it (from `ip: main+0xNNNN`)
- What ownership violation it represents
- How it maps to the exploit phase

## Exploit ↔ Lancet Correspondence
Table mapping each exploit phase to Lancet detection type.
```

### run_lancet.sh
- Auto-detects PIN location
- Finds lancet.so in the repo
- Runs with correct arguments (allocator hooks, target lib, etc.)
- Saves output to lancet/raw.log

## Cases To Create

Priority order (these have binaries + exploits + Lancet output already):

### Tier 1: Deep analysis cases (have exploit chain analysis)
1. ✅ `CVE-2024-4323_fluentbit` — DONE (template)
2. `CVE-2019-11932_whatsapp` — libgif double-free → heap spray
3. `CVE-2020-9273_proftpd` — pool UAF → ROP
4. `CVE-2025-49844_redis` — Lua type confusion → arb R/W
5. `CVE-2021-3156_sudo` — Baron Samedit heap overflow
6. `CPV15_nginx` — intra-struct overflow (needs -struct_layout)

### Tier 2: Have binary + Lancet output
7. `CVE-2024-6387_openssh` — regreSSHion
8. `CVE-2026-32746_telnetd` — buffer overflow
9. `CVE-2024-12084_rsync` — heap OOB
10. `CVE-2025-3277_sqlite` — integer overflow

### Tier 3: FFmpeg CVEs (batch — same structure)
11-19. `CVE-2026-392{10-18}_ffmpeg` — various heap bugs

### Tier 4: OSS-Fuzz cases (from tests/ossfuzz/)
20+. Top cases by detection richness from the 175-case dataset

## How To Add a New Case

```bash
# 1. Create directory
mkdir -p dataset/CVE-YYYY-NNNNN_target/{src,bin,poc,exp,lancet}

# 2. Copy binary, exploit, PoC
cp /path/to/binary dataset/CVE-YYYY-NNNNN_target/bin/
cp /path/to/exploit.c dataset/CVE-YYYY-NNNNN_target/exp/
cp /path/to/poc.bin dataset/CVE-YYYY-NNNNN_target/poc/

# 3. Copy run_lancet.sh from template and adjust
cp dataset/CVE-2024-4323_fluentbit/run_lancet.sh dataset/CVE-YYYY-NNNNN_target/
# Edit: change binary path and any special args

# 4. Run Lancet
cd dataset/CVE-YYYY-NNNNN_target && bash run_lancet.sh

# 5. Write analysis.md
# - Read lancet/raw.log
# - For each exploit phase, find the corresponding Lancet detection lines
# - Explain each key line briefly

# 6. Write metadata.json
# - Fill in detection counts from raw.log
# - Match exploit phases to Lancet detections
```

## Environment

- **Local**: PIN 3.28 on Ubuntu 24.04 (x86_64), path: `/home/seondst/Desktop/Code/`
- **Remote**: PIN 4.2 on Ubuntu 26.04 (`secondst@pve-research.tail0f6352.ts.net`, password `000`)
- **Lancet**: `obj-intel64/lancet.so` — build: `make -j$(nproc)` (PIN 3.28) or set `PIN_ROOT` in makefile for PIN 4.2
- **Key tools**: `addr2line -e <bin> -f <offset>` for PC → function, `objdump -d -M intel <bin>` for disasm

## Lancet Usage Guide

### Basic Usage
```bash
# Simplest — analyze a binary with its PoC input
pin -t lancet.so -nolog 0 -noreason 0 -- ./target_binary poc_input

# With custom allocator (e.g., nginx pool allocator)
pin -t lancet.so -nolog 0 -noreason 0 -malloc ngx_palloc -free ngx_pfree -- ./nginx ...

# With target library (bug is in a .so, not main binary)
pin -t lancet.so -nolog 0 -noreason 0 -targetlib libxml2.so -- ./fuzzer poc

# With struct layout for intra-struct overflow detection
pin -t lancet.so -nolog 0 -noreason 0 -struct_layout structs.file -- ./target poc

# Skip noisy functions
pin -t lancet.so -nolog 0 -noreason 0 -skip "zend_str_tolower_copy,vim_snprintf" -- ./target poc
```

### KNOB Reference
| KNOB | Default | Description |
|------|---------|-------------|
| `-nolog` | 1 (off) | Set to 0 to enable ownership.log and ins_trace.log |
| `-noreason` | 0 | Set to 1 to disable ownership reasoning (faster, no detections) |
| `-noheap` | 0 | Disable heap allocation tracking |
| `-targetlib` | "" | Instrument this shared library alongside main |
| `-skip` | "" | Comma-separated function names to skip |
| `-malloc` | "malloc" | Allocation function name (auto-detected for nginx/PHP/jemalloc) |
| `-free` | "free" | Free function name |
| `-struct_layout` | "" | Path to struct layout file for sub-subject splitting |
| `-logdir` | "./logs" | Output directory for log files |

### Output Files
- `logs/ownership.log` — ownership violation detections (the main output)
- `logs/ins_trace.log` — instruction trace (every analyzed instruction)

### Reading Lancet Output

Each line in `ownership.log` is a detection. Format: `[TYPE] ip: REGION+OFFSET details...`

**Detection types and what they mean:**
| Detection | Meaning | Exploit Phase |
|-----------|---------|---------------|
| `[INCONSISTENCY mov write reg UAF]` | Write to freed memory (cell_owner=HEAP) | Heap corruption, UAF write |
| `[INCONSISTENCY mov read UAF]` | Read from freed memory | UAF read, dangling reference |
| `[INCONSISTENCY arithmetic -> CROSSBOUNDARY]` | Pointer arithmetic crosses allocation boundary | OOB access |
| `[memcpy CROSSBOUNDARY write/read]` | memcpy/memmove spans two allocations | Heap spray, bulk OOB |
| `[RETURN ADDRESS HIJACK]` | RET pops address pointing to non-code region | Control flow hijack |
| `[STACK PIVOT]` | After RET, RSP is outside stack region | Stack pivot to heap |
| `[UNTRUSTEDPTRDEREF]` | Read from address with no known owner | Corrupted pointer deref |
| `[MovRead high untrusted deref]` | Read via address > 0x7fffffffffff | Corrupted ptr (e.g., 0x4141414141414141) |
| `[INTRA_OBJECT_OVERFLOW]` | Byte write clobbers a pointer within same allocation | Intra-struct overflow |
| `[CORRUPTED_PTR_LOAD]` | Load from cell where cell_owner ≠ value_owner | Intra-struct overflow (with -struct_layout) |
| `[dangling/expired]` | Using a pointer whose target was freed | Dangling pointer chain |
| `[UNINITIALIZED mov read]` | Reading from tracked allocation where value_owner = -1 | Uninitialized memory |
| `[exploit primitive] write in .got.plt` | Write to .got.plt region | GOT overwrite |
| `[CRASH]` | PIN caught SIGSEGV | Program crashed |

**PC → function mapping:**
```bash
# Log says: ip: main+0x72e3f
# Get function name:
addr2line -e ./target_binary -f 0x72e3f
# Output: ngx_http_userid_filter
```

### Auto-Detection

Lancet auto-detects custom allocators for: nginx (`ngx_palloc`), PHP (`_emalloc`), jemalloc, tcmalloc, GLib, mimalloc. When auto-detected, the `-malloc`/`-free` knobs are overridden automatically.

### Target Binary Requirements

**Do NOT use ASan-compiled binaries.** PIN's `RTN_ReplaceSignature` conflicts with ASan's malloc interception — Lancet's allocation hooks won't fire, producing 0 UAF detections.

```bash
# WRONG — ASan intercepts malloc, Lancet can't hook it
gcc -fsanitize=address -g -o target target.c

# CORRECT — clean build, Lancet hooks malloc in libc
gcc -g -O0 -fno-omit-frame-pointer -o target target.c
```

If you only have an ASan binary, rebuild from source without `-fsanitize=address`. For OSS-Fuzz cases, each `tests/ossfuzz/*/build.sh` can be modified: strip `-fsanitize=*` flags and replace `clang` with `gcc`.

### Struct Layout Files (Approach A)

For intra-struct overflow detection, generate a struct layout file from DWARF:
```bash
python3 tools/extract_structs.py ./target_binary -o structs.file
# Then run:
pin -t lancet.so -nolog 0 -struct_layout structs.file -- ./target poc
```
This splits each matching allocation into per-field sub-subjects. When an overflow crosses a field boundary, `cell_owner ≠ value_owner` in the output precisely identifies the source and destination fields.

## Development Lessons & Pitfalls

### PIN 4.x Migration
1. **RTN_InsertCall(IPOINT_AFTER) on RTN is unreliable on PIN 4.x** — doesn't fire for malloc/free/mmap. Solution: use `RTN_ReplaceSignature` for malloc/free/calloc/realloc (wraps the original function, calls it via `PIN_CallApplicationFunction`). Exception: mmap cannot be replaced (PIN itself uses mmap internally — replacing it crashes the runtime). For mmap, keep IPOINT_AFTER + IARG_PROTOTYPE.
2. **PIN 4.x pinrt/signal.h defines REG_RAX as anonymous enum** conflicting with LEVEL_BASE::REG_RAX. Fix: add `-DPIN_DISABLE_CRT_REG_DEF` to CXXFLAGS.
3. **PIN 4.x uses Musl CRT** — `u_int32_t` doesn't exist. Use `uint32_t`.
4. **PIN 4.x pin-g++ enforces -Werror** — fix member init order, sign compare, unused variables.
5. **Stack frame cleanup**: moved from `rtn_callback IPOINT_AFTER` to `XedSolverBefore`'s RET instruction handler (instruction-level, works on both PIN 3.x and 4.x).

### Byte-Write Sub-Register Filter
The XED handler skips `src_width < 32` writes (e.g., `mov byte [rax], dl`) to avoid FPs from sub-register operations (PHP `xor al, al`). But this means byte-by-byte buffer overflow writes (like base64 decode) are invisible to normal ownership tracking. The `INTRA_OBJECT_OVERFLOW` check runs in this filtered path to detect when a byte write clobbers a pre-existing pointer.

### Struct Layout Mode
- With `-struct_layout`, byte writes also update `value_owner` (records WHO wrote the cell).
- Without it, byte-write `value_owner` updates are skipped (causes FPs on linked data structures where adjacent allocations naturally have `co ≠ vo`).
- CROSSBOUNDARY between sub-subjects preserves the original register pointee (doesn't refresh to destination field ID), so `value_owner` traces back to the overflow SOURCE field.

### Pool Allocators (nginx)
- nginx has `ngx_palloc(pool, size)` where arg0=pool, arg1=size. Lancet's `AllocatorSignature.size_arg` field handles this.
- `ngx_pcalloc` and `ngx_pnalloc` bypass `ngx_palloc`, so they're registered as `AllocatorAlias` and hooked separately.
- For statically-linked binaries, allocator hooks are applied in the main image's `image_callback` (after main hook, before return).

### Hot-Path Filter
Per-PC execution count limit (64×). After 64 hits, an instruction is skipped. This prevents analyzing the same hot loop millions of times. Trade-off: if a bug manifests only after the 65th iteration, it's missed. In practice, all 175 OSS-Fuzz cases detect with this filter on.

### False Positive Control
- Generic `co ≠ vo` INCONSISTENCY removed (produced thousands of noise entries). Only specific violation types reported.
- RSP/RBP arithmetic excluded from CROSSBOUNDARY (stack management, not pointer corruption).
- Per-PC dedup via `shouldReport(hash(addrString), detection_type)`.
- Pointer-value dedup for dangling/expired pointers.

## Validation

After creating a case, verify:
1. `run_lancet.sh` produces output (non-zero lancet/raw.log)
2. `metadata.json` detection counts match raw.log
3. `analysis.md` key lines actually exist in raw.log (grep to verify)
4. Each exploit phase has at least one corresponding Lancet detection
5. addr2line the top PCs — they should be in vuln-related functions, not just framework code
