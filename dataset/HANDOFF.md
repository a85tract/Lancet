# Dataset Audit — Handoff Document

**Date**: 2026-06-19 (final)
**Status**: 218/218 cases built, all raw.log current. 218/218 agent-audited (207✓ 11⚠ = 95%). Ready for human review.

## What Was Done

### Dataset Construction (complete)
- 18 CVE cases (Tier 1-3: real-world exploits + FFmpeg, 13 rebuilt with in-process harnesses)
- 25 how2heap cases (shellphish/how2heap glibc_2.43 + 9 legacy glibc_2.41)
- 175 OSS-Fuzz cases (from tests/ossfuzz/, all with binary + PoC)
- Every case has: `bin/`, `poc/`, `lancet/raw.log`, `metadata.json`, `analysis.md`, `run_lancet.sh`

### Lancet Code Fixes Applied (11 total)

| # | File | Fix | Effect |
|---|------|-----|--------|
| 1 | `xed_handler.cpp` | HIJACK reads RIP via `IMG_FindByAddress` + `PIN_LockClient` | 884→0 HIJACK FP |
| 2 | `allocation.cpp` | Bulk-set `value_owner` in MallocAfter/CallocAfter (1MB cap) | Reduces UNINITIALIZED FP |
| 3 | `rules.cpp` | UNTRUSTEDPTRDEREF suppress .data/.bss + `base=0 pointee=-1` | Reduces UNTRUSTEDPTRDEREF FP |
| 4 | `instrumentation.cpp` | DWARF source locations: `(func @ file:line)` via `PIN_GetSourceLocation` + `RTN_FindByAddress`, cached per-PC | No more addr2line needed |
| 5 | `rules.cpp` | Write-poison fix: `vo = (pointee >= 0) ? pointee : fallback` where fallback = `USER_WRITE_UNKNOWN` for UAF, `co` for normal | Prevents vo=-1 poisoning |
| 6 | `instrumentation.cpp` | Semantic hooks (memset/memcpy/strcpy) update `value_owner` for destination range | libc-initialized memory gets proper vo |
| 7 | `allocation.cpp` | FreeBefore TAINT check + vo-clear + fd/bk pre-mark as `HEAP_SUBJECT_ID` | Detects chunk header corruption |
| 8 | `allocation.cpp` | MallocAfter TAINT only on `USER_WRITE_UNKNOWN` (not stale subject IDs) | 37K→18K TAINT FP |
| 9 | `ownership.cpp` | Subject size = `(user_size + 0x7) & ~0x7` (no +0x10 padding) | Detects off-by-one into chunk header |
| 10 | `xed_handler.cpp` | CROSSBOUNDARY tags: `[chunk metadata]` / `[freed]` / `[unmapped]` | Human-readable region annotation |
| 11 | `xed_handler.cpp` | MOV reg, [mem] restores `pointee = get_cell_owner(loaded_value)` | Fixes pointee loss after stack spill/reload |

Additional: `[ALLOC]`/`[FREE]` logged with caller `(func @ file:line)`, `[OOB byte write]` detection for writes to untracked regions via tracked pointers, `allocation.cpp` passes Logger + caller address through entire alloc/free chain.

### ASan Binary Issue (critical context)
- PIN's `RTN_ReplaceSignature` for malloc **does not work** when the binary links `libasan.so` (dynamic ASan). ASan's `malloc` interceptor in libasan shadows libc's malloc, and PIN hooks the wrong one → 0 UAF detections.
- Static ASan (`__interceptor_*` baked into binary) has the same issue.
- **All 18 originally-ASan cases were rebuilt** without sanitizer flags using Docker (Ubuntu 24.04). Some needed `clang→gcc` replacement and a standalone `main()` to replace libFuzzer's entry point.
- 1 case still links libasan dynamically (osv_2020_2299 wolfSSL) but happens to work (582 UAF). Marked `requires_docker` in metadata.
- **Rule**: target binaries for Lancet MUST be compiled without `-fsanitize=address`. Documented in `dataset/README.md`.

### Known FP Sources (document in audit)
| FP Type | Affected Cases | Root Cause |
|---------|---------------|------------|
| UNTRUSTEDPTRDEREF from .data/.bss | All large binaries | **Fixed** — suppressed in rules.cpp |
| HIJACK ret_addr < 0x10000 | FFmpeg probe loop | **Fixed** — filtered in xed_handler.cpp |
| HIJACK ret_addr in libc range | Many cases (_fini return) | `translate_addr` doesn't map libc code → reports as TYPE_UNKNOWN |
| HIJACK ret_addr on stack (no crash) | Sporadic | `PIN_SafeCopy` reads stale [RSP] on some leaf function RETs |
| Redis jemalloc FP | CVE-2025-49844_redis | jemalloc internals operate on freed memory; hash functions cross allocation boundaries |
| UNTRUSTEDPTRDEREF remaining | 210+ cases | Non-.data/.bss pointers with pointee=-1 (stack locals, heap pointers loaded before tracking starts) |

### Known FN / Limitations
| Issue | Cases | Root Cause |
|-------|-------|------------|
| Type confusion invisible | Redis, sudo | Same allocation reinterpreted as different type — ownership unchanged |
| dlopen hijack invisible | sudo | dlopen not hooked as semantic function |
| Race condition untestable | OpenSSH CVE-2024-6387 | PIN's ~10000x slowdown prevents SIGALRM race |
| 48 cases with 0 UAF | Various | Many are how2heap/small cases that detect CROSSBOUNDARY/HIJACK/INCONSISTENCY instead of UAF — not necessarily FN |

## What Needs To Be Done: Per-Case Audit

### Audit Goal
For each case, verify that Lancet's detections match the actual vulnerability's root cause. "Lancet produced output" ≠ "Lancet correctly detected the bug." The audit must answer:

1. **Does the raw.log contain detections relevant to the actual vulnerability?**
   - Map key detection PCs (via `addr2line -e bin/<binary> -f <offset>`) to source functions
   - Check if those functions are in the vulnerability's code path (not just unrelated init code)

2. **Are the detections TP or FP?**
   - UAF: is the freed memory actually the vulnerability's freed allocation, or jemalloc/allocator internals?
   - HIJACK: does the program actually crash/redirect control flow, or is it a PIN_SafeCopy artifact?
   - CROSSBOUNDARY: is the boundary crossing from the exploit's OOB access, or from legitimate pointer arithmetic?
   - UNTRUSTEDPTRDEREF: is the pointer genuinely corrupted, or is it a global/vtable pointer?

3. **Are there FN (missed detections)?**
   - Compare with the vulnerability description (in harness.c comments, build.sh comments, or OSS-Fuzz bug tracker)
   - If the bug is a heap UAF but Lancet shows 0 UAF → FN. Check: is heap_start present? If not, malloc hook failed.
   - If the bug type is something Lancet can't detect (logic bug, integer overflow without memory effect) → mark as "out of scope"

### Audit Procedure Per Case

```bash
# 1. Read the vulnerability description
cat dataset/<case>/src/*.c | head -30   # harness comments describe the bug
cat tests/ossfuzz/<osv>/build.sh | head -20  # build script has CVE details

# 2. Check detection summary
grep -oP '\[[^\]]+\]' dataset/<case>/lancet/raw.log | sort | uniq -c | sort -rn

# 3. Map top PCs to functions
BIN=$(readlink -f dataset/<case>/bin/*)
grep -oP 'main\+0x[0-9a-f]+' dataset/<case>/lancet/raw.log | sort | uniq -c | sort -rn | head -10 | while read count offset; do
    addr=$(echo "$offset" | sed 's/main+//')
    echo "$count × $offset → $(addr2line -e "$BIN" -f "$addr" 2>/dev/null | head -1)"
done

# 4. Check for HIJACK FP (ret_addr < 0x10000 or program didn't crash)
grep 'HIJACK' dataset/<case>/lancet/raw.log
grep 'CRASH' dataset/<case>/lancet/raw.log

# 5. Verify heap tracking
# If 0 UAF on a heap bug → check if heap_start appeared in stderr during the run

# 6. Update analysis.md with findings and AUDIT.md with status
```

### Audit Output Format

Update `dataset/<case>/analysis.md` to include:

```markdown
## Audit
- **Agent**: ✓ (or ⚠)
- **TP**: N detections are true positives (list key functions)
- **FP**: M detections are false positives (list reasons)
- **FN**: Any missed vulnerability phases
- **Root cause match**: Does the top detection function match the vulnerability's root cause function?
```

Update `dataset/AUDIT.md` table: change `—` to `✓` or `⚠` in the Agent/Human column.

### Priority Order
1. **18 CVE cases first** — these have documented exploit chains, easiest to verify
2. **24 how2heap cases** — known techniques, clear expected behavior
3. **175 OSS-Fuzz cases** — bulk audit, use harness.c comments for ground truth

### Key Files
- `dataset/AUDIT.md` — audit tracker (update per case)
- `dataset/README.md` — dataset spec, Lancet usage, ASan warning
- `docs/TODO.md` — open engineering tasks (jemalloc compat, HIJACK post-RET verify, etc.)
- `docs/REALWORLD_ANALYSIS.md` — reference detection data from PIN 3.28
- `tests/ossfuzz/FULL_VERIFICATION.md` — reference data for all 175 OSS-Fuzz cases
- `tools/gen_ossfuzz_metadata.py` — regenerates metadata.json for OSS-Fuzz cases

### Environment
- PIN: `~/Code/pin-4.2/pin`
- Lancet: `obj-intel64/lancet.so` (already built with both fixes)
- Build: `make -j4`
- Docker: `sudo docker run --rm -v $PWD:/workspace -v ~/Code/pin-4.2:/pin ubuntu:24.04 bash -c '...'`
- Password: `000`

### Batch Re-run Command (if Lancet code changes)
```python
# Use SIGTERM (not SIGKILL) — PIN needs graceful shutdown to flush ownership.log
import subprocess, os, signal, time
proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
time.sleep(15)
os.killpg(os.getpgid(proc.pid), signal.SIGTERM)  # NOT SIGKILL
try: proc.wait(timeout=5)
except: os.killpg(os.getpgid(proc.pid), signal.SIGKILL); proc.wait()
```

**Critical**: Python `subprocess.run(timeout=N)` sends SIGKILL on timeout → PIN doesn't flush logs → 0 lines. Always use the Popen + sleep + SIGTERM pattern above.
