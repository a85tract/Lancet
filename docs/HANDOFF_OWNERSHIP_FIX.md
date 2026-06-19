# Ownership Fix — Dev Session Handoff (Round 2)

**Date**: 2026-06-18
**Prerequisite**: Read `docs/FIX_UNINITIALIZED.md` for design rationale.
**Goal**: Fix TAINT FP (30K → ~200) from round 1, then full re-run + re-audit.

## Current State (after round 1)

11 fixes already applied and built:

| # | File | Fix | Round |
|---|------|-----|-------|
| 1 | `src/xed_handler.cpp` | HIJACK reads RIP not [RSP], IMG_FindByAddress + PIN_LockClient | Prior |
| 2 | `src/allocation.cpp` | Bulk-set value_owners in MallocAfter/CallocAfter | Prior |
| 3 | `src/rules.cpp` | UNTRUSTEDPTRDEREF suppress .data/.bss + base=0x0 pointee=-1 | Prior |
| 4 | `src/instrumentation.cpp` | DWARF source locations (filename:line) | Prior |
| 5 | `src/ownership.cpp` | get_value_owner aligned fallback | Prior |
| 6 | `src/xed_handler.cpp` | STACK PIVOT post-RET rsp fix | Prior |
| 7 | `src/rules.cpp` | Write-poison fix: `(pointee >= 0) ? pointee : co` | Round 1 |
| 8 | `src/rules.cpp` | INCONSISTENCY write check: `pointee == -1` not `vo == -1` | Round 1 |
| 9 | `src/instrumentation.cpp` | Semantic hooks (memset/memcpy/strcpy) update value_owners | Round 1 |
| 10 | `src/allocation.cpp` | Bulk-set cap raised to 0x20000 (1MB) | Round 1 |
| 11 | `src/allocation.cpp` | TAINT checks at FreeBefore (ptr-8) and MallocAfter (ret) | Round 1 |

Global stats after round 1 full re-run:
```
Total: 948,479 lines
HIJACK: 0           (eliminated)
UNINITIALIZED: 11,721  (-43% from 20,452)
TAINT: 30,832       (NEW — needs FP fix)
UAF: ~427K          (stable)
```

## Problem: TAINT has 30K FP from 2 causes

### Cause A: MallocAfter FP (18,790 = 61%)

Normal `write → free → reuse` cycle:
```
1. buf = malloc(N)        → subject 5
2. *buf = user_data       → vo[buf] = 5  (XED tracks the write)
3. free(buf)              → ptmalloc writes fd at buf[0] INSIDE LIBC (invisible to XED)
                            vo[buf] still = 5 (stale user vo)
4. new = malloc(N)        → returns buf (reused from freelist)
   MallocAfter checks vo[buf] = 5 → "free-list poisoned!" → FP
```

The fix: in `FreeBefore`, AFTER the TAINT check, pre-mark fd/bk as allocator-owned. This simulates the libc write that XED can't see. Genuine tcache poisoning (user writes AFTER free at step 3.5) overwrites the pre-mark → TAINT still fires.

### Cause B: FreeBefore FP (12,042 = 39%)

Subject overlaps next chunk header. `alloc_new_subject` uses:
```cpp
aligned = (user_size + 0x10) & ~0xf
```

The `+0x10` makes every subject extend 16 bytes beyond user data, covering the NEXT chunk's entire header (prev_size + size). Normal user writes to the allocation set vo in the overlap zone → FreeBefore sees user vo at `ptr-8` → FP.

Verified for all malloc sizes:
```
malloc(  8):  subject=16B,  next header at +0..+15   → INSIDE subject
malloc( 64):  subject=80B,  next header at +64..+79  → INSIDE subject
malloc(120):  subject=128B, next header at +112..+127 → INSIDE subject
```

The fix: in `FreeBefore`, check if the vo subject at `ptr-8` is the SAME as the cell_owner there (= the adjacent allocation writing to its own territory). Only report TAINT if vo comes from a DIFFERENT subject (= cross-subject corruption).

## What To Implement: 2 changes

### Change A: Pre-mark fd/bk in FreeBefore

**File**: `src/allocation.cpp`, in `FreeBefore`

Add AFTER the existing TAINT check, BEFORE `free_subject()`:

```cpp
VOID AllocationManager::FreeBefore(ADDRINT ptr) {
    if (gConfig.debug_output)
        std::cout << "free(" << toHex(ptr) << ")" << std::endl;

    // === EXISTING TAINT check (from round 1) — keep as-is but refine below ===
    // ... (see Change B for the refined version)

    // Pre-mark fd/bk as allocator-owned.
    // ptmalloc will write fd (ptr+0) and bk (ptr+8) inside libc (invisible to XED).
    // Without this, the next malloc sees stale user vo → TAINT FP.
    // Genuine tcache poisoning (user writes AFTER free) overwrites this pre-mark.
    if (ptr && ownership_) {
        ownership_->update_value_owner(ptr, HEAP_SUBJECT_ID);
        ownership_->update_value_owner(ptr + 8, HEAP_SUBJECT_ID);
    }

    // Existing free logic
    pending_free_ptr_ = ptr;
    FreeResult res = ownership_->free_subject(pending_free_ptr_);
    // ... rest unchanged ...
}
```

### Change B: Refine FreeBefore TAINT check — exclude adjacent-subject overlap

**File**: `src/allocation.cpp`, in `FreeBefore`

Replace the existing TAINT check with this refined version:

```cpp
    // Ownership boundary check: chunk header should be allocator-owned.
    // Only report if vo belongs to a DIFFERENT subject than the cell_owner at ptr-8.
    // The adjacent allocation's subject includes the next chunk's header
    // (due to +0x10 in aligned calculation), so vo = adjacent_subject is expected.
    if (ptr && ownership_) {
        int64_t size_vo = ownership_->get_value_owner(ptr - 8);
        if (size_vo > STACK_SUBJECT_ID) {
            int64_t header_co = ownership_->get_cell_owner(ptr - 8);
            // Cross-subject: vo written by a different subject than the cell owner
            // = genuine corruption (OOB write from another allocation)
            if (size_vo != header_co) {
                logOwnership->log("[HEAP METADATA TAINT] free(", toHex(ptr),
                    "): chunk size at ", toHex(ptr - 8),
                    " has vo=", size_vo, " but co=", header_co,
                    " (cross-subject header corruption)\n");
            }
        }
    }
```

Key: `size_vo != header_co` means a DIFFERENT subject wrote to this address than the one owning it. That's cross-subject corruption (heap overflow into adjacent header). If `size_vo == header_co`, it's the adjacent allocation writing to its own territory (expected overlap).

### MallocAfter TAINT check — no change needed

The existing MallocAfter check stays as-is. After Change A (pre-mark fd/bk), normal reuse cycles will have `vo = HEAP_SUBJECT_ID` (0, not > STACK_SUBJECT_ID) → no FP. Genuine tcache poisoning overwrites the pre-mark → TAINT fires.

## Build & Verify

```bash
cd /home/secondst/Code/lancet_advanced
make -j4
```

### Smoke test

```bash
# 1. tcache_poisoning: MUST have TAINT (genuine fd poisoning after free)
cd dataset/h2h_tcache_poisoning && bash run_lancet.sh &
PID=$!; sleep 12; kill -TERM $PID; wait $PID 2>/dev/null
echo "=== tcache_poisoning ==="
echo "TAINT: $(grep -c 'TAINT' lancet/raw.log)"
echo "UAF: $(grep -c 'UAF' lancet/raw.log)"
echo "UNINIT: $(grep -c 'UNINITIALIZED' lancet/raw.log)"
grep 'TAINT' lancet/raw.log
cd ../..

# 2. house_of_einherjar: SHOULD have free TAINT (null-byte corrupts prev_size from different subject)
cd dataset/h2h_house_of_einherjar && bash run_lancet.sh &
PID=$!; sleep 12; kill -TERM $PID; wait $PID 2>/dev/null
echo "=== house_of_einherjar ==="
echo "TAINT: $(grep -c 'TAINT' lancet/raw.log)"
echo "CROSSBOUNDARY: $(grep -c 'CROSSBOUNDARY' lancet/raw.log)"
grep 'TAINT' lancet/raw.log
cd ../..

# 3. radare2 (was 2560 TAINT FP): should drop to near 0
cd dataset/ossfuzz_osv_2020_1094 && bash run_lancet.sh &
PID=$!; sleep 15; kill -TERM $PID; wait $PID 2>/dev/null
echo "=== radare2 osv_2020_1094 ==="
echo "TAINT: $(grep -c 'TAINT' lancet/raw.log)"
echo "UAF: $(grep -c 'UAF' lancet/raw.log)"
cd ../..

# 4. whatsapp: regression — UAF must be preserved
cd dataset/CVE-2019-11932_whatsapp && bash run_lancet.sh &
PID=$!; sleep 15; kill -TERM $PID; wait $PID 2>/dev/null
echo "=== whatsapp ==="
echo "UAF: $(grep -c 'UAF' lancet/raw.log)"
echo "INTRA: $(grep -c 'INTRA_OBJECT' lancet/raw.log)"
echo "TAINT: $(grep -c 'TAINT' lancet/raw.log)"
cd ../..
```

### Expected after smoke test

| Case | TAINT | UAF | Key check |
|------|------:|----:|-----------|
| tcache_poisoning | 1+ | 1 | TAINT must fire (fd written AFTER free) |
| house_of_einherjar | 1+ | 0 | TAINT from cross-subject null-byte write |
| radare2 osv_2020_1094 | 0-5 | ~19K | Was 2560 → should be near 0 |
| whatsapp | 0 | ~76 | UAF preserved, no spurious TAINT |

## Full Re-run

After smoke test passes, re-run all 217 cases:

```python
import subprocess, os, signal, time, glob

for case_dir in sorted(glob.glob("dataset/CVE-*") + glob.glob("dataset/h2h_*") + glob.glob("dataset/ossfuzz_*")):
    run_script = os.path.join(case_dir, "run_lancet.sh")
    if not os.path.exists(run_script):
        continue
    print(f"Re-running {case_dir}...")
    proc = subprocess.Popen(
        ["bash", run_script],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid, cwd=case_dir
    )
    time.sleep(15)
    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        proc.wait()
```

### After full re-run

1. Regenerate all metadata.json
2. Verify global stats:
   - HIJACK: 0
   - TAINT: ~200 (down from 30,832)
   - UNINITIALIZED: ~11,700 (unchanged — remaining sources need more hooks)
   - UAF: ~427K (stable)
3. Report stats and hand off for per-case audit

## Regression Must-Pass

| Case | Metric | Must Retain |
|------|--------|-------------|
| CVE-2019-11932_whatsapp | ~76 UAF, 1 INTRA_OBJECT | ±5% |
| CVE-2024-4323_fluentbit | ~1599 UAF, 8-9 STACK_PIVOT | ±10% |
| CVE-2025-3277_sqlite | ~6394 UAF | ±5% |
| h2h_tcache_poisoning | 1 UAF, 1+ TAINT | TAINT must be present |
| h2h_house_of_einherjar | 2-3 CROSSBOUNDARY, 1+ TAINT | Both must be present |
| h2h_unsafe_unlink | 3 CROSSBOUNDARY | Must be present |
| h2h_house_of_water | 9 UAF, 18 CROSSBOUNDARY | ±2 |
| ossfuzz_osv_2020_1042 | ~1335 UAF | ±10% |

## Files modified

- `src/allocation.cpp` (Changes A + B: FreeBefore pre-mark + refined TAINT check)

No other files changed — Changes 1-5 from round 1 are already applied.

## Environment

- PIN: `~/Code/pin-4.2/pin`
- Lancet: `obj-intel64/lancet.so`
- Build: `make -j4`
- Password: `000`
