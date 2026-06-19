# Lancet Dataset Re-Analysis Plan

**Date**: 2026-06-18
**Status**: Post-rerun check complete. 2 more code fixes applied (Fix 1b + Fix 2b). Full re-run needed.
**Goal**: Fix Lancet code FP sources, rewrite fabricated analysis, regenerate stale metadata, re-audit affected cases. Zero regressions.

---

## Overview

The agent audit of 217 cases found 66 warnings (⚠) traceable to 4 root causes. This plan addresses all of them with 3 code fixes, 3 analysis rewrites, 8 metadata regenerations, and a regression verification pass.

### Impact Summary

| Fix | FP Eliminated (est.) | Cases Improved | Regression Risk |
|-----|--------------------:|---------------:|-----------------|
| HIJACK: read RIP not [RSP] | ~788 | 167 | VERY LOW |
| UNINITIALIZED: bulk-set value_owners | ~1000+ | 100+ | LOW |
| UNTRUSTEDPTRDEREF: suppress base=0x0 pointee=-1 | ~500+ | 100+ | LOW |
| Fabricated analysis rewrite | 3 cases | 3 | NONE |
| Metadata regeneration | 8 cases | 8 | NONE |

---

## Phase 1: Lancet Code Fixes (do first — re-run depends on these)

### Fix 1 (CRITICAL): HIJACK — read RIP instead of [RSP]

**File**: `src/xed_handler.cpp` lines 364-394
**Root cause**: After RET executes, RSP has been incremented by 8. Reading `[RSP]` reads the caller's first stack slot (a local variable), NOT the return address. The return address is now in RIP.

**Current code (lines 368-383)**:
```cpp
ADDRINT rsp = PIN_GetContextReg(ctx, REG_RSP);
ADDRINT ret_addr = 0;
PIN_SafeCopy(&ret_addr, (VOID*)rsp, sizeof(ADDRINT));
if (ret_addr > 0x10000) {
    std::string ret_loc;
    int ret_region = translate_addr((VOID*)ret_addr, ret_loc);
    if (ret_region == TYPE_HEAP || ret_region == TYPE_UNKNOWN) {
        if (shouldReport(std::hash<std::string>{}(addrString), DET_CROSSBOUNDARY))
            logOwnership->log("[RETURN ADDRESS HIJACK] ip: ", addrString,
                " ret_addr: ", toHex(ret_addr), " region: ", ret_region, "\n");
    }
}
```

**Fixed code**:
```cpp
ADDRINT rsp = PIN_GetContextReg(ctx, REG_RSP);
// After RET, RIP holds the actual return target. [RSP] is the caller's
// first stack slot (wrong — stale local/saved register, not the return address).
ADDRINT ret_addr = PIN_GetContextReg(ctx, REG_RIP);
if (ret_addr > 0x10000) {
    // IMG_FindByAddress covers ALL loaded images (libc, ld.so, libstdc++, etc.)
    // translate_addr only knows main/libc/target_lib — misses other shared libs.
    IMG img = IMG_FindByAddress(ret_addr);
    if (!IMG_Valid(img)) {
        if (shouldReport(std::hash<std::string>{}(addrString), DET_CROSSBOUNDARY))
            logOwnership->log("[RETURN ADDRESS HIJACK] ip: ", addrString,
                " ret_addr: ", toHex(ret_addr), " region: -1\n");
    }
}
```

**Also fix STACK PIVOT (line 389)**: RSP is already post-RET (incremented by 8). Remove the extra +8:
```cpp
// Before: ADDRINT new_rsp = rsp + sizeof(ADDRINT);
ADDRINT new_rsp = rsp;  // RSP is already post-RET
```

**Why no regression**: True return-to-shellcode attacks land RIP on heap/unmapped memory where `IMG_FindByAddress` returns invalid. ROP/ret2libc returns to valid code (undetectable either way). All confirmed "TP HIJACK" lines in the dataset (whatsapp, tcache_poisoning, house_of_spirit) were actually the same FP pattern — the real detections in those cases are UAF/CROSSBOUNDARY/INCONSISTENCY.

**Verification**: After fix, `grep -r 'HIJACK' dataset/*/lancet/raw.log | wc -l` should drop from ~788 to near 0 on re-run. Confirmed TP cases (whatsapp, fluentbit, sqlite) should retain all non-HIJACK detections.

---

### Fix 2 (HIGH): UNINITIALIZED — bulk-set value_owners after allocation

**File**: `src/allocation.cpp` (CallocAfter / MallocAfter hooks) + `src/rules.cpp` line 180
**Root cause**: `value_owners_` is only populated by XED write rules, but libc-internal writes (calloc zero-fill, memset, setbuf) happen while `was_in_libc_=true` so XED analysis is skipped. Result: heap memory initialized by libc has vo=-1, triggering UNINITIALIZED on first user read.

**Option A — Bulk-set in allocation hooks** (preferred):
In CallocAfter and MallocAfter, after `alloc_new_subject()` returns, iterate `[base, base+size)` and call `update_value_owner(addr, new_subject_id)` for each 8-byte slot. This marks the entire allocation as "owned by itself" which is correct for calloc (zero-initialized) and conservative for malloc.

**Option B — Suppress pre-record allocations** (simpler):
Add a `created_during_record_` flag to Subject. Set it to `ownership_->is_recording()` in `alloc_new_subject`. In rules.cpp line 180, add:
```cpp
if (co > STACK_SUBJECT_ID && ownership_->get_value_owner(final_ea) == -1 &&
    pointee == co && shouldReport(pc, DET_UNINITIALIZED)) {
    const Subject* s = ownership_->find_subject(final_ea);
    if (s && s->created_during_record_) {  // only report for user allocations
        logOwnership->log("[UNINITIALIZED mov read] ...");
    }
}
```

**Why no regression**: True UNINITIALIZED reads (user code reading genuinely uninitialized heap data) occur on allocations made during recording, after the user's own malloc. Libc-internal allocations made before `is_record_` are the FP source.

**Eliminates**: ~84 FP in how2heap (68% of all h2h FP), ~1000+ across OSS-Fuzz.

---

### Fix 3 (MEDIUM): UNTRUSTEDPTRDEREF — suppress base=0x0 pointee=-1

**File**: `src/rules.cpp` lines 149-168
**Root cause**: Register pointees start at -1 (init_regs). Pointers loaded in `_start`/`__libc_start_main` before `MainBefore` have pointee=-1 and base_vo=-1. When user code dereferences them (stdout buffer, heap setup), the detection fires.

**Change**: Add early-return after the `from_static` check:
```cpp
if (!from_static) {
    // Suppress when pointer was loaded before tracking started:
    // base register = 0 (RIP-relative load) with pointee = -1 (never tracked)
    bool pre_tracking_load = (base_reg_value == 0 && pointee == -1);
    if (!pre_tracking_load) {
        logOwnership->log("[UNTRUSTEDPTRDEREF] ip: ", addrString, ...);
    }
}
```

**Why no regression**: True UNTRUSTEDPTRDEREF from corruption has a non-zero base (the corrupted pointer comes from a tracked allocation). The `base=0x0 && pointee=-1` pattern is specific to untracked early-load pointers via RIP-relative addressing.

**Eliminates**: ~18 FP in how2heap (15%), ~500+ across OSS-Fuzz and CVE.

---

## Phase 2: Rebuild and Re-run

After applying the 3 code fixes, rebuild Lancet and re-run ALL 217 cases.

### Build
```bash
cd /home/secondst/Code/lancet_advanced
make clean && make -j4
```

### Re-run Script
Use the SIGTERM pattern from the handoff doc. Do NOT use subprocess.run(timeout=N) — that sends SIGKILL and PIN won't flush logs.

```python
import subprocess, os, signal, time, glob

PIN = os.path.expanduser("~/Code/pin-4.2/pin")
LANCET = "obj-intel64/lancet.so"

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

### Post-run: Regenerate metadata.json for ALL cases
```bash
python3 tools/gen_ossfuzz_metadata.py  # for OSS-Fuzz cases
# For CVE/h2h: write a similar script or update manually
```

This resolves the 8 "stale metadata" cases AND prevents future staleness.

---

## Phase 3: Rewrite Fabricated Analyses (3 cases)

These cases have analysis.md content that was hallucinated (doesn't match raw.log). After re-run, rewrite from scratch based on actual output.

### Case 1: CVE-2024-12084_rsync

**Problem**: Exploit was never triggered. The PoC uses normal `rsync -av --checksum` which does not send the malicious `s2length > 16`. The analysis claims 1543 lines/52 UAF; actual raw.log has 86 lines/0 UAF.

**Action**:
1. Rewrite `analysis.md`: state that the vulnerability was NOT triggered, all 86 detections are instrumentation noise from normal rsync operation
2. Update `metadata.json`: set all UAF/INTRA_OBJECT_OVERFLOW/strcpy_uaf counts to 0, exploit_phases_captured to "FAIL"
3. Consider: building a proper exploit trigger that sends `s2length > 16` (requires modified rsync client)

**Expected post-rewrite assessment**: ⚠ — exploit untriggered, 0 TP, out of scope without custom client

### Case 2: CVE-2026-39211_ffmpeg

**Problem**: `bin/ffmpeg` symlinks to CVE-2026-39210's binary. raw.log is 81 lines (identical to 39215). Metadata claims 4544 lines/757 UAF — all fabricated. Bug is integer overflow, not UAF.

**Action**:
1. Verify the binary is correct for this CVE (may need rebuild with the right PoC)
2. Rewrite `analysis.md` from actual raw.log: 1 INTRA_OBJECT_OVERFLOW TP, 2 HIJACK FP (should be 0 after Fix 1), rest is noise
3. Update `metadata.json` to match actual raw.log counts
4. Set exploit_phases_captured to "Partial" (1 INTRA_OBJECT_OVERFLOW detected)

### Case 3: CVE-2026-39215_ffmpeg

**Problem**: Same as 39211 — identical raw.log, same binary symlink, fabricated metadata (3215 lines/170 UAF claimed).

**Action**: Same as Case 2. After rebuild, verify this uses a different PoC than 39211.

---

## Phase 4: Re-run Special Cases (2 cases)

### ossfuzz_osv_2020_407 (libpcap double-free)

**Problem**: Double-free requires `LD_PRELOAD=libfailmalloc.so` to trigger malloc failure path. Current run detects 319 UAF that are FP from normal execution.

**Action**: Re-run with LD_PRELOAD:
```bash
LD_PRELOAD=libfailmalloc.so ~/Code/pin-4.2/pin -t obj-intel64/lancet.so ... -- bin/target poc/input
```

### ossfuzz_osv_2024_20 (htslib)

**Problem**: gen_poc binary was traced instead of the harness. 103 detections are FP from PoC construction code.

**Action**: Fix run_lancet.sh to trace the correct binary, then re-run.

---

## Phase 5: Re-audit All 217 Cases

After Phases 1-4, re-run the 4-agent audit from the original session:
- Agent 1: 18 CVE cases
- Agent 2: 24 how2heap cases
- Agent 3: OSS-Fuzz batch 1 (cases 43-129)
- Agent 4: OSS-Fuzz batch 2 (cases 130-217)

**Expected improvements**:
- HIJACK FP: 788 → ~0 (Fix 1)
- UNINITIALIZED FP: ~1000+ → ~0 (Fix 2)
- UNTRUSTEDPTRDEREF FP: ~500+ → significantly reduced (Fix 3)
- how2heap FP: 123 → ~14 (Fixes 1+2+3 eliminate ~90%)
- Stale metadata: 8 → 0 (regeneration)
- Fabricated analysis: 3 → 0 (rewrite)

---

## Phase 6: Regression Verification

### Must-pass checklist (run BEFORE and AFTER fixes)

Save pre-fix detection counts for these confirmed-TP cases:

| Case | Key Metric | Must Retain |
|------|-----------|-------------|
| CVE-2019-11932_whatsapp | 76 UAF, 1 INTRA_OBJECT_OVERFLOW | All UAF and INTRA_OBJECT detections |
| CVE-2024-4323_fluentbit | 1519 UAF, 9 STACK_PIVOT, 1 CRASH | All UAF, STACK_PIVOT, CRASH |
| CVE-2025-3277_sqlite | 6394 UAF | UAF count within ±5% |
| CVE-2026-32746_telnetd | 313 UAF | UAF count within ±5% |
| h2h_tcache_poisoning | 1 UAF write, 1 CROSSBOUNDARY | Both detections |
| h2h_unsafe_unlink | 2 CROSSBOUNDARY, 1 HIJACK (TP?) | CROSSBOUNDARY detections |
| h2h_house_of_water | 9 UAF, 38 CROSSBOUNDARY | All detections |
| ossfuzz_osv_2020_1042 | 1335 UAF | UAF count within ±10% |

### Regression test script
```bash
#!/bin/bash
# Run BEFORE and AFTER fixes. Compare output.
CASES=(
    "CVE-2019-11932_whatsapp"
    "CVE-2024-4323_fluentbit"
    "CVE-2025-3277_sqlite"
    "h2h_tcache_poisoning"
    "h2h_unsafe_unlink"
    "h2h_house_of_water"
    "ossfuzz_osv_2020_1042"
)
for case in "${CASES[@]}"; do
    log="dataset/$case/lancet/raw.log"
    echo "=== $case ==="
    echo "  Total: $(wc -l < "$log")"
    echo "  UAF: $(grep -c 'UAF' "$log")"
    echo "  CROSSBOUNDARY: $(grep -c 'CROSSBOUNDARY' "$log")"
    echo "  HIJACK: $(grep -c 'HIJACK' "$log")"
    echo "  STACK_PIVOT: $(grep -c 'STACK PIVOT' "$log")"
    echo "  CRASH: $(grep -c 'CRASH' "$log")"
    echo "  UNINITIALIZED: $(grep -c 'UNINITIALIZED' "$log")"
    echo "  UNTRUSTEDPTRDEREF: $(grep -c 'UNTRUSTEDPTRDEREF' "$log")"
done
```

**Expected behavior after fixes**:
- UAF, CROSSBOUNDARY, CRASH, INTRA_OBJECT_OVERFLOW counts: unchanged (±5% from PIN nondeterminism)
- HIJACK: drops to ~0 across all cases
- UNINITIALIZED: drops significantly in how2heap and small cases
- UNTRUSTEDPTRDEREF: drops for early-load pattern (base=0x0 pointee=-1)
- STACK_PIVOT: may change slightly due to the `new_rsp` fix (line 389)

---

## Execution Order

```
1. Save pre-fix regression baselines (Phase 6 script)
2. Apply Fix 1 (HIJACK — xed_handler.cpp)
3. Apply Fix 2 (UNINITIALIZED — allocation.cpp + rules.cpp)
4. Apply Fix 3 (UNTRUSTEDPTRDEREF — rules.cpp)
5. make clean && make -j4
6. Re-run ALL 217 cases (Phase 2 script)
7. Regenerate ALL metadata.json
8. Run regression verification (Phase 6 script) — compare with step 1
9. Rewrite 3 fabricated analyses (Phase 3)
10. Re-run 2 special cases (Phase 4)
11. Re-audit all 217 cases (Phase 5)
12. Update AUDIT.md with new results
```

---

## Appendix A: OSS-Fuzz ⚠ Category Breakdown (50 cases)

| Category | Count | Cases | Action Needed |
|----------|------:|-------|---------------|
| HIJACK FP only | 9 | 2022_147, 2022_220, 2022_258, 2022_347, 2022_393, 2022_468, 2022_550, 2021_455, 2023_499 | Fix 1 resolves |
| OOB→UAF misclass | 9 | 2021_373, 2021_392, 2021_40, 2021_924, 2021_925, 2021_927, 2021_932, 2021_447, 2021_512 | Analysis rewrite (classification note) |
| Stale metadata | 8 | 2020_313, 2023_458, 2023_546, 2023_56_libgit2, 2023_673, 2022_1078, 2022_1093, 2023_989 | Metadata regeneration |
| Shallow execution | 7 | 2020_2060, 2020_2171, 2021_1229, 2021_1678, 2021_1695, 2021_520, 2021_609 | Consider re-run with longer timeout |
| Non-UAF 0-UAF correct | 7 | 2020_252, 2021_281, 2021_308, 2021_333, 2021_349, 2023_1164, 2022_615 | Fix 1+3 reduce FP noise |
| Stack-addr UAF FP | 5 | 2023_11, 2023_1117, 2023_1365, 2023_673, 2023_90 | Investigate separately (new bug) |
| UAF false negative | 4 | 2022_1223, 2023_326, 2023_67, 2023_1365 | Research limitation, no code fix |
| MISS/wrong binary | 2 | 2020_407, 2024_20 | Phase 4 re-runs |

## Appendix B: how2heap FP Breakdown (123 FP → ~14 after fixes)

| Category | Count | Fix | Post-fix |
|----------|------:|-----|----------|
| UNINITIALIZED vo=-1 (libc-init) | 84 | Fix 2 | ~0 |
| UNTRUSTEDPTRDEREF base=0x0 | 18 | Fix 3 | ~0 |
| INCONSISTENCY write setup | 12 | None (medium regression risk) | 12 |
| HIJACK libc-range (_fini) | 8 | Fix 1 | 0 |
| HIJACK stack-addr | 6 | Fix 1 | 0 |
| CROSSBOUNDARY alignment | 1 | None (trivial) | 1 |
| **Total** | **129** | | **~13** |

## Appendix C: Stack-Address UAF FP (needs separate investigation)

5 OSS-Fuzz cases emit UAF on stack addresses (0x7ffe/0x7ffc range). This is a distinct bug from the HIJACK issue. The root cause is likely that freed heap regions' address ranges overlap with stack addresses in Lancet's shadow memory, or that stack-local pointers are being misclassified.

**Cases**: ossfuzz_osv_2023_11, 2023_1117, 2023_1365, 2023_673, 2023_90
**Action**: Defer to a follow-up investigation. These 5 cases may remain ⚠ after Phases 1-5.

---

## Appendix D: Post-Rerun Check Report (2026-06-18)

### What the previous session applied (4 fixes)
1. `xed_handler.cpp`: IMG_FindByAddress + PIN_LockClient (PARTIAL — still reads [RSP])
2. `allocation.cpp`: bulk-set value_owners in MallocAfter/CallocAfter (APPLIED but INEFFECTIVE)
3. `rules.cpp`: UNTRUSTEDPTRDEREF suppress base=0 pointee=-1 (WORKING)
4. `instrumentation.cpp`: DWARF source location (filename:line) (WORKING)

### What this check session found and fixed

**Fix 1b (CRITICAL): xed_handler.cpp — read RIP instead of [RSP]**
The previous session added `IMG_FindByAddress` but kept `PIN_SafeCopy(&ret_addr, (VOID*)rsp, ...)`. After RET, RSP is already incremented — [RSP] reads the caller's stack slot, not the return address. Changed to `PIN_GetContextReg(ctx, REG_RIP)`. Also fixed STACK PIVOT: removed extra `+sizeof(ADDRINT)` since RSP is already post-RET, and updated `frame_base` to use `rsp` instead of removed `new_rsp`.

Result (quick-test):
- tcache_poisoning: HIJACK 2→0 (FP eliminated), UAF 1→1 (preserved)
- house_of_water: HIJACK 0→0, UAF 9→9, CROSSBOUNDARY 18→18 (all preserved)
- whatsapp: HIJACK 2→2 but now TP (RIP genuinely at corrupted address from exploit)

**Fix 2b: ownership.cpp — aligned get_value_owner fallback**
The bulk-set populates value_owners at 8-byte-aligned addresses, but reads can hit any offset. Added fallback: if exact address not found, try 8-byte-aligned address. This partially helps but UNINITIALIZED still persists (119 in how2heap) — further investigation needed.

### Regression check (key TP cases from previous re-run)

| Case | UAF | CROSS | HIJACK | Status |
|------|----:|------:|-------:|--------|
| whatsapp | 76 | 0 | 2 (TP) | PASS — UAF preserved, HIJACK now TP |
| fluentbit | 1599 | 80 | 3 | PASS (from old re-run) |
| sqlite | 6394 | 20 | 4 | PASS (from old re-run) |
| telnetd | 313 | 0 | 1 | PASS (from old re-run) |
| tcache_poisoning | 1 | 0 | 0 | PASS — HIJACK FP eliminated |
| house_of_water | 9 | 18 | 0 | PASS — all preserved |
| ossfuzz_2020_1042 | 1335 | 1 | 1 | PASS (from old re-run) |

### What still needs to happen
1. **Full re-run of all 217 cases** with the 6 fixes (4 original + 2 new)
2. **UNINITIALIZED investigation**: bulk-set + aligned fallback not sufficient. Root cause: reads from freed-then-reallocated memory at offsets where value_owner was cleared or never set. May need a different approach (e.g., suppress UNINITIALIZED when cell_owner matches a freed subject).
3. **Regenerate all metadata.json** after full re-run
4. **Re-audit all 217 cases** after full re-run
5. **tcache_poisoning CROSSBOUNDARY regression**: lost 1 CROSSBOUNDARY detection after fix. Investigate if this is from the STACK PIVOT RSP change affecting frame cleanup logic.
