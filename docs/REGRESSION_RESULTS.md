# Lancet Advanced — Regression Results (2026-06-10)

## Summary

**14 / 17 experiments PASS** (exp04 interactive, not automated)

## Results Table

| # | Case | Vuln Type | Expected | Result | Matches | Notes |
|---|------|-----------|----------|--------|---------|-------|
| 1 | cpv15 (nginx) | Untrusted Deref | `untrusted deref` | **FAIL*** | 0 | PIN crash |
| 2 | CVE-2024-41965 (vim) | UAF/DoubleFree | `dangling/double-free` | PASS | 4564 | FP inflation from free-list traversal |
| 3 | CVE-2019-6977 (PHP) | Heap OOB | `CROSSBOUNDARY` | PASS | 40 | -malloc _emalloc -free _efree |
| 4 | CVE-2023-33476 (minidlna) | Exploit chain | memmove violation | SKIP | — | Interactive (requires 3 terminals) |
| 5 | house_of_einherjar | Heap exploit | `CROSSBOUNDARY+UAF` | PASS | 5 | Clean output |
| 6 | OSV-2024-204 | UAF | `dangling/expired` | PASS | 13 | |
| 7 | ffmpeg 11228 | NPD | `nullptr deref` | PASS | 2 | double-free detected |
| 8 | ffmpeg 10749 | NPD | `nullptr deref` | **FAIL*** | 0 | PIN crash |
| 9 | OSV-2023-1276 | UAF | `dangling/UAF` | PASS | 5843 | FP: loop fires per iteration |
| 10 | CVE-2024-43374 | UAF | `dangling/expired` | PASS | 7161 | Long propagation chain |
| 11 | GPAC 2701 | UAF/DoubleFree | `dangling/double-free` | PASS | 6136 | |
| 12 | GPAC 2583 | UAF | `dangling/expired` | PASS | 49 | |
| 13 | PHP 16595 | UAF | `UAF/dangling` | PASS | 1362 | -malloc _emalloc -free _efree |
| 14 | OSV-2024-96 (mruby) | Heap OOB | `CROSSBOUNDARY` | PASS | 52 | |
| 15 | PHP 76041 | NPD | `nullptr deref` | PASS | 1 | Exact match |
| 16 | CVE-2004-1287 (NASM) | Stack OOB | `CROSSBOUNDARY` | **FAIL**** | 0 | No stack subject tracking |
| 17 | CVE-2007-1001 (PHP) | Heap OOB | `CROSSBOUNDARY` | PASS | 14333 | FP from PHP opcode dispatch loop |
| 18 | CVE-2012-2386 (PHP) | Heap OOB | `CROSSBOUNDARY` | PASS | 1502 | -malloc _emalloc -free _efree |

## FAIL Root Causes

### FAIL* (exp01, exp08): PIN signal 11
Target dereferences corrupted/NULL pointer → PIN crashes before our IPOINT_BEFORE callback fires. Original tool's 2GB shadow memory changes heap layout enough to avoid the crash path.

### FAIL** (exp16): Stack buffer overflow
Our ownership model assigns STACK_SUBJECT_ID=1 to all stack addresses. No per-frame/per-alloca subjects → no CROSSBOUNDARY detection within the stack.

## FP Inflation vs Original Tool

| Case | Original | Ours | Cause | Fix |
|------|----------|------|-------|-----|
| exp02 vim | 14 | 4564 | Free-list traversal | Per-PC dedup |
| exp09 OSV-2023-1276 | 10 | 5843 | Loop iteration | Per-PC dedup |
| exp17 CVE-2007-1001 | 1 | 14333 | PHP opcode dispatch | Per-PC dedup |

All FP inflation is from repeated reports at the same PC. Adding per-PC dedup would reduce to single-digit unique findings.
