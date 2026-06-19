# Ownership Boundary — Design & Fix

## Core Invariant

Lancet's ownership model tracks **who wrote each byte**. The ownership boundary between user code and allocator code is the foundation for two detection directions:

```
         User code (XED-instrumented)     │    ptmalloc (libc, XED-skipped)
         vo = user_subject (≥2)           │    vo = -1 or HEAP_SUBJECT_ID (0)
                                          │
  ← User reads vo=-1 from alloc region    │    UNINITIALIZED (user probing metadata)
  → Alloc consumes vo=user_subject        │    HEAP METADATA TAINT (corruption)
```

**Both detections derive from the same invariant**: memory written by user should have `vo = user_subject`; memory written by allocator should have `vo ∈ {-1, 0}`. Violations in either direction indicate a boundary crossing.

When ownership is tracked correctly:
- `UNINITIALIZED` fires only for user reads of allocator-only data (padding, chunk headers, genuinely uninit'd heap)
- `TAINT` fires only when allocator processes user-corrupted metadata (OOB write into adjacent header, tcache fd poisoning)
- Normal user reads of user-written data → no detection (vo = user_subject ≠ -1)
- Normal user reads of libc-memset'd data → no detection (vo = dst_co, set by semantic hook)

**The 20K FP exists because ownership tracking is broken, not because the rule is wrong.** Fix the tracking → both directions become precise.

## What's broken (3 leaks in ownership tracking)

### Leak 1: Write-poison (4,768 events, 206/217 cases)

```cpp
// rules.cpp line 50
ownership_->update_value_owner(final_ea, pointee);
// When pointee=-1 (register lost after libc call), this POISONS vo to -1
// → subsequent reads see "allocator data" when it's actually "user data"
```

User writes with clobbered registers set `vo = -1` (should be `vo = co`). The ownership model loses track of the user write.

### Leak 2: Invisible libc data-plane writes

Semantic hooks (MemsetBefore, MemcpyBefore, StrcpyBefore) fire for memset/memcpy/strcpy but don't call `update_value_owner`. XED skips libc instructions. Result: libc-initialized data has `vo = -1`, indistinguishable from allocator metadata.

### Leak 3: Bulk-set cap and size mismatch

MallocAfter bulk-sets `vo = subject_id` only for `pending_malloc_size_` bytes (user-requested) with a 1024-slot (8KB) cap. Allocations > 8KB and padding bytes beyond user size have no coverage.

## Fix: Seal the 3 leaks

### Leak 1 fix: Preserve ownership on user writes

**File**: `src/rules.cpp`

In `rulesMovWrite` (line 50) and `rulesMovWriteImm` (line 88):

```cpp
// Before:
ownership_->update_value_owner(final_ea, pointee);

// After:
// User code wrote here. Even if register tracking was lost (pointee=-1),
// the memory is NOW user-owned. Use co (the allocation) as owner.
ownership_->update_value_owner(final_ea, (pointee >= 0) ? pointee : co);
```

The INCONSISTENCY write check (line 71) uses `pointee == -1` instead of `vo == -1`:
```cpp
// Before: else if (co > STACK_SUBJECT_ID && vo == -1 && ...)
// After:  
else if (co > STACK_SUBJECT_ID && pointee == -1 && shouldReport(pc, DET_INCON_W)) {
```

Same detection (user writing with untracked pointer), but vo is no longer poisoned.

### Leak 2 fix: Track libc data-plane writes via semantic hooks

**File**: `src/instrumentation.cpp`

Add to `MemsetBefore` (after existing CROSSBOUNDARY/UAF checks):
```cpp
if (dst_co > STACK_SUBJECT_ID && size <= 0x100000) {
    size_t slots = (size + 7) / 8;
    for (size_t i = 0; i < slots; i++)
        ownership_->update_value_owner(dst + i * 8, dst_co);
}
```

Same pattern for `MemcpyBefore` and `StrcpyBefore`.

Semantic hooks fire for ALL callers (including libc-internal). After the fix, `memset(buf, 0, N)` correctly marks [buf, buf+N) as owned by the destination allocation.

### Leak 3 fix: Raise bulk-set cap

**File**: `src/allocation.cpp`

```cpp
if (slots <= 0x20000) {  // 1MB cap (was 8KB)
```

Keep using `pending_malloc_size_` (NOT aligned size). Padding bytes intentionally keep `vo = -1` — they belong to the allocator, not the user.

## Consequence: TAINT detection becomes free

With ownership properly tracked, add one check at the allocator boundary:

**File**: `src/allocation.cpp`, `FreeBefore` — BEFORE `free_subject`:

```cpp
VOID AllocationManager::FreeBefore(ADDRINT ptr) {
    if (!ptr) return;

    // Ownership boundary check: chunk header should be allocator-owned.
    // If a user subject wrote the size field, the header is corrupted.
    int64_t size_vo = ownership_->get_value_owner(ptr - 8);
    if (size_vo > STACK_SUBJECT_ID) {
        logOwnership->log("[HEAP METADATA TAINT] free(", toHex(ptr),
            "): chunk size field (at ", toHex(ptr - 8),
            ") has vo=", size_vo, " (user subject wrote allocator metadata)\n");
    }

    // Existing free logic
    pending_free_ptr_ = ptr;
    FreeResult res = ownership_->free_subject(pending_free_ptr_);
    // ...
}
```

**File**: `src/allocation.cpp`, `MallocAfter` — BEFORE bulk-set:

```cpp
VOID AllocationManager::MallocAfter(ADDRINT ret) {
    if (!ret) return;

    // Ownership boundary check: returned chunk's fd pointer (at ret+0, used by
    // tcache/fastbin) should be allocator-owned. If a user subject wrote it,
    // the free-list was poisoned (tcache poisoning, fastbin dup, etc.)
    int64_t fd_vo = ownership_->get_value_owner(ret);
    if (fd_vo > STACK_SUBJECT_ID) {
        logOwnership->log("[HEAP METADATA TAINT] malloc() returned ", toHex(ret),
            ": fd/tcache_next (at ", toHex(ret),
            ") has vo=", fd_vo, " (user subject poisoned free-list)\n");
    }

    // Existing allocation logic
    int64_t id = ownership_->alloc_new_subject(ret, pending_malloc_size_);
    // ... bulk-set ...
}
```

### What this catches

| Technique | User write | Allocator reads | TAINT fires at |
|---|---|---|---|
| tcache_poisoning | UAF write to fd at `a+0` | malloc follows fd | MallocAfter: `vo(ret) = user_subject` |
| fastbin_dup | double-free + fd write | malloc follows fd | MallocAfter: `vo(ret) = user_subject` |
| unsafe_unlink | OOB write to fd/bk at `chunk+0x10` | free unlinks | FreeBefore: `vo(ptr-8) = user_subject` |
| house_of_einherjar | null-byte write to prev_size | free backward-merges | FreeBefore: `vo(ptr-16) = user_subject` |
| overlapping_chunks | OOB overwrite chunk size | free reads corrupted size | FreeBefore: `vo(ptr-8) = user_subject` |
| poison_null_byte | null-byte to next chunk prev_inuse | free consolidates wrong | FreeBefore: `vo(ptr-8) = user_subject` |
| house_of_spirit | fake chunk setup on stack | free processes fake chunk | FreeBefore: `vo(ptr-8) = user_subject` |

### What this does NOT catch (out of scope)

- Type confusion (same allocation reinterpreted) — ownership unchanged
- dlopen hijack — not an allocator boundary issue
- Race conditions — PIN timing prevents

## Expected numbers after all fixes

| Metric | Before | After |
|--------|-------:|------:|
| UNINITIALIZED total | 20,509 | ~200 (padding/genuine uninit only) |
| UNINITIALIZED precision | 5.4% | ~90%+ (padding probes are TP) |
| New HEAP METADATA TAINT | 0 | ~50-200 (from how2heap + exploit CVEs) |
| INCONSISTENCY write (vo=-1→pointee=-1) | 4,768 | 4,768 (unchanged, check variable changes) |
| UAF/CROSSBOUNDARY | unchanged | unchanged |

## Summary: 3 leak fixes + 2 boundary checks = complete ownership model

The 3 leak fixes (write-poison, semantic hooks, bulk-set cap) restore ownership integrity. The 2 boundary checks (FreeBefore header, MallocAfter fd) are natural consequences — they fall out of the ownership invariant for free.

This is not a new rule. It's the ownership model working as designed, with the tracking gaps sealed.
