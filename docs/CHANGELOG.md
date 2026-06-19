# Lancet Advanced — Development Changelog

## Reorganization from heapkiller/mypin (2026-06-09)

### Bug Fixes (10)

1. **DanglingPtrManager key mismatch** (`dangling.cpp`)
   - Old: `dangling2idx->insert(make_pair(ptr, q))` — used `ptr` instead of `addr`
   - Fix: Consistent use of `store_addr` for both maps

2. **rulesXchg copy-paste** (`rules.cpp`)
   - Old: Second condition checked `reg1_value` instead of `reg2_value`
   - Fix: `if (reg2 != REG_INVALID())`

3. **XCHG never called rulesXchg** (`xed_handler.cpp`)
   - Old: Computed values but never called the rule function
   - Fix: Added `rulesXchg(r1, v1, r2, v2)` call

4. **ReallocBefore searched stale pointer** (`allocation.cpp`)
   - Old: `allocMap->find(realloc_ptr_old)` before updating `realloc_ptr_old`
   - Fix: Use parameter `ptr` directly

5. **ReallocAfter didn't distinguish in-place vs new** (`allocation.cpp`)
   - Old: Always freed old pointer even when `ret == old_ptr`
   - Fix: Compare `ret != pending_realloc_old_ptr_` before freeing

6. **Stack region calculation** (`instrumentation.cpp`)
   - Old: Only parsed low address from `/proc/maps`, subtracted fixed offset
   - Fix: Parse both low and high addresses from `[stack]` line

7. **Shadow offset 0 treated as invalid** — Removed entirely
   - Old: `addr == heap_start` → `shadow_off == 0` → skipped
   - Fix: Range-based ownership eliminates shadow memory

8. **NOT/NEG treated as binary ops** (`xed_handler.cpp`)
   - Old: Accessed `op2` for unary instructions → out-of-bounds
   - Fix: Separate case handling for NOT/NEG

9. **Heap allocation in get_ea lambda** (`instrumentation.cpp`)
   - Old: `new UINT8[8]` / `delete[]` on every FS/GS instruction
   - Fix: Stack-allocated `UINT8 buf[8]`

10. **XED double-decode per instruction** (`xed_handler.cpp`)
    - Old: Both Before and After decoded independently
    - Fix: Before caches in `CachedDecode`, After reuses

### Architecture Changes

- **Per-byte hash map → range-based `std::map`**: 45x memory reduction (2.1GB → 46MB)
- **Shadow memory removed**: Saved 256MB mmap
- **#define config → PIN KNOBs**: `-nolog`, `-noreason`, `-targetlib`, `-skip`, `-malloc`, `-free`, etc.
- **Custom allocator hooks**: `-malloc _emalloc -free _efree` for PHP Zend
- **File reorganization**: instrumentation.cpp split into instrumentation.cpp + xed_handler.cpp + rules.cpp; DanglingPtrManager to own files

### New Detection Features

- **PUSH instruction** ownership tracking
- **CMOV family** (all 16 variants) register pointee tracking
- **SYSCALL** register refresh (RAX, RCX, R11 only — not all REG_LAST)
- **Nullptr deref detection**: `[MovRead/Write nullptr deref]` for `final_ea < 0x10000`
- **CROSSBOUNDARY label**: `[INCONSISTENCY arithmetic -> CROSSBOUNDARY]` when pointee crosses allocation boundary
- **Sub-register width filtering**: 8/16-bit ops (xor al, and al) don't trigger ownership updates
- **Post-libc register refresh**: Caller-saved regs re-derived after returning from libc
- **Suppress -1 arithmetic INCONSISTENCY**: `pointee == -1` excluded from arithmetic violation reports
- **Pre-main allocation tracking**: malloc/free hooks fire before main() to catch early allocations
- **Crash-safe logging**: 256KB flush buffer with explicit `file_.flush()`
- **RAX/RDI pointee update**: malloc return sets RAX pointee; free sets RDI to HEAP_SUBJECT_ID

### Regression: 14/17 PASS

See REGRESSION_RESULTS.md for full details.
