# Pre-Analysis Pruning Design

## Motivation

For large programs like PHP, 72% of analyzed instructions are in main code. Many of these are in functions that never touch heap memory (string formatting, math, logging). Pruning these saves analysis time without losing detection capability.

## Approach 1: Profile-Guided Pruning (recommended, easiest)

Two-pass execution:
1. **Pass 1 (baseline)**: Run with `-noreason 1` (allocation tracking only, no XED analysis). Record which heap allocation subjects are created and freed. Output: a list of allocation PCs (malloc/free call sites).
2. **Pass 2 (lancet)**: Only analyze functions that are on the call path between allocation sites and crash/exit. All other functions are skipped.

Implementation:
- Pass 1 collects `{malloc_callsite_PC, free_callsite_PC}` pairs
- Between passes: compute the set of functions that contain these PCs (from symbol table)
- Pass 2: `ins_callback` checks if the current instruction's RTN is in the "interesting" set; skip if not

Estimated speedup: 3-10x for large programs (most functions don't allocate/free).

## Approach 2: Static Call Graph Pruning

At image load time:
1. Build a static call graph from the binary's symbol table + relocations
2. Mark functions that call malloc/free/realloc (directly or transitively)
3. Only instrument marked functions

Implementation:
- In `image_callback`: iterate all RTNs, check if they contain `call malloc@plt` / `call free@plt`
- Walk the call graph backward to find all callers
- Prune functions not in the caller set

Limitation: doesn't handle indirect calls (function pointers, vtables).

## Approach 3: Hot-Path Filtering via Instruction Count

Skip XED analysis for instructions that have been executed > N times at the same PC without producing a detection. The intuition: if a PC has been analyzed 1000 times without finding a bug, it's likely benign.

Implementation:
```cpp
std::unordered_map<ADDRINT, uint32_t> exec_count_;
const uint32_t MAX_ANALYSIS_PER_PC = 100;

// In XedSolverBefore:
if (++exec_count_[(ADDRINT)ip] > MAX_ANALYSIS_PER_PC) return;
```

Estimated speedup: 2-5x for programs with hot loops (PHP image processing, GPAC media parsing).
Trade-off: might miss bugs that manifest only after many iterations (time-of-check-time-of-use).

## Approach 4: Data-Flow Guided Pruning

Only analyze instructions where:
- The source or destination operand is a KNOWN heap pointer (register with pointee > STACK_SUBJECT_ID)
- Or the effective address falls within a tracked allocation

Skip all other instructions (stack-local computations, flag operations, etc.).

Implementation: Check register pointees BEFORE XED decode. If no register involved in the instruction holds a heap pointer, skip decode entirely.

```cpp
// Fast check: any GP register currently points to heap?
bool heap_relevant = false;
for (auto reg : {REG_RAX, REG_RBX, ..., REG_R15}) {
    if (ownership_->get_reg_pointee(reg) > STACK_SUBJECT_ID) {
        heap_relevant = true;
        break;
    }
}
if (!heap_relevant) return; // skip this instruction
```

Estimated speedup: 5-20x (most instructions don't involve heap pointers).
Risk: misses cases where a register BECOMES a heap pointer via computation (LEA, ADD).

## Multi-Layer Integration

These pruning strategies can be combined:
- Layer 0: Static pruning (call graph) — eliminates functions at image load time
- Layer 1: Profile-guided — eliminates cold paths based on baseline run
- Layer 2: Hot-path filter — eliminates repetitive analysis at runtime
- Layer 3: Data-flow check — eliminates heap-irrelevant instructions per-execution

Each layer is independently configurable via KNOBs:
```
-prune-static 1      # enable call graph pruning
-prune-profile baseline.log  # use baseline profiling data
-prune-hotpath 100    # max analysis per PC
-prune-dataflow 1     # skip heap-irrelevant instructions
```
