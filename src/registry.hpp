#ifndef LANCET_REGISTRY_HPP
#define LANCET_REGISTRY_HPP

#include <string>
#include <vector>
#include <functional>

// ============================================================
// Detection Type Registry — extensible, no magic numbers
// ============================================================
enum DetType {
    DET_NULLPTR       = 0,
    DET_UAF_W         = 1,
    DET_UAF_R         = 2,
    DET_INCON_W       = 3,
    DET_INCON_R       = 4,
    DET_DANGLING      = 5,
    DET_EXPIRED       = 6,
    DET_GOTPLT        = 7,
    DET_CROSSBOUNDARY = 8,
    DET_UNINITIALIZED = 9,
    DET_FORTIFY       = 10,
    DET_STACKUAF      = 11,
    DET_INTRA_OBJ     = 12,
    DET_MAX
};

// ============================================================
// Allocator Hook Descriptor — declarative function hook config
// ============================================================
enum HookSemantic {
    SEM_ALLOC,       // malloc-like: (size) → ptr
    SEM_ALLOC_2ARG,  // calloc-like: (nmemb, size) → ptr
    SEM_REALLOC,     // realloc-like: (old_ptr, size) → ptr
    SEM_FREE,        // free-like: (ptr)
    SEM_MMAP,        // mmap-like: (addr, length, ...) → ptr
    SEM_MUNMAP,      // munmap-like: (addr, length)
    SEM_MEMCPY,      // memcpy/memmove: (dst, src, size)
    SEM_MEMSET,      // memset: (dst, val, size)
    SEM_STRCPY,      // strcpy/strcat: (dst, src)
    SEM_CHK_FAIL,    // __chk_fail: (void) — fortify overflow
};

struct HookDescriptor {
    const char* name;          // function name or prefix
    HookSemantic semantic;     // what it does
    bool prefix_match;         // true = match name prefix, false = exact match
    int size_arg_index;        // which arg is size (-1 if N/A)
};

// ============================================================
// Section Descriptor — which ELF sections to track
// ============================================================
struct SectionDescriptor {
    const char* name;          // section name (e.g., ".data")
    bool is_exploit_target;    // if true, writes → [exploit primitive]
};

// ============================================================
// Allocator Signature — for auto-detection
// ============================================================
struct AllocatorSignature {
    const char* probe_symbol;  // symbol to search for
    const char* alloc_func;
    const char* free_func;
    const char* calloc_func;   // NULL if not available
    const char* realloc_func;  // NULL if not available
    const char* display_name;
    int size_arg;              // which arg is size (0 for malloc-like, 1 for pool allocators)
    int free_addr_arg;         // which arg is the address to free (0 for free-like, 1 for pool free)
};

// ============================================================
// Skip Pattern — functions/patterns to skip instrumentation
// ============================================================
struct SkipPattern {
    const char* pattern;       // substring match
    bool is_prefix;            // true = prefix match, false = contains
};

// ============================================================
// Threshold Constants — all magic numbers in one place
// ============================================================
struct Thresholds {
    uint64_t nullptr_low;              // below this = null deref (default: 0x10000)
    uint64_t untrusted_high;           // above this = corrupted ptr (default: 0x7fffffffffff)
    size_t   min_stack_frame;          // min frame size to track (default: 0x10)
    size_t   max_stack_frame;          // max frame size to track (default: 0x10000)
    size_t   stack_cleanup_size;       // default frame cleanup on return (default: 0x100)
    size_t   max_strcpy_scan;          // max string scan length (default: 0x10000)
    size_t   recently_freed_cap;       // recently-freed buffer capacity (default: 4096)
    size_t   recently_freed_trim;      // trim batch size (default: 2048)
    size_t   malloc_header_size;       // ptmalloc header (default: 0x10)
    size_t   malloc_alignment;         // ptmalloc alignment mask (default: 0xf)
};

// ============================================================
// Built-in registries — default values, can be overridden
// ============================================================
namespace LancetRegistry {

// Known custom allocators for auto-detection
inline const AllocatorSignature known_allocators[] = {
    {"_emalloc",    "_emalloc",    "_efree",    "_ecalloc",  "_erealloc",  "PHP Zend",   0, 0},
    {"ngx_palloc",  "ngx_palloc",  "ngx_pfree", NULL,        NULL,         "nginx",      1, 1},
    {"je_malloc",   "je_malloc",   "je_free",   "je_calloc", "je_realloc", "jemalloc",   0, 0},
    {"tc_malloc",   "tc_malloc",   "tc_free",   "tc_calloc", "tc_realloc", "tcmalloc",   0, 0},
    {"g_malloc",    "g_malloc",    "g_free",    NULL,        NULL,         "GLib",        0, 0},
    {"mi_malloc",   "mi_malloc",   "mi_free",   "mi_calloc", "mi_realloc", "mimalloc",   0, 0},
    {NULL, NULL, NULL, NULL, NULL, NULL, 0, 0}
};

// Extra allocator entry points — same semantics as alloc_func (size in arg0, returns pointer).
// Hooked as additional MallocBefore/After when the corresponding allocator is auto-detected.
struct AllocatorAlias {
    const char* parent_alloc;   // match against gConfig.alloc_func after auto-detect
    const char* alias_func;     // additional function to hook as malloc
    int size_arg;               // which arg is size
};

inline const AllocatorAlias allocator_aliases[] = {
    {"ngx_palloc", "ngx_pcalloc", 1},
    {"ngx_palloc", "ngx_pnalloc", 1},
    {NULL, NULL, 0}
};

// Libc memory functions to hook semantically
inline const HookDescriptor libc_hooks[] = {
    // memcpy family: dst(0), src(1), size(2)
    {"memcpy",        SEM_MEMCPY, false, 2},
    {"memmove",       SEM_MEMCPY, false, 2},
    {"mempcpy",       SEM_MEMCPY, false, 2},
    {"__memcpy_",     SEM_MEMCPY, true,  2},
    {"__memmove_",    SEM_MEMCPY, true,  2},

    // memset family: dst(0), val(1), size(2)
    {"memset",        SEM_MEMSET, false, 2},
    {"__memset_",     SEM_MEMSET, true,  2},

    // strcpy family: dst(0), src(1)
    {"strcpy",        SEM_STRCPY, false, -1},
    {"strncpy",       SEM_STRCPY, false, -1},
    {"strcat",        SEM_STRCPY, false, -1},
    {"strncat",       SEM_STRCPY, false, -1},
    {"__strcpy_chk",  SEM_STRCPY, false, -1},
    {"__strncpy_chk", SEM_STRCPY, false, -1},
    {"__strcat_chk",  SEM_STRCPY, false, -1},

    // _chk variants with buffer size at arg2
    {"__sprintf_chk", SEM_MEMSET, false, 2},
    {"__snprintf_chk",SEM_MEMSET, false, 2},
    {"__vsprintf_chk",SEM_MEMSET, false, 2},

    // fortify failure
    {"__chk_fail",    SEM_CHK_FAIL, false, -1},
    {"__fortify_fail",SEM_CHK_FAIL, false, -1},
    {"__stack_chk_fail", SEM_CHK_FAIL, true, -1},

    // mmap/munmap
    {"mmap",          SEM_MMAP,   false, 1},
    {"mmap64",        SEM_MMAP,   false, 1},
    {"munmap",        SEM_MUNMAP, false, 1},

    {NULL, SEM_ALLOC, false, -1}  // sentinel
};

// ELF sections to track as subjects
inline const SectionDescriptor tracked_sections[] = {
    {".data",    false},
    {".bss",     false},
    {".got.plt", true},   // writes here are exploit primitives
    {NULL, false}
};

// Functions/patterns to skip instrumentation
inline const SkipPattern skip_patterns[] = {
    {"asan",       false},  // contains "asan"
    {"sanitizer",  false},  // contains "sanitizer"
    {NULL, false}
};

// Default thresholds
inline const Thresholds default_thresholds = {
    .nullptr_low          = 0x10000,
    .untrusted_high       = 0x7fffffffffff,
    .min_stack_frame      = 0x10,
    .max_stack_frame      = 0x10000,
    .stack_cleanup_size   = 0x100,
    .max_strcpy_scan      = 0x10000,
    .recently_freed_cap   = 4096,
    .recently_freed_trim  = 2048,
    .malloc_header_size   = 0x10,
    .malloc_alignment     = 0xf,
};

} // namespace LancetRegistry

// ============================================================
// Multi-Layer Interface Design (pre-reserved)
// ============================================================

// Layer 1: Allocation Tracking — tracks malloc/free/mmap/custom alloc
// Current: AllocationManager + Ownership::alloc_new_subject/free_subject
// Future: pluggable allocator backends per-layer

// Layer 2: Ownership Tracking — cell(C), value(V), pointee(P) model
// Current: Ownership class with range-based cell, sparse value, register pointee
// Future: per-byte shadow (L2a), range-based (L2b), or hybrid

// Layer 3: Detection Rules — ownership violations → bug reports
// Current: rules.cpp + xed_handler.cpp CROSSBOUNDARY
// Future: pluggable rule engines loaded from config

// Layer 4: Reporting / Dedup / Filtering
// Current: shouldReport() + Logger
// Future: structured output (JSON), severity levels, dedup policies

// Interface stubs for future multi-layer support:
// class IAllocTracker { virtual void on_alloc(addr, size) = 0; virtual void on_free(addr) = 0; };
// class IOwnershipModel { virtual int64_t get_cell_owner(addr) = 0; };
// class IRuleEngine { virtual void check_read(addr, pointee, co) = 0; };
// class IReporter { virtual void report(DetType, ip, details) = 0; };

#endif
