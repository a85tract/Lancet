#include "instrumentation.hpp"
#include "config.hpp"
#include <cstdint>
#include <sys/types.h>

// Callback wrappers (PIN requires plain function pointers)
VOID RecordMemReadWrapper(VOID* ip, VOID* addr, uint32_t insSize) {
    gInstrumentation->RecordMemRead(ip, addr, insSize);
}
// Legacy wrappers (PIN 3.x IPOINT_BEFORE/AFTER style)
VOID MallocBeforeWrapper(ADDRINT size, CONTEXT* ctx) { gInstrumentation->MallocBefore(size, ctx); }
VOID MallocAfterWrapper(ADDRINT ret) { gInstrumentation->MallocAfter(ret); }
VOID CallocBeforeWrapper(ADDRINT nmemb, ADDRINT size, CONTEXT* ctx) { gInstrumentation->CallocBefore(nmemb, size, ctx); }
VOID CallocAfterWrapper(ADDRINT ret) { gInstrumentation->CallocAfter(ret); }
VOID ReallocBeforeWrapper(ADDRINT ptr, ADDRINT size, CONTEXT* ctx) { gInstrumentation->ReallocBefore(ptr, size, ctx); }
VOID ReallocAfterWrapper(ADDRINT ret) { gInstrumentation->ReallocAfter(ret); }
VOID FreeBeforeWrapper(ADDRINT ptr, CONTEXT* ctx) { gInstrumentation->FreeBefore(ptr, 0); }
VOID FreeAfterWrapper() { gInstrumentation->FreeAfter(); }

// RTN_ReplaceSignature wrappers (PIN 4.x compatible — call original via ORIG_FUNCPTR)
void* MallocReplace(AFUNPTR origFunc, size_t size, int size_arg_idx, CONTEXT* ctx, ADDRINT retip) {
    ADDRINT actual_size = size;
    gInstrumentation->MallocBefore(actual_size, ctx);
    void* ret = nullptr;
    PIN_CallApplicationFunction(ctx, PIN_ThreadId(), CALLINGSTD_DEFAULT, origFunc,
        NULL, PIN_PARG(void*), &ret, PIN_PARG(size_t), size, PIN_PARG_END());
    gInstrumentation->MallocAfter((ADDRINT)ret, retip);
    return ret;
}

void* MallocReplaceArg1(AFUNPTR origFunc, size_t arg0, size_t arg1, CONTEXT* ctx, ADDRINT retip) {
    gInstrumentation->MallocBefore(arg1, ctx);
    void* ret = nullptr;
    PIN_CallApplicationFunction(ctx, PIN_ThreadId(), CALLINGSTD_DEFAULT, origFunc,
        NULL, PIN_PARG(void*), &ret, PIN_PARG(size_t), arg0, PIN_PARG(size_t), arg1, PIN_PARG_END());
    gInstrumentation->MallocAfter((ADDRINT)ret, retip);
    return ret;
}

void* CallocReplace(AFUNPTR origFunc, size_t nmemb, size_t size, CONTEXT* ctx, ADDRINT retip) {
    gInstrumentation->CallocBefore(nmemb, size, ctx);
    void* ret = nullptr;
    PIN_CallApplicationFunction(ctx, PIN_ThreadId(), CALLINGSTD_DEFAULT, origFunc,
        NULL, PIN_PARG(void*), &ret, PIN_PARG(size_t), nmemb, PIN_PARG(size_t), size, PIN_PARG_END());
    gInstrumentation->CallocAfter((ADDRINT)ret, retip);
    return ret;
}

void* ReallocReplace(AFUNPTR origFunc, void* ptr, size_t size, CONTEXT* ctx, ADDRINT retip) {
    gInstrumentation->ReallocBefore((ADDRINT)ptr, size, ctx);
    void* ret = nullptr;
    PIN_CallApplicationFunction(ctx, PIN_ThreadId(), CALLINGSTD_DEFAULT, origFunc,
        NULL, PIN_PARG(void*), &ret, PIN_PARG(void*), ptr, PIN_PARG(size_t), size, PIN_PARG_END());
    gInstrumentation->ReallocAfter((ADDRINT)ret, retip);
    return ret;
}

void FreeReplace(AFUNPTR origFunc, void* ptr, int addr_arg_idx, CONTEXT* ctx, ADDRINT retip) {
    gInstrumentation->FreeBefore((ADDRINT)ptr, retip);
    PIN_CallApplicationFunction(ctx, PIN_ThreadId(), CALLINGSTD_DEFAULT, origFunc,
        NULL, PIN_PARG(void), PIN_PARG(void*), ptr, PIN_PARG_END());
    gInstrumentation->FreeAfter();
}

void FreeReplaceArg1(AFUNPTR origFunc, size_t arg0, void* ptr, CONTEXT* ctx, ADDRINT retip) {
    gInstrumentation->FreeBefore((ADDRINT)ptr, retip);
    PIN_CallApplicationFunction(ctx, PIN_ThreadId(), CALLINGSTD_DEFAULT, origFunc,
        NULL, PIN_PARG(void), PIN_PARG(size_t), arg0, PIN_PARG(void*), ptr, PIN_PARG_END());
    gInstrumentation->FreeAfter();
}
VOID MainBeforeWrapper(CONTEXT* ctx) { gInstrumentation->MainBefore(ctx); }
VOID RepStosBeforeWrapper(ADDRINT dst, ADDRINT count, VOID* ip) { gInstrumentation->RepStosBefore(dst, count, ip); }
VOID RepMovsBeforeWrapper(ADDRINT dst, ADDRINT src, ADDRINT count, UINT32 elem_size, VOID* ip) { gInstrumentation->RepMovsBefore(dst, src, count, elem_size, ip); }
VOID MemcpyBeforeWrapper(ADDRINT dst, ADDRINT src, ADDRINT size, VOID* ip) { gInstrumentation->MemcpyBefore(dst, src, size, ip); }
VOID MemsetBeforeWrapper(ADDRINT dst, ADDRINT val, ADDRINT size, VOID* ip) { gInstrumentation->MemsetBefore(dst, val, size, ip); }
VOID StrcpyBeforeWrapper(ADDRINT dst, ADDRINT src, VOID* ip) { gInstrumentation->StrcpyBefore(dst, src, ip); }
VOID MmapAfterWrapper(ADDRINT ret, ADDRINT length) { gInstrumentation->MmapAfter(ret, length); }

void* MmapReplace(AFUNPTR origFunc, void* addr, size_t length, int prot, int flags, int fd, size_t offset, CONTEXT* ctx, ADDRINT retip) {
    void* ret = nullptr;
    PIN_CallApplicationFunction(ctx, PIN_ThreadId(), CALLINGSTD_DEFAULT, origFunc,
        NULL, PIN_PARG(void*), &ret,
        PIN_PARG(void*), addr, PIN_PARG(size_t), length,
        PIN_PARG(int), prot, PIN_PARG(int), flags,
        PIN_PARG(int), fd, PIN_PARG(size_t), offset,
        PIN_PARG_END());
    gInstrumentation->MmapAfter((ADDRINT)ret, length);
    return ret;
}
VOID MunmapBeforeWrapper(ADDRINT addr, ADDRINT length) { gInstrumentation->MunmapBefore(addr, length); }
VOID StackFrameEntryWrapper(ADDRINT rsp, ADDRINT frame_size, VOID* ip) {
    if (!gInstrumentation) return;
    // Engine A: create stack frame subject for [rsp - frame_size, rsp)
    ADDRINT frame_base = rsp - frame_size;
    gInstrumentation->getOwnership()->alloc_new_subject(frame_base, frame_size);
}
// Called AFTER function returns: RSP is restored to caller's value.
// The callee's frame [rsp_entry - frame_size, rsp_entry) is now dead.
// We mark it by creating+freeing a subject from saved_rbp to current_rsp.
VOID StackFrameExitWrapper(ADDRINT rsp, ADDRINT rbp) {
    if (!gInstrumentation) return;
    // After return, RBP holds the caller's frame pointer (restored by pop rbp/leave).
    // The dead frame was between (roughly) rsp and some lower address.
    // We approximate: mark [rsp - 0x100, rsp) as recently freed (conservative).
    // This covers most local variables in the returned function.
    ADDRINT frame_base = rsp - 0x100;
    gInstrumentation->getOwnership()->alloc_new_subject(frame_base, 0x100);
    gInstrumentation->getOwnership()->free_subject(frame_base);
}
VOID XedSolverBeforeWrapper(VOID* ip, VOID* addr, uint32_t insSize, uint32_t opSize, CONTEXT* ctx) {
    gInstrumentation->XedSolverBefore(ip, addr, insSize, opSize, ctx);
}
VOID XedSolverAfterWrapper(VOID* ip, VOID* addr, uint32_t insSize, uint32_t opSize, CONTEXT* ctx) {
    gInstrumentation->XedSolverAfter(ip, addr, insSize, opSize, ctx);
}

Instrumentation::Instrumentation()
    : current_pc_idx(0)
    , heap_inited_(false)
    , is_record_(false)
    , was_in_libc_(false)
    , has_debug_info_(false)
    , heap_start_(UNKNOWN_ADDR)
    , libc_start_(UNKNOWN_ADDR), libc_end_(UNKNOWN_ADDR)
    , stack_start_(UNKNOWN_ADDR), stack_end_(UNKNOWN_ADDR)
    , main_start_(UNKNOWN_ADDR), main_end_(UNKNOWN_ADDR)
    , target_lib_start_(UNKNOWN_ADDR), target_lib_end_(UNKNOWN_ADDR)
    , got_plt_start_(0), got_plt_end_(0)
{
    ownership_ = new Ownership();

    std::string log_dir = gConfig.log_dir;
    bool log_enabled = !gConfig.no_log;
    logOwnership = new Logger(log_dir + "/ownership.log", log_enabled);
    logInsTrace  = new Logger(log_dir + "/ins_trace.log", log_enabled);

    ownership_->set_logger(logOwnership);
    alloc_mgr_ = new AllocationManager(ownership_, logOwnership);

    cached_.valid = false;
    std::cout << GREEN << "[lancet] Instrumentation initialized" << RESET << std::endl;
}

Instrumentation::~Instrumentation() {
    delete logOwnership;
    delete logInsTrace;
    delete ownership_;
    delete alloc_mgr_;
}

ADDRINT Instrumentation::get_mod_size(ADDRINT Address, std::string modName) {
    if (Address == UNKNOWN_ADDR) return UNKNOWN_ADDR;

    IMG img = IMG_FindByAddress(Address);
    if (!IMG_Valid(img)) return UNKNOWN_ADDR;

    ADDRINT start = IMG_LowAddress(img);
    ADDRINT end = IMG_HighAddress(img);

    if (modName == "libc") {
        std::cout << GREEN << "libc: " << toHex(start) << " - " << toHex(end) << RESET << std::endl;
        libc_start_ = start;
        libc_end_ = end;
    } else if (modName == "main") {
        std::cout << GREEN << "main: " << toHex(start) << " - " << toHex(end) << RESET << std::endl;
        main_start_ = start;
        main_end_ = end;
    } else if (modName == "target_lib") {
        std::cout << GREEN << "target_lib: " << toHex(start) << " - " << toHex(end) << RESET << std::endl;
        target_lib_start_ = start;
        target_lib_end_ = end;
    }
    return end - start;
}

VOID Instrumentation::RecordMemRead(VOID* ip, VOID* addr, uint32_t insSize) {
    if (!is_record_) return;
    if (!heap_inited_) {
        heap_inited_ = record_heap();
    }
}

// Allocation hooks: always track (even before main) to catch pre-main allocations.
// XED rules only run after is_record_ is set by MainBefore.
VOID Instrumentation::MallocBefore(ADDRINT size, CONTEXT* ctx) {
    if (gConfig.no_heap_analysis) return;
    alloc_mgr_->SetContext(ctx);
    alloc_mgr_->MallocBefore(size);
}

VOID Instrumentation::MallocAfter(ADDRINT ret, ADDRINT caller) {
    if (gConfig.no_heap_analysis) return;
    alloc_mgr_->MallocAfter(ret, caller);
}

VOID Instrumentation::FreeBefore(ADDRINT ptr, ADDRINT caller) {
    if (gConfig.no_heap_analysis) return;
    alloc_mgr_->FreeBefore(ptr, caller);
}

VOID Instrumentation::FreeAfter() {
    if (gConfig.no_heap_analysis) return;
    alloc_mgr_->FreeAfter();
}

VOID Instrumentation::CallocBefore(ADDRINT nmemb, ADDRINT size, CONTEXT* ctx) {
    if (gConfig.no_heap_analysis) return;
    alloc_mgr_->SetContext(ctx);
    alloc_mgr_->CallocBefore(nmemb, size);
}

VOID Instrumentation::CallocAfter(ADDRINT ret, ADDRINT caller) {
    if (gConfig.no_heap_analysis) return;
    alloc_mgr_->CallocAfter(ret, caller);
}

VOID Instrumentation::ReallocBefore(ADDRINT ptr, ADDRINT size, CONTEXT* ctx) {
    if (gConfig.no_heap_analysis) return;
    alloc_mgr_->SetContext(ctx);
    alloc_mgr_->ReallocBefore(ptr, size);
}

VOID Instrumentation::ReallocAfter(ADDRINT ret, ADDRINT caller) {
    if (gConfig.no_heap_analysis) return;
    alloc_mgr_->ReallocAfter(ret, caller);
}

VOID Instrumentation::MainBefore(CONTEXT* ctx) {
    is_record_ = true;
    ownership_->init_regs(ctx);
}

void Instrumentation::trackDataSection(ADDRINT addr, size_t size, const std::string& name) {
    if (size > 0) {
        int64_t id = ownership_->alloc_new_subject(addr, size);
        std::cout << GREEN << "[lancet] tracked " << name << " section: "
                  << toHex(addr) << " size: " << toHex(size) << " subject: " << id << RESET << std::endl;
        if (name == ".got.plt") {
            got_plt_start_ = addr;
            got_plt_end_ = addr + size;
        }
    }
}

VOID Instrumentation::MmapAfter(ADDRINT ret, ADDRINT length) {
    if (ret == (ADDRINT)-1 || length == 0) return; // MAP_FAILED
    ownership_->alloc_new_subject(ret, length);
    if (gConfig.debug_output)
        std::cout << "mmap(" << toHex(length) << ") -> " << toHex(ret) << std::endl;
}

VOID Instrumentation::MunmapBefore(ADDRINT addr, ADDRINT length) {
    if (!addr || length == 0) return;
    ownership_->free_subject(addr);
    if (gConfig.debug_output)
        std::cout << "munmap(" << toHex(addr) << ", " << toHex(length) << ")" << std::endl;
}

// REP MOVS handler: inline memcpy (rep movsb/movsw/movsd/movsq)
VOID Instrumentation::RepMovsBefore(ADDRINT dst, ADDRINT src, ADDRINT count, UINT32 elem_size, VOID* ip) {
    ADDRINT byte_size = count * elem_size;
    MemcpyBefore(dst, src, byte_size, ip);
}

// Per-PC dedup: combine PC + detection_type into a single key.
// Returns true if this is the first time we see this (pc, type) pair.
bool Instrumentation::shouldReport(ADDRINT pc, int detection_type) {
    uint64_t key = (pc << 4) | (detection_type & 0xf);
    return reported_detections_.insert(key).second;
}

VOID Instrumentation::RepStosBefore(ADDRINT dst, ADDRINT count, VOID* ip) {
    if (!is_record_ || gConfig.no_reasoning || count == 0) return;

    std::string addrString;
    int code_region = translate_addr(ip, addrString);
    if (code_region == TYPE_LIBC) return;

    int64_t start_owner = ownership_->get_cell_owner(dst);
    int64_t end_owner = ownership_->get_cell_owner(dst + count - 1);

    if (start_owner > STACK_SUBJECT_ID && start_owner != end_owner) {
        logOwnership->log("[STOS CROSSBOUNDARY] ip: ", addrString,
            " dst: ", toHex(dst), " count: ", (int64_t)count,
            " owner_start: ", start_owner, " owner_end: ", end_owner, "\n");
    }
    if (start_owner == HEAP_SUBJECT_ID || end_owner == HEAP_SUBJECT_ID) {
        logOwnership->log("[STOS UAF] ip: ", addrString,
            " write to freed memory at: ", toHex(dst), " count: ", (int64_t)count, "\n");
    }
}

// Semantic hook: memcpy/memmove(dst, src, size)
// Check both source read and destination write ownership at function-call level.
VOID Instrumentation::MemcpyBefore(ADDRINT dst, ADDRINT src, ADDRINT size, VOID* ip) {
    if (!is_record_ || gConfig.no_reasoning || size == 0) return;

    // Integer overflow detection: size > half of address space is always a bug
    // (e.g., SIZE_MAX from integer underflow like vlen = end - start when end < start)
    if (size > ((ADDRINT)-1 >> 1)) {
        logOwnership->log("[memcpy INTEGER OVERFLOW] dst: ", toHex(dst),
            " src: ", toHex(src), " size: ", toHex(size), " (likely integer underflow)\n");
        return;
    }

    int64_t dst_co = ownership_->get_cell_owner(dst);
    int64_t dst_end_co = ownership_->get_cell_owner(dst + size - 1);
    int64_t src_co = ownership_->get_cell_owner(src);
    int64_t src_end_co = ownership_->get_cell_owner(src + size - 1);

    // CROSSBOUNDARY: write starts in tracked allocation but ends in different or unknown region
    if (dst_co > STACK_SUBJECT_ID && dst_co != dst_end_co) {
        logOwnership->log("[memcpy CROSSBOUNDARY write] dst: ", toHex(dst),
            " size: ", (int64_t)size, " owner_start: ", dst_co, " owner_end: ", dst_end_co, "\n");
    }
    // CROSSBOUNDARY: read starts in tracked allocation but ends in different or unknown region
    if (src_co > STACK_SUBJECT_ID && src_co != src_end_co) {
        logOwnership->log("[memcpy CROSSBOUNDARY read] src: ", toHex(src),
            " size: ", (int64_t)size, " owner_start: ", src_co, " owner_end: ", src_end_co, "\n");
    }
    // UAF: writing to freed memory
    if (dst_co == HEAP_SUBJECT_ID || dst_end_co == HEAP_SUBJECT_ID) {
        logOwnership->log("[memcpy UAF write] dst: ", toHex(dst), " size: ", (int64_t)size, "\n");
    }
    // UAF: reading from freed memory
    if (src_co == HEAP_SUBJECT_ID || src_end_co == HEAP_SUBJECT_ID) {
        logOwnership->log("[memcpy UAF read] src: ", toHex(src), " size: ", (int64_t)size, "\n");
    }
    // memmove violation (paper exp04): source value owner vs dest cell owner mismatch
    if (src_co > 0 && dst_co > 0 && src_co != dst_co) {
        logOwnership->log("[memmove violation] src_vo: ", src_co, " dst_co: ", dst_co,
            " src: ", toHex(src), " dst: ", toHex(dst), " size: ", (int64_t)size, "\n");
    }
    // Track the write: memcpy initializes the destination range.
    if (dst_co > STACK_SUBJECT_ID && size <= 0x100000) {
        size_t slots = (size + 7) / 8;
        for (size_t i = 0; i < slots; i++)
            ownership_->update_value_owner(dst + i * 8, dst_co);
    }
}

// Semantic hook: memset(dst, val, size)
VOID Instrumentation::MemsetBefore(ADDRINT dst, ADDRINT val, ADDRINT size, VOID* ip) {
    if (!is_record_ || gConfig.no_reasoning || size == 0) return;

    if (size > ((ADDRINT)-1 >> 1)) {
        logOwnership->log("[memset INTEGER OVERFLOW] dst: ", toHex(dst),
            " size: ", toHex(size), " (likely integer underflow)\n");
        return;
    }

    int64_t dst_co = ownership_->get_cell_owner(dst);
    int64_t dst_end_co = ownership_->get_cell_owner(dst + size - 1);

    if (dst_co > STACK_SUBJECT_ID && dst_co != dst_end_co) {
        logOwnership->log("[memset CROSSBOUNDARY] dst: ", toHex(dst),
            " size: ", (int64_t)size, " owner_start: ", dst_co, " owner_end: ", dst_end_co, "\n");
    }
    if (dst_co == HEAP_SUBJECT_ID || dst_end_co == HEAP_SUBJECT_ID) {
        logOwnership->log("[memset UAF] dst: ", toHex(dst), " size: ", (int64_t)size, "\n");
    }
    // Track the write: memset initializes the destination range.
    if (dst_co > STACK_SUBJECT_ID && size <= 0x100000) {
        size_t slots = (size + 7) / 8;
        for (size_t i = 0; i < slots; i++)
            ownership_->update_value_owner(dst + i * 8, dst_co);
    }
}

// Semantic hook: strcpy/strncpy/strcat(dst, src, ...)
// For strcpy we don't know the length until the string is scanned,
// so we check the first byte ownership and let XedSolver catch per-byte issues.
VOID Instrumentation::StrcpyBefore(ADDRINT dst, ADDRINT src, VOID* ip) {
    if (!is_record_ || gConfig.no_reasoning) return;

    // Compute actual length via PIN_SafeCopy scan
    size_t len = 0;
    char buf;
    while (len < 0x10000) {
        if (PIN_SafeCopy(&buf, (const VOID*)(src + len), 1) != 1) break;
        if (buf == '\0') break;
        len++;
    }
    if (len == 0) return;

    int64_t dst_co = ownership_->get_cell_owner(dst);
    int64_t dst_end_co = ownership_->get_cell_owner(dst + len);

    if (dst_co != dst_end_co && dst_co > 0 && dst_end_co >= 0) {
        logOwnership->log("[strcpy CROSSBOUNDARY] dst: ", toHex(dst),
            " len: ", (int64_t)len, " owner_start: ", dst_co, " owner_end: ", dst_end_co, "\n");
    }
    if (dst_co == HEAP_SUBJECT_ID || dst_end_co == HEAP_SUBJECT_ID) {
        logOwnership->log("[strcpy UAF] dst: ", toHex(dst), " len: ", (int64_t)len, "\n");
    }
    // Track the write: strcpy initializes the destination range.
    if (dst_co > STACK_SUBJECT_ID && len <= 0x100000) {
        size_t slots = (len + 8) / 8;
        for (size_t i = 0; i < slots; i++)
            ownership_->update_value_owner(dst + i * 8, dst_co);
    }
}

void Instrumentation::append_source_loc(ADDRINT ip, std::string& out) {
    // Cache: avoid repeated DWARF + RTN lookups for the same PC
    static std::unordered_map<ADDRINT, std::string> loc_cache;
    auto it = loc_cache.find(ip);
    if (it != loc_cache.end()) {
        out += it->second;
        return;
    }
    std::string suffix;
    INT32 col = 0, line = 0;
    std::string fname;
    std::string func_name;
    PIN_LockClient();
    PIN_GetSourceLocation(ip, &col, &line, &fname);
    RTN rtn = RTN_FindByAddress(ip);
    if (RTN_Valid(rtn)) func_name = RTN_Name(rtn);
    PIN_UnlockClient();
    if (!func_name.empty() || (line > 0 && !fname.empty())) {
        suffix = " (";
        if (!func_name.empty()) {
            suffix += func_name;
        }
        if (line > 0 && !fname.empty()) {
            auto slash = fname.rfind('/');
            if (slash != std::string::npos) fname = fname.substr(slash + 1);
            if (!func_name.empty()) suffix += " @ ";
            suffix += fname + ":" + std::to_string(line);
        }
        suffix += ")";
    }
    loc_cache[ip] = suffix;
    out += suffix;
}

int Instrumentation::translate_addr(VOID* p_ip, std::string& out) {
    ADDRINT ip = (ADDRINT)p_ip;

    // Fast path: classify region without string construction
    if (ip >= libc_start_ && ip <= libc_end_) return TYPE_LIBC;
    if (ip >= main_start_ && ip <= main_end_) {
        char buf[32];
        snprintf(buf, sizeof(buf), "main+0x%lx", ip - main_start_);
        out = buf;
        append_source_loc(ip, out);
        return TYPE_MAIN;
    }
    if (ip >= target_lib_start_ && ip <= target_lib_end_) {
        char buf[40];
        snprintf(buf, sizeof(buf), "target_lib+0x%lx", ip - target_lib_start_);
        out = buf;
        append_source_loc(ip, out);
        return TYPE_TARGETLIB;
    }
    // All other regions: skip analysis (no string needed)
    return TYPE_UNKNOWN;
}

// BUG-6 fix: parse both low and high from /proc/maps
bool Instrumentation::record_heap() {
    pid_t pid = PIN_GetPid();
    std::string path = "/proc/" + std::to_string(pid) + "/maps";
    std::ifstream f(path);
    if (!f.is_open()) {
        std::cout << "[lancet] error: cannot open " << path << std::endl;
        return false;
    }

    bool found_heap = false;
    std::string line;
    while (std::getline(f, line)) {
        if (line.find("[heap]") != std::string::npos) {
            size_t dash = line.find('-');
            size_t space = line.find(' ');
            if (dash != std::string::npos && space != std::string::npos) {
                heap_start_ = std::stoul(line.substr(0, dash), nullptr, 16);
                std::cout << "[lancet] heap_start: " << toHex(heap_start_) << std::endl;
                found_heap = true;
            }
        } else if (line.find("[stack]") != std::string::npos && stack_start_ == UNKNOWN_ADDR) {
            size_t dash = line.find('-');
            size_t space = line.find(' ');
            if (dash != std::string::npos && space != std::string::npos) {
                // stack_lo is the LOW address, stack_hi is the HIGH address
                ADDRINT lo = std::stoul(line.substr(0, dash), nullptr, 16);
                ADDRINT hi = std::stoul(line.substr(dash + 1, space - dash - 1), nullptr, 16);
                stack_start_ = lo;
                stack_end_ = hi;
                std::cout << "[lancet] stack: " << toHex(lo) << " - " << toHex(hi) << std::endl;
            }
        }
    }
    f.close();

    if (found_heap) {
        ownership_->set_regions(stack_start_, stack_end_, heap_start_,
                                heap_start_ + HEAP_SIZE_ESTIMATE);
    }
    return found_heap;
}

// Compute effective address for memory operand
ADDRINT Instrumentation::compute_ea(const xed_decoded_inst_t* xedd, CONTEXT* ctx, uint32_t insSize) {
    ADDRINT seg_val = 0;
    xed_reg_enum_t seg_reg = xed_decoded_inst_get_seg_reg(xedd, 0);
    xed_reg_enum_t base_reg = xed_decoded_inst_get_base_reg(xedd, 0);
    xed_reg_enum_t index_reg = xed_decoded_inst_get_index_reg(xedd, 0);
    xed_uint_t scale = xed_decoded_inst_get_scale(xedd, 0);
    xed_int64_t disp = xed_decoded_inst_get_memory_displacement(xedd, 0);

    // BUG-9 fix: stack-allocated buffer instead of heap
    if (seg_reg == XED_REG_FS) {
        UINT8 buf[8];
        PIN_GetContextRegval(ctx, REG_SEG_FS_BASE, buf);
        seg_val = *(ADDRINT*)buf;
    } else if (seg_reg == XED_REG_GS) {
        UINT8 buf[8];
        PIN_GetContextRegval(ctx, REG_SEG_GS_BASE, buf);
        seg_val = *(ADDRINT*)buf;
    }

    ADDRINT base_val = PIN_GetContextReg(ctx, CommonTools::ConvertXedRegToPinReg(base_reg));
    ADDRINT index_val = PIN_GetContextReg(ctx, CommonTools::ConvertXedRegToPinReg(index_reg));
    ADDRINT ea = seg_val + base_val + index_val * scale + disp;

    if (base_reg == XED_REG_RIP) {
        ea += insSize;
    }
    return ea;
}
