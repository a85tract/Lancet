#ifndef LANCET_INSTRUMENTATION_HPP
#define LANCET_INSTRUMENTATION_HPP

#include "pin.H"
#include "xed-interface.h"
#include "config.hpp"
#include "common.hpp"
#include "log.hpp"
#include "ownership.hpp"
#include "allocation.hpp"
#include "dangling.hpp"
#include <unordered_map>
#include <unordered_set>

#define TYPE_LIBC      0
#define TYPE_MAIN      1
#define TYPE_HEAP      3
#define TYPE_TARGETLIB 4
#define TYPE_UNKNOWN   (-1)

#define HEAP_SIZE_ESTIMATE (0x21000ULL * 8000ULL)

struct CachedDecode {
    xed_decoded_inst_t xedd;
    const xed_inst_t* xi;
    xed_iclass_enum_t iclass;
    char disasm[200];
    std::string addr_string;
    int code_region;
    bool valid;
};

class Instrumentation {
public:
    Logger* logOwnership;
    Logger* logInsTrace;
    size_t current_pc_idx;
    DanglingPtrManager dangling_mgr_;
    AllocationManager* alloc_mgr_;

    Instrumentation();
    ~Instrumentation();

    VOID RecordMemRead(VOID* ip, VOID* addr, uint32_t insSize);
    VOID MallocBefore(ADDRINT size, CONTEXT* ctx);
    VOID MallocAfter(ADDRINT ret, ADDRINT caller = 0);
    VOID CallocBefore(ADDRINT nmemb, ADDRINT size, CONTEXT* ctx);
    VOID CallocAfter(ADDRINT ret, ADDRINT caller = 0);
    VOID ReallocBefore(ADDRINT ptr, ADDRINT size, CONTEXT* ctx);
    VOID ReallocAfter(ADDRINT ret, ADDRINT caller = 0);
    VOID FreeBefore(ADDRINT ptr, ADDRINT caller = 0);
    VOID FreeAfter();
    VOID MainBefore(CONTEXT* ctx);
    ADDRINT get_mod_size(ADDRINT Address, std::string modName);

    // XED instruction handlers (xed_handler.cpp)
    VOID XedSolverBefore(VOID* ip, VOID* addr, uint32_t insSize, uint32_t opSize, CONTEXT* ctx);
    VOID XedSolverAfter(VOID* ip, VOID* addr, uint32_t insSize, uint32_t opSize, CONTEXT* ctx);

    // REP STOS handler (rules.cpp)
    VOID RepStosBefore(ADDRINT dst, ADDRINT count, VOID* ip);

    // Semantic libc function hooks — detect ownership violations at function-call level
    // instead of tracing inside libc. Covers memcpy, memmove, memset, strcpy, strncpy, strcat.
    VOID MemcpyBefore(ADDRINT dst, ADDRINT src, ADDRINT size, VOID* ip);
    VOID MemsetBefore(ADDRINT dst, ADDRINT val, ADDRINT size, VOID* ip);
    VOID StrcpyBefore(ADDRINT dst, ADDRINT src, VOID* ip);

    // REP MOVS handler (inline memcpy)
    VOID RepMovsBefore(ADDRINT dst, ADDRINT src, ADDRINT count, UINT32 elem_size, VOID* ip);

    // mmap/munmap hooks
    VOID MmapAfter(ADDRINT ret, ADDRINT length);
    VOID MunmapBefore(ADDRINT addr, ADDRINT length);

    // Track data sections as subjects
    void trackDataSection(ADDRINT addr, size_t size, const std::string& name);

    // Stack frame tracking engine
    Ownership* getOwnership() { return ownership_; }
    void setRecord(bool v) { is_record_ = v; }
    bool record_heap();

private:
    Ownership* ownership_;
    bool heap_inited_;
    bool is_record_;
    bool was_in_libc_;
    bool has_debug_info_;
    ADDRINT heap_start_;
    ADDRINT libc_start_, libc_end_;
    ADDRINT stack_start_, stack_end_;
    ADDRINT main_start_, main_end_;
    ADDRINT target_lib_start_, target_lib_end_;

    CachedDecode cached_;

    // Per-PC dedup: only report the first occurrence of each detection type per PC
    std::unordered_set<uint64_t> reported_detections_;
    bool shouldReport(ADDRINT pc, int detection_type);

    // .got.plt region tracking for exploit primitive detection
    ADDRINT got_plt_start_, got_plt_end_;

    // Engine A: stack of active frame subjects for scope tracking
    struct FrameInfo { ADDRINT base; size_t size; };
    std::vector<FrameInfo> frame_stack_;

    void append_source_loc(ADDRINT ip, std::string& out);
    int translate_addr(VOID* p_ip, std::string& out);
    ADDRINT compute_ea(const xed_decoded_inst_t* xedd, CONTEXT* ctx, uint32_t insSize);

    // Detection rules (rules.cpp) — code_region passed to avoid string matching
    bool rulesMovWrite(ADDRINT final_ea, int64_t written_value, int64_t pointee, std::string& addrString, int code_region);
    bool rulesMovWriteImm(ADDRINT final_ea, int64_t pointee, std::string& addrString, int code_region);
    bool rulesMovRead(ADDRINT final_ea, xed_reg_enum_t base_reg_enum, ADDRINT base_reg_value, REG reg0, std::string& addrString, int code_region);
    bool rulesLeave(ADDRINT reg_rsp_value, ADDRINT reg_rbp_value);
    bool rulesXchg(REG reg1, ADDRINT reg1_value, REG reg2, ADDRINT reg2_value);
    bool rulesSyscall(CONTEXT* ctx);
    bool rulesPush(ADDRINT target_addr, int64_t pointee, std::string& addrString);
};

extern Instrumentation* gInstrumentation;

// PIN callback wrappers
VOID RecordMemReadWrapper(VOID* ip, VOID* addr, uint32_t insSize);
VOID MallocBeforeWrapper(ADDRINT size, CONTEXT* ctx);
VOID MallocAfterWrapper(ADDRINT ret);
VOID CallocBeforeWrapper(ADDRINT nmemb, ADDRINT size, CONTEXT* ctx);
VOID CallocAfterWrapper(ADDRINT ret);
VOID ReallocBeforeWrapper(ADDRINT ptr, ADDRINT size, CONTEXT* ctx);
VOID ReallocAfterWrapper(ADDRINT ret);
VOID FreeBeforeWrapper(ADDRINT ptr, CONTEXT* ctx);
VOID FreeAfterWrapper();
VOID MainBeforeWrapper(CONTEXT* ctx);
VOID XedSolverBeforeWrapper(VOID* ip, VOID* addr, uint32_t insSize, uint32_t opSize, CONTEXT* ctx);
VOID XedSolverAfterWrapper(VOID* ip, VOID* addr, uint32_t insSize, uint32_t opSize, CONTEXT* ctx);
VOID RepStosBeforeWrapper(ADDRINT dst, ADDRINT count, VOID* ip);
VOID MemcpyBeforeWrapper(ADDRINT dst, ADDRINT src, ADDRINT size, VOID* ip);
VOID MemsetBeforeWrapper(ADDRINT dst, ADDRINT val, ADDRINT size, VOID* ip);
VOID StrcpyBeforeWrapper(ADDRINT dst, ADDRINT src, VOID* ip);
VOID StackFrameEntryWrapper(ADDRINT rsp, ADDRINT frame_size, VOID* ip);
VOID StackFrameExitWrapper(ADDRINT rsp, ADDRINT rbp);
VOID RepMovsBeforeWrapper(ADDRINT dst, ADDRINT src, ADDRINT count, UINT32 elem_size, VOID* ip);
VOID MmapAfterWrapper(ADDRINT ret, ADDRINT length);
VOID MunmapBeforeWrapper(ADDRINT addr, ADDRINT length);

// RTN_ReplaceSignature wrappers (PIN 4.x — replace entire function, call original internally)
void* MallocReplace(AFUNPTR origFunc, size_t size, int size_arg_idx, CONTEXT* ctx, ADDRINT retip);
void* MallocReplaceArg1(AFUNPTR origFunc, size_t arg0, size_t arg1, CONTEXT* ctx, ADDRINT retip);
void* CallocReplace(AFUNPTR origFunc, size_t nmemb, size_t size, CONTEXT* ctx, ADDRINT retip);
void* ReallocReplace(AFUNPTR origFunc, void* ptr, size_t size, CONTEXT* ctx, ADDRINT retip);
void FreeReplace(AFUNPTR origFunc, void* ptr, int addr_arg_idx, CONTEXT* ctx, ADDRINT retip);
void FreeReplaceArg1(AFUNPTR origFunc, size_t arg0, void* ptr, CONTEXT* ctx, ADDRINT retip);
void* MmapReplace(AFUNPTR origFunc, void* addr, size_t length, int prot, int flags, int fd, size_t offset, CONTEXT* ctx, ADDRINT retip);

#endif
