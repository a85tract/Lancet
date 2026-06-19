/*
 * Lancet: A Formalization Framework for Crash and Exploit Pathology
 * USENIX Security 2025 — Dai, Linvill, Chen, Kaki
 *
 * Reorganized and bug-fixed implementation.
 */
#include <iostream>
#include <fstream>
#include <sstream>
#include "common.hpp"
#include "config.hpp"
#include "registry.hpp"
#include "instrumentation.hpp"

using std::cerr;
using std::endl;

// Global state
Instrumentation* gInstrumentation = nullptr;
LancetConfig gConfig;

// PIN KNOBs (command-line arguments)
static KNOB<BOOL> KnobNoLog(KNOB_MODE_WRITEONCE, "pintool", "nolog", "1",
    "Disable ownership/trace logging (default: on)");
static KNOB<BOOL> KnobNoReasoning(KNOB_MODE_WRITEONCE, "pintool", "noreason", "0",
    "Disable ownership reasoning/rules");
static KNOB<BOOL> KnobNoHeap(KNOB_MODE_WRITEONCE, "pintool", "noheap", "0",
    "Disable heap allocation tracking");
static KNOB<BOOL> KnobDebug(KNOB_MODE_WRITEONCE, "pintool", "debug", "0",
    "Enable verbose debug output");
static KNOB<std::string> KnobTargetLib(KNOB_MODE_WRITEONCE, "pintool", "targetlib", "",
    "Target library name to instrument (e.g. libgpac.so)");
static KNOB<std::string> KnobSkipFuncs(KNOB_MODE_WRITEONCE, "pintool", "skip", "",
    "Comma-separated list of functions to skip");
static KNOB<std::string> KnobLogDir(KNOB_MODE_WRITEONCE, "pintool", "logdir", "./logs",
    "Directory for log output");
static KNOB<std::string> KnobAllocFunc(KNOB_MODE_WRITEONCE, "pintool", "malloc", "malloc",
    "Allocation function name (e.g. _emalloc for PHP Zend)");
static KNOB<std::string> KnobFreeFunc(KNOB_MODE_WRITEONCE, "pintool", "free", "free",
    "Free function name (e.g. _efree for PHP Zend)");
static KNOB<std::string> KnobCallocFunc(KNOB_MODE_WRITEONCE, "pintool", "calloc", "calloc",
    "Calloc function name");
static KNOB<std::string> KnobReallocFunc(KNOB_MODE_WRITEONCE, "pintool", "realloc", "realloc",
    "Realloc function name");
static KNOB<std::string> KnobStructLayout(KNOB_MODE_WRITEONCE, "pintool", "struct_layout", "",
    "Struct layout file for field-level sub-subject splitting");

// Skip sites: [start, end) ranges of addresses to skip instrumentation
static std::vector<std::pair<ADDRINT, ADDRINT>> skipsites;

static std::vector<std::string> parse_csv(const std::string& s) {
    std::vector<std::string> result;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (!item.empty()) result.push_back(item);
    }
    return result;
}

VOID rtn_callback(RTN rtn, VOID* v) {
    std::string name = RTN_Name(rtn);

    // Stack frame cleanup on function return is now handled in XedSolverBefore's
    // RET_NEAR/RET_FAR handler (instruction-level), replacing the rtn_callback
    // IPOINT_AFTER approach which doesn't fire reliably on PIN 4.x.

    // Skip ASAN/sanitizer functions
    if (name.find("asan") != std::string::npos || name.find("sanitizer") != std::string::npos) {
        RTN_Open(rtn);
        ADDRINT start = RTN_Address(rtn);
        ADDRINT end = start + RTN_Size(rtn);
        skipsites.push_back(std::make_pair(start, end));
        RTN_Close(rtn);
        return;
    }
    // Skip user-specified functions
    for (auto& skip : gConfig.skip_funcs) {
        if (name == skip) {
            RTN_Open(rtn);
            ADDRINT start = RTN_Address(rtn);
            ADDRINT end = start + RTN_Size(rtn);
            skipsites.push_back(std::make_pair(start, end));
            if (gConfig.debug_output)
                std::cout << "[lancet] Skip: " << skip << " [" << toHex(start) << ", " << toHex(end) << ")" << std::endl;
            RTN_Close(rtn);
        }
    }
}

VOID ins_callback(INS ins, VOID* v) {
    ADDRINT addr = INS_Address(ins);
    for (auto& skip : skipsites) {
        if (addr >= skip.first && addr < skip.second) return;
    }

    // REP STOS (memset): track ownership of destination range
    UINT32 opcode = INS_Opcode(ins);
    if (opcode == XED_ICLASS_REP_STOSB || opcode == XED_ICLASS_REP_STOSD ||
        opcode == XED_ICLASS_REP_STOSQ || opcode == XED_ICLASS_REP_STOSW) {
        INS_InsertCall(ins, IPOINT_BEFORE,
            (AFUNPTR)RepStosBeforeWrapper,
            IARG_REG_VALUE, REG_RDI,
            IARG_REG_VALUE, REG_RCX,
            IARG_INST_PTR,
            IARG_END);
        return;
    }
    // REP MOVS (inline memcpy): track ownership of src→dst copy range
    // RCX = element count. Element size: MOVSB=1, MOVSW=2, MOVSD=4, MOVSQ=8
    if (opcode == XED_ICLASS_REP_MOVSB || opcode == XED_ICLASS_REP_MOVSD ||
        opcode == XED_ICLASS_REP_MOVSQ || opcode == XED_ICLASS_REP_MOVSW) {
        // Use RepMovsBefore which scales RCX to bytes
        UINT32 elem_size = (opcode == XED_ICLASS_REP_MOVSB) ? 1 :
                           (opcode == XED_ICLASS_REP_MOVSW) ? 2 :
                           (opcode == XED_ICLASS_REP_MOVSD) ? 4 : 8;
        INS_InsertCall(ins, IPOINT_BEFORE,
            (AFUNPTR)RepMovsBeforeWrapper,
            IARG_REG_VALUE, REG_RDI,   // dst
            IARG_REG_VALUE, REG_RSI,   // src
            IARG_REG_VALUE, REG_RCX,   // count (elements)
            IARG_UINT32, elem_size,
            IARG_INST_PTR,
            IARG_END);
        return;
    }
    // Single STOS/MOVS without REP: skip
    if (opcode == XED_ICLASS_STOSB || opcode == XED_ICLASS_STOSD ||
        opcode == XED_ICLASS_STOSQ || opcode == XED_ICLASS_STOSW ||
        opcode == XED_ICLASS_MOVSB || opcode == XED_ICLASS_MOVSD ||
        opcode == XED_ICLASS_MOVSQ || opcode == XED_ICLASS_MOVSW) {
        return;
    }

    // XED-based instruction analysis
    INS_InsertCall(ins, IPOINT_BEFORE,
        (AFUNPTR)XedSolverBeforeWrapper,
        IARG_CALL_ORDER, 100,
        IARG_INST_PTR, IARG_UINT32, 0,
        IARG_UINT32, INS_Size(ins), IARG_UINT32, 0,
        IARG_CONTEXT, IARG_END);

    if (INS_IsValidForIpointAfter(ins)) {
        INS_InsertCall(ins, IPOINT_AFTER,
            (AFUNPTR)XedSolverAfterWrapper,
            IARG_CALL_ORDER, 101,
            IARG_INST_PTR, IARG_UINT32, 0,
            IARG_UINT32, INS_Size(ins), IARG_UINT32, 0,
            IARG_CONTEXT, IARG_END);
    }

    // Lazy heap initialization via first memory read
    UINT32 memOps = INS_MemoryOperandCount(ins);
    for (UINT32 i = 0; i < memOps; i++) {
        if (INS_MemoryOperandIsRead(ins, i)) {
            INS_InsertCall(ins, IPOINT_BEFORE,
                (AFUNPTR)RecordMemReadWrapper,
                IARG_CALL_ORDER, 101,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, i,
                IARG_UINT32, INS_Size(ins),
                IARG_END);
        }
    }
}

VOID image_callback(IMG img, VOID* v) {
    std::string imgName = IMG_Name(img);
    ADDRINT base = IMG_LowAddress(img);

    // Hook main()
    RTN mainRtn = RTN_FindByName(img, "main");
    ADDRINT mainAddr = RTN_Address(mainRtn);
    ADDRINT mainBase = CommonTools::get_mod_base(mainAddr);

    // Auto-detect custom allocators from registry
    if (gConfig.alloc_func == "malloc") {
        for (const auto& sig : LancetRegistry::known_allocators) {
            if (!sig.probe_symbol) break;
            RTN r = RTN_FindByName(img, sig.probe_symbol);
            if (RTN_Valid(r)) {
                gConfig.alloc_func = sig.alloc_func;
                gConfig.free_func  = sig.free_func;
                if (sig.calloc_func)  gConfig.calloc_func  = sig.calloc_func;
                if (sig.realloc_func) gConfig.realloc_func = sig.realloc_func;
                gConfig.alloc_size_arg = sig.size_arg;
                gConfig.free_addr_arg  = sig.free_addr_arg;
                std::cout << GREEN << "[lancet] Auto-detected " << sig.display_name
                          << " allocator: " << sig.alloc_func << "/" << sig.free_func
                          << " size_arg=" << sig.size_arg << RESET << std::endl;
                break;
            }
        }
    }

    // Hook main() and track sections
    if (mainBase != UNKNOWN_ADDR) {
        gInstrumentation->get_mod_size(mainBase, "main");
        for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
            std::string secName = SEC_Name(sec);
            for (const auto& sd : LancetRegistry::tracked_sections) {
                if (!sd.name) break;
                if (secName == sd.name) {
                    gInstrumentation->trackDataSection(SEC_Address(sec), SEC_Size(sec), secName);
                    break;
                }
            }
        }
        if (RTN_Valid(mainRtn)) {
            RTN_Open(mainRtn);
            RTN_InsertCall(mainRtn, IPOINT_BEFORE, (AFUNPTR)MainBeforeWrapper,
                IARG_CONTEXT, IARG_END);
            RTN_Close(mainRtn);
        }
        // For statically linked binaries: if a custom allocator was auto-detected
        // and lives in the main image, hook it here before returning.
        if (gConfig.alloc_func != "malloc") {
            PROTO pa = PROTO_Allocate(PIN_PARG(void*), CALLINGSTD_DEFAULT,
                "palloc", PIN_PARG(size_t), PIN_PARG(size_t), PIN_PARG_END());
            PROTO pf = PROTO_Allocate(PIN_PARG(void), CALLINGSTD_DEFAULT,
                "pfree", PIN_PARG(size_t), PIN_PARG(void*), PIN_PARG_END());
            RTN allocRtn = RTN_FindByName(img, gConfig.alloc_func.c_str());
            RTN freeRtn2 = RTN_FindByName(img, gConfig.free_func.c_str());
            if (RTN_Valid(allocRtn)) {
                RTN_ReplaceSignature(allocRtn, (AFUNPTR)MallocReplaceArg1,
                    IARG_PROTOTYPE, pa, IARG_ORIG_FUNCPTR,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_CONTEXT, IARG_RETURN_IP, IARG_END);
            }
            if (RTN_Valid(freeRtn2)) {
                RTN_ReplaceSignature(freeRtn2, (AFUNPTR)FreeReplaceArg1,
                    IARG_PROTOTYPE, pf, IARG_ORIG_FUNCPTR,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_CONTEXT, IARG_RETURN_IP, IARG_END);
            }
            for (const auto& alias : LancetRegistry::allocator_aliases) {
                if (!alias.parent_alloc) break;
                if (gConfig.alloc_func != alias.parent_alloc) continue;
                RTN aliasRtn = RTN_FindByName(img, alias.alias_func);
                if (RTN_Valid(aliasRtn)) {
                    RTN_ReplaceSignature(aliasRtn, (AFUNPTR)MallocReplaceArg1,
                        IARG_PROTOTYPE, pa, IARG_ORIG_FUNCPTR,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                        IARG_CONTEXT, IARG_RETURN_IP, IARG_END);
                    std::cout << GREEN << "[lancet] Hooked allocator alias: "
                              << alias.alias_func << RESET << std::endl;
                }
            }
        }
        return;
    }

    // Check for target library
    if (!gConfig.target_lib.empty() && imgName.find(gConfig.target_lib) != std::string::npos) {
        std::cout << GREEN << "Target lib: " << imgName << " base: " << toHex(base) << RESET << std::endl;
        gInstrumentation->get_mod_size(base, "target_lib");
        return;
    }

    // Hook allocator functions via RTN_ReplaceSignature (PIN 4.x compatible)
    // Skip non-libc images for standard malloc — hooking PLT stubs in the main
    // image can conflict with the real libc hook on some PIE binaries.
    // Hook allocator functions via RTN_ReplaceSignature (PIN 4.x compatible)
    RTN mallocRtn  = RTN_FindByName(img, gConfig.alloc_func.c_str());
    RTN callocRtn  = RTN_FindByName(img, gConfig.calloc_func.c_str());
    RTN reallocRtn = RTN_FindByName(img, gConfig.realloc_func.c_str());
    RTN freeRtn    = RTN_FindByName(img, gConfig.free_func.c_str());

    ADDRINT mallocAddr = RTN_Address(mallocRtn);
    ADDRINT libcBase = CommonTools::get_mod_base(mallocAddr);

    if (libcBase != UNKNOWN_ADDR && imgName.find("libc") != std::string::npos) {
        gInstrumentation->get_mod_size(libcBase, "libc");
    }

    PROTO protoMalloc = PROTO_Allocate(PIN_PARG(void*), CALLINGSTD_DEFAULT,
        "malloc", PIN_PARG(size_t), PIN_PARG_END());
    PROTO protoMalloc2 = PROTO_Allocate(PIN_PARG(void*), CALLINGSTD_DEFAULT,
        "palloc", PIN_PARG(size_t), PIN_PARG(size_t), PIN_PARG_END());
    PROTO protoCalloc = PROTO_Allocate(PIN_PARG(void*), CALLINGSTD_DEFAULT,
        "calloc", PIN_PARG(size_t), PIN_PARG(size_t), PIN_PARG_END());
    PROTO protoRealloc = PROTO_Allocate(PIN_PARG(void*), CALLINGSTD_DEFAULT,
        "realloc", PIN_PARG(void*), PIN_PARG(size_t), PIN_PARG_END());
    PROTO protoFree = PROTO_Allocate(PIN_PARG(void), CALLINGSTD_DEFAULT,
        "free", PIN_PARG(void*), PIN_PARG_END());
    PROTO protoFree2 = PROTO_Allocate(PIN_PARG(void), CALLINGSTD_DEFAULT,
        "pfree", PIN_PARG(size_t), PIN_PARG(void*), PIN_PARG_END());

    if (RTN_Valid(mallocRtn)) {
        if (gConfig.alloc_size_arg == 0) {
            RTN_ReplaceSignature(mallocRtn, (AFUNPTR)MallocReplace,
                IARG_PROTOTYPE, protoMalloc,
                IARG_ORIG_FUNCPTR,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_UINT32, 0,
                IARG_CONTEXT, IARG_RETURN_IP, IARG_END);
        } else {
            RTN_ReplaceSignature(mallocRtn, (AFUNPTR)MallocReplaceArg1,
                IARG_PROTOTYPE, protoMalloc2,
                IARG_ORIG_FUNCPTR,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_CONTEXT, IARG_RETURN_IP, IARG_END);
        }
    }

    if (RTN_Valid(callocRtn)) {
        RTN_ReplaceSignature(callocRtn, (AFUNPTR)CallocReplace,
            IARG_PROTOTYPE, protoCalloc,
            IARG_ORIG_FUNCPTR,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_CONTEXT, IARG_RETURN_IP, IARG_END);
    }

    if (RTN_Valid(reallocRtn)) {
        RTN_ReplaceSignature(reallocRtn, (AFUNPTR)ReallocReplace,
            IARG_PROTOTYPE, protoRealloc,
            IARG_ORIG_FUNCPTR,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_CONTEXT, IARG_RETURN_IP, IARG_END);
    }

    if (RTN_Valid(freeRtn)) {
        if (gConfig.free_addr_arg == 0) {
            RTN_ReplaceSignature(freeRtn, (AFUNPTR)FreeReplace,
                IARG_PROTOTYPE, protoFree,
                IARG_ORIG_FUNCPTR,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_UINT32, 0,
                IARG_CONTEXT, IARG_RETURN_IP, IARG_END);
        } else {
            RTN_ReplaceSignature(freeRtn, (AFUNPTR)FreeReplaceArg1,
                IARG_PROTOTYPE, protoFree2,
                IARG_ORIG_FUNCPTR,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_CONTEXT, IARG_RETURN_IP, IARG_END);
        }
    }

    // Hook allocator aliases (e.g. ngx_pcalloc, ngx_pnalloc for nginx)
    for (const auto& alias : LancetRegistry::allocator_aliases) {
        if (!alias.parent_alloc) break;
        if (gConfig.alloc_func != alias.parent_alloc) continue;
        RTN aliasRtn = RTN_FindByName(img, alias.alias_func);
        if (RTN_Valid(aliasRtn)) {
            if (alias.size_arg == 0) {
                RTN_ReplaceSignature(aliasRtn, (AFUNPTR)MallocReplace,
                    IARG_PROTOTYPE, protoMalloc,
                    IARG_ORIG_FUNCPTR,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_UINT32, 0,
                    IARG_CONTEXT, IARG_RETURN_IP, IARG_END);
            } else {
                RTN_ReplaceSignature(aliasRtn, (AFUNPTR)MallocReplaceArg1,
                    IARG_PROTOTYPE, protoMalloc2,
                    IARG_ORIG_FUNCPTR,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_CONTEXT, IARG_RETURN_IP, IARG_END);
            }
            std::cout << GREEN << "[lancet] Hooked allocator alias: " << alias.alias_func << RESET << std::endl;
        }
    }

    // Registry-driven semantic hooks — iterate all routines, match against registry
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
            std::string rname = RTN_Name(rtn);

            for (const auto& hook : LancetRegistry::libc_hooks) {
                if (!hook.name) break;
                bool match = hook.prefix_match
                    ? (rname.find(hook.name) == 0)
                    : (rname == hook.name);
                if (!match) continue;

                RTN_Open(rtn);
                switch (hook.semantic) {
                case SEM_MEMCPY:
                    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MemcpyBeforeWrapper,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                        IARG_INST_PTR, IARG_END);
                    break;
                case SEM_MEMSET:
                    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MemsetBeforeWrapper,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                        IARG_INST_PTR, IARG_END);
                    break;
                case SEM_STRCPY:
                    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)StrcpyBeforeWrapper,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                        IARG_INST_PTR, IARG_END);
                    break;
                case SEM_CHK_FAIL:
                    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)(+[](VOID* ip) {
                        if (gInstrumentation && gInstrumentation->logOwnership) {
                            gInstrumentation->logOwnership->log(
                                "[FORTIFY buffer overflow detected] at analyzed_ins_cnt: ",
                                (int64_t)gInstrumentation->current_pc_idx, "\n");
                            gInstrumentation->logOwnership->flush();
                        }
                        std::cout << "[lancet] FORTIFY overflow detected" << std::endl;
                    }), IARG_INST_PTR, IARG_END);
                    break;
                case SEM_MMAP:
                {
                    // mmap cannot use RTN_ReplaceSignature — PIN itself uses mmap
                    // internally and replacing it crashes the runtime. Use IPOINT_AFTER
                    // with IARG_PROTOTYPE for PIN 4.x compatibility.
                    PROTO protoMmap = PROTO_Allocate(PIN_PARG(void*), CALLINGSTD_DEFAULT,
                        "mmap", PIN_PARG(void*), PIN_PARG(size_t), PIN_PARG(int),
                        PIN_PARG(int), PIN_PARG(int), PIN_PARG(size_t), PIN_PARG_END());
                    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MmapAfterWrapper,
                        IARG_PROTOTYPE, protoMmap,
                        IARG_FUNCRET_EXITPOINT_VALUE,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                        IARG_END);
                    break;
                }
                case SEM_MUNMAP:
                    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MunmapBeforeWrapper,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                        IARG_END);
                    break;
                default:
                    break;
                }
                RTN_Close(rtn);
                break; // matched — don't check remaining registry entries for this RTN
            }
        }
    }
}

VOID Fini(INT32 code, VOID* v) {
    std::cout << GREEN << "[lancet] Exited successfully." << RESET << std::endl;
    delete gInstrumentation;
    gInstrumentation = nullptr;
}

VOID ForkChildCallback(THREADID tid, const CONTEXT* ctx, VOID* v) {
    std::cout << GREEN << "[lancet] fork: child process started, re-initializing"
              << RESET << std::endl;
    if (gInstrumentation) {
        gInstrumentation->record_heap();
        gInstrumentation->setRecord(true);
        gInstrumentation->getOwnership()->init_regs(const_cast<CONTEXT*>(ctx));
    }
}

// PIN internal exception handler: survive crashes from corrupted pointer dereferences.
// Instead of PIN crashing with "Tool caused signal 11", flush logs and report.
EXCEPT_HANDLING_RESULT InternalExceptionHandler(THREADID tid, EXCEPTION_INFO* pExceptInfo, PHYSICAL_CONTEXT* pCtx, VOID* v) {
    ADDRINT fault_addr = PIN_GetExceptionAddress(pExceptInfo);
    (void)PIN_GetExceptionCode(pExceptInfo);
    ADDRINT pc = PIN_GetPhysicalContextReg(pCtx, REG_INST_PTR);

    if (gInstrumentation && gInstrumentation->logOwnership) {
        std::string addrStr;
        gInstrumentation->logOwnership->log("[CRASH] signal at PC: ", toHex(pc),
            " fault_addr: ", toHex(fault_addr), "\n");
        if (fault_addr < 0x10000 || fault_addr > 0x7fffffffffff) {
            gInstrumentation->logOwnership->log("[MovRead high untrusted deref] ip: ", toHex(pc),
                " final_ea: ", toHex(fault_addr), "\n");
        }
        gInstrumentation->logOwnership->flush();
    }

    std::cout << RED << "[lancet] CRASH at PC " << toHex(pc)
              << " accessing " << toHex(fault_addr) << RESET << std::endl;

    PIN_ExitProcess(139); // 128 + SIGSEGV(11)
    return EHR_UNHANDLED;
}

INT32 Usage() {
    cerr << "Lancet: heap ownership-based vulnerability detector" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

int main(int argc, char* argv[]) {
    setbuf(stdout, NULL);

    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return Usage();

    // Populate global config from KNOBs
    gConfig.no_log          = KnobNoLog.Value();
    gConfig.no_reasoning    = KnobNoReasoning.Value();
    gConfig.no_heap_analysis = KnobNoHeap.Value();
    gConfig.debug_output    = KnobDebug.Value();
    gConfig.target_lib      = KnobTargetLib.Value();
    gConfig.skip_funcs      = parse_csv(KnobSkipFuncs.Value());
    gConfig.log_dir         = KnobLogDir.Value();
    gConfig.alloc_func      = KnobAllocFunc.Value();
    gConfig.free_func       = KnobFreeFunc.Value();
    gConfig.calloc_func     = KnobCallocFunc.Value();
    gConfig.realloc_func    = KnobReallocFunc.Value();
    gConfig.alloc_size_arg  = 0;
    gConfig.free_addr_arg   = 0;

    std::cout << GREEN << "[lancet] Config: nolog=" << gConfig.no_log
              << " noreason=" << gConfig.no_reasoning
              << " noheap=" << gConfig.no_heap_analysis
              << " targetlib=" << gConfig.target_lib
              << " malloc=" << gConfig.alloc_func
              << " free=" << gConfig.free_func
              << " logdir=" << gConfig.log_dir << RESET << std::endl;

    gInstrumentation = new Instrumentation();

    // Load struct layouts for field-level sub-subject splitting (Approach A)
    std::string struct_layout_path = KnobStructLayout.Value();
    if (!struct_layout_path.empty()) {
        gInstrumentation->getOwnership()->load_struct_layouts(struct_layout_path);
    }

    RTN_AddInstrumentFunction(rtn_callback, 0);
    IMG_AddInstrumentFunction(image_callback, 0);
    INS_AddInstrumentFunction(ins_callback, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_AddInternalExceptionHandler(InternalExceptionHandler, 0);
    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, ForkChildCallback, 0);

    PIN_StartProgram();
    return 0;
}
