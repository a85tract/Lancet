#include "instrumentation.hpp"
#include "config.hpp"
#include "registry.hpp"

bool Instrumentation::rulesMovWrite(ADDRINT final_ea, int64_t written_value, int64_t pointee, std::string& addrString, int code_region) {
    // Dedup key: hash of addrString (e.g. "main+0x1234") — stable across runs
    ADDRINT pc = std::hash<std::string>{}(addrString);

    if (final_ea < LancetRegistry::default_thresholds.nullptr_low && shouldReport(pc, DET_NULLPTR)) {
        logOwnership->log("[MovWrite nullptr deref] ip: ", addrString,
            " final_ea: ", toHex(final_ea), "\n");
    } else if (final_ea > LancetRegistry::default_thresholds.untrusted_high && shouldReport(pc, DET_NULLPTR)) {
        logOwnership->log("[MovWrite high untrusted deref] ip: ", addrString,
            " final_ea: ", toHex(final_ea), " pointee: ", pointee,
            " written: ", toHex(written_value), "\n");
    }

    // .got.plt exploit primitive detection
    if (got_plt_start_ && final_ea >= got_plt_start_ && final_ea < got_plt_end_) {
        if (shouldReport(pc, DET_GOTPLT))
            logOwnership->log("[exploit primitive] write in .got.plt region at: ", toHex(final_ea),
                " by: ", addrString, "\n");
    }

    int64_t co = ownership_->get_cell_owner(final_ea);

    // Approach B: detect intra-object pointer clobbering (32+ bit writes).
    // Read the old 8-byte value at the write address. If it's a tracked pointer
    // to a DIFFERENT allocation, and we're overwriting it with non-pointer data
    // from the SAME allocation, this indicates intra-struct overflow.
    if (co > STACK_SUBJECT_ID && co == pointee &&
        (code_region == TYPE_MAIN || code_region == TYPE_TARGETLIB)) {
        char old_buf[8] = {0};
        PIN_SafeCopy(old_buf, (VOID*)final_ea, 8);
        uint64_t old_val = *(uint64_t*)old_buf;
        int64_t old_val_co = ownership_->get_cell_owner(old_val);
        int64_t new_val_co = ownership_->get_cell_owner(written_value);
        if (old_val_co > STACK_SUBJECT_ID && old_val_co != co &&
            new_val_co <= STACK_SUBJECT_ID && written_value != 0 &&
            shouldReport(pc, DET_INTRA_OBJ)) {
            const Subject* subj = ownership_->find_subject(final_ea);
            ADDRINT offset = subj ? (final_ea - subj->base) : 0;
            logOwnership->log("[INTRA_OBJECT_OVERFLOW] ip: ", addrString,
                " at: ", toHex(final_ea), " offset: +", toHex(offset),
                " subject: ", co, " clobbers ptr ", toHex(old_val),
                " (owner: ", old_val_co, ")\n");
        }
    }

    // Don't poison vo with -1 when register lost pointee after libc call.
    // Normal write: fallback to co (the allocation owns the write).
    // UAF write (co=HEAP_SUBJECT_ID): use USER_WRITE_UNKNOWN to mark
    // "user wrote to freed memory" for TAINT detection at malloc/free.
    int64_t fallback = (co == HEAP_SUBJECT_ID) ? USER_WRITE_UNKNOWN : co;
    ownership_->update_value_owner(final_ea, (pointee >= 0) ? pointee : fallback);
    int64_t vo = ownership_->get_value_owner(final_ea);

    int64_t co_written = ownership_->get_cell_owner(written_value);
    if (co_written == HEAP_SUBJECT_ID) {
        dangling_mgr_.addDanglingPtr(final_ea, written_value, current_pc_idx);
        if (shouldReport(written_value, DET_DANGLING))
            logOwnership->log("Store dangling pointer: ", toHex(written_value), " at: ", toHex(final_ea), "\n");
    }

    if ((co == HEAP_SUBJECT_ID || vo == HEAP_SUBJECT_ID) && shouldReport(pc, DET_UAF_W)) {
        logOwnership->log("[INCONSISTENCY mov write reg UAF] ip: ", addrString,
            " UAF write at: ", toHex(final_ea), "\n");
        if (dangling_mgr_.hasDanglingRecord(final_ea)) {
            size_t first = dangling_mgr_.getFirstDanglingIdx(final_ea);
            logOwnership->log("first time found dangling pointer at: ", first,
                " distance: ", current_pc_idx - first, "\n");
        }
    }
    // Heap write with untracked pointer (pointee=-1): external input or clobbered register
    else if (co > STACK_SUBJECT_ID && pointee == -1 && shouldReport(pc, DET_INCON_W)) {
        logOwnership->log("[INCONSISTENCY mov write reg] ip: ", addrString,
            " co: ", co, " vo: ", vo, ", ", vo, " write ", co, "\n");
    }
    return true;
}

bool Instrumentation::rulesMovWriteImm(ADDRINT final_ea, int64_t pointee, std::string& addrString, int code_region) {
    ADDRINT pc = std::hash<std::string>{}(addrString);

    // .got.plt exploit primitive
    if (got_plt_start_ && final_ea >= got_plt_start_ && final_ea < got_plt_end_) {
        if (shouldReport(pc, DET_GOTPLT))
            logOwnership->log("[exploit primitive] write in .got.plt region at: ", toHex(final_ea),
                " by: ", addrString, "\n");
    }

    int64_t co = ownership_->get_cell_owner(final_ea);
    int64_t fallback_imm = (co == HEAP_SUBJECT_ID) ? USER_WRITE_UNKNOWN : co;
    ownership_->update_value_owner(final_ea, (pointee >= 0) ? pointee : fallback_imm);
    int64_t vo = ownership_->get_value_owner(final_ea);

    // co != vo alone is not a bug — only report UAF (freed memory).
    if ((co == HEAP_SUBJECT_ID || vo == HEAP_SUBJECT_ID) && shouldReport(pc, DET_UAF_W)) {
        logOwnership->log("[INCONSISTENCY mov write imm UAF] ip: ", addrString,
            " UAF write at: ", toHex(final_ea), "\n");
        if (dangling_mgr_.hasDanglingRecord(final_ea)) {
            size_t first = dangling_mgr_.getFirstDanglingIdx(final_ea);
            logOwnership->log("first time found dangling pointer at: ", first,
                " distance: ", current_pc_idx - first, "\n");
        }
    }
    return true;
}

bool Instrumentation::rulesMovRead(ADDRINT final_ea, xed_reg_enum_t base_reg_enum,
                                   ADDRINT base_reg_value, REG reg0, std::string& addrString, int code_region) {
    ADDRINT pc = std::hash<std::string>{}(addrString);

    // Null/low address dereference
    if (final_ea < LancetRegistry::default_thresholds.nullptr_low && shouldReport(pc, DET_NULLPTR)) {
        logOwnership->log("[MovRead nullptr deref] ip: ", addrString,
            " final_ea: ", toHex(final_ea), "\n");
    }
    // High untrusted address dereference (corrupted pointer, e.g. 0x6363636363636371)
    else if (final_ea > LancetRegistry::default_thresholds.untrusted_high && shouldReport(pc, DET_NULLPTR)) {
        int64_t pointee_early = ownership_->get_reg_pointee(CommonTools::ConvertXedRegToPinReg(base_reg_enum));
        int64_t base_vo = ownership_->get_value_owner(base_reg_value);
        const Subject* src_subj = ownership_->find_subject(base_reg_value);
        logOwnership->log("[MovRead high untrusted deref] ip: ", addrString,
            " final_ea: ", toHex(final_ea),
            " base: ", toHex(base_reg_value), " pointee: ", pointee_early,
            " base_vo: ", base_vo,
            src_subj ? " src_subject: " : "", src_subj ? std::to_string(src_subj->id) : "",
            src_subj ? " src_base: " : "", src_subj ? toHex(src_subj->base) : "",
            "\n");
    }

    int64_t pointee = ownership_->get_reg_pointee(CommonTools::ConvertXedRegToPinReg(base_reg_enum));
    int64_t co = ownership_->get_cell_owner(final_ea);

    // UAF or stack-use-after-scope: if co==0 on a stack address, it's use-after-scope
    if ((pointee == HEAP_SUBJECT_ID || co == HEAP_SUBJECT_ID) && shouldReport(pc, DET_UAF_R)) {
        // A stack address with freed status → use-after-scope (returned stack var)
        bool on_stack = (base_reg_value != 0 &&
                         ownership_->get_cell_owner(base_reg_value) == STACK_SUBJECT_ID);
        if (on_stack && co == HEAP_SUBJECT_ID) {
            logOwnership->log("STACKREADUSEAFTERSCOPE at: ", toHex(final_ea),
                " ip: ", addrString, "\n");
        } else {
            logOwnership->log("[INCONSISTENCY mov read UAF] ip: ", addrString,
                " UAF read at: ", toHex(final_ea), "\n");
        }
        if (dangling_mgr_.hasDanglingRecord(final_ea)) {
            size_t first = dangling_mgr_.getFirstDanglingIdx(final_ea);
            logOwnership->log("first time found dangling pointer at: ", first,
                " distance: ", current_pc_idx - first, "\n");
        }
    }
    // UNTRUSTEDPTRDEREF: reading from address outside all known regions,
    // only in main/target_lib code (not libc/unknown shared libraries)
    else if (co == -1 && final_ea >= 0x10000 && final_ea <= LancetRegistry::default_thresholds.untrusted_high &&
             (code_region == TYPE_MAIN || code_region == TYPE_TARGETLIB) &&
             shouldReport(pc, DET_INCON_R)) {
        int64_t base_vo = ownership_->get_value_owner(base_reg_value);
        const Subject* src_subj = ownership_->find_subject(base_reg_value);
        // Suppress when base pointer comes from .data/.bss (global/static storage).
        // These are legitimate program pointers, not corruption artifacts.
        // .data = subject 2, .bss = subject 3 (first two tracked sections).
        bool from_static = (src_subj && src_subj->id >= 2 && src_subj->id <= 3);
        // Suppress pointers loaded before tracking started: RIP-relative loads
        // produce base=0 with pointee=-1 (register never updated by XED hooks).
        bool pre_tracking = (base_reg_value == 0 && pointee == -1);
        if (!from_static && !pre_tracking) {
            logOwnership->log("[UNTRUSTEDPTRDEREF] ip: ", addrString,
                " final_ea: ", toHex(final_ea),
                " base: ", toHex(base_reg_value), " pointee: ", pointee,
                " base_vo: ", base_vo,
                src_subj ? " src_subject: " : "", src_subj ? std::to_string(src_subj->id) : "",
                src_subj ? " src_base: " : "", src_subj ? toHex(src_subj->base) : "",
                "\n");
        }
    }
    // INCONSISTENCY mov read: heap pointer reads from different subject (OOB read)
    // Only in main/target_lib to avoid noise from shared library internals
    else if (pointee != co && final_ea != base_reg_value &&
             pointee > STACK_SUBJECT_ID && co > STACK_SUBJECT_ID &&
             (code_region == TYPE_MAIN || code_region == TYPE_TARGETLIB) &&
             shouldReport(pc, DET_INCON_R)) {
        logOwnership->log("[INCONSISTENCY mov read] ip: ", addrString,
            " base: ", toHex(base_reg_value), " pointee: ", pointee, " read from ", co, "\n");
    }
    // UNINITIALIZED: reading from tracked allocation where value owner was never set
    if (co > STACK_SUBJECT_ID && ownership_->get_value_owner(final_ea) == -1 &&
        pointee == co && shouldReport(pc, DET_UNINITIALIZED)) {
        logOwnership->log("[UNINITIALIZED mov read] ip: ", addrString,
            " co: ", co, " vo: -1\n");
    }

    // Post-action: read the value and track ownership
    char op0[8] = {0};
    PIN_SafeCopy(op0, (VOID*)final_ea, 8);
    uint64_t read_val = *(uint64_t*)op0;
    int64_t val_owner = ownership_->get_cell_owner(read_val);

    if (CommonTools::is_valid_pointer(read_val) && dangling_mgr_.isExpiredPtr(final_ea, read_val)) {
        if (shouldReport(read_val, DET_EXPIRED)) {
            logOwnership->log(addrString, " Using expired pointer: ", toHex(read_val),
                " from ", toHex(final_ea), "\n");
            // Distance lookup uses final_ea (the store address), matching addDanglingPtr's key
            if (dangling_mgr_.hasDanglingRecord(final_ea)) {
                size_t first = dangling_mgr_.getFirstDanglingIdx(final_ea);
                logOwnership->log("first time found dangling pointer at: ", first,
                    " distance: ", current_pc_idx - first, "\n");
            }
        }
    }

    if (val_owner == HEAP_SUBJECT_ID) {
        dangling_mgr_.addDanglingPtr(final_ea, read_val, current_pc_idx);
        if (shouldReport(read_val, DET_DANGLING))
            logOwnership->log(addrString, " Read a dangling pointer ", toHex(read_val),
                " from ", toHex(final_ea), "\n");
    }

    // With struct sub-subjects: detect reads where co != vo, meaning the
    // cell was written by a different sub-subject (intra-struct overflow).
    // Without struct layouts, co != vo is normal for linked data structures.
    if (ownership_->struct_layout_count() > 0) {
        int64_t src_vo = ownership_->get_value_owner(final_ea);
        if (co > STACK_SUBJECT_ID && src_vo > STACK_SUBJECT_ID && src_vo != co &&
            (code_region == TYPE_MAIN || code_region == TYPE_TARGETLIB) &&
            shouldReport(pc, DET_INTRA_OBJ)) {
            logOwnership->log("[CORRUPTED_PTR_LOAD] ip: ", addrString,
                " loaded: ", toHex(read_val), " from cell: ", toHex(final_ea),
                " cell_owner: ", co, " value_owner: ", src_vo, "\n");
        }
    }

    if (reg0 != REG_INVALID()) {
        ownership_->assign_reg_pointee(reg0, read_val);
    }
    return true;
}

bool Instrumentation::rulesLeave(ADDRINT reg_rsp_value, ADDRINT reg_rbp_value) {
    int64_t rsp_id = ownership_->get_cell_owner(reg_rsp_value);
    int64_t rbp_id = ownership_->get_cell_owner(reg_rbp_value);
    ownership_->assign_reg_pointee_id(REG_RSP, rsp_id);
    ownership_->assign_reg_pointee_id(REG_RBP, rbp_id);
    return true;
}

bool Instrumentation::rulesXchg(REG reg1, ADDRINT reg1_value, REG reg2, ADDRINT reg2_value) {
    if (reg1 != REG_INVALID()) {
        int64_t id = ownership_->get_cell_owner(reg1_value);
        ownership_->assign_reg_pointee_id(reg1, id);
    }
    if (reg2 != REG_INVALID()) {
        int64_t id = ownership_->get_cell_owner(reg2_value);
        ownership_->assign_reg_pointee_id(reg2, id);
    }
    return true;
}

bool Instrumentation::rulesSyscall(CONTEXT* ctx) {
    static const REG syscall_regs[] = {REG_RAX, REG_RCX, REG_R11};
    for (auto reg : syscall_regs) {
        ADDRINT val = PIN_GetContextReg(ctx, reg);
        ownership_->assign_reg_pointee(reg, val);
    }
    return true;
}

bool Instrumentation::rulesPush(ADDRINT target_addr, int64_t pointee, std::string& addrString) {
    ownership_->update_value_owner(target_addr, pointee);
    return true;
}
