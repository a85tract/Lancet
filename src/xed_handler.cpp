#include "registry.hpp"
#include "instrumentation.hpp"
#include "config.hpp"
#include <cstdint>

VOID Instrumentation::XedSolverBefore(VOID* ip, VOID* addr, uint32_t insSize, uint32_t opSize, CONTEXT* ctx) {
    if (!is_record_ || gConfig.no_reasoning) return;

    // Hot-path filter: skip PCs that have been analyzed many times without new findings.
    // This eliminates repeated analysis of hot loops (e.g., pixel processing, parser loops).
    static std::unordered_map<ADDRINT, uint16_t> exec_count;
    ADDRINT raw_ip = (ADDRINT)ip;
    if (++exec_count[raw_ip] > 64) return;

    std::string addrString;
    int code_region = translate_addr(ip, addrString);

    // Skip non-user code: libc AND unknown shared libraries.
    if (code_region != TYPE_MAIN && code_region != TYPE_TARGETLIB) {
        was_in_libc_ = true;
        return;
    }

    // Refresh caller-saved register pointees after returning from non-user code.
    if (was_in_libc_) {
        static const REG caller_saved[] = {
            REG_RAX, REG_RCX, REG_RDX, REG_RSI, REG_RDI,
            REG_R8, REG_R9, REG_R10, REG_R11
        };
        for (auto reg : caller_saved) {
            ownership_->correct_reg_id(reg, ctx);
        }
        was_in_libc_ = false;
    }

    logInsTrace->log("ip: ", addrString, "\n");
    current_pc_idx++;

    // Decode instruction once, cache for XedSolverAfter
    xed_state_t dstate;
    dstate.mmode = XED_MACHINE_MODE_LONG_64;
    uint8_t itext[XED_MAX_INSTRUCTION_BYTES] = {0};
    PIN_SafeCopy(itext, ip, insSize);
    xed_decoded_inst_zero_set_mode(&cached_.xedd, &dstate);
    xed_error_enum_t err = xed_decode(&cached_.xedd, itext, insSize);

    if (err != XED_ERROR_NONE) {
        cached_.valid = false;
        return;
    }

    cached_.xi = xed_decoded_inst_inst(&cached_.xedd);
    cached_.iclass = xed_decoded_inst_get_iclass(&cached_.xedd);
    xed_format_context(XED_SYNTAX_INTEL, &cached_.xedd, cached_.disasm, sizeof(cached_.disasm), 0, 0, 0);
    cached_.addr_string = addrString;
    cached_.code_region = code_region;
    cached_.valid = true;

    const xed_decoded_inst_t* xedd = &cached_.xedd;
    const xed_inst_t* xi = cached_.xi;
    xed_iclass_enum_t iclass = cached_.iclass;

    const xed_operand_t* op1 = NULL;
    const xed_operand_t* op2 = NULL;
    xed_operand_enum_t oe1 = XED_OPERAND_INVALID;
    xed_operand_enum_t oe2 = XED_OPERAND_INVALID;

    switch (iclass) {

    case XED_ICLASS_CMP:
    case XED_ICLASS_TEST:
        op1 = xed_inst_operand(xi, 0);
        oe1 = xed_operand_name(op1);
        if (oe1 == XED_OPERAND_MEM0 || oe1 == XED_OPERAND_MEM1) {
            ADDRINT ea = compute_ea(xedd, ctx, insSize);
            xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd, 0);
            ADDRINT base_val = PIN_GetContextReg(ctx, CommonTools::ConvertXedRegToPinReg(base));
            rulesMovRead(ea, base, base_val, REG_INVALID(), addrString, code_region);
        }
        break;

    case XED_ICLASS_MOV:
    case XED_ICLASS_MOVZX:
    case XED_ICLASS_MOVSX:
    case XED_ICLASS_MOVSXD:
    case XED_ICLASS_MOVD:
    case XED_ICLASS_MOVQ:
        op1 = xed_inst_operand(xi, 0);
        op2 = xed_inst_operand(xi, 1);
        oe1 = xed_operand_name(op1);
        oe2 = xed_operand_name(op2);

        if (xed_operand_is_register(oe1) && xed_operand_is_register(oe2)) {
            // mov reg, reg
            xed_reg_enum_t xed_dst = xed_decoded_inst_get_reg(xedd, oe1);
            xed_uint_t dst_width = xed_get_register_width_bits64(xed_dst);
            if (dst_width < 32) break;  // partial reg move doesn't change pointer ownership

            REG pr1 = CommonTools::ConvertXedRegToPinReg(xed_dst);
            REG pr2 = CommonTools::ConvertXedRegToPinReg(xed_decoded_inst_get_reg(xedd, oe2));
            if (pr1 != REG_INVALID() && pr2 != REG_INVALID()) {
                ownership_->dup_reg_pointee(pr1, pr2);
            }
        }
        else if (xed_operand_is_register(oe1) && (oe2 == XED_OPERAND_IMM0 || oe2 == XED_OPERAND_IMM1)) {
            // mov reg, imm
            xed_reg_enum_t xed_dst = xed_decoded_inst_get_reg(xedd, oe1);
            xed_uint_t dst_width = xed_get_register_width_bits64(xed_dst);
            if (dst_width < 32) break;  // setting AL/AX to imm doesn't change RAX pointee

            uint64_t imm = xed_decoded_inst_get_unsigned_immediate(xedd);
            ownership_->assign_reg_pointee(
                CommonTools::ConvertXedRegToPinReg(xed_dst), imm);
        }
        else if ((oe1 == XED_OPERAND_MEM0 || oe1 == XED_OPERAND_MEM1) && xed_operand_is_register(oe2)) {
            // mov mem, reg
            xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd, 0);
            xed_reg_enum_t index = xed_decoded_inst_get_index_reg(xedd, 0);
            xed_reg_enum_t written_reg = xed_decoded_inst_get_reg(xedd, oe2);

            // Skip XMM writes
            if (written_reg >= XED_REG_XMM0 && written_reg <= XED_REG_XMM31) break;

            xed_uint_t src_width = xed_get_register_width_bits64(written_reg);

            int64_t pointee = ownership_->get_reg_pointee(CommonTools::ConvertXedRegToPinReg(base));
            ADDRINT base_val = PIN_GetContextReg(ctx, CommonTools::ConvertXedRegToPinReg(base));
            ADDRINT index_val = PIN_GetContextReg(ctx, CommonTools::ConvertXedRegToPinReg(index));
            ADDRINT written_value = PIN_GetContextReg(ctx, CommonTools::ConvertXedRegToPinReg(written_reg));

            if (!CommonTools::is_valid_pointer(base_val) && CommonTools::is_valid_pointer(index_val)) {
                pointee = ownership_->get_reg_pointee(CommonTools::ConvertXedRegToPinReg(index));
            }

            if (base != XED_REG_INVALID) {
                ADDRINT ea = compute_ea(xedd, ctx, insSize);
                if (src_width < 32) {
                    // 8/16-bit writes can't carry pointers, so skip normal ownership
                    // tracking (pointee propagation). But still detect violations and
                    // update value_owner to record WHO wrote to this cell.
                    int64_t co = ownership_->get_cell_owner(ea);
                    if ((code_region == TYPE_MAIN || code_region == TYPE_TARGETLIB)) {
                        // OOB byte write: writing to untracked region via a tracked pointer
                        // (e.g., off-by-one null byte into chunk metadata)
                        if (co == -1 && pointee > STACK_SUBJECT_ID) {
                            ADDRINT pc = std::hash<std::string>{}(addrString);
                            if (shouldReport(pc, DET_CROSSBOUNDARY)) {
                                const Subject* prev = ownership_->find_subject(ea - 1);
                                const Subject* next = ownership_->find_subject(ea + 0x10);
                                const char* tag = (prev || next) ? " [chunk metadata]" : " [unmapped]";
                                logOwnership->log("[OOB byte write] ip: ", addrString,
                                    " write at: ", toHex(ea), " from subject ", pointee,
                                    tag, "\n");
                            }
                        }
                        else if (co > STACK_SUBJECT_ID && co != pointee && pointee > STACK_SUBJECT_ID) {
                            // Sub-subject CROSSBOUNDARY: writer's pointee doesn't match
                            // the cell owner. This is a field-boundary violation.
                            ADDRINT pc = std::hash<std::string>{}(addrString);
                            if (shouldReport(pc, DET_INTRA_OBJ)) {
                                const Subject* subj = ownership_->find_subject(ea);
                                ADDRINT offset = subj ? (ea - subj->base) : 0;
                                logOwnership->log("[INTRA_OBJECT_OVERFLOW] ip: ", addrString,
                                    " byte write at: ", toHex(ea), " offset: +", toHex(offset),
                                    " cell_owner: ", co, " writer_pointee: ", pointee, "\n");
                            }
                        } else if (co == pointee) {
                            // Same subject — check if overwriting a pointer from another subject
                            char old_buf[8] = {0};
                            PIN_SafeCopy(old_buf, (VOID*)ea, 8);
                            uint64_t old_val = *(uint64_t*)old_buf;
                            int64_t old_val_co = ownership_->get_cell_owner(old_val);
                            if (old_val_co > STACK_SUBJECT_ID && old_val_co != co) {
                                ADDRINT pc = std::hash<std::string>{}(addrString);
                                if (shouldReport(pc, DET_INTRA_OBJ)) {
                                    const Subject* subj = ownership_->find_subject(ea);
                                    ADDRINT offset = subj ? (ea - subj->base) : 0;
                                    logOwnership->log("[INTRA_OBJECT_OVERFLOW] ip: ", addrString,
                                        " byte write at: ", toHex(ea), " offset: +", toHex(offset),
                                        " subject: ", co, " clobbers ptr ", toHex(old_val),
                                        " (owner: ", old_val_co, ")\n");
                                }
                            }
                        }
                        // Update value_owner only when struct layouts are active,
                        // so later reads see co!=vo for intra-struct overflow.
                        // Without struct layouts, byte writes are from normal code
                        // (adjacent allocations) and vo updates would cause FPs.
                        if (ownership_->struct_layout_count() > 0)
                            ownership_->update_value_owner(ea, pointee);
                    }
                } else {
                    rulesMovWrite(ea, written_value, pointee, addrString, code_region);
                }
            }
        }
        else if ((oe1 == XED_OPERAND_MEM0 || oe1 == XED_OPERAND_MEM1) &&
                 (oe2 == XED_OPERAND_IMM0 || oe2 == XED_OPERAND_IMM1)) {
            // mov mem, imm
            xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd, 0);
            int64_t pointee = ownership_->get_reg_pointee(CommonTools::ConvertXedRegToPinReg(base));
            if (pointee != -1 && base != XED_REG_INVALID) {
                ADDRINT ea = compute_ea(xedd, ctx, insSize);
                rulesMovWriteImm(ea, pointee, addrString, code_region);
            }
        }
        else if (xed_operand_is_register(oe1) && (oe2 == XED_OPERAND_MEM0 || oe2 == XED_OPERAND_MEM1)) {
            // mov reg, mem
            xed_reg_enum_t xed_dst = xed_decoded_inst_get_reg(xedd, oe1);
            xed_uint_t dst_width = xed_get_register_width_bits64(xed_dst);
            if (dst_width < 32) break;

            ADDRINT ea = compute_ea(xedd, ctx, insSize);
            xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd, 0);
            ADDRINT base_val = PIN_GetContextReg(ctx, CommonTools::ConvertXedRegToPinReg(base));
            REG reg0 = CommonTools::ConvertXedRegToPinReg(xed_dst);
            ownership_->correct_reg_id(CommonTools::ConvertXedRegToPinReg(base), ctx);
            rulesMovRead(ea, base, base_val, reg0, addrString, code_region);

            // Restore pointee for the loaded value: when a pointer is loaded from
            // stack/heap, assign its cell_owner as the pointee. This prevents
            // pointee loss after stack spill/reload (T9: house_of_einherjar FN).
            if (dst_width >= 64 && reg0 != REG_INVALID()) {
                char buf[8] = {0};
                PIN_SafeCopy(buf, (VOID*)ea, 8);
                ADDRINT loaded_val = *(ADDRINT*)buf;
                if (CommonTools::is_valid_pointer(loaded_val)) {
                    int64_t loaded_co = ownership_->get_cell_owner(loaded_val);
                    if (loaded_co > STACK_SUBJECT_ID || loaded_co == HEAP_SUBJECT_ID) {
                        ownership_->assign_reg_pointee_id(reg0, loaded_co);
                    }
                }
            }
        }
        break;

    case XED_ICLASS_LEA:
        op1 = xed_inst_operand(xi, 0);
        op2 = xed_inst_operand(xi, 1);
        oe1 = xed_operand_name(op1);
        oe2 = xed_operand_name(op2);
        if (xed_operand_is_register(oe1) && oe2 == XED_OPERAND_AGEN) {
            ADDRINT ea = compute_ea(xedd, ctx, insSize);
            ownership_->assign_reg_pointee(
                CommonTools::ConvertXedRegToPinReg(xed_decoded_inst_get_reg(xedd, oe1)), ea);
        }
        break;

    case XED_ICLASS_PUSH:
        op1 = xed_inst_operand(xi, 0);
        oe1 = xed_operand_name(op1);
        if (xed_operand_is_register(oe1)) {
            REG pr = CommonTools::ConvertXedRegToPinReg(xed_decoded_inst_get_reg(xedd, oe1));
            if (pr != REG_INVALID()) {
                ADDRINT rsp = PIN_GetContextReg(ctx, REG_RSP);
                int64_t pointee = ownership_->get_reg_pointee(pr);
                rulesPush(rsp - 8, pointee, addrString);
            }
        }
        break;

    // Engine A: on LEAVE, mark the departing stack frame as freed
    // so that subsequent access to returned stack pointers → STACKREADUSEAFTERSCOPE
    case XED_ICLASS_LEAVE:
    {
        if (code_region == TYPE_MAIN || code_region == TYPE_TARGETLIB) {
            ADDRINT rsp = PIN_GetContextReg(ctx, REG_RSP);
            ADDRINT rbp = PIN_GetContextReg(ctx, REG_RBP);
            if (rbp > rsp && (rbp - rsp) < 0x10000) {
                size_t frame_size = rbp - rsp;
                // Create subject for the frame and immediately free it
                // This populates recently_freed_ so get_cell_owner returns HEAP_SUBJECT_ID
                ownership_->alloc_new_subject(rsp, frame_size);
                ownership_->free_subject(rsp);
            }
        }
        break;
    }

    // Engine A: stack frame tracking via SUB RSP, imm (main/target_lib only)
    case XED_ICLASS_SUB:
    {
        if (code_region != TYPE_MAIN && code_region != TYPE_TARGETLIB) break;
        op1 = xed_inst_operand(xi, 0);
        op2 = xed_inst_operand(xi, 1);
        oe1 = xed_operand_name(op1);
        oe2 = xed_operand_name(op2);
        if (xed_operand_is_register(oe1) && (oe2 == XED_OPERAND_IMM0 || oe2 == XED_OPERAND_IMM1)) {
            xed_reg_enum_t dst_reg = xed_decoded_inst_get_reg(xedd, oe1);
            if (dst_reg == XED_REG_RSP || dst_reg == XED_REG_ESP) {
                uint64_t frame_size = xed_decoded_inst_get_unsigned_immediate(xedd);
                if (frame_size >= 0x10 && frame_size <= 0x10000) {
                    ADDRINT rsp = PIN_GetContextReg(ctx, REG_RSP);
                    ADDRINT frame_base = rsp - frame_size;
                    ownership_->alloc_new_subject(frame_base, frame_size);
                    frame_stack_.push_back({frame_base, frame_size});
                }
            }
        }
        break;
    }

    default:
        break;
    }
}

VOID Instrumentation::XedSolverAfter(VOID* ip, VOID* addr, uint32_t insSize, uint32_t opSize, CONTEXT* ctx) {
    if (!is_record_) return;

    // Use cached decode from Before if available; otherwise decode fresh
    xed_decoded_inst_t* xedd;
    const xed_inst_t* xi;
    xed_iclass_enum_t iclass;
    std::string addrString;
    int code_region;

    if (cached_.valid) {
        xedd = &cached_.xedd;
        xi = cached_.xi;
        iclass = cached_.iclass;
        addrString = cached_.addr_string;
        code_region = cached_.code_region;
        cached_.valid = false;
    } else {
        // Fallback: decode fresh (for instructions skipped in Before)
        code_region = translate_addr(ip, addrString);
        if (code_region != TYPE_MAIN && code_region != TYPE_TARGETLIB) return;

        static xed_decoded_inst_t fallback_xedd;
        xed_state_t dstate;
        dstate.mmode = XED_MACHINE_MODE_LONG_64;
        uint8_t itext[XED_MAX_INSTRUCTION_BYTES] = {0};
        PIN_SafeCopy(itext, ip, insSize);
        xed_decoded_inst_zero_set_mode(&fallback_xedd, &dstate);
        if (xed_decode(&fallback_xedd, itext, insSize) != XED_ERROR_NONE) return;
        xedd = &fallback_xedd;
        xi = xed_decoded_inst_inst(xedd);
        iclass = xed_decoded_inst_get_iclass(xedd);
    }

    if (code_region != TYPE_MAIN && code_region != TYPE_TARGETLIB) return;

    const xed_operand_t* op1 = NULL;
    const xed_operand_t* op2 = NULL;
    xed_operand_enum_t oe1 = XED_OPERAND_INVALID;
    xed_operand_enum_t oe2 = XED_OPERAND_INVALID;

    switch (iclass) {

    case XED_ICLASS_POP:
        op1 = xed_inst_operand(xi, 0);
        oe1 = xed_operand_name(op1);
        if (xed_operand_is_register(oe1)) {
            REG pr = CommonTools::ConvertXedRegToPinReg(xed_decoded_inst_get_reg(xedd, oe1));
            if (pr != REG_INVALID()) {
                ADDRINT val = PIN_GetContextReg(ctx, pr);
                if (CommonTools::is_valid_pointer(val)) {
                    int64_t owner = ownership_->get_cell_owner(val);
                    ownership_->assign_reg_pointee_id(pr, owner);
                }
            }
        }
        break;

    case XED_ICLASS_LEAVE:
    {
        ADDRINT rsp = PIN_GetContextReg(ctx, REG_RSP);
        ADDRINT rbp = PIN_GetContextReg(ctx, REG_RBP);
        if (!gConfig.no_reasoning) rulesLeave(rsp, rbp);

        // R1: Stack pivot detection — after LEAVE, RSP must still be on the stack
        ADDRINT slo = ownership_->get_stack_lo();
        ADDRINT shi = ownership_->get_stack_hi();
        if (slo != 0 && (rsp < slo || rsp > shi)) {
            logOwnership->log("[STACK PIVOT] ip: ", addrString,
                " RSP ", toHex(rsp), " left stack [", toHex(slo), ",", toHex(shi), "]\n");
        }

        // Engine A: free the most recent stack frame (scope exit)
        if (!frame_stack_.empty()) {
            auto& top = frame_stack_.back();
            if (top.base < rsp) {
                ownership_->free_subject(top.base);
                frame_stack_.pop_back();
            }
        }
        break;
    }

    // R2: Return address integrity — on RET, check that the return target is valid code
    case XED_ICLASS_RET_NEAR:
    case XED_ICLASS_RET_FAR:
    {
        ADDRINT rsp = PIN_GetContextReg(ctx, REG_RSP);
        // After RET executes, RIP holds the actual return target.
        // Reading [RSP] is WRONG here: RSP was already incremented by 8,
        // so [RSP] points to the caller's first stack slot (a local variable
        // or saved register), not the return address.
        ADDRINT ret_addr = PIN_GetContextReg(ctx, REG_RIP);
        if (ret_addr > 0x10000) {
            PIN_LockClient();
            IMG ret_img = IMG_FindByAddress(ret_addr);
            PIN_UnlockClient();
            if (!IMG_Valid(ret_img)) {
                if (shouldReport(std::hash<std::string>{}(addrString), DET_CROSSBOUNDARY))
                    logOwnership->log("[RETURN ADDRESS HIJACK] ip: ", addrString,
                        " ret_addr: ", toHex(ret_addr), " region: -1\n");
            }
        }

        // R1: RSP after RET should remain on stack.
        // RSP is already post-RET (incremented by 8). No need to add another 8.
        ADDRINT slo = ownership_->get_stack_lo();
        ADDRINT shi = ownership_->get_stack_hi();
        if (slo != 0 && (rsp < slo || rsp > shi)) {
            logOwnership->log("[STACK PIVOT] ip: ", addrString,
                " RSP ", toHex(rsp), " left stack after RET\n");
        }

        // Stack frame cleanup on RET — mark the callee's frame as freed.
        // This replaces the rtn_callback IPOINT_AFTER approach which
        // doesn't fire reliably on PIN 4.x.
        {
            ADDRINT frame_base = rsp - 0x100;
            ownership_->alloc_new_subject(frame_base, 0x100);
            ownership_->free_subject(frame_base);
        }
        break;
    }

    // BUG-8 fix: handle unary NOT/NEG separately from binary ops
    case XED_ICLASS_NOT:
    case XED_ICLASS_NEG:
        op1 = xed_inst_operand(xi, 0);
        oe1 = xed_operand_name(op1);
        if (xed_operand_is_register(oe1)) {
            REG pr = CommonTools::ConvertXedRegToPinReg(xed_decoded_inst_get_reg(xedd, oe1));
            if (pr != REG_INVALID()) {
                ADDRINT val = PIN_GetContextReg(ctx, pr);
                if (CommonTools::is_valid_pointer(val)) {
                    int64_t owner = ownership_->get_cell_owner(val);
                    ownership_->assign_reg_pointee_id(pr, owner);
                }
            }
        }
        break;

    case XED_ICLASS_ADD:
    case XED_ICLASS_SUB:
    case XED_ICLASS_XOR:
    case XED_ICLASS_AND:
    case XED_ICLASS_OR:
    case XED_ICLASS_SHL:
    case XED_ICLASS_SHR:
    case XED_ICLASS_SAR:
    case XED_ICLASS_MUL:
    case XED_ICLASS_IMUL:
    case XED_ICLASS_DIV:
    case XED_ICLASS_IDIV:
    {
        op1 = xed_inst_operand(xi, 0);
        oe1 = xed_operand_name(op1);
        unsigned nops = xed_decoded_inst_noperands(xedd);
        if (nops >= 2) {
            op2 = xed_inst_operand(xi, 1);
            oe2 = xed_operand_name(op2);
        }

        if (xed_operand_is_register(oe1)) {
            xed_reg_enum_t xed_dst = xed_decoded_inst_get_reg(xedd, oe1);

            // Skip sub-register (8/16-bit) arithmetic — these are typically
            // allocator bitmap ops (xor al, and al) that don't change pointer
            // ownership semantics. Only track 32/64-bit pointer arithmetic.
            xed_uint_t dst_width = xed_get_register_width_bits64(xed_dst);
            if (dst_width < 32) {
                break;
            }

            REG pr_dst = CommonTools::ConvertXedRegToPinReg(xed_dst);
            if (pr_dst != REG_INVALID()) {
                // RSP/RBP arithmetic (sub rsp, add rsp, etc.) is stack management,
                // not pointer arithmetic — never a CROSSBOUNDARY bug.
                if (pr_dst == REG_RSP || pr_dst == REG_RBP) {
                    ADDRINT dst_val = PIN_GetContextReg(ctx, pr_dst);
                    ownership_->assign_reg_pointee_id(pr_dst, ownership_->get_cell_owner(dst_val));
                    break;
                }

                ADDRINT dst_val = PIN_GetContextReg(ctx, pr_dst);
                if (CommonTools::is_valid_pointer(dst_val)) {
                    int64_t old_pointee = ownership_->get_reg_pointee(pr_dst);

                    int64_t pointee = old_pointee;
                    if (op2 && xed_operand_is_register(oe2)) {
                        REG pr2 = CommonTools::ConvertXedRegToPinReg(xed_decoded_inst_get_reg(xedd, oe2));
                        if (pr2 != REG_INVALID()) {
                            ADDRINT v2 = PIN_GetContextReg(ctx, pr2);
                            if (CommonTools::is_valid_pointer(v2)) {
                                pointee = ownership_->get_reg_pointee(pr2);
                            }
                        }
                    }
                    pointee = ownership_->get_reg_pointee(
                        (pointee != old_pointee) ?
                            CommonTools::ConvertXedRegToPinReg(xed_decoded_inst_get_reg(xedd, oe2)) : pr_dst);

                    int64_t new_owner = ownership_->get_cell_owner(dst_val);

                    // When crossing between sub-subjects of the same struct,
                    // preserve the ORIGINAL pointee so value_owner traces the
                    // overflow source, not the destination field.
                    bool intra_struct_cross = false;
                    if (new_owner != pointee && pointee > STACK_SUBJECT_ID &&
                        new_owner > STACK_SUBJECT_ID && ownership_->struct_layout_count() > 0) {
                        const Subject* old_subj = ownership_->find_subject(
                            PIN_GetContextReg(ctx, pr_dst) - 1); // check neighbor
                        const Subject* new_subj = ownership_->find_subject(dst_val);
                        if (old_subj && new_subj) {
                            int64_t diff = new_owner - pointee;
                            if (diff > 0 && diff < 16) {
                                intra_struct_cross = true;
                            }
                        }
                    }

                    if (!intra_struct_cross)
                        ownership_->assign_reg_pointee_id(pr_dst, new_owner);

                    // CROSSBOUNDARY: pointer arithmetic crosses allocation boundary
                    if (new_owner != pointee && pointee > STACK_SUBJECT_ID) {
                        ADDRINT dedup_key = std::hash<std::string>{}(addrString);
                        if (gInstrumentation->shouldReport(dedup_key, DET_CROSSBOUNDARY)) {
                            // Annotate the destination region
                            const char* region_tag = "";
                            if (new_owner == -1) {
                                // Check if the address is in the gap between two allocations
                                // (ptmalloc chunk header: prev_size + size field)
                                const Subject* prev = ownership_->find_subject(dst_val - 1);
                                const Subject* next = ownership_->find_subject(dst_val + 0x10);
                                if (prev || next)
                                    region_tag = " [chunk metadata]";
                                else
                                    region_tag = " [unmapped]";
                            } else if (new_owner == HEAP_SUBJECT_ID) {
                                region_tag = " [freed]";
                            }
                            logOwnership->log("[INCONSISTENCY arithmetic -> CROSSBOUNDARY] ip: ", addrString, " ",
                                cached_.disasm, " id before: ", pointee, " after: ", new_owner,
                                region_tag, " value: ", toHex(dst_val), "\n");
                        }
                    }
                }
            }
        }
        break;
    }

    // BUG-3 fix: XCHG now calls rulesXchg
    case XED_ICLASS_XCHG:
    {
        op1 = xed_inst_operand(xi, 0);
        op2 = xed_inst_operand(xi, 1);
        oe1 = xed_operand_name(op1);
        oe2 = xed_operand_name(op2);
        REG r1 = xed_operand_is_register(oe1) ?
            CommonTools::ConvertXedRegToPinReg(xed_decoded_inst_get_reg(xedd, oe1)) : REG_INVALID();
        REG r2 = xed_operand_is_register(oe2) ?
            CommonTools::ConvertXedRegToPinReg(xed_decoded_inst_get_reg(xedd, oe2)) : REG_INVALID();
        ADDRINT v1 = (r1 != REG_INVALID()) ? PIN_GetContextReg(ctx, r1) : 0;
        ADDRINT v2 = (r2 != REG_INVALID()) ? PIN_GetContextReg(ctx, r2) : 0;
        rulesXchg(r1, v1, r2, v2);
        break;
    }

    case XED_ICLASS_SYSCALL:
        rulesSyscall(ctx);
        break;

    // Conditional moves: update pointee if the move happened
    case XED_ICLASS_CMOVB: case XED_ICLASS_CMOVBE:
    case XED_ICLASS_CMOVL: case XED_ICLASS_CMOVLE:
    case XED_ICLASS_CMOVNB: case XED_ICLASS_CMOVNBE:
    case XED_ICLASS_CMOVNL: case XED_ICLASS_CMOVNLE:
    case XED_ICLASS_CMOVNZ: case XED_ICLASS_CMOVZ:
    case XED_ICLASS_CMOVS: case XED_ICLASS_CMOVNS:
    case XED_ICLASS_CMOVP: case XED_ICLASS_CMOVNP:
    case XED_ICLASS_CMOVO: case XED_ICLASS_CMOVNO:
    {
        // After execution: if move happened, dst reg has new value
        op1 = xed_inst_operand(xi, 0);
        op2 = xed_inst_operand(xi, 1);
        oe1 = xed_operand_name(op1);
        oe2 = xed_operand_name(op2);
        if (xed_operand_is_register(oe1)) {
            REG pr = CommonTools::ConvertXedRegToPinReg(xed_decoded_inst_get_reg(xedd, oe1));
            if (pr != REG_INVALID()) {
                ADDRINT val = PIN_GetContextReg(ctx, pr);
                int64_t owner = ownership_->get_cell_owner(val);
                ownership_->assign_reg_pointee_id(pr, owner);
            }
        }
        break;
    }

    default:
        break;
    }
}
