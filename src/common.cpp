#include "common.hpp"

REG CommonTools::ConvertXedRegToPinReg(xed_reg_enum_t r) {
    switch (r) {
        case XED_REG_INVALID: return REG_INVALID();

        // 64-bit GPRs
        case XED_REG_RAX: return REG_RAX;
        case XED_REG_RCX: return REG_RCX;
        case XED_REG_RDX: return REG_RDX;
        case XED_REG_RBX: return REG_RBX;
        case XED_REG_RSP: return REG_RSP;
        case XED_REG_RBP: return REG_RBP;
        case XED_REG_RSI: return REG_RSI;
        case XED_REG_RDI: return REG_RDI;
        case XED_REG_R8:  return REG_R8;
        case XED_REG_R9:  return REG_R9;
        case XED_REG_R10: return REG_R10;
        case XED_REG_R11: return REG_R11;
        case XED_REG_R12: return REG_R12;
        case XED_REG_R13: return REG_R13;
        case XED_REG_R14: return REG_R14;
        case XED_REG_R15: return REG_R15;

        // 32-bit → parent 64-bit (zeroes upper 32 bits on write, tracked as parent)
        case XED_REG_EAX: return REG_RAX;
        case XED_REG_ECX: return REG_RCX;
        case XED_REG_EDX: return REG_RDX;
        case XED_REG_EBX: return REG_RBX;
        case XED_REG_ESP: return REG_RSP;
        case XED_REG_EBP: return REG_RBP;
        case XED_REG_ESI: return REG_RSI;
        case XED_REG_EDI: return REG_RDI;
        case XED_REG_R8D:  return REG_R8;
        case XED_REG_R9D:  return REG_R9;
        case XED_REG_R10D: return REG_R10;
        case XED_REG_R11D: return REG_R11;
        case XED_REG_R12D: return REG_R12;
        case XED_REG_R13D: return REG_R13;
        case XED_REG_R14D: return REG_R14;
        case XED_REG_R15D: return REG_R15;

        // 16-bit → parent
        case XED_REG_AX:  return REG_RAX;
        case XED_REG_CX:  return REG_RCX;
        case XED_REG_DX:  return REG_RDX;
        case XED_REG_BX:  return REG_RBX;
        case XED_REG_SP:  return REG_RSP;
        case XED_REG_BP:  return REG_RBP;
        case XED_REG_SI:  return REG_RSI;
        case XED_REG_DI:  return REG_RDI;
        case XED_REG_R8W:  return REG_R8;
        case XED_REG_R9W:  return REG_R9;
        case XED_REG_R10W: return REG_R10;
        case XED_REG_R11W: return REG_R11;
        case XED_REG_R12W: return REG_R12;
        case XED_REG_R13W: return REG_R13;
        case XED_REG_R14W: return REG_R14;
        case XED_REG_R15W: return REG_R15;

        // 8-bit low → parent
        case XED_REG_AL:  return REG_RAX;
        case XED_REG_CL:  return REG_RCX;
        case XED_REG_DL:  return REG_RDX;
        case XED_REG_BL:  return REG_RBX;
        case XED_REG_SPL: return REG_RSP;
        case XED_REG_BPL: return REG_RBP;
        case XED_REG_SIL: return REG_RSI;
        case XED_REG_DIL: return REG_RDI;
        case XED_REG_R8B:  return REG_R8;
        case XED_REG_R9B:  return REG_R9;
        case XED_REG_R10B: return REG_R10;
        case XED_REG_R11B: return REG_R11;
        case XED_REG_R12B: return REG_R12;
        case XED_REG_R13B: return REG_R13;
        case XED_REG_R14B: return REG_R14;
        case XED_REG_R15B: return REG_R15;

        // 8-bit high → parent
        case XED_REG_AH: return REG_RAX;
        case XED_REG_CH: return REG_RCX;
        case XED_REG_DH: return REG_RDX;
        case XED_REG_BH: return REG_RBX;

        // IP
        case XED_REG_RIP: return REG_RIP;
        case XED_REG_EIP: return REG_RIP;
        case XED_REG_IP:  return REG_IP;

        // Flags
        case XED_REG_FLAGS:  return REG_FLAGS;
        case XED_REG_EFLAGS: return REG_EFLAGS;
        case XED_REG_RFLAGS: return REG_RFLAGS;

        // Segment
        case XED_REG_ES: return REG_SEG_ES;
        case XED_REG_CS: return REG_SEG_CS;
        case XED_REG_SS: return REG_SEG_SS;
        case XED_REG_DS: return REG_SEG_DS;
        case XED_REG_FS: return REG_SEG_FS;
        case XED_REG_GS: return REG_SEG_GS;

        // Control/Debug regs
        case XED_REG_CR0: return REG_CR0;
        case XED_REG_CR1: return REG_CR1;
        case XED_REG_CR2: return REG_CR2;
        case XED_REG_CR3: return REG_CR3;
        case XED_REG_CR4: return REG_CR4;
        case XED_REG_DR0: return REG_DR0;
        case XED_REG_DR1: return REG_DR1;
        case XED_REG_DR2: return REG_DR2;
        case XED_REG_DR3: return REG_DR3;
        case XED_REG_DR4: return REG_DR4;
        case XED_REG_DR5: return REG_DR5;
        case XED_REG_DR6: return REG_DR6;
        case XED_REG_DR7: return REG_DR7;

        // x87 FPU
        case XED_REG_ST0: return REG_ST0;
        case XED_REG_ST1: return REG_ST1;
        case XED_REG_ST2: return REG_ST2;
        case XED_REG_ST3: return REG_ST3;
        case XED_REG_ST4: return REG_ST4;
        case XED_REG_ST5: return REG_ST5;
        case XED_REG_ST6: return REG_ST6;
        case XED_REG_ST7: return REG_ST7;

        // Mask regs
        case XED_REG_K0: return REG_K0;
        case XED_REG_K1: return REG_K1;
        case XED_REG_K2: return REG_K2;
        case XED_REG_K3: return REG_K3;
        case XED_REG_K4: return REG_K4;
        case XED_REG_K5: return REG_K5;
        case XED_REG_K6: return REG_K6;
        case XED_REG_K7: return REG_K7;

        case XED_REG_MXCSR: return REG_MXCSR;
        case XED_REG_LDTR:  return REG_LDTR;
        case XED_REG_TR:    return REG_TR;
        case XED_REG_TILECONFIG: return REG_TILECONFIG;

        // TMM regs
        case XED_REG_TMM0: return REG_TMM0;
        case XED_REG_TMM1: return REG_TMM1;
        case XED_REG_TMM2: return REG_TMM2;
        case XED_REG_TMM3: return REG_TMM3;
        case XED_REG_TMM4: return REG_TMM4;
        case XED_REG_TMM5: return REG_TMM5;
        case XED_REG_TMM6: return REG_TMM6;
        case XED_REG_TMM7: return REG_TMM7;

        // XMM → INVALID (we don't track SIMD ownership)
        case XED_REG_XMM0: case XED_REG_XMM1: case XED_REG_XMM2: case XED_REG_XMM3:
        case XED_REG_XMM4: case XED_REG_XMM5: case XED_REG_XMM6: case XED_REG_XMM7:
        case XED_REG_XMM8: case XED_REG_XMM9: case XED_REG_XMM10: case XED_REG_XMM11:
        case XED_REG_XMM12: case XED_REG_XMM13: case XED_REG_XMM14: case XED_REG_XMM15:
        case XED_REG_XMM16: case XED_REG_XMM17: case XED_REG_XMM18: case XED_REG_XMM19:
        case XED_REG_XMM20: case XED_REG_XMM21: case XED_REG_XMM22: case XED_REG_XMM23:
        case XED_REG_XMM24: case XED_REG_XMM25: case XED_REG_XMM26: case XED_REG_XMM27:
        case XED_REG_XMM28: case XED_REG_XMM29: case XED_REG_XMM30: case XED_REG_XMM31:
            return REG_INVALID();

        // YMM
        case XED_REG_YMM0: return REG_YMM0;
        case XED_REG_YMM1: return REG_YMM1;
        case XED_REG_YMM2: return REG_YMM2;
        case XED_REG_YMM3: return REG_YMM3;
        case XED_REG_YMM4: return REG_YMM4;
        case XED_REG_YMM5: return REG_YMM5;
        case XED_REG_YMM6: return REG_YMM6;
        case XED_REG_YMM7: return REG_YMM7;
        case XED_REG_YMM8: return REG_YMM8;
        case XED_REG_YMM9: return REG_YMM9;
        case XED_REG_YMM10: return REG_YMM10;
        case XED_REG_YMM11: return REG_YMM11;
        case XED_REG_YMM12: return REG_YMM12;
        case XED_REG_YMM13: return REG_YMM13;
        case XED_REG_YMM14: return REG_YMM14;
        case XED_REG_YMM15: return REG_YMM15;

        // ZMM
        case XED_REG_ZMM0: return REG_ZMM0;
        case XED_REG_ZMM1: return REG_ZMM1;
        case XED_REG_ZMM2: return REG_ZMM2;
        case XED_REG_ZMM3: return REG_ZMM3;
        case XED_REG_ZMM4: return REG_ZMM4;
        case XED_REG_ZMM5: return REG_ZMM5;
        case XED_REG_ZMM6: return REG_ZMM6;
        case XED_REG_ZMM7: return REG_ZMM7;
        case XED_REG_ZMM8: return REG_ZMM8;
        case XED_REG_ZMM9: return REG_ZMM9;
        case XED_REG_ZMM10: return REG_ZMM10;
        case XED_REG_ZMM11: return REG_ZMM11;
        case XED_REG_ZMM12: return REG_ZMM12;
        case XED_REG_ZMM13: return REG_ZMM13;
        case XED_REG_ZMM14: return REG_ZMM14;
        case XED_REG_ZMM15: return REG_ZMM15;

        default: return REG_INVALID();
    }
}

ADDRINT CommonTools::get_mod_base(ADDRINT Address) {
    if (Address == UNKNOWN_ADDR) return UNKNOWN_ADDR;
    IMG img = IMG_FindByAddress(Address);
    if (IMG_Valid(img)) {
        ADDRINT base = IMG_LoadOffset(img);
        if (base == 0) base = IMG_LowAddress(img);
        return base;
    }
    return UNKNOWN_ADDR;
}

bool CommonTools::is_valid_pointer(ADDRINT addr) {
    char buf;
    return PIN_SafeCopy(&buf, (const VOID*)addr, 1) == 1;
}
