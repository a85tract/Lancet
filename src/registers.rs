use iced_x86::Register;
use serde::{Deserialize, Serialize};

pub const REG_TABLE_ID_X86_64_V1: u16 = 1;
pub const REG_COUNT: usize = 19;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RegId(pub u8);

pub const RAX: RegId = RegId(0);
pub const RBX: RegId = RegId(1);
pub const RCX: RegId = RegId(2);
pub const RDX: RegId = RegId(3);
pub const RSI: RegId = RegId(4);
pub const RDI: RegId = RegId(5);
pub const RBP: RegId = RegId(6);
pub const RSP: RegId = RegId(7);
pub const R8: RegId = RegId(8);
pub const R9: RegId = RegId(9);
pub const R10: RegId = RegId(10);
pub const R11: RegId = RegId(11);
pub const R12: RegId = RegId(12);
pub const R13: RegId = RegId(13);
pub const R14: RegId = RegId(14);
pub const R15: RegId = RegId(15);
pub const RIP: RegId = RegId(16);
pub const RFLAGS: RegId = RegId(17);
pub const CR3: RegId = RegId(18);

pub const REG_NAMES: [&str; REG_COUNT] = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15", "rip", "rflags", "cr3",
];

impl RegId {
    pub fn bit(self) -> u64 {
        1u64 << self.0
    }

    pub fn name(self) -> &'static str {
        REG_NAMES[self.0 as usize]
    }
}

pub fn id_from_name(name: &str) -> Option<RegId> {
    let lower = name.trim().to_ascii_lowercase();
    let canonical = match lower.as_str() {
        "eax" | "ax" | "al" | "ah" => "rax",
        "ebx" | "bx" | "bl" | "bh" => "rbx",
        "ecx" | "cx" | "cl" | "ch" => "rcx",
        "edx" | "dx" | "dl" | "dh" => "rdx",
        "esi" | "si" | "sil" => "rsi",
        "edi" | "di" | "dil" => "rdi",
        "ebp" | "bp" | "bpl" => "rbp",
        "esp" | "sp" | "spl" => "rsp",
        "r8d" | "r8w" | "r8b" => "r8",
        "r9d" | "r9w" | "r9b" => "r9",
        "r10d" | "r10w" | "r10b" => "r10",
        "r11d" | "r11w" | "r11b" => "r11",
        "r12d" | "r12w" | "r12b" => "r12",
        "r13d" | "r13w" | "r13b" => "r13",
        "r14d" | "r14w" | "r14b" => "r14",
        "r15d" | "r15w" | "r15b" => "r15",
        "eip" => "rip",
        "eflags" => "rflags",
        other => other,
    };
    REG_NAMES
        .iter()
        .position(|name| *name == canonical)
        .map(|idx| RegId(idx as u8))
}

pub fn id_from_iced(register: Register) -> Option<RegId> {
    use iced_x86::Register::*;
    match register.full_register() {
        RAX | EAX | AX | AL | AH => Some(RAX_ID),
        RBX | EBX | BX | BL | BH => Some(RBX_ID),
        RCX | ECX | CX | CL | CH => Some(RCX_ID),
        RDX | EDX | DX | DL | DH => Some(RDX_ID),
        RSI | ESI | SI | SIL => Some(RSI_ID),
        RDI | EDI | DI | DIL => Some(RDI_ID),
        RBP | EBP | BP | BPL => Some(RBP_ID),
        RSP | ESP | SP | SPL => Some(RSP_ID),
        R8 | R8D | R8W | R8L => Some(R8_ID),
        R9 | R9D | R9W | R9L => Some(R9_ID),
        R10 | R10D | R10W | R10L => Some(R10_ID),
        R11 | R11D | R11W | R11L => Some(R11_ID),
        R12 | R12D | R12W | R12L => Some(R12_ID),
        R13 | R13D | R13W | R13L => Some(R13_ID),
        R14 | R14D | R14W | R14L => Some(R14_ID),
        R15 | R15D | R15W | R15L => Some(R15_ID),
        RIP | EIP => Some(RIP_ID),
        _ => std::option::Option::None,
    }
}

const RAX_ID: RegId = RegId(0);
const RBX_ID: RegId = RegId(1);
const RCX_ID: RegId = RegId(2);
const RDX_ID: RegId = RegId(3);
const RSI_ID: RegId = RegId(4);
const RDI_ID: RegId = RegId(5);
const RBP_ID: RegId = RegId(6);
const RSP_ID: RegId = RegId(7);
const R8_ID: RegId = RegId(8);
const R9_ID: RegId = RegId(9);
const R10_ID: RegId = RegId(10);
const R11_ID: RegId = RegId(11);
const R12_ID: RegId = RegId(12);
const R13_ID: RegId = RegId(13);
const R14_ID: RegId = RegId(14);
const R15_ID: RegId = RegId(15);
const RIP_ID: RegId = RegId(16);

pub fn iced_register_name(register: Register) -> Option<&'static str> {
    id_from_iced(register).map(|id| id.name())
}
