use iced_x86::{Instruction, MemorySize, Mnemonic, OpAccess, Register, UsedMemory};

use crate::registers::{RIP, RegId, id_from_iced};
use crate::trace::TraceRecord;
use crate::vuln::AccessKind;

#[derive(Debug, Clone)]
pub struct DecodedInstruction {
    pub instruction: Instruction,
    pub accesses: Vec<ResolvedAccess>,
}

#[derive(Debug, Clone, Copy)]
pub struct ResolvedAccess {
    pub address: u64,
    pub size: u32,
    pub kind: AccessKind,
    pub base: Option<RegId>,
    pub index: Option<RegId>,
}

pub fn decode(
    record: &TraceRecord,
    info_factory: &mut iced_x86::InstructionInfoFactory,
) -> Result<DecodedInstruction, String> {
    let mut decoder = iced_x86::Decoder::with_ip(
        64,
        &record.bytecode,
        record.pc,
        iced_x86::DecoderOptions::NONE,
    );
    if !decoder.can_decode() {
        return Err(format!("cannot decode @ 0x{:x}", record.pc));
    }
    let mut instruction = Instruction::default();
    decoder.decode_out(&mut instruction);
    if instruction.len() == 0 {
        return Err(format!("zero length instruction @ 0x{:x}", record.pc));
    }
    if is_call(&instruction) || is_ret(&instruction) {
        return Ok(DecodedInstruction {
            instruction,
            accesses: Vec::new(),
        });
    }
    let info = info_factory.info(&instruction);
    let mut accesses = Vec::new();
    for mem in info.used_memory() {
        let Some(kind) = access_kind(mem.access()) else {
            continue;
        };
        let address = compute_address(mem, &instruction, record)?;
        let mut size = mem.memory_size().size() as u32;
        if size == 0 && is_rep_string(&instruction) {
            let count = record.reg(crate::registers::RCX).unwrap_or(0);
            size = count.saturating_mul(rep_element_size(instruction.mnemonic()) as u64) as u32;
        }
        accesses.push(ResolvedAccess {
            address,
            size,
            kind,
            base: id_from_iced(mem.base()),
            index: id_from_iced(mem.index()),
        });
    }
    Ok(DecodedInstruction {
        instruction,
        accesses,
    })
}

pub fn register_value(record: &TraceRecord, register: Register) -> Option<u64> {
    if register == Register::None {
        return Some(0);
    }
    if register == Register::RIP || register == Register::EIP {
        return record.reg(RIP);
    }
    id_from_iced(register).and_then(|id| record.reg(id))
}

fn compute_address(
    mem: &UsedMemory,
    instruction: &Instruction,
    record: &TraceRecord,
) -> Result<u64, String> {
    let mut missing = Vec::new();
    let address = mem.virtual_address(0, |reg, _, _| match reg {
        Register::None => Some(0),
        Register::RIP => Some(record.pc.wrapping_add(instruction.len() as u64)),
        Register::EIP => Some((record.pc.wrapping_add(instruction.len() as u64)) as u32 as u64),
        Register::FS | Register::GS | Register::CS | Register::DS | Register::ES | Register::SS => {
            Some(0)
        }
        other => id_from_iced(other)
            .and_then(|id| record.reg(id))
            .or_else(|| {
                missing.push(format!("{other:?}"));
                None
            }),
    });
    address.ok_or_else(|| format!("missing regs for memory address: {missing:?}"))
}

fn access_kind(access: OpAccess) -> Option<AccessKind> {
    match access {
        OpAccess::Read | OpAccess::CondRead => Some(AccessKind::Read),
        OpAccess::Write | OpAccess::CondWrite => Some(AccessKind::Write),
        OpAccess::ReadWrite | OpAccess::ReadCondWrite => Some(AccessKind::ReadWrite),
        OpAccess::None | OpAccess::NoMemAccess => None,
    }
}

pub fn is_call(instruction: &Instruction) -> bool {
    instruction.is_call_near() || instruction.is_call_far()
}
pub fn is_ret(instruction: &Instruction) -> bool {
    matches!(
        instruction.mnemonic(),
        Mnemonic::Ret | Mnemonic::Retf | Mnemonic::Iret | Mnemonic::Iretd | Mnemonic::Iretq
    )
}
pub fn is_lea(instruction: &Instruction) -> bool {
    instruction.mnemonic() == Mnemonic::Lea
}
pub fn is_pointer_arith(instruction: &Instruction) -> bool {
    matches!(instruction.mnemonic(), Mnemonic::Add | Mnemonic::Sub)
}

fn is_rep_string(instruction: &Instruction) -> bool {
    if !(instruction.has_rep_prefix() || instruction.has_repne_prefix()) {
        return false;
    }
    matches!(
        instruction.mnemonic(),
        Mnemonic::Movsb
            | Mnemonic::Movsw
            | Mnemonic::Movsd
            | Mnemonic::Movsq
            | Mnemonic::Stosb
            | Mnemonic::Stosw
            | Mnemonic::Stosd
            | Mnemonic::Stosq
    )
}

fn rep_element_size(mnemonic: Mnemonic) -> u32 {
    match mnemonic {
        Mnemonic::Movsw | Mnemonic::Stosw => 2,
        Mnemonic::Movsd | Mnemonic::Stosd => 4,
        Mnemonic::Movsq | Mnemonic::Stosq => 8,
        _ => 1,
    }
}

pub fn mem_size_is_pointer(size: u32) -> bool {
    size == 8
}

pub fn memory_size_for_op(size: MemorySize) -> u32 {
    size.size() as u32
}
