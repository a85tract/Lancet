use std::collections::HashMap;

use iced_x86::{Instruction, InstructionInfoFactory, Mnemonic, OpKind, Register};
use thiserror::Error;

use crate::config::{Config, SymbolConfig};
use crate::decode::{self, DecodedInstruction, ResolvedAccess};
use crate::ownership::{
    ALLOCATOR_SUBJECT, MemoryModel, OwnerSet, RegState, owner_set_one, sets_intersect,
};
use crate::registers::{RAX, RegId, id_from_iced};
use crate::trace::TRACE_FLAG_IS_CALL;
use crate::trace::TraceRecord;
use crate::vuln::{AccessKind, Violation, ViolationKind};

#[derive(Debug, Error)]
pub enum AnalyzerError {
    #[error("decode failed: {0}")]
    Decode(String),
}

#[derive(Debug, Default)]
pub struct AnalysisResult {
    pub violations: Vec<Violation>,
    pub memory_events: Vec<MemoryEvent>,
}

#[derive(Debug, serde::Serialize)]
pub struct MemoryEvent {
    pub step: u64,
    pub pc: String,
    pub kind: String,
    pub symbol: Option<String>,
    pub ptr: Option<String>,
    pub size: Option<String>,
}

#[derive(Debug, Clone)]
struct PendingAlloc {
    return_pc: u64,
    size: u64,
    symbol: Option<String>,
}
#[derive(Debug, Clone)]
struct PendingFree {
    return_pc: u64,
    ptr: u64,
    pointer_owners: OwnerSet,
    symbol: Option<String>,
    call_pc: u64,
    call_step: u64,
}

pub struct Analyzer {
    config: Config,
    mem: MemoryModel,
    regs: HashMap<RegId, RegState>,
    info_factory: InstructionInfoFactory,
    violations: Vec<Violation>,
    memory_events: Vec<MemoryEvent>,
    pending_allocs: Vec<PendingAlloc>,
    pending_frees: Vec<PendingFree>,
}

impl Analyzer {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            mem: MemoryModel::new(),
            regs: HashMap::new(),
            info_factory: InstructionInfoFactory::new(),
            violations: Vec::new(),
            memory_events: Vec::new(),
            pending_allocs: Vec::new(),
            pending_frees: Vec::new(),
        }
    }

    pub fn process_record(&mut self, record: &TraceRecord) -> Result<(), AnalyzerError> {
        self.apply_pending(record);
        let decoded =
            decode::decode(record, &mut self.info_factory).map_err(AnalyzerError::Decode)?;
        self.observe_accesses(record, &decoded);
        self.apply_instruction_semantics(record, &decoded);
        self.observe_call(record, &decoded.instruction);
        Ok(())
    }

    pub fn finish(self) -> AnalysisResult {
        AnalysisResult {
            violations: self.violations,
            memory_events: self.memory_events,
        }
    }

    fn apply_pending(&mut self, record: &TraceRecord) {
        let mut allocs = Vec::new();
        self.pending_allocs.retain(|pending| {
            if pending.return_pc == record.pc {
                allocs.push(pending.clone());
                false
            } else {
                true
            }
        });
        for pending in allocs {
            if let Some(ptr) = record.reg(RAX).filter(|v| *v != 0) {
                self.add_allocation(
                    record.step,
                    record.pc,
                    ptr,
                    pending.size,
                    pending.symbol.clone(),
                );
                self.regs.insert(
                    RAX,
                    RegState {
                        value_owners: owner_set_one(
                            self.subject_at_start(ptr).unwrap_or(ALLOCATOR_SUBJECT),
                        ),
                        pointee_owners: owner_set_one(
                            self.subject_at_start(ptr).unwrap_or(ALLOCATOR_SUBJECT),
                        ),
                    },
                );
            }
        }
        let mut frees = Vec::new();
        self.pending_frees.retain(|pending| {
            if pending.return_pc == record.pc {
                frees.push(pending.clone());
                false
            } else {
                true
            }
        });
        for pending in frees {
            self.handle_free(
                pending.call_step,
                pending.call_pc,
                pending.ptr,
                pending.pointer_owners,
                pending.symbol,
            );
        }
    }

    fn observe_call(&mut self, record: &TraceRecord, instruction: &Instruction) {
        if !decode::is_call(instruction) && record.flags & TRACE_FLAG_IS_CALL == 0 {
            return;
        }
        let target = record.branch_target.or_else(|| {
            if instruction.is_call_near() {
                Some(instruction.near_branch_target())
            } else {
                None
            }
        });
        let Some(target) = target else {
            return;
        };
        let return_pc = record.pc.wrapping_add(instruction.len() as u64);
        let symbol = self.config.symbol(target).cloned();
        if self.config.malloc_addrs.contains(&target) {
            let size = symbol
                .as_ref()
                .and_then(|s| self.resolve_alloc_size(record, s))
                .unwrap_or(0);
            self.pending_allocs.push(PendingAlloc {
                return_pc,
                size,
                symbol: symbol.map(|s| s.name),
            });
        } else if self.config.free_addrs.contains(&target) {
            let ptr = symbol
                .as_ref()
                .and_then(|s| s.import_reg)
                .and_then(|reg| record.reg(reg))
                .unwrap_or(0);
            let pointer_owners = symbol
                .as_ref()
                .and_then(|s| s.import_reg)
                .map(|reg| self.reg_state(reg).pointee_owners)
                .unwrap_or_default();
            self.pending_frees.push(PendingFree {
                return_pc,
                ptr,
                pointer_owners,
                symbol: symbol.map(|s| s.name),
                call_pc: record.pc,
                call_step: record.step,
            });
        }
    }

    fn resolve_alloc_size(&self, record: &TraceRecord, symbol: &SymbolConfig) -> Option<u64> {
        if let Some(size) = symbol.malloc_size {
            return Some(size);
        }
        if symbol.use_value_to_size {
            return record.value;
        }
        symbol.import_reg.and_then(|reg| record.reg(reg)).map(|v| {
            if symbol.offset == 0 {
                v
            } else {
                ((v as i128) + symbol.offset as i128).max(0) as u64
            }
        })
    }

    fn add_allocation(&mut self, step: u64, pc: u64, ptr: u64, size: u64, symbol: Option<String>) {
        let subject = self.mem.fresh_heap_subject(ptr, size);
        let mut reported_overlap = false;
        for off in 0..size {
            let addr = ptr.saturating_add(off);
            let active_existing: Vec<_> = self
                .mem
                .cell(addr)
                .cell_owners
                .iter()
                .copied()
                .filter(|owner| *owner != ALLOCATOR_SUBJECT && !self.mem.subject_freed(*owner))
                .collect();
            if !active_existing.is_empty() && !reported_overlap {
                let mut pointer = owner_set_one(subject);
                pointer.extend(active_existing.iter().copied());
                self.record(
                    step,
                    pc,
                    ViolationKind::MemoryOverlap,
                    AccessKind::Other,
                    addr,
                    1,
                    pointer,
                    self.mem.cell(addr),
                    Some("malloc returned a cell with active non-allocator owners".into()),
                );
                reported_overlap = true;
            }
            let cell = self.mem.cell_mut(addr);
            cell.cell_owners.shift_remove(&ALLOCATOR_SUBJECT);
            cell.cell_owners.insert(subject);
            if cell.value_owners.is_empty() {
                cell.value_owners.insert(ALLOCATOR_SUBJECT);
            }
        }
        self.memory_events.push(MemoryEvent {
            step,
            pc: hex(pc),
            kind: "allocation".into(),
            symbol,
            ptr: Some(hex(ptr)),
            size: Some(hex(size)),
        });
    }

    fn handle_free(
        &mut self,
        step: u64,
        pc: u64,
        ptr: u64,
        pointer_owners: OwnerSet,
        symbol: Option<String>,
    ) {
        if ptr == 0 {
            self.record_simple(
                step,
                pc,
                ViolationKind::InvalidFree,
                AccessKind::Free,
                ptr,
                0,
                pointer_owners,
                "free(NULL or unavailable) is not tracked as an active allocation",
            );
            return;
        }
        if pointer_owners
            .iter()
            .any(|owner| self.mem.subject_freed(*owner))
            || self.mem.freed_subject_at_start(ptr).is_some()
        {
            self.record_simple(
                step,
                pc,
                ViolationKind::DoubleFree,
                AccessKind::Free,
                ptr,
                0,
                pointer_owners.clone(),
                "free of an already freed subject",
            );
            return;
        }
        let Some(subject) = self.mem.active_subject_at_start(ptr) else {
            let note = if self.mem.active_subject_containing(ptr).is_some() {
                "free pointer is inside an allocation but not at its start"
            } else {
                "free pointer is not an active allocation start"
            };
            self.record_simple(
                step,
                pc,
                ViolationKind::InvalidFree,
                AccessKind::Free,
                ptr,
                0,
                pointer_owners,
                note,
            );
            return;
        };
        self.mem.mark_freed(subject);
        let (start, size) = self
            .mem
            .subjects
            .get(&subject)
            .and_then(|s| s.start.zip(s.size))
            .unwrap_or((ptr, 0));
        for off in 0..size {
            let cell = self.mem.cell_mut(start.saturating_add(off));
            cell.cell_owners.shift_remove(&subject);
            cell.cell_owners.insert(ALLOCATOR_SUBJECT);
        }
        self.memory_events.push(MemoryEvent {
            step,
            pc: hex(pc),
            kind: "free".into(),
            symbol,
            ptr: Some(hex(ptr)),
            size: None,
        });
    }

    fn observe_accesses(&mut self, record: &TraceRecord, decoded: &DecodedInstruction) {
        for access in &decoded.accesses {
            let size = access.size.max(1);
            for off in 0..size {
                let addr = access.address.saturating_add(off as u64);
                self.observe_one_access(record, access, addr);
            }
        }
    }

    fn observe_one_access(&mut self, record: &TraceRecord, access: &ResolvedAccess, addr: u64) {
        let pointer_owners = self.pointer_owner_from_access(access);
        let cell = self.mem.cell(addr);
        if addr < 0x1000
            && matches!(
                access.kind,
                AccessKind::Read | AccessKind::Write | AccessKind::ReadWrite
            )
        {
            self.record(
                record.step,
                record.pc,
                ViolationKind::NullPointerDereference,
                access.kind,
                addr,
                1,
                pointer_owners.clone(),
                cell.clone(),
                None,
            );
        }
        let is_read = matches!(access.kind, AccessKind::Read | AccessKind::ReadWrite);
        let is_write = matches!(access.kind, AccessKind::Write | AccessKind::ReadWrite);
        if is_read || is_write {
            let uaf = pointer_owners.iter().copied().find(|owner| {
                self.mem.subject_freed(*owner) && self.mem.subject_contains(*owner, addr)
            });
            if uaf.is_some() {
                let kind = if is_write {
                    ViolationKind::UseAfterFreeWrite
                } else {
                    ViolationKind::UseAfterFreeRead
                };
                self.record(
                    record.step,
                    record.pc,
                    kind,
                    access.kind,
                    addr,
                    1,
                    pointer_owners.clone(),
                    cell.clone(),
                    Some("stale pointer owner refers to a freed allocation range".into()),
                );
                return;
            }
            if !pointer_owners.is_empty() && !sets_intersect(&pointer_owners, &cell.cell_owners) {
                let kind = if is_write {
                    ViolationKind::OutOfBoundsWrite
                } else {
                    ViolationKind::OutOfBoundsRead
                };
                self.record(
                    record.step,
                    record.pc,
                    kind,
                    access.kind,
                    addr,
                    1,
                    pointer_owners.clone(),
                    cell.clone(),
                    None,
                );
            }
            if is_read
                && !cell.cell_owners.is_empty()
                && !cell.cell_owners.contains(&ALLOCATOR_SUBJECT)
                && !sets_intersect(&cell.cell_owners, &cell.value_owners)
            {
                self.record(
                    record.step,
                    record.pc,
                    ViolationKind::UninitializedRead,
                    access.kind,
                    addr,
                    1,
                    pointer_owners,
                    cell,
                    None,
                );
            }
        }
    }

    fn apply_instruction_semantics(&mut self, record: &TraceRecord, decoded: &DecodedInstruction) {
        let ins = &decoded.instruction;
        if decode::is_call(ins) || decode::is_ret(ins) {
            return;
        }
        if decode::is_lea(ins) {
            self.apply_lea(record, ins);
            return;
        }
        if decode::is_pointer_arith(ins) {
            self.apply_arith(record, ins);
        }
        self.apply_loads_and_stores(record, decoded);
        self.apply_register_writes(record, ins);
    }

    fn apply_loads_and_stores(&mut self, record: &TraceRecord, decoded: &DecodedInstruction) {
        let ins = &decoded.instruction;
        for access in &decoded.accesses {
            if matches!(access.kind, AccessKind::Read | AccessKind::ReadWrite) {
                if let Some(dst) = first_written_reg(ins) {
                    let mut state = self.state_from_memory(access);
                    if access.size != 8 {
                        state.pointee_owners.clear();
                    }
                    self.regs.insert(dst, state);
                }
            }
            if matches!(access.kind, AccessKind::Write | AccessKind::ReadWrite) {
                let src = first_read_reg_not_addr(ins, access);
                let pointer_owners = self.pointer_owner_from_access(access);
                let mut src_pointee = src
                    .map(|reg| self.reg_state(reg).pointee_owners)
                    .unwrap_or_default();
                if access.size != 8 {
                    src_pointee.clear();
                }
                for off in 0..access.size.max(1) {
                    let addr = access.address.saturating_add(off as u64);
                    let cell_owners = self.mem.cell(addr).cell_owners;
                    let cell = self.mem.cell_mut(addr);
                    cell.value_owners = if pointer_owners.is_empty() {
                        cell_owners
                    } else {
                        pointer_owners.clone()
                    };
                    cell.pointee_owners = src_pointee.clone();
                    cell.last_write_pc = Some(record.pc);
                }
            }
        }
    }

    fn apply_register_writes(&mut self, record: &TraceRecord, ins: &Instruction) {
        if ins.mnemonic() != Mnemonic::Mov {
            return;
        }
        if ins.op_count() < 2 || ins.op0_kind() != OpKind::Register {
            return;
        }
        let Some(dst) = id_from_iced(ins.op0_register()) else {
            return;
        };
        match ins.op1_kind() {
            OpKind::Register => {
                if let Some(src) = id_from_iced(ins.op1_register()) {
                    self.regs.insert(dst, self.reg_state(src));
                }
            }
            OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate32to64
            | OpKind::Immediate64 => {
                let value = immediate(ins);
                let mut owners = self.mem.owner_for_address(value);
                if owners.is_empty() {
                    owners = OwnerSet::new();
                }
                self.regs.insert(
                    dst,
                    RegState {
                        value_owners: owners.clone(),
                        pointee_owners: owners,
                    },
                );
            }
            _ => {
                let _ = record;
            }
        }
    }

    fn apply_lea(&mut self, record: &TraceRecord, ins: &Instruction) {
        let Some(dst) = id_from_iced(ins.op0_register()) else {
            return;
        };
        let result = record
            .reg(dst)
            .unwrap_or_else(|| compute_lea_result(record, ins).unwrap_or(0));
        let mut owners = OwnerSet::new();
        if let Some(base) = id_from_iced(ins.memory_base()) {
            owners.extend(self.reg_state(base).pointee_owners);
        }
        if let Some(index) = id_from_iced(ins.memory_index()) {
            owners.extend(self.reg_state(index).pointee_owners);
        }
        self.check_cross_boundary(record.step, record.pc, result, &owners);
        owners.extend(self.mem.owner_for_address(result));
        self.regs.insert(
            dst,
            RegState {
                value_owners: owners.clone(),
                pointee_owners: owners,
            },
        );
    }

    fn apply_arith(&mut self, record: &TraceRecord, ins: &Instruction) {
        if ins.op_count() < 2 || ins.op0_kind() != OpKind::Register {
            return;
        }
        let Some(dst) = id_from_iced(ins.op0_register()) else {
            return;
        };
        let Some(left) = record.reg(dst) else {
            return;
        };
        let Some(right) = right_operand_value(record, ins) else {
            return;
        };
        let result = match ins.mnemonic() {
            Mnemonic::Add => left.wrapping_add(right),
            Mnemonic::Sub => left.wrapping_sub(right),
            _ => return,
        };
        let mut state = self.reg_state(dst);
        self.check_cross_boundary(record.step, record.pc, result, &state.pointee_owners);
        state
            .pointee_owners
            .extend(self.mem.owner_for_address(result));
        self.regs.insert(dst, state);
    }

    fn check_cross_boundary(&mut self, step: u64, pc: u64, result: u64, pointer_owners: &OwnerSet) {
        if pointer_owners.is_empty() {
            return;
        }
        let result_cell = self.mem.cell(result);
        if result_cell.cell_owners.is_empty() {
            return;
        }
        if !sets_intersect(pointer_owners, &result_cell.cell_owners) {
            self.record(
                step,
                pc,
                ViolationKind::CrossBoundary,
                AccessKind::Other,
                result,
                1,
                pointer_owners.clone(),
                result_cell,
                Some("pointer arithmetic moved into a different subject".into()),
            );
        }
    }

    fn pointer_owner_from_access(&self, access: &ResolvedAccess) -> OwnerSet {
        let mut owners = OwnerSet::new();
        if let Some(base) = access.base {
            owners.extend(self.reg_state(base).pointee_owners);
        }
        if let Some(index) = access.index {
            owners.extend(self.reg_state(index).pointee_owners);
        }
        owners
    }

    fn state_from_memory(&self, access: &ResolvedAccess) -> RegState {
        let mut state = RegState::default();
        for off in 0..access.size.max(1) {
            let cell = self.mem.cell(access.address.saturating_add(off as u64));
            state.value_owners.extend(cell.value_owners);
            state.pointee_owners.extend(cell.pointee_owners);
        }
        state
    }

    fn reg_state(&self, reg: RegId) -> RegState {
        self.regs.get(&reg).cloned().unwrap_or_default()
    }
    fn subject_at_start(&self, ptr: u64) -> Option<u64> {
        self.mem.active_subject_at_start(ptr)
    }

    fn record_simple(
        &mut self,
        step: u64,
        pc: u64,
        kind: ViolationKind,
        access: AccessKind,
        address: u64,
        size: u32,
        pointer_owners: OwnerSet,
        note: &str,
    ) {
        let cell = self.mem.cell(address);
        self.record(
            step,
            pc,
            kind,
            access,
            address,
            size,
            pointer_owners,
            cell,
            Some(note.into()),
        );
    }

    fn record(
        &mut self,
        step: u64,
        pc: u64,
        kind: ViolationKind,
        access: AccessKind,
        address: u64,
        size: u32,
        pointer_owners: OwnerSet,
        cell: crate::ownership::CellState,
        note: Option<String>,
    ) {
        if !self.config.violation_enabled(kind) {
            return;
        }
        let pc_label = hex(pc);
        let pointer_labels = self.mem.labels(&pointer_owners);
        let cell_labels = self.mem.labels(&cell.cell_owners);
        let value_labels = self.mem.labels(&cell.value_owners);
        if let Some(prev) = self.violations.last_mut() {
            let prev_addr = parse_hex_label(&prev.address).unwrap_or(u64::MAX);
            let prev_size = parse_hex_label(&prev.size).unwrap_or(0);
            if prev.step == step
                && prev.pc == pc_label
                && prev.kind == kind
                && prev.access == access
                && prev_addr.saturating_add(prev_size) == address
                && prev.pointer_owners == pointer_labels
                && prev.cell_owners == cell_labels
                && prev.value_owners == value_labels
                && prev.note == note
            {
                prev.size = hex(prev_size.saturating_add(size as u64));
                return;
            }
        }
        self.violations.push(Violation {
            step,
            pc: pc_label,
            kind,
            access,
            address: hex(address),
            size: hex(size as u64),
            pointer_owners: pointer_labels,
            cell_owners: cell_labels,
            value_owners: value_labels,
            note,
        });
    }
}

fn first_written_reg(ins: &Instruction) -> Option<RegId> {
    for i in 0..ins.op_count() {
        if ins.op_kind(i) == OpKind::Register {
            // Heuristic: first register operand of load-like instruction is destination.
            return id_from_iced(match i {
                0 => ins.op0_register(),
                1 => ins.op1_register(),
                2 => ins.op2_register(),
                3 => ins.op3_register(),
                _ => Register::None,
            });
        }
    }
    None
}

fn first_read_reg_not_addr(ins: &Instruction, access: &ResolvedAccess) -> Option<RegId> {
    for i in 0..ins.op_count() {
        if ins.op_kind(i) != OpKind::Register {
            continue;
        }
        let reg = match i {
            0 => ins.op0_register(),
            1 => ins.op1_register(),
            2 => ins.op2_register(),
            3 => ins.op3_register(),
            _ => Register::None,
        };
        let Some(id) = id_from_iced(reg) else {
            continue;
        };
        if Some(id) == access.base || Some(id) == access.index {
            continue;
        }
        // In Intel syntax, register operand after memory destination is usually source.
        if i > 0 || ins.op0_kind() != OpKind::Register {
            return Some(id);
        }
    }
    None
}

fn compute_lea_result(record: &TraceRecord, ins: &Instruction) -> Option<u64> {
    let base = if ins.memory_base() == Register::None {
        0
    } else {
        decode::register_value(record, ins.memory_base())?
    };
    let index = if ins.memory_index() == Register::None {
        0
    } else {
        decode::register_value(record, ins.memory_index())?
    };
    Some(
        base.wrapping_add(index.wrapping_mul(ins.memory_index_scale() as u64))
            .wrapping_add(ins.memory_displacement64()),
    )
}

fn right_operand_value(record: &TraceRecord, ins: &Instruction) -> Option<u64> {
    match ins.op1_kind() {
        OpKind::Register => id_from_iced(ins.op1_register()).and_then(|id| record.reg(id)),
        _ => Some(immediate(ins)),
    }
}

fn immediate(ins: &Instruction) -> u64 {
    match ins.op1_kind() {
        OpKind::Immediate8 => ins.immediate8() as u64,
        OpKind::Immediate8to16 => ins.immediate8to16() as u64,
        OpKind::Immediate8to32 => ins.immediate8to32() as u64,
        OpKind::Immediate8to64 => ins.immediate8to64() as u64,
        OpKind::Immediate16 => ins.immediate16() as u64,
        OpKind::Immediate32 => ins.immediate32() as u64,
        OpKind::Immediate32to64 => ins.immediate32to64() as u64,
        OpKind::Immediate64 => ins.immediate64(),
        _ => 0,
    }
}

fn hex(value: u64) -> String {
    format!("0x{value:016x}")
}

fn parse_hex_label(label: &str) -> Option<u64> {
    let trimmed = label.trim();
    let raw = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    u64::from_str_radix(raw, 16).ok()
}
