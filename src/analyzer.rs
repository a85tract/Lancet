use std::collections::HashMap;

use iced_x86::{Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use thiserror::Error;

use crate::config::{Config, PageAllocatorConfig, SymbolConfig};
use crate::decode::{self, DecodedInstruction, ResolvedAccess};
use crate::ownership::{
    ALLOCATOR_SUBJECT, MemoryModel, OwnerSet, RegState, SubjectKind, owner_set_one, sets_intersect,
};
use crate::registers::{RAX, RBP, RCX, RDI, RDX, RSI, RSP, RegId, id_from_iced};
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
    call_pc: u64,
    call_step: u64,
    zero_initialized: bool,
    lookahead_left: u8,
}

#[derive(Debug, Clone)]
struct PendingRealloc {
    return_pc: u64,
    old_ptr: u64,
    old_pointer_owners: OwnerSet,
    size: u64,
    symbol: Option<String>,
    call_pc: u64,
    call_step: u64,
    lookahead_left: u8,
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

#[derive(Debug, Clone)]
struct PendingPageAlloc {
    return_pc: u64,
    order: u64,
    call_pc: u64,
    call_step: u64,
    symbol: Option<String>,
    lookahead_left: u8,
}

#[derive(Debug, Clone)]
struct PendingPageFree {
    return_pc: u64,
    page_ptr: u64,
    order: u64,
    call_pc: u64,
    call_step: u64,
    symbol: Option<String>,
}

const PAGE_SIZE: u64 = 0x1000;
const PAGE_STRUCT_SHIFT: u32 = 6;
const PAGE_SHIFT: u32 = 12;

pub struct Analyzer {
    config: Config,
    mem: MemoryModel,
    regs: HashMap<RegId, RegState>,
    info_factory: InstructionInfoFactory,
    violations: Vec<Violation>,
    memory_events: Vec<MemoryEvent>,
    pending_allocs: Vec<PendingAlloc>,
    pending_reallocs: Vec<PendingRealloc>,
    pending_frees: Vec<PendingFree>,
    pending_page_allocs: Vec<PendingPageAlloc>,
    pending_page_frees: Vec<PendingPageFree>,
    stack_pages: HashMap<u64, u64>,
    global_pages: HashMap<u64, u64>,
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
            pending_reallocs: Vec::new(),
            pending_frees: Vec::new(),
            pending_page_allocs: Vec::new(),
            pending_page_frees: Vec::new(),
            stack_pages: HashMap::new(),
            global_pages: HashMap::new(),
        }
    }

    pub fn process_record(&mut self, record: &TraceRecord) -> Result<(), AnalyzerError> {
        self.apply_pending(record);
        self.synchronize_sampled_registers(record);
        let decoded =
            decode::decode(record, &mut self.info_factory).map_err(AnalyzerError::Decode)?;
        self.ensure_static_subjects(record, &decoded);
        self.observe_accesses(record, &decoded);
        self.observe_call(record, &decoded.instruction);
        self.apply_instruction_semantics(record, &decoded);
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
            if pending.return_pc == record.pc
                || (pending.lookahead_left > 0 && record.step > pending.call_step)
            {
                allocs.push(pending.clone());
                false
            } else {
                true
            }
        });
        for pending in allocs {
            if let Some(ptr) = record.reg(RAX).filter(|v| *v != 0) {
                self.add_allocation(
                    pending.call_step,
                    pending.call_pc,
                    ptr,
                    pending.size,
                    pending.symbol.clone(),
                    pending.zero_initialized,
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
            } else if pending.lookahead_left > 1 {
                let mut retry = pending;
                retry.lookahead_left -= 1;
                self.pending_allocs.push(retry);
            }
        }

        let mut reallocs = Vec::new();
        self.pending_reallocs.retain(|pending| {
            if pending.return_pc == record.pc
                || (pending.lookahead_left > 0 && record.step > pending.call_step)
            {
                reallocs.push(pending.clone());
                false
            } else {
                true
            }
        });
        for pending in reallocs {
            match record.reg(RAX) {
                Some(new_ptr) if new_ptr != 0 => {
                    if pending.old_ptr != 0 {
                        self.handle_free(
                            pending.call_step,
                            pending.call_pc,
                            pending.old_ptr,
                            pending.old_pointer_owners.clone(),
                            pending.symbol.as_ref().map(|name| format!("{name}:old")),
                        );
                    }
                    self.add_allocation(
                        pending.call_step,
                        pending.call_pc,
                        new_ptr,
                        pending.size,
                        pending.symbol.clone(),
                        false,
                    );
                    self.regs.insert(
                        RAX,
                        RegState {
                            value_owners: owner_set_one(
                                self.subject_at_start(new_ptr).unwrap_or(ALLOCATOR_SUBJECT),
                            ),
                            pointee_owners: owner_set_one(
                                self.subject_at_start(new_ptr).unwrap_or(ALLOCATOR_SUBJECT),
                            ),
                        },
                    );
                }
                Some(0) if pending.size == 0 && pending.old_ptr != 0 => {
                    self.handle_free(
                        pending.call_step,
                        pending.call_pc,
                        pending.old_ptr,
                        pending.old_pointer_owners,
                        pending.symbol,
                    );
                }
                _ if pending.lookahead_left > 1 => {
                    let mut retry = pending;
                    retry.lookahead_left -= 1;
                    self.pending_reallocs.push(retry);
                }
                _ => {}
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

        let mut page_allocs = Vec::new();
        self.pending_page_allocs.retain(|pending| {
            if pending.return_pc == record.pc
                || (pending.lookahead_left > 0 && record.step > pending.call_step)
            {
                page_allocs.push(pending.clone());
                false
            } else {
                true
            }
        });
        for pending in page_allocs {
            if let Some(page_ptr) = record.reg(RAX).filter(|v| *v != 0) {
                if let Some((base, size)) = self.page_allocation_range(page_ptr, pending.order) {
                    self.add_page_allocation(
                        pending.call_step,
                        pending.call_pc,
                        page_ptr,
                        base,
                        size,
                        pending.symbol.clone(),
                    );
                    let owner = self
                        .mem
                        .active_subject_containing(base)
                        .unwrap_or(ALLOCATOR_SUBJECT);
                    self.regs.insert(
                        RAX,
                        RegState {
                            value_owners: owner_set_one(owner),
                            pointee_owners: owner_set_one(owner),
                        },
                    );
                }
            } else if pending.lookahead_left > 1 {
                let mut retry = pending;
                retry.lookahead_left -= 1;
                self.pending_page_allocs.push(retry);
            }
        }

        let mut page_frees = Vec::new();
        self.pending_page_frees.retain(|pending| {
            if pending.return_pc == record.pc {
                page_frees.push(pending.clone());
                false
            } else {
                true
            }
        });
        for pending in page_frees {
            self.handle_page_free(
                pending.call_step,
                pending.call_pc,
                pending.page_ptr,
                pending.order,
                pending.symbol,
            );
        }
    }

    fn observe_call(&mut self, record: &TraceRecord, instruction: &Instruction) {
        let is_call_like = decode::is_call(instruction)
            || is_jump(instruction)
            || record.flags & TRACE_FLAG_IS_CALL != 0;
        if !is_call_like {
            return;
        }
        let target = record.branch_target.or_else(|| {
            if instruction.is_call_near() || instruction.is_jmp_short_or_near() {
                Some(instruction.near_branch_target())
            } else {
                None
            }
        });
        let Some(target) = target else {
            return;
        };
        let return_pc = self
            .config
            .skip_return_for(target)
            .unwrap_or_else(|| record.pc.wrapping_add(instruction.len() as u64));
        let symbol = self.config.symbol(target).cloned();
        if symbol
            .as_ref()
            .is_some_and(|s| self.apply_library_summary(record, s))
        {
            return;
        }
        if is_page_alloc_symbol(symbol.as_ref(), target, self.config.page_allocator) {
            let order = record.reg(RSI).unwrap_or(0);
            self.pending_page_allocs.push(PendingPageAlloc {
                return_pc,
                order,
                call_pc: record.pc,
                call_step: record.step,
                symbol: symbol.map(|s| s.name),
                lookahead_left: 0,
            });
        } else if is_page_free_symbol(symbol.as_ref(), target, self.config.page_allocator) {
            let page_ptr = symbol
                .as_ref()
                .and_then(|s| s.import_reg)
                .and_then(|reg| record.reg(reg))
                .or_else(|| record.reg(RDI))
                .unwrap_or(0);
            let order = record.reg(RSI).unwrap_or(0);
            self.pending_page_frees.push(PendingPageFree {
                return_pc,
                page_ptr,
                order,
                call_pc: record.pc,
                call_step: record.step,
                symbol: symbol.map(|s| s.name),
            });
        } else if symbol.as_ref().is_some_and(|s| is_realloc_name(&s.name)) {
            let old_ptr = record.reg(RDI).unwrap_or(0);
            let old_pointer_owners = self.reg_state(RDI).pointee_owners;
            let size = record.reg(RSI).unwrap_or(0);
            self.pending_reallocs.push(PendingRealloc {
                return_pc,
                old_ptr,
                old_pointer_owners,
                size,
                symbol: symbol.as_ref().map(|s| s.name.clone()),
                call_pc: record.pc,
                call_step: record.step,
                lookahead_left: 0,
            });
        } else if self.config.malloc_addrs.contains(&target)
            || symbol.as_ref().is_some_and(|s| is_alloc_name(&s.name))
        {
            let size = symbol
                .as_ref()
                .and_then(|s| self.resolve_alloc_size(record, s))
                .or(self.config.malloc_size)
                .unwrap_or_else(|| record.reg(RDI).unwrap_or(0));
            let zero_initialized = symbol.as_ref().is_some_and(|s| s.zero_initialized);
            self.pending_allocs.push(PendingAlloc {
                return_pc,
                size,
                symbol: symbol.as_ref().map(|s| s.name.clone()),
                call_pc: record.pc,
                call_step: record.step,
                zero_initialized,
                lookahead_left: 0,
            });
        } else if self.config.free_addrs.contains(&target)
            || symbol.as_ref().is_some_and(|s| is_free_name(&s.name))
        {
            let ptr = symbol
                .as_ref()
                .and_then(|s| s.import_reg)
                .and_then(|reg| record.reg(reg))
                .or_else(|| record.reg(RDI))
                .unwrap_or(0);
            let pointer_owners = symbol
                .as_ref()
                .and_then(|s| s.import_reg)
                .map(|reg| self.reg_state(reg).pointee_owners)
                .or_else(|| Some(self.reg_state(RDI).pointee_owners))
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
        let lower = symbol.name.to_ascii_lowercase();
        if lower.contains("calloc") {
            return record
                .reg(RDI)
                .zip(record.reg(RSI))
                .map(|(nmemb, size)| nmemb.saturating_mul(size));
        }
        if is_realloc_name(&lower) {
            return record.reg(RSI);
        }
        if symbol.use_value_to_size {
            return record
                .value
                .map(|value| apply_value_size(value, symbol.value_size));
        }
        symbol.import_reg.and_then(|reg| record.reg(reg)).map(|v| {
            if symbol.offset == 0 {
                v
            } else {
                ((v as i128) + symbol.offset as i128).max(0) as u64
            }
        })
    }

    fn apply_library_summary(&mut self, record: &TraceRecord, symbol: &SymbolConfig) -> bool {
        let name = symbol.name.to_ascii_lowercase();
        if name.contains("memcpy") || name.contains("memmove") || name.contains("mempcpy") {
            let Some(dst) = record.reg(RDI) else {
                return false;
            };
            let Some(src) = record.reg(RSI) else {
                return false;
            };
            let len = record.reg(RDX).unwrap_or(0);
            self.copy_memory_summary(record, dst, src, len);
            self.regs.insert(RAX, self.reg_state(RDI));
            self.memory_events.push(MemoryEvent {
                step: record.step,
                pc: hex(record.pc),
                kind: "memcpy-summary".into(),
                symbol: Some(symbol.name.clone()),
                ptr: Some(hex(dst)),
                size: Some(hex(len)),
            });
            return true;
        }
        if name.contains("memset") || name.contains("bzero") || name.contains("clear_user") {
            let Some(dst) = record.reg(RDI) else {
                return false;
            };
            let len = if name.contains("bzero") {
                record.reg(RSI).unwrap_or(0)
            } else {
                record.reg(RDX).unwrap_or(0)
            };
            self.set_memory_summary(record, dst, len);
            self.regs.insert(RAX, self.reg_state(RDI));
            self.memory_events.push(MemoryEvent {
                step: record.step,
                pc: hex(record.pc),
                kind: "memset-summary".into(),
                symbol: Some(symbol.name.clone()),
                ptr: Some(hex(dst)),
                size: Some(hex(len)),
            });
            return true;
        }
        false
    }

    fn add_allocation(
        &mut self,
        step: u64,
        pc: u64,
        ptr: u64,
        size: u64,
        symbol: Option<String>,
        zero_initialized: bool,
    ) {
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
            if zero_initialized {
                cell.value_owners.clear();
                cell.value_owners.insert(subject);
            } else if cell.value_owners.is_empty() {
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

    fn add_page_allocation(
        &mut self,
        step: u64,
        pc: u64,
        page_ptr: u64,
        base: u64,
        size: u64,
        symbol: Option<String>,
    ) {
        let subject = self.mem.fresh_subject(SubjectKind::Page, base, size);
        for off in 0..size {
            let cell = self.mem.cell_mut(base.saturating_add(off));
            cell.cell_owners.shift_remove(&ALLOCATOR_SUBJECT);
            cell.cell_owners.insert(subject);
            if cell.value_owners.is_empty() {
                cell.value_owners.insert(ALLOCATOR_SUBJECT);
            }
        }
        self.memory_events.push(MemoryEvent {
            step,
            pc: hex(pc),
            kind: "page-allocation".into(),
            symbol,
            ptr: Some(hex(page_ptr)),
            size: Some(hex(size)),
        });
    }

    fn handle_page_free(
        &mut self,
        step: u64,
        pc: u64,
        page_ptr: u64,
        order: u64,
        symbol: Option<String>,
    ) {
        let Some((base, size)) = self.page_allocation_range(page_ptr, order) else {
            return;
        };
        let Some(subject) = self.mem.active_subject_containing(base) else {
            self.record_simple(
                step,
                pc,
                ViolationKind::InvalidFree,
                AccessKind::Free,
                base,
                0,
                OwnerSet::new(),
                "free_pages target is not an active page allocation",
            );
            return;
        };
        self.mem.mark_freed(subject);
        for off in 0..size {
            let cell = self.mem.cell_mut(base.saturating_add(off));
            cell.cell_owners.shift_remove(&subject);
            cell.cell_owners.insert(ALLOCATOR_SUBJECT);
        }
        self.memory_events.push(MemoryEvent {
            step,
            pc: hex(pc),
            kind: "page-free".into(),
            symbol,
            ptr: Some(hex(page_ptr)),
            size: Some(hex(size)),
        });
    }

    fn page_allocation_range(&self, page_ptr: u64, order: u64) -> Option<(u64, u64)> {
        let PageAllocatorConfig {
            vmemmap_start,
            page_offset_base,
        } = self.config.page_allocator?;
        let offset = page_ptr.checked_sub(vmemmap_start)?;
        let page_index = offset >> PAGE_STRUCT_SHIFT;
        let bytes = page_index.checked_shl(PAGE_SHIFT)?;
        let base = page_offset_base.checked_add(bytes)?;
        let pages = 1u64.checked_shl(order as u32)?;
        let size = pages.checked_mul(PAGE_SIZE)?;
        Some((base, size))
    }

    fn synchronize_sampled_registers(&mut self, record: &TraceRecord) {
        for (&reg, &value) in &record.regs {
            let inferred = self.owner_set_for_value(value);
            if inferred.is_empty() {
                continue;
            }
            let state = self.regs.entry(reg).or_default();
            state.value_owners.extend(inferred.iter().copied());
            state.pointee_owners.extend(inferred);
        }
    }

    fn owner_set_for_value(&self, value: u64) -> OwnerSet {
        let mut owners = self.mem.owner_for_address(value);
        if let Some(subject) = self.mem.active_subject_containing(value) {
            owners.insert(subject);
        }
        if let Some(subject) = self.mem.freed_subject_containing(value) {
            owners.insert(subject);
        }
        owners
    }

    fn ensure_static_subjects(&mut self, record: &TraceRecord, decoded: &DecodedInstruction) {
        for access in &decoded.accesses {
            let size = access.size.max(1);
            if self.pointer_owner_from_access(access).is_empty() && self.is_stack_access(access) {
                self.ensure_stack_page(access.address, size);
            } else if self.should_treat_as_global(record, access) {
                self.ensure_global_page(access.address, size);
            }
        }
    }

    fn is_stack_access(&self, access: &ResolvedAccess) -> bool {
        matches!(access.base, Some(reg) if reg == RSP || reg == RBP)
    }

    fn should_treat_as_global(&self, _record: &TraceRecord, access: &ResolvedAccess) -> bool {
        if !self.mem.cell(access.address).cell_owners.is_empty()
            || self.mem.active_subject_containing(access.address).is_some()
            || self.mem.freed_subject_containing(access.address).is_some()
        {
            return false;
        }
        if let Some((base, size)) = self.config.module_range
            && access.address >= base
            && access.address < base.saturating_add(size)
        {
            return true;
        }
        is_high_half_address(access.address) && self.pointer_owner_from_access(access).is_empty()
    }

    fn ensure_stack_page(&mut self, addr: u64, size: u32) {
        let start = addr & !(PAGE_SIZE - 1);
        if self.stack_pages.contains_key(&start) {
            return;
        }
        let subject = self
            .mem
            .ensure_range_owner(SubjectKind::Stack, start, PAGE_SIZE);
        for off in 0..size.max(1) {
            let cell = self.mem.cell_mut(addr.saturating_add(off as u64));
            cell.cell_owners.insert(subject);
            if cell.value_owners.is_empty() {
                cell.value_owners.insert(subject);
            }
        }
        self.stack_pages.insert(start, subject);
    }

    fn ensure_global_page(&mut self, addr: u64, size: u32) {
        let start = addr & !(PAGE_SIZE - 1);
        if self.global_pages.contains_key(&start) {
            return;
        }
        let subject = self
            .mem
            .ensure_range_owner(SubjectKind::Global, start, PAGE_SIZE);
        for off in 0..size.max(1) {
            let cell = self.mem.cell_mut(addr.saturating_add(off as u64));
            cell.cell_owners.insert(subject);
            if cell.value_owners.is_empty() {
                cell.value_owners.insert(subject);
            }
        }
        self.global_pages.insert(start, subject);
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
        self.observe_one_access_with_pointer(record, access, addr, pointer_owners);
    }

    fn observe_one_access_with_pointer(
        &mut self,
        record: &TraceRecord,
        access: &ResolvedAccess,
        addr: u64,
        pointer_owners: OwnerSet,
    ) {
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
            if let Some(owner) = uaf {
                let kind = if self.mem.subject_kind(owner) == SubjectKind::Stack {
                    if is_write {
                        ViolationKind::StackUseAfterScopeWrite
                    } else {
                        ViolationKind::StackUseAfterScopeRead
                    }
                } else if is_write {
                    ViolationKind::UseAfterFreeWrite
                } else {
                    ViolationKind::UseAfterFreeRead
                };
                let note = if self.mem.subject_kind(owner) == SubjectKind::Stack {
                    "stale pointer owner refers to an expired stack range"
                } else {
                    "stale pointer owner refers to a freed allocation range"
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
                    Some(note.into()),
                );
                return;
            }
            if pointer_owners
                .iter()
                .any(|owner| self.mem.subject_freed(*owner))
            {
                self.record(
                    record.step,
                    record.pc,
                    ViolationKind::ExpiredPointerDereference,
                    access.kind,
                    addr,
                    1,
                    pointer_owners.clone(),
                    cell.clone(),
                    Some("dereference through an expired pointer owner".into()),
                );
                return;
            }
            if cell.cell_owners.is_empty() && addr >= 0x1000 {
                let (kind, note) = if pointer_owners.is_empty() {
                    (
                        ViolationKind::UntrustedPtr,
                        "dereference of an address with no modeled cell owner",
                    )
                } else if is_write {
                    (
                        ViolationKind::OutOfBoundsWrite,
                        "pointer owner is known but target cell has no owner",
                    )
                } else {
                    (
                        ViolationKind::OutOfBoundsRead,
                        "pointer owner is known but target cell has no owner",
                    )
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
                    Some(note.into()),
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

    fn copy_memory_summary(&mut self, record: &TraceRecord, dst: u64, src: u64, len: u64) {
        let src_pointer = self.reg_state(RSI).pointee_owners;
        let dst_pointer = self.reg_state(RDI).pointee_owners;
        let mut source_cells = Vec::with_capacity(len.min(4096) as usize);
        for off in 0..len {
            let src_addr = src.saturating_add(off);
            let dst_addr = dst.saturating_add(off);
            let read = ResolvedAccess {
                address: src_addr,
                size: 1,
                kind: AccessKind::Read,
                base: Some(RSI),
                index: None,
            };
            let write = ResolvedAccess {
                address: dst_addr,
                size: 1,
                kind: AccessKind::Write,
                base: Some(RDI),
                index: None,
            };
            self.observe_one_access_with_pointer(record, &read, src_addr, src_pointer.clone());
            self.observe_one_access_with_pointer(record, &write, dst_addr, dst_pointer.clone());
            source_cells.push(self.mem.cell(src_addr));
        }
        for (off, src_cell) in source_cells.into_iter().enumerate() {
            let dst_addr = dst.saturating_add(off as u64);
            let dst_cell = self.mem.cell_mut(dst_addr);
            dst_cell.value_owners = src_cell.value_owners;
            dst_cell.pointee_owners = src_cell.pointee_owners;
            dst_cell.last_write_pc = Some(record.pc);
        }
    }

    fn set_memory_summary(&mut self, record: &TraceRecord, dst: u64, len: u64) {
        let dst_pointer = self.reg_state(RDI).pointee_owners;
        for off in 0..len {
            let dst_addr = dst.saturating_add(off);
            let write = ResolvedAccess {
                address: dst_addr,
                size: 1,
                kind: AccessKind::Write,
                base: Some(RDI),
                index: None,
            };
            self.observe_one_access_with_pointer(record, &write, dst_addr, dst_pointer.clone());
            let cell_owners = self.mem.cell(dst_addr).cell_owners;
            let cell = self.mem.cell_mut(dst_addr);
            cell.value_owners = if cell_owners.is_empty() {
                dst_pointer.clone()
            } else {
                cell_owners
            };
            cell.pointee_owners.clear();
            cell.last_write_pc = Some(record.pc);
        }
    }

    fn apply_instruction_semantics(&mut self, record: &TraceRecord, decoded: &DecodedInstruction) {
        let ins = &decoded.instruction;
        if decode::is_call(ins) || decode::is_ret(ins) {
            return;
        }
        if self.apply_stack_semantics(record, ins) {
            return;
        }
        if self.apply_rep_string(record, ins) {
            return;
        }
        if decode::is_lea(ins) {
            self.apply_lea(record, ins);
            return;
        }
        self.apply_loads_and_stores(record, decoded);
        self.apply_register_writes(record, ins);
    }

    fn apply_stack_semantics(&mut self, record: &TraceRecord, ins: &Instruction) -> bool {
        match ins.mnemonic() {
            Mnemonic::Push => {
                let Some(old_rsp) = record.reg(RSP) else {
                    return false;
                };
                let size = stack_slot_size(ins);
                let new_rsp = old_rsp.saturating_sub(size);
                let src_state = stack_source_state(self, record, ins);
                self.allocate_stack_object(
                    record.step,
                    record.pc,
                    new_rsp,
                    size,
                    true,
                    src_state.pointee_owners,
                );
                self.regs.insert(
                    RSP,
                    RegState {
                        value_owners: self.owner_set_for_value(new_rsp),
                        pointee_owners: self.owner_set_for_value(new_rsp),
                    },
                );
                true
            }
            Mnemonic::Pop => {
                let Some(old_rsp) = record.reg(RSP) else {
                    return false;
                };
                let size = stack_slot_size(ins);
                if ins.op0_kind() == OpKind::Register
                    && let Some(dst) = id_from_iced(ins.op0_register())
                {
                    let access = ResolvedAccess {
                        address: old_rsp,
                        size: size as u32,
                        kind: AccessKind::Read,
                        base: Some(RSP),
                        index: None,
                    };
                    let mut state = self.state_from_memory(&access);
                    if !is_pointer_width(size as u32) {
                        state.pointee_owners.clear();
                    }
                    self.regs.insert(dst, state);
                }
                self.free_stack_range(record.step, record.pc, old_rsp, size);
                let new_rsp = old_rsp.saturating_add(size);
                self.regs.insert(
                    RSP,
                    RegState {
                        value_owners: self.owner_set_for_value(new_rsp),
                        pointee_owners: self.owner_set_for_value(new_rsp),
                    },
                );
                true
            }
            Mnemonic::Sub
                if ins.op0_kind() == OpKind::Register
                    && id_from_iced(ins.op0_register()) == Some(RSP) =>
            {
                let Some(old_rsp) = record.reg(RSP) else {
                    return false;
                };
                let Some(size) = right_operand_value(record, ins) else {
                    return false;
                };
                let new_rsp = old_rsp.saturating_sub(size);
                self.allocate_stack_object(
                    record.step,
                    record.pc,
                    new_rsp,
                    size,
                    false,
                    OwnerSet::new(),
                );
                self.regs.insert(
                    RSP,
                    RegState {
                        value_owners: self.owner_set_for_value(new_rsp),
                        pointee_owners: self.owner_set_for_value(new_rsp),
                    },
                );
                true
            }
            Mnemonic::Add
                if ins.op0_kind() == OpKind::Register
                    && id_from_iced(ins.op0_register()) == Some(RSP) =>
            {
                let Some(old_rsp) = record.reg(RSP) else {
                    return false;
                };
                let Some(size) = right_operand_value(record, ins) else {
                    return false;
                };
                self.free_stack_range(record.step, record.pc, old_rsp, size);
                let new_rsp = old_rsp.saturating_add(size);
                self.regs.insert(
                    RSP,
                    RegState {
                        value_owners: self.owner_set_for_value(new_rsp),
                        pointee_owners: self.owner_set_for_value(new_rsp),
                    },
                );
                true
            }
            Mnemonic::Leave => {
                let Some(old_rsp) = record.reg(RSP) else {
                    return false;
                };
                let Some(old_rbp) = record.reg(RBP) else {
                    return false;
                };
                let end = old_rbp.saturating_add(8);
                if end > old_rsp {
                    self.free_stack_range(record.step, record.pc, old_rsp, end - old_rsp);
                }
                true
            }
            _ => false,
        }
    }

    fn allocate_stack_object(
        &mut self,
        step: u64,
        pc: u64,
        start: u64,
        size: u64,
        initialized: bool,
        pointee_owners: OwnerSet,
    ) {
        let size = size.max(1);
        let subject = self.mem.fresh_subject(SubjectKind::Stack, start, size);
        for off in 0..size {
            let addr = start.saturating_add(off);
            let cell = self.mem.cell_mut(addr);
            cell.cell_owners.insert(subject);
            if initialized {
                cell.value_owners.clear();
                cell.value_owners.insert(subject);
            } else if cell.value_owners.is_empty() {
                cell.value_owners.insert(ALLOCATOR_SUBJECT);
            }
            cell.pointee_owners = pointee_owners.clone();
        }
        self.memory_events.push(MemoryEvent {
            step,
            pc: hex(pc),
            kind: "stack-allocation".into(),
            symbol: None,
            ptr: Some(hex(start)),
            size: Some(hex(size)),
        });
    }

    fn free_stack_range(&mut self, step: u64, pc: u64, start: u64, size: u64) {
        let size = size.max(1);
        let subjects =
            self.mem
                .active_subjects_of_kind_overlapping(SubjectKind::Stack, start, size);
        for subject in subjects {
            let (subject_start, subject_size) = self
                .mem
                .subjects
                .get(&subject)
                .and_then(|s| s.start.zip(s.size))
                .unwrap_or((start, size));
            self.mem.mark_freed(subject);
            for off in 0..subject_size.max(1) {
                self.mem
                    .cell_mut(subject_start.saturating_add(off))
                    .cell_owners
                    .shift_remove(&subject);
            }
        }
        self.memory_events.push(MemoryEvent {
            step,
            pc: hex(pc),
            kind: "stack-free".into(),
            symbol: None,
            ptr: Some(hex(start)),
            size: Some(hex(size)),
        });
    }

    fn apply_loads_and_stores(&mut self, record: &TraceRecord, decoded: &DecodedInstruction) {
        let ins = &decoded.instruction;
        for access in &decoded.accesses {
            if matches!(access.kind, AccessKind::Write | AccessKind::ReadWrite) {
                let src = first_read_reg_not_addr(ins, access);
                let pointer_owners = self.pointer_owner_from_access(access);
                let mut src_pointee = src
                    .map(|reg| self.reg_state(reg).pointee_owners)
                    .unwrap_or_default();
                if access.size != 8 {
                    src_pointee.clear();
                }
                if let Some(src) = src {
                    self.check_dangling_pointer_copy(record, src);
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
        if ins.op_count() == 0 || ins.op0_kind() != OpKind::Register {
            return;
        }
        let Some(dst) = id_from_iced(ins.op0_register()) else {
            return;
        };
        match ins.mnemonic() {
            mnemonic
                if matches!(
                    mnemonic,
                    Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsxd | Mnemonic::Movsx
                ) || is_cmov(mnemonic) =>
            {
                let copy_pointee = is_pointer_width(ins.op0_register().size() as u32)
                    && (ins.mnemonic() == Mnemonic::Mov || is_cmov(ins.mnemonic()));
                let mut state = match ins.op1_kind() {
                    OpKind::Register => {
                        if let Some(src) = id_from_iced(ins.op1_register()) {
                            self.check_dangling_pointer_copy(record, src);
                            self.reg_state(src)
                        } else {
                            RegState::default()
                        }
                    }
                    OpKind::Memory => self
                        .first_memory_read_state(record, ins)
                        .unwrap_or_default(),
                    OpKind::Immediate8
                    | OpKind::Immediate8to16
                    | OpKind::Immediate8to32
                    | OpKind::Immediate8to64
                    | OpKind::Immediate16
                    | OpKind::Immediate32
                    | OpKind::Immediate32to64
                    | OpKind::Immediate64 => state_for_immediate(self, immediate(ins)),
                    _ => RegState::default(),
                };
                if !copy_pointee {
                    state.pointee_owners.clear();
                }
                if is_cmov(ins.mnemonic()) {
                    let mut old = self.reg_state(dst);
                    old.value_owners.extend(state.value_owners);
                    old.pointee_owners.extend(state.pointee_owners);
                    self.regs.insert(dst, old);
                } else {
                    self.regs.insert(dst, state);
                }
            }
            Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::Adc
            | Mnemonic::Sbb
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Xor
            | Mnemonic::Shl
            | Mnemonic::Sal
            | Mnemonic::Shr
            | Mnemonic::Sar => {
                if ins.mnemonic() == Mnemonic::Xor
                    && ins.op1_kind() == OpKind::Register
                    && ins.op1_register().full_register() == ins.op0_register().full_register()
                {
                    self.regs.remove(&dst);
                    return;
                }
                let Some(left) = record.reg(dst) else {
                    return;
                };
                let Some(right) = right_operand_value(record, ins) else {
                    return;
                };
                let Some(result) = binary_result(ins.mnemonic(), left, right) else {
                    return;
                };
                let mut state = self.reg_state(dst);
                if is_cross_boundary_mnemonic(ins.mnemonic()) {
                    self.check_cross_boundary(
                        record.step,
                        record.pc,
                        result,
                        &state.pointee_owners,
                    );
                }
                if let Some(right_reg) = right_operand_register(ins) {
                    state
                        .pointee_owners
                        .extend(self.reg_state(right_reg).pointee_owners);
                    self.check_dangling_pointer_copy(record, right_reg);
                }
                let result_owners = self.owner_set_for_value(result);
                if replace_pointee_owner_for_mnemonic(ins.mnemonic()) {
                    state.pointee_owners = result_owners;
                } else {
                    state.pointee_owners.extend(result_owners);
                }
                state.value_owners.extend(state.pointee_owners.clone());
                self.regs.insert(dst, state);
            }
            Mnemonic::Xchg => {
                if let Some(src) = id_from_iced(ins.op1_register()) {
                    let dst_state = self.reg_state(dst);
                    let src_state = self.reg_state(src);
                    self.regs.insert(dst, src_state);
                    self.regs.insert(src, dst_state);
                }
            }
            mnemonic if is_setcc(mnemonic) => {
                self.regs.remove(&dst);
            }
            _ => {
                let _ = record;
            }
        }
    }

    fn first_memory_read_state(&self, record: &TraceRecord, ins: &Instruction) -> Option<RegState> {
        let mut factory = InstructionInfoFactory::new();
        let info = factory.info(ins);
        for mem in info.used_memory() {
            let access = mem.access();
            if !matches!(
                access,
                OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
            ) {
                continue;
            }
            let address = mem.virtual_address(0, |reg, _, _| match reg {
                Register::None => Some(0),
                Register::RIP => Some(record.pc.wrapping_add(ins.len() as u64)),
                Register::EIP => Some((record.pc.wrapping_add(ins.len() as u64)) as u32 as u64),
                Register::FS
                | Register::GS
                | Register::CS
                | Register::DS
                | Register::ES
                | Register::SS => Some(0),
                other => id_from_iced(other).and_then(|id| record.reg(id)),
            })?;
            let access = ResolvedAccess {
                address,
                size: mem.memory_size().size() as u32,
                kind: AccessKind::Read,
                base: id_from_iced(mem.base()),
                index: id_from_iced(mem.index()),
            };
            let mut state = self.state_from_memory(&access);
            if !is_pointer_width(access.size) {
                state.pointee_owners.clear();
            }
            if state.pointee_owners.len() > 1 {
                // This mirrors Lancet's "untrusted pointer" check: a single
                // pointer-sized value should not be assembled from bytes with
                // incompatible pointee owners.
                // It is reported by observe/access path through explicit record
                // below only when callers copy the value.
            }
            return Some(state);
        }
        None
    }

    fn apply_rep_string(&mut self, record: &TraceRecord, ins: &Instruction) -> bool {
        if is_rep_movs_instruction(ins) {
            let Some(count) = record.reg(RCX) else {
                return false;
            };
            let Some(src_base) = record.reg(RSI) else {
                return false;
            };
            let Some(dst_base) = record.reg(RDI) else {
                return false;
            };
            let elem = rep_movs_element_size(ins.mnemonic()) as u64;
            let backwards = record
                .reg(crate::registers::RFLAGS)
                .is_some_and(|flags| flags & (1 << 10) != 0);
            for i in 0..count {
                let off = i.saturating_mul(elem);
                let src = if backwards {
                    src_base.wrapping_sub(off)
                } else {
                    src_base.wrapping_add(off)
                };
                let dst = if backwards {
                    dst_base.wrapping_sub(off)
                } else {
                    dst_base.wrapping_add(off)
                };
                let read = ResolvedAccess {
                    address: src,
                    size: elem as u32,
                    kind: AccessKind::Read,
                    base: Some(RSI),
                    index: None,
                };
                let state = self.state_from_memory(&read);
                for byte in 0..elem {
                    let src_cell = self.mem.cell(src.saturating_add(byte));
                    let dst_cell = self.mem.cell_mut(dst.saturating_add(byte));
                    dst_cell.value_owners = src_cell.value_owners;
                    dst_cell.pointee_owners = if elem == 8 {
                        state.pointee_owners.clone()
                    } else {
                        OwnerSet::new()
                    };
                    dst_cell.last_write_pc = Some(record.pc);
                }
            }
            return true;
        }
        if is_rep_stos_instruction(ins) {
            let Some(count) = record.reg(RCX) else {
                return false;
            };
            let Some(dst_base) = record.reg(RDI) else {
                return false;
            };
            let elem = rep_stos_element_size(ins.mnemonic()) as u64;
            let backwards = record
                .reg(crate::registers::RFLAGS)
                .is_some_and(|flags| flags & (1 << 10) != 0);
            let src_state = self.reg_state(RAX);
            for i in 0..count {
                let off = i.saturating_mul(elem);
                let dst = if backwards {
                    dst_base.wrapping_sub(off)
                } else {
                    dst_base.wrapping_add(off)
                };
                for byte in 0..elem {
                    let cell_owners = self.mem.cell(dst.saturating_add(byte)).cell_owners;
                    let cell = self.mem.cell_mut(dst.saturating_add(byte));
                    cell.value_owners = if src_state.value_owners.is_empty() {
                        cell_owners
                    } else {
                        src_state.value_owners.clone()
                    };
                    cell.pointee_owners = if elem == 8 {
                        src_state.pointee_owners.clone()
                    } else {
                        OwnerSet::new()
                    };
                    cell.last_write_pc = Some(record.pc);
                }
            }
            return true;
        }
        false
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

    fn check_dangling_pointer_copy(&mut self, record: &TraceRecord, src: RegId) {
        let state = self.reg_state(src);
        if state.pointee_owners.is_empty() {
            return;
        }
        let Some(address) = record.reg(src) else {
            return;
        };
        let cell = self.mem.cell(address);
        let points_to_freed = state
            .pointee_owners
            .iter()
            .any(|owner| self.mem.subject_freed(*owner));
        let points_outside_owner = !cell.cell_owners.is_empty()
            && !sets_intersect(&state.pointee_owners, &cell.cell_owners);
        if points_to_freed || points_outside_owner {
            let kind = if points_to_freed {
                ViolationKind::DanglingPointer
            } else {
                ViolationKind::UntrustedPtr
            };
            self.record(
                record.step,
                record.pc,
                kind,
                AccessKind::Other,
                address,
                1,
                state.pointee_owners,
                cell,
                Some("copying a pointer whose owner no longer matches its pointee".into()),
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

    #[allow(clippy::too_many_arguments)]
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

    #[allow(clippy::too_many_arguments)]
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
        OpKind::Memory => None,
        _ => Some(immediate(ins)),
    }
}

fn immediate(ins: &Instruction) -> u64 {
    immediate_at(ins, 1)
}

fn immediate_at(ins: &Instruction, operand: u32) -> u64 {
    match ins.op_kind(operand) {
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

fn state_for_immediate(analyzer: &Analyzer, value: u64) -> RegState {
    let owners = analyzer.owner_set_for_value(value);
    RegState {
        value_owners: owners.clone(),
        pointee_owners: owners,
    }
}

fn stack_slot_size(ins: &Instruction) -> u64 {
    for i in 0..ins.op_count() {
        if ins.op_kind(i) == OpKind::Register {
            let reg = match i {
                0 => ins.op0_register(),
                1 => ins.op1_register(),
                2 => ins.op2_register(),
                3 => ins.op3_register(),
                _ => Register::None,
            };
            return u64::from((reg.size() as u32).max(8));
        }
    }
    8
}

fn stack_source_state(analyzer: &Analyzer, record: &TraceRecord, ins: &Instruction) -> RegState {
    match ins.op0_kind() {
        OpKind::Register => id_from_iced(ins.op0_register())
            .map(|reg| analyzer.reg_state(reg))
            .unwrap_or_default(),
        OpKind::Immediate8
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate32to64
        | OpKind::Immediate64 => state_for_immediate(analyzer, immediate_at(ins, 0)),
        OpKind::Memory => analyzer
            .first_memory_read_state(record, ins)
            .unwrap_or_default(),
        _ => RegState::default(),
    }
}

fn is_pointer_width(size: u32) -> bool {
    size == 8
}

fn binary_result(mnemonic: Mnemonic, left: u64, right: u64) -> Option<u64> {
    Some(match mnemonic {
        Mnemonic::Add | Mnemonic::Adc => left.wrapping_add(right),
        Mnemonic::Sub | Mnemonic::Sbb => left.wrapping_sub(right),
        Mnemonic::And => left & right,
        Mnemonic::Or => left | right,
        Mnemonic::Xor => left ^ right,
        Mnemonic::Shl | Mnemonic::Sal => left.wrapping_shl((right & 0x3f) as u32),
        Mnemonic::Shr | Mnemonic::Sar => left.wrapping_shr((right & 0x3f) as u32),
        _ => return None,
    })
}

fn right_operand_register(ins: &Instruction) -> Option<RegId> {
    if ins.op1_kind() == OpKind::Register {
        id_from_iced(ins.op1_register())
    } else {
        None
    }
}

fn replace_pointee_owner_for_mnemonic(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Xor
            | Mnemonic::Shl
            | Mnemonic::Sal
            | Mnemonic::Shr
            | Mnemonic::Sar
    )
}

fn is_cross_boundary_mnemonic(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Add | Mnemonic::Sub | Mnemonic::Adc | Mnemonic::Sbb
    )
}

fn is_cmov(mnemonic: Mnemonic) -> bool {
    format!("{mnemonic:?}").starts_with("Cmov")
}

fn is_setcc(mnemonic: Mnemonic) -> bool {
    format!("{mnemonic:?}").starts_with("Set")
}

fn is_jump(instruction: &Instruction) -> bool {
    instruction.is_jmp_short_or_near() || instruction.is_jmp_far()
}

fn is_high_half_address(address: u64) -> bool {
    (address >> 63) == 1
}

fn is_alloc_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    (lower.contains("alloc") || lower.contains("kmalloc") || lower.contains("vmalloc"))
        && !lower.contains("free")
}

fn is_free_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("free") || lower == "kfree"
}

fn is_realloc_name(name: &str) -> bool {
    name.to_ascii_lowercase().contains("realloc")
}

fn is_page_alloc_symbol(
    symbol: Option<&SymbolConfig>,
    _target: u64,
    page_allocator: Option<PageAllocatorConfig>,
) -> bool {
    page_allocator.is_some()
        && symbol.is_some_and(|s| matches!(s.name.as_str(), "alloc_pages" | "__alloc_pages"))
}

fn is_page_free_symbol(
    symbol: Option<&SymbolConfig>,
    _target: u64,
    page_allocator: Option<PageAllocatorConfig>,
) -> bool {
    page_allocator.is_some()
        && symbol.is_some_and(|s| matches!(s.name.as_str(), "free_pages" | "__free_pages"))
}

fn apply_value_size(value: u64, value_size: Option<u8>) -> u64 {
    let Some(size) = value_size else {
        return value;
    };
    if size == 0 {
        0
    } else if size >= 8 {
        value
    } else {
        let bits = size as u32 * 8;
        value & ((1u64 << bits) - 1)
    }
}

fn is_rep_movs_instruction(instruction: &Instruction) -> bool {
    if !(instruction.has_rep_prefix() || instruction.has_repne_prefix()) {
        return false;
    }
    matches!(
        instruction.mnemonic(),
        Mnemonic::Movsb | Mnemonic::Movsw | Mnemonic::Movsd | Mnemonic::Movsq
    )
}

fn is_rep_stos_instruction(instruction: &Instruction) -> bool {
    if !(instruction.has_rep_prefix() || instruction.has_repne_prefix()) {
        return false;
    }
    matches!(
        instruction.mnemonic(),
        Mnemonic::Stosb | Mnemonic::Stosw | Mnemonic::Stosd | Mnemonic::Stosq
    )
}

fn rep_movs_element_size(mnemonic: Mnemonic) -> u32 {
    match mnemonic {
        Mnemonic::Movsw => 2,
        Mnemonic::Movsd => 4,
        Mnemonic::Movsq => 8,
        _ => 1,
    }
}

fn rep_stos_element_size(mnemonic: Mnemonic) -> u32 {
    match mnemonic {
        Mnemonic::Stosw => 2,
        Mnemonic::Stosd => 4,
        Mnemonic::Stosq => 8,
        _ => 1,
    }
}
