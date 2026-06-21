use std::collections::HashMap;

use iced_x86::{Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use thiserror::Error;

use crate::config::{Config, FieldConfig, PageAllocatorConfig, SymbolConfig};
use crate::decode::{self, DecodedInstruction, ResolvedAccess};
use crate::ownership::{
    ALLOCATOR_SUBJECT, MemoryModel, OwnerSet, RegState, SubjectKind, owner_set_one,
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

#[derive(Debug)]
pub struct AnalysisResult {
    pub config: Config,
    pub violations: Vec<Violation>,
    pub memory_events: Vec<MemoryEvent>,
}

#[derive(Debug, serde::Serialize)]
pub struct MemoryEvent {
    pub step: u64,
    pub pc: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
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
    wide_regs: HashMap<Register, Vec<RegState>>,
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
        let mut analyzer = Self {
            config,
            mem: MemoryModel::new(),
            regs: HashMap::new(),
            wide_regs: HashMap::new(),
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
        };
        analyzer.install_configured_field_subjects();
        analyzer
    }

    pub fn process_record(&mut self, record: &TraceRecord) -> Result<(), AnalyzerError> {
        self.apply_pending(record);
        self.synchronize_sampled_registers(record);
        let decoded = decode::decode(record, &mut self.info_factory, self.config.segment_bases)
            .map_err(AnalyzerError::Decode)?;
        self.ensure_static_subjects(record, &decoded);
        self.observe_accesses(record, &decoded);
        self.observe_call(record, &decoded.instruction);
        self.apply_instruction_semantics(record, &decoded);
        Ok(())
    }

    pub fn finish(self) -> AnalysisResult {
        AnalysisResult {
            config: self.config,
            violations: self.violations,
            memory_events: self.memory_events,
        }
    }

    fn install_configured_field_subjects(&mut self) {
        let configured = self.config.field_subjects.clone();
        for object in configured {
            let parent = self.mem.fresh_subject_named(
                SubjectKind::Global,
                object.start,
                object.size,
                Some(object.name.clone()),
                None,
            );
            for off in 0..object.size.max(1) {
                self.mem
                    .cell_mut(object.start.saturating_add(off))
                    .cell_owners
                    .insert(parent);
            }
            self.install_field_children(
                parent,
                SubjectKind::Global,
                object.start,
                &object.name,
                &object.fields,
            );
        }
    }

    fn install_field_children(
        &mut self,
        parent: u64,
        kind: SubjectKind,
        object_start: u64,
        object_name: &str,
        fields: &[FieldConfig],
    ) {
        for field in fields {
            let start = object_start.saturating_add(field.offset);
            let subject = self.mem.fresh_subject_named(
                kind,
                start,
                field.size,
                Some(format!("{object_name}.{}", field.name)),
                Some(parent),
            );
            for off in 0..field.size.max(1) {
                let cell = self.mem.cell_mut(start.saturating_add(off));
                cell.cell_owners.shift_remove(&parent);
                cell.cell_owners.insert(subject);
                if cell.value_owners.is_empty() {
                    cell.value_owners.insert(subject);
                }
            }
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
                let subject = self.add_allocation(
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
                        value_owners: owner_set_one(subject),
                        pointee_owners: owner_set_one(subject),
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
                    let subject = self.add_allocation(
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
                            value_owners: owner_set_one(subject),
                            pointee_owners: owner_set_one(subject),
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
        if symbol.is_bulk {
            let kind = if name.contains("free") {
                "bulk-free-summary"
            } else {
                "bulk-allocation-summary"
            };
            self.memory_events.push(MemoryEvent {
                step: record.step,
                pc: hex(record.pc),
                kind: kind.into(),
                subject: None,
                symbol: Some(symbol.name.clone()),
                ptr: record.reg(RCX).or_else(|| record.reg(RDI)).map(hex),
                size: record.reg(RDX).map(hex),
            });
            return true;
        }
        if name.contains("memcpy")
            || name.contains("memmove")
            || name.contains("mempcpy")
            || name.contains("copy_from_user")
            || name.contains("copy_to_user")
        {
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
                subject: None,
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
                subject: None,
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
    ) -> u64 {
        let type_hint = self.allocation_type_hint(pc, ptr, symbol.as_deref());
        let subject_name = type_hint.as_deref().map(|ty| format!("{ty}@{}", hex(ptr)));
        let subject = if subject_name.is_some() {
            self.mem
                .fresh_heap_subject_named(ptr, size, subject_name.clone())
        } else {
            self.mem.fresh_heap_subject(ptr, size)
        };
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
        let mut return_subject = subject;
        if let Some(type_hint) = type_hint.as_deref()
            && let Some(layout) = self.config.type_layouts.get(type_hint).cloned()
            && layout.size.is_none_or(|layout_size| layout_size <= size)
        {
            let name = subject_name.unwrap_or_else(|| format!("{type_hint}@{}", hex(ptr)));
            self.install_field_children(subject, SubjectKind::Heap, ptr, &name, &layout.fields);
            if let Some(child) = self.child_subject_at_start(subject, ptr) {
                return_subject = child;
            }
        }
        self.memory_events.push(MemoryEvent {
            step,
            pc: hex(pc),
            kind: "allocation".into(),
            subject: Some(self.mem.subject_label(subject)),
            symbol,
            ptr: Some(hex(ptr)),
            size: Some(hex(size)),
        });
        return_subject
    }

    fn allocation_type_hint(&self, call_pc: u64, ptr: u64, symbol: Option<&str>) -> Option<String> {
        self.config
            .allocation_type_hints
            .get(&call_pc)
            .or_else(|| self.config.allocation_type_hints.get(&ptr))
            .cloned()
            .or_else(|| {
                symbol.and_then(|name| {
                    self.config
                        .type_layouts
                        .contains_key(name)
                        .then(|| name.to_string())
                })
            })
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
        if let Some(subject) = self.active_heap_subject_at_start_for_pointer(ptr, &pointer_owners) {
            let cell = self.mem.cell(ptr);
            if cell.cell_owners.len() > 1 {
                self.record(
                    step,
                    pc,
                    ViolationKind::InvalidFree,
                    AccessKind::Free,
                    ptr,
                    0,
                    pointer_owners,
                    cell,
                    Some("free target has multiple cell owners".into()),
                );
            }
            self.free_active_subject(step, pc, ptr, subject, symbol);
            return;
        }
        let Some(_containing_subject) = self.mem.active_subject_containing(ptr) else {
            let cell = self.mem.cell(ptr);
            if cell.cell_owners.contains(&ALLOCATOR_SUBJECT)
                || pointer_owners
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
            self.record_simple(
                step,
                pc,
                ViolationKind::InvalidFree,
                AccessKind::Free,
                ptr,
                0,
                pointer_owners,
                "free pointer is not an active allocation start",
            );
            return;
        };
        self.record_simple(
            step,
            pc,
            ViolationKind::InvalidFree,
            AccessKind::Free,
            ptr,
            0,
            pointer_owners,
            "free pointer is inside an allocation but not at its start",
        );
    }

    fn free_active_subject(
        &mut self,
        step: u64,
        pc: u64,
        ptr: u64,
        subject: u64,
        symbol: Option<String>,
    ) {
        let subjects_to_free = self.mem.subject_and_descendants(subject);
        for freed_subject in &subjects_to_free {
            self.mem.mark_freed(*freed_subject);
        }
        let (start, size) = self
            .mem
            .subjects
            .get(&subject)
            .and_then(|s| s.start.zip(s.size))
            .unwrap_or((ptr, 0));
        for off in 0..size {
            let cell = self.mem.cell_mut(start.saturating_add(off));
            for freed_subject in &subjects_to_free {
                cell.cell_owners.shift_remove(freed_subject);
            }
            cell.cell_owners.insert(ALLOCATOR_SUBJECT);
        }
        self.memory_events.push(MemoryEvent {
            step,
            pc: hex(pc),
            kind: "free".into(),
            subject: Some(self.mem.subject_label(subject)),
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
            subject: Some(self.mem.subject_label(subject)),
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
            subject: Some(self.mem.subject_label(subject)),
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
            if state.value_owners.is_empty() {
                state.value_owners.extend(inferred.iter().copied());
            }
            if state.pointee_owners.is_empty() {
                state.pointee_owners.extend(inferred);
            }
        }
    }

    fn owner_set_for_value(&self, value: u64) -> OwnerSet {
        let mut owners = self.mem.owner_for_address(value);
        if let Some(subject) = self.mem.active_subject_containing(value) {
            owners.insert(subject);
        }
        if owners.is_empty()
            && let Some(subject) = self.mem.freed_subject_containing(value)
        {
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

    fn ensure_global_page(&mut self, addr: u64, _size: u32) {
        let start = addr & !(PAGE_SIZE - 1);
        if self.global_pages.contains_key(&start) {
            return;
        }
        let subject = self
            .mem
            .ensure_range_owner(SubjectKind::Global, start, PAGE_SIZE);
        for off in 0..PAGE_SIZE {
            let cell = self.mem.cell_mut(start.saturating_add(off));
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
            let stack_model_alias =
                self.is_active_stack_model_alias(&pointer_owners, &cell.cell_owners);
            let mut pointer_matches_cell = pointer_owners.is_empty()
                || same_owners(&pointer_owners, &cell.cell_owners)
                || stack_model_alias;
            if !stack_model_alias {
                if !pointer_owners.is_empty()
                    && cell.cell_owners.contains(&ALLOCATOR_SUBJECT)
                    && pointer_owners.iter().any(|owner| {
                        matches!(
                            self.mem.subject_kind(*owner),
                            SubjectKind::Heap | SubjectKind::Page
                        )
                    })
                {
                    self.record(
                        record.step,
                        record.pc,
                        if is_write {
                            ViolationKind::UseAfterFreeWrite
                        } else {
                            ViolationKind::UseAfterFreeRead
                        },
                        access.kind,
                        addr,
                        1,
                        pointer_owners.clone(),
                        cell.clone(),
                        Some("heap pointer reaches a cell co-owned by allocator".into()),
                    );
                    return;
                }
                if !pointer_owners.is_empty() && pointer_owners.len() > 1 {
                    self.record(
                        record.step,
                        record.pc,
                        if is_write {
                            ViolationKind::OutOfBoundsWrite
                        } else {
                            ViolationKind::OutOfBoundsRead
                        },
                        access.kind,
                        addr,
                        1,
                        pointer_owners.clone(),
                        cell.clone(),
                        Some("pointer has multiple pointee owners".into()),
                    );
                    pointer_matches_cell = false;
                } else if !pointer_owners.is_empty()
                    && !same_owners(&pointer_owners, &cell.cell_owners)
                {
                    let kind = self.strict_mismatch_kind(&pointer_owners, is_write);
                    self.record(
                        record.step,
                        record.pc,
                        kind,
                        access.kind,
                        addr,
                        1,
                        pointer_owners.clone(),
                        cell.clone(),
                        Some("pointee owners differ from target cell owners".into()),
                    );
                    return;
                }
            }
            if is_read
                && !cell.cell_owners.is_empty()
                && pointer_matches_cell
                && !same_owners(&cell.cell_owners, &cell.value_owners)
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

    fn strict_mismatch_kind(&self, pointer_owners: &OwnerSet, is_write: bool) -> ViolationKind {
        if pointer_owners.iter().any(|owner| {
            matches!(
                self.mem.subject_kind(*owner),
                SubjectKind::Heap | SubjectKind::Page
            )
        }) {
            if is_write {
                ViolationKind::UseAfterFreeWrite
            } else {
                ViolationKind::UseAfterFreeRead
            }
        } else if pointer_owners
            .iter()
            .any(|owner| self.mem.subject_kind(*owner) == SubjectKind::Stack)
        {
            if is_write {
                ViolationKind::StackUseAfterScopeWrite
            } else {
                ViolationKind::StackUseAfterScopeRead
            }
        } else {
            ViolationKind::ExpiredPointerDereference
        }
    }

    fn is_active_stack_model_alias(
        &self,
        pointer_owners: &OwnerSet,
        cell_owners: &OwnerSet,
    ) -> bool {
        !pointer_owners.is_empty()
            && !cell_owners.is_empty()
            && pointer_owners
                .iter()
                .chain(cell_owners.iter())
                .all(|owner| self.mem.subject_kind(*owner) == SubjectKind::Stack)
            && pointer_owners
                .iter()
                .all(|owner| !self.mem.subject_freed(*owner))
            && cell_owners
                .iter()
                .all(|owner| !self.mem.subject_freed(*owner))
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
        let page_subjects: Vec<_> = self.stack_pages.values().copied().collect();
        for off in 0..size {
            let addr = start.saturating_add(off);
            let cell = self.mem.cell_mut(addr);
            for page_subject in &page_subjects {
                cell.cell_owners.shift_remove(page_subject);
            }
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
            subject: Some(self.mem.subject_label(subject)),
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
            if self.stack_pages.values().any(|page| *page == subject) {
                continue;
            }
            let (subject_start, subject_size) = self
                .mem
                .subjects
                .get(&subject)
                .and_then(|s| s.start.zip(s.size))
                .unwrap_or((start, size));
            self.mem.mark_freed(subject);
            for off in 0..subject_size.max(1) {
                let addr = subject_start.saturating_add(off);
                let stack_page = self.stack_page_subject_for_addr(addr);
                let cell = self.mem.cell_mut(addr);
                cell.cell_owners.shift_remove(&subject);
                if let Some(stack_page) = stack_page {
                    cell.cell_owners.insert(stack_page);
                }
            }
        }
        self.memory_events.push(MemoryEvent {
            step,
            pc: hex(pc),
            kind: "stack-free".into(),
            subject: None,
            symbol: None,
            ptr: Some(hex(start)),
            size: Some(hex(size)),
        });
    }

    fn apply_loads_and_stores(&mut self, record: &TraceRecord, decoded: &DecodedInstruction) {
        let ins = &decoded.instruction;
        for access in &decoded.accesses {
            if matches!(access.kind, AccessKind::Write | AccessKind::ReadWrite) {
                let src = first_read_register_not_addr(ins, access);
                let pointer_owners = self.pointer_owner_from_access(access);
                let src_pointee = self.source_pointee_bytes(src, access.size);
                if let Some(src) = src.and_then(id_from_iced) {
                    self.check_dangling_pointer_copy(record, src);
                }
                for off in 0..access.size.max(1) {
                    let addr = access.address.saturating_add(off as u64);
                    let cell_owners = self.mem.cell(addr).cell_owners;
                    let value_owners = if pointer_owners.is_empty()
                        || self.is_active_stack_model_alias(&pointer_owners, &cell_owners)
                    {
                        cell_owners.clone()
                    } else {
                        pointer_owners.clone()
                    };
                    let cell = self.mem.cell_mut(addr);
                    cell.value_owners = value_owners;
                    cell.pointee_owners =
                        src_pointee.get(off as usize).cloned().unwrap_or_default();
                    cell.last_write_pc = Some(record.pc);
                }
            }
        }
    }

    fn source_pointee_bytes(&self, src: Option<Register>, size: u32) -> Vec<OwnerSet> {
        let size = size.max(1) as usize;
        let mut out = vec![OwnerSet::new(); size];
        let Some(src) = src else {
            return out;
        };
        if let Some(reg) = id_from_iced(src) {
            if size == 8 {
                let owners = self.reg_state(reg).pointee_owners;
                out.fill(owners);
            }
            return out;
        }
        let Some(src) = canonical_wide_register(src) else {
            return out;
        };
        if let Some(states) = self.wide_regs.get(&src) {
            for (idx, state) in states.iter().take(size).enumerate() {
                out[idx] = state.pointee_owners.clone();
            }
        }
        out
    }

    fn apply_register_writes(&mut self, record: &TraceRecord, ins: &Instruction) {
        if ins.op_count() == 0 || ins.op0_kind() != OpKind::Register {
            return;
        }
        let dst_register = ins.op0_register();
        let Some(dst) = id_from_iced(dst_register) else {
            self.apply_wide_register_write(record, ins);
            return;
        };
        match ins.mnemonic() {
            mnemonic
                if matches!(
                    mnemonic,
                    Mnemonic::Mov
                        | Mnemonic::Movbe
                        | Mnemonic::Movzx
                        | Mnemonic::Movsxd
                        | Mnemonic::Movsx
                        | Mnemonic::Movd
                        | Mnemonic::Movq
                ) || is_cmov(mnemonic) =>
            {
                let copy_pointee = is_pointer_width(ins.op0_register().size() as u32)
                    && matches!(
                        ins.mnemonic(),
                        Mnemonic::Mov | Mnemonic::Movbe | Mnemonic::Movq
                    )
                    || (is_pointer_width(ins.op0_register().size() as u32)
                        && is_cmov(ins.mnemonic()));
                let mut state = match ins.op1_kind() {
                    OpKind::Register => {
                        if let Some(src) = id_from_iced(ins.op1_register()) {
                            self.check_dangling_pointer_copy(record, src);
                            self.reg_state(src)
                        } else if let Some(src) = canonical_wide_register(ins.op1_register()) {
                            self.wide_state_union(src, ins.op0_register().size() as u32)
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
            | Mnemonic::Imul
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Xor
            | Mnemonic::Shl
            | Mnemonic::Sal
            | Mnemonic::Shr
            | Mnemonic::Sar
            | Mnemonic::Rol
            | Mnemonic::Ror => {
                if ins.mnemonic() == Mnemonic::Xor
                    && ins.op1_kind() == OpKind::Register
                    && ins.op1_register().full_register() == ins.op0_register().full_register()
                {
                    self.regs.remove(&dst);
                    return;
                }
                self.apply_binary_register_write(record, ins, dst);
            }
            Mnemonic::Inc | Mnemonic::Dec | Mnemonic::Neg | Mnemonic::Not | Mnemonic::Bswap => {
                self.apply_unary_register_write(record, ins, dst);
            }
            Mnemonic::Xchg => {
                if let Some(src) = id_from_iced(ins.op1_register()) {
                    let dst_state = self.reg_state(dst);
                    let src_state = self.reg_state(src);
                    self.regs.insert(dst, src_state);
                    self.regs.insert(src, dst_state);
                } else if let Some(src) = canonical_wide_register(ins.op1_register()) {
                    let dst_state = self.reg_state(dst);
                    let src_state = self.wide_state_union(src, ins.op0_register().size() as u32);
                    self.regs.insert(dst, src_state);
                    self.wide_regs
                        .insert(src, vec![dst_state; ins.op1_register().size()]);
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

    fn apply_binary_register_write(&mut self, record: &TraceRecord, ins: &Instruction, dst: RegId) {
        let (left_state, right_state, result) =
            if ins.mnemonic() == Mnemonic::Imul && ins.op_count() >= 3 {
                let left_state = self.operand_state(record, ins, 1);
                let right_state = self.operand_state(record, ins, 2);
                let result = operand_value(record, ins, 1)
                    .zip(operand_value(record, ins, 2))
                    .map(|(left, right)| left.wrapping_mul(right));
                (left_state, right_state, result)
            } else {
                let left_state = self.reg_state(dst);
                let right_state = self.operand_state(record, ins, 1);
                let result = record
                    .reg(dst)
                    .zip(operand_value(record, ins, 1))
                    .and_then(|(left, right)| binary_result(ins.mnemonic(), left, right));
                (left_state, right_state, result)
            };

        let mut state = left_state;
        if pointer_difference_yields_integer(ins.mnemonic(), &state, &right_state) {
            state.pointee_owners.clear();
        } else {
            state.pointee_owners.extend(right_state.pointee_owners);
        }
        if let Some(right_reg) = operand_register(ins, 1).and_then(id_from_iced) {
            self.check_dangling_pointer_copy(record, right_reg);
        }

        if let Some(result) = result {
            if is_cross_boundary_mnemonic(ins.mnemonic()) {
                self.check_cross_boundary(record.step, record.pc, result, &state.pointee_owners);
            }
            state
                .pointee_owners
                .extend(self.owner_set_for_value(result));
        }
        state.value_owners.extend(state.pointee_owners.clone());
        self.regs.insert(dst, state);
    }

    fn apply_unary_register_write(&mut self, record: &TraceRecord, ins: &Instruction, dst: RegId) {
        let mut state = self.reg_state(dst);
        let Some(old) = record.reg(dst) else {
            return;
        };
        let result = match ins.mnemonic() {
            Mnemonic::Inc => old.wrapping_add(1),
            Mnemonic::Dec => old.wrapping_sub(1),
            Mnemonic::Neg => old.wrapping_neg(),
            Mnemonic::Not => !old,
            Mnemonic::Bswap => match ins.op0_register().size() {
                2 => old.swap_bytes() >> 48,
                4 => (old as u32).swap_bytes() as u64,
                8 => old.swap_bytes(),
                _ => old,
            },
            _ => old,
        };
        if matches!(ins.mnemonic(), Mnemonic::Inc | Mnemonic::Dec) {
            self.check_cross_boundary(record.step, record.pc, result, &state.pointee_owners);
        }
        state
            .pointee_owners
            .extend(self.owner_set_for_value(result));
        state.value_owners.extend(state.pointee_owners.clone());
        self.regs.insert(dst, state);
    }

    fn operand_state(&self, record: &TraceRecord, ins: &Instruction, operand: u32) -> RegState {
        match ins.op_kind(operand) {
            OpKind::Register => {
                let reg = operand_register(ins, operand).unwrap_or(Register::None);
                if let Some(reg) = id_from_iced(reg) {
                    self.reg_state(reg)
                } else if let Some(reg) = canonical_wide_register(reg) {
                    self.wide_state_union(
                        reg,
                        operand_register(ins, operand).unwrap().size() as u32,
                    )
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
            | OpKind::Immediate64 => state_for_immediate(self, immediate_at(ins, operand)),
            _ => RegState::default(),
        }
    }

    fn apply_wide_register_write(&mut self, record: &TraceRecord, ins: &Instruction) {
        let Some(dst) = canonical_wide_register(ins.op0_register()) else {
            return;
        };
        let size = first_memory_read_access(record, ins, self.config.segment_bases)
            .map(|access| access.size)
            .unwrap_or_else(|| ins.op0_register().size() as u32)
            .max(1) as usize;
        if is_same_register_zero_idiom(ins) {
            self.wide_regs.remove(&dst);
            return;
        }
        let source_states = self.wide_operand_states(record, ins, 1, size);
        let states = if is_transfer_mnemonic(ins.mnemonic()) {
            source_states
        } else {
            self.union_wide_states(
                self.wide_regs.get(&dst).cloned().unwrap_or_default(),
                source_states,
                size,
            )
        };
        if !states.is_empty() {
            self.wide_regs.insert(dst, states);
        }
    }

    fn wide_operand_states(
        &self,
        record: &TraceRecord,
        ins: &Instruction,
        operand: u32,
        default_size: usize,
    ) -> Vec<RegState> {
        match ins.op_kind(operand) {
            OpKind::Memory => first_memory_read_access(record, ins, self.config.segment_bases)
                .map(|access| self.state_from_memory_bytes(&access))
                .unwrap_or_default(),
            OpKind::Register => {
                let Some(src) = operand_register(ins, operand) else {
                    return Vec::new();
                };
                if let Some(src) = canonical_wide_register(src) {
                    self.wide_regs.get(&src).cloned().unwrap_or_default()
                } else if let Some(src_id) = id_from_iced(src) {
                    let state = self.reg_state(src_id);
                    vec![state; default_size.min(src.size().max(1))]
                } else {
                    Vec::new()
                }
            }
            OpKind::Immediate8
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate32to64
            | OpKind::Immediate64 => {
                let state = state_for_immediate(self, immediate_at(ins, operand));
                vec![state; default_size]
            }
            _ => Vec::new(),
        }
    }

    fn union_wide_states(
        &self,
        mut left: Vec<RegState>,
        right: Vec<RegState>,
        size: usize,
    ) -> Vec<RegState> {
        left.resize_with(size, RegState::default);
        for (idx, right_state) in right.into_iter().take(size).enumerate() {
            left[idx].value_owners.extend(right_state.value_owners);
            left[idx].pointee_owners.extend(right_state.pointee_owners);
        }
        left
    }

    fn state_from_memory_bytes(&self, access: &ResolvedAccess) -> Vec<RegState> {
        let mut states = Vec::with_capacity(access.size.max(1) as usize);
        for off in 0..access.size.max(1) {
            let cell = self.mem.cell(access.address.saturating_add(off as u64));
            states.push(RegState {
                value_owners: cell.value_owners,
                pointee_owners: cell.pointee_owners,
            });
        }
        states
    }

    fn wide_state_union(&self, reg: Register, max_size: u32) -> RegState {
        let mut state = RegState::default();
        if let Some(states) = self.wide_regs.get(&reg) {
            for byte_state in states.iter().take(max_size.max(1) as usize) {
                state.value_owners.extend(byte_state.value_owners.clone());
                state
                    .pointee_owners
                    .extend(byte_state.pointee_owners.clone());
            }
        }
        state
    }

    fn first_memory_read_state(&self, record: &TraceRecord, ins: &Instruction) -> Option<RegState> {
        if let Some(access) = first_memory_read_access(record, ins, self.config.segment_bases) {
            let mut state = self.state_from_memory(&access);
            if !is_pointer_width(access.size) {
                state.pointee_owners.clear();
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
        if !same_owners(pointer_owners, &result_cell.cell_owners) {
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
            && !same_owners(&state.pointee_owners, &cell.cell_owners)
            && !self.is_active_stack_model_alias(&state.pointee_owners, &cell.cell_owners);
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

    fn active_heap_subject_at_start_for_pointer(
        &self,
        ptr: u64,
        pointer_owners: &OwnerSet,
    ) -> Option<u64> {
        pointer_owners
            .iter()
            .copied()
            .find(|owner| {
                self.mem.subjects.get(owner).is_some_and(|subject| {
                    subject.kind == SubjectKind::Heap
                        && !subject.freed
                        && subject.start == Some(ptr)
                })
            })
            .or_else(|| self.mem.active_subject_at_start(ptr))
    }

    fn child_subject_at_start(&self, parent: u64, ptr: u64) -> Option<u64> {
        self.mem
            .subjects
            .values()
            .filter(|subject| {
                subject.parent == Some(parent) && !subject.freed && subject.start == Some(ptr)
            })
            .max_by_key(|subject| subject.id)
            .map(|subject| subject.id)
    }

    fn stack_page_subject_for_addr(&self, addr: u64) -> Option<u64> {
        let page_start = addr & !(PAGE_SIZE - 1);
        self.stack_pages.get(&page_start).copied()
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

fn first_read_register_not_addr(ins: &Instruction, access: &ResolvedAccess) -> Option<Register> {
    for i in 0..ins.op_count() {
        if ins.op_kind(i) != OpKind::Register {
            continue;
        }
        let reg = operand_register(ins, i)?;
        let id = id_from_iced(reg);
        if id.is_some() && (id == access.base || id == access.index) {
            continue;
        }
        // In Intel syntax, register operand after memory destination is usually source.
        if i > 0 || ins.op0_kind() != OpKind::Register {
            return Some(reg);
        }
    }
    None
}

fn first_memory_read_access(
    record: &TraceRecord,
    ins: &Instruction,
    segment_bases: crate::config::SegmentBases,
) -> Option<ResolvedAccess> {
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
            Register::FS => Some(record.fs_base.or(segment_bases.fs).unwrap_or(0)),
            Register::GS => Some(record.gs_base.or(segment_bases.gs).unwrap_or(0)),
            Register::CS | Register::DS | Register::ES | Register::SS => Some(0),
            other => id_from_iced(other).and_then(|id| record.reg(id)),
        })?;
        return Some(ResolvedAccess {
            address,
            size: mem.memory_size().size() as u32,
            kind: AccessKind::Read,
            base: id_from_iced(mem.base()),
            index: id_from_iced(mem.index()),
        });
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
    operand_value(record, ins, 1)
}

fn operand_value(record: &TraceRecord, ins: &Instruction, operand: u32) -> Option<u64> {
    match ins.op_kind(operand) {
        OpKind::Register => operand_register(ins, operand)
            .and_then(id_from_iced)
            .and_then(|id| record.reg(id)),
        OpKind::Memory => None,
        _ => Some(immediate_at(ins, operand)),
    }
}

fn immediate(ins: &Instruction) -> u64 {
    immediate_at(ins, 1)
}

fn operand_register(ins: &Instruction, operand: u32) -> Option<Register> {
    let reg = match operand {
        0 => ins.op0_register(),
        1 => ins.op1_register(),
        2 => ins.op2_register(),
        3 => ins.op3_register(),
        4 => ins.op4_register(),
        _ => Register::None,
    };
    (reg != Register::None).then_some(reg)
}

fn canonical_wide_register(register: Register) -> Option<Register> {
    let register = register.full_register();
    if register == Register::None || register.size() == 0 || id_from_iced(register).is_some() {
        return None;
    }
    let name = format!("{register:?}");
    if name.starts_with("XMM")
        || name.starts_with("YMM")
        || name.starts_with("ZMM")
        || name.starts_with("MM")
    {
        Some(register)
    } else {
        None
    }
}

fn is_transfer_mnemonic(mnemonic: Mnemonic) -> bool {
    let name = format!("{mnemonic:?}");
    name.starts_with("Mov")
        || name.starts_with("Vmov")
        || name.starts_with("Cmov")
        || name.starts_with("Pshuf")
        || name.starts_with("Shuf")
}

fn is_same_register_zero_idiom(ins: &Instruction) -> bool {
    let name = format!("{:?}", ins.mnemonic());
    let is_xor = name == "Xor"
        || name == "Xorps"
        || name == "Xorpd"
        || name == "Pxor"
        || name == "Vxorps"
        || name == "Vxorpd"
        || name == "Vpxor"
        || name == "Vpxord"
        || name == "Vpxorq";
    is_xor
        && ins.op0_kind() == OpKind::Register
        && ins.op1_kind() == OpKind::Register
        && ins.op0_register().full_register() == ins.op1_register().full_register()
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

fn same_owners(left: &OwnerSet, right: &OwnerSet) -> bool {
    left.len() == right.len() && left.iter().all(|owner| right.contains(owner))
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

fn pointer_difference_yields_integer(
    mnemonic: Mnemonic,
    left: &RegState,
    right: &RegState,
) -> bool {
    matches!(mnemonic, Mnemonic::Sub | Mnemonic::Sbb)
        && !left.pointee_owners.is_empty()
        && !right.pointee_owners.is_empty()
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
