use std::collections::HashMap;

use indexmap::IndexSet;
use serde::Serialize;

use crate::vuln::SubjectId;

pub const ALLOCATOR_SUBJECT: SubjectId = 0;

pub type OwnerSet = IndexSet<SubjectId>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubjectKind {
    Allocator,
    Heap,
    Stack,
    Global,
    Page,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct Subject {
    pub id: SubjectId,
    pub kind: SubjectKind,
    pub start: Option<u64>,
    pub size: Option<u64>,
    pub freed: bool,
    pub name: Option<String>,
    pub parent: Option<SubjectId>,
}

#[derive(Debug, Clone, Default)]
pub struct CellState {
    pub cell_owners: OwnerSet,
    pub value_owners: OwnerSet,
    pub pointee_owners: OwnerSet,
    pub last_write_pc: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct RegState {
    pub value_owners: OwnerSet,
    pub pointee_owners: OwnerSet,
}

#[derive(Debug, Clone)]
pub struct MemoryModel {
    pub subjects: HashMap<SubjectId, Subject>,
    cells: HashMap<u64, CellState>,
    next_subject: SubjectId,
}

impl Default for MemoryModel {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryModel {
    pub fn new() -> Self {
        let mut subjects = HashMap::new();
        subjects.insert(
            ALLOCATOR_SUBJECT,
            Subject {
                id: ALLOCATOR_SUBJECT,
                kind: SubjectKind::Allocator,
                start: None,
                size: None,
                freed: false,
                name: Some("allocator".into()),
                parent: None,
            },
        );
        Self {
            subjects,
            cells: HashMap::new(),
            next_subject: 1,
        }
    }

    pub fn fresh_heap_subject(&mut self, start: u64, size: u64) -> SubjectId {
        self.fresh_subject(SubjectKind::Heap, start, size)
    }

    pub fn fresh_heap_subject_named(
        &mut self,
        start: u64,
        size: u64,
        name: Option<String>,
    ) -> SubjectId {
        self.fresh_subject_named(SubjectKind::Heap, start, size, name, None)
    }

    pub fn fresh_subject(&mut self, kind: SubjectKind, start: u64, size: u64) -> SubjectId {
        self.fresh_subject_named(kind, start, size, None, None)
    }

    pub fn fresh_subject_named(
        &mut self,
        kind: SubjectKind,
        start: u64,
        size: u64,
        name: Option<String>,
        parent: Option<SubjectId>,
    ) -> SubjectId {
        let id = self.next_subject;
        self.next_subject = self.next_subject.saturating_add(1);
        self.subjects.insert(
            id,
            Subject {
                id,
                kind,
                start: Some(start),
                size: Some(size),
                freed: false,
                name,
                parent,
            },
        );
        id
    }

    pub fn cell(&self, addr: u64) -> CellState {
        self.cells.get(&addr).cloned().unwrap_or_default()
    }
    pub fn cell_mut(&mut self, addr: u64) -> &mut CellState {
        self.cells.entry(addr).or_default()
    }

    pub fn owner_for_address(&self, addr: u64) -> OwnerSet {
        self.cell(addr).cell_owners
    }

    pub fn ensure_range_owner(&mut self, kind: SubjectKind, start: u64, size: u64) -> SubjectId {
        if let Some(subject) = self.subject_containing_kind(kind, start) {
            return subject;
        }
        let subject = self.fresh_subject(kind, start, size.max(1));
        for off in 0..size.max(1) {
            self.cell_mut(start.saturating_add(off))
                .cell_owners
                .insert(subject);
        }
        subject
    }

    pub fn subject_containing_kind(&self, kind: SubjectKind, ptr: u64) -> Option<SubjectId> {
        self.subjects
            .values()
            .find(|s| {
                s.kind == kind
                    && !s.freed
                    && s.start.zip(s.size).is_some_and(|(start, size)| {
                        ptr >= start && ptr < start.saturating_add(size)
                    })
            })
            .map(|s| s.id)
    }

    pub fn active_subject_at_start(&self, ptr: u64) -> Option<SubjectId> {
        self.subjects
            .values()
            .filter(|s| s.kind == SubjectKind::Heap && !s.freed && s.start == Some(ptr))
            .max_by_key(|s| s.id)
            .map(|s| s.id)
    }

    pub fn active_subject_containing(&self, ptr: u64) -> Option<SubjectId> {
        self.subjects
            .values()
            .find(|s| {
                matches!(
                    s.kind,
                    SubjectKind::Heap | SubjectKind::Page | SubjectKind::Stack
                ) && !s.freed
                    && s.start.zip(s.size).is_some_and(|(start, size)| {
                        ptr >= start && ptr < start.saturating_add(size)
                    })
            })
            .map(|s| s.id)
    }

    pub fn freed_subject_containing(&self, ptr: u64) -> Option<SubjectId> {
        self.subjects
            .values()
            .find(|s| {
                matches!(
                    s.kind,
                    SubjectKind::Heap | SubjectKind::Page | SubjectKind::Stack
                ) && s.freed
                    && s.start.zip(s.size).is_some_and(|(start, size)| {
                        ptr >= start && ptr < start.saturating_add(size)
                    })
            })
            .map(|s| s.id)
    }

    pub fn freed_subject_at_start(&self, ptr: u64) -> Option<SubjectId> {
        self.subjects
            .values()
            .find(|s| s.kind == SubjectKind::Heap && s.freed && s.start == Some(ptr))
            .map(|s| s.id)
    }

    pub fn subject_kind(&self, subject: SubjectId) -> SubjectKind {
        self.subjects
            .get(&subject)
            .map(|s| s.kind)
            .unwrap_or(SubjectKind::Unknown)
    }

    pub fn active_subjects_of_kind_overlapping(
        &self,
        kind: SubjectKind,
        start: u64,
        size: u64,
    ) -> Vec<SubjectId> {
        let end = start.saturating_add(size.max(1));
        self.subjects
            .values()
            .filter(|s| {
                s.kind == kind
                    && !s.freed
                    && s.start.zip(s.size).is_some_and(|(s_start, s_size)| {
                        let s_end = s_start.saturating_add(s_size.max(1));
                        start < s_end && s_start < end
                    })
            })
            .map(|s| s.id)
            .collect()
    }

    pub fn subject_contains(&self, subject: SubjectId, addr: u64) -> bool {
        self.subjects
            .get(&subject)
            .and_then(|s| s.start.zip(s.size))
            .is_some_and(|(start, size)| addr >= start && addr < start.saturating_add(size))
    }

    pub fn subject_freed(&self, subject: SubjectId) -> bool {
        self.subjects.get(&subject).is_some_and(|s| s.freed)
    }

    pub fn mark_freed(&mut self, subject: SubjectId) {
        if let Some(s) = self.subjects.get_mut(&subject) {
            s.freed = true;
        }
    }

    pub fn subject_and_descendants(&self, subject: SubjectId) -> Vec<SubjectId> {
        let mut out = vec![subject];
        let mut idx = 0;
        while idx < out.len() {
            let parent = out[idx];
            let children: Vec<_> = self
                .subjects
                .values()
                .filter(|candidate| candidate.parent == Some(parent))
                .map(|candidate| candidate.id)
                .collect();
            for child in children {
                if !out.contains(&child) {
                    out.push(child);
                }
            }
            idx += 1;
        }
        out
    }

    pub fn subject_label(&self, subject: SubjectId) -> String {
        if subject == ALLOCATOR_SUBJECT {
            return "allocator".into();
        }
        if let Some(name) = self.subjects.get(&subject).and_then(|s| s.name.as_ref()) {
            return name.clone();
        }
        match self
            .subjects
            .get(&subject)
            .map(|s| s.kind)
            .unwrap_or(SubjectKind::Unknown)
        {
            SubjectKind::Heap => format!("heap:{subject}"),
            SubjectKind::Stack => format!("stack:{subject}"),
            SubjectKind::Global => format!("global:{subject}"),
            SubjectKind::Page => format!("page:{subject}"),
            SubjectKind::Allocator => "allocator".into(),
            SubjectKind::Unknown => format!("unknown:{subject}"),
        }
    }

    pub fn labels(&self, owners: &OwnerSet) -> Vec<String> {
        owners.iter().map(|id| self.subject_label(*id)).collect()
    }
}

pub fn owner_set_one(subject: SubjectId) -> OwnerSet {
    let mut set = OwnerSet::new();
    set.insert(subject);
    set
}

pub fn sets_intersect(a: &OwnerSet, b: &OwnerSet) -> bool {
    a.iter().any(|id| b.contains(id))
}
