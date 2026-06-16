use serde::Serialize;

use crate::analyzer::{AnalysisResult, MemoryEvent};
use crate::metadata::{SourceLocation, SourceResolver};
use crate::vuln::{AccessKind, Violation, ViolationKind};

#[derive(Debug, Serialize)]
pub struct FcsReport {
    pub version: u32,
    pub findings: Vec<FcsFinding>,
}

#[derive(Debug, Serialize)]
pub struct FcsFinding {
    pub id: String,
    pub kind: String,
    pub cwe: String,
    pub severity: String,
    pub primary_step: u64,
    pub primary_pc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceLocation>,
    pub access: FcsAccess,
    pub subjects: FcsSubjects,
    pub evidence: Vec<FcsEvidence>,
    pub aliases: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FcsAccess {
    pub kind: AccessKind,
    pub address: String,
    pub size: String,
}

#[derive(Debug, Serialize)]
pub struct FcsSubjects {
    pub pointer_owners: Vec<String>,
    pub cell_owners: Vec<String>,
    pub value_owners: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct FcsEvidence {
    pub role: String,
    pub step: u64,
    pub pc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub fn build_report(
    result: &AnalysisResult,
    resolver: &mut SourceResolver,
    max_findings: usize,
    include_raw_evidence: bool,
) -> FcsReport {
    let mut findings = Vec::new();
    for violation in &result.violations {
        if !is_fcs_kind(violation.kind) {
            continue;
        }
        let id = format!("FCS-{}", findings.len() + 1);
        let mut evidence = Vec::new();
        if include_raw_evidence {
            evidence.extend(contextual_evidence(result, violation, resolver));
            evidence.push(FcsEvidence {
                role: primary_role(violation.kind).into(),
                step: violation.step,
                pc: violation.pc.clone(),
                source: resolver.resolve_label(&violation.pc),
                note: violation.note.clone(),
            });
        }
        findings.push(FcsFinding {
            id,
            kind: finding_kind(violation.kind).into(),
            cwe: cwe_for_kind(violation.kind).into(),
            severity: severity_for_kind(violation.kind).into(),
            primary_step: violation.step,
            primary_pc: violation.pc.clone(),
            source: resolver.resolve_label(&violation.pc),
            access: FcsAccess {
                kind: violation.access,
                address: violation.address.clone(),
                size: violation.size.clone(),
            },
            subjects: FcsSubjects {
                pointer_owners: violation.pointer_owners.clone(),
                cell_owners: violation.cell_owners.clone(),
                value_owners: violation.value_owners.clone(),
            },
            evidence,
            aliases: alias_summary(violation),
            note: violation.note.clone(),
        });
        if findings.len() >= max_findings {
            break;
        }
    }
    FcsReport {
        version: 1,
        findings,
    }
}

pub fn render_markdown(report: &FcsReport) -> String {
    let mut out = String::new();
    out.push_str("# FCS Report\n\n");
    if report.findings.is_empty() {
        out.push_str("No FCS findings were generated.\n");
        return out;
    }
    for finding in &report.findings {
        out.push_str(&format!(
            "## {}: {} ({})\n\n",
            finding.id, finding.kind, finding.cwe
        ));
        out.push_str(&format!(
            "- Primary: step {} pc `{}` access {:?} `{}` size `{}`\n",
            finding.primary_step,
            finding.primary_pc,
            finding.access.kind,
            finding.access.address,
            finding.access.size
        ));
        if let Some(source) = &finding.source {
            out.push_str(&format!("- Source: {}\n", source_label(source)));
        }
        if !finding.subjects.pointer_owners.is_empty() {
            out.push_str(&format!(
                "- Pointer owners: `{}`\n",
                finding.subjects.pointer_owners.join("`, `")
            ));
        }
        if !finding.subjects.cell_owners.is_empty() {
            out.push_str(&format!(
                "- Cell owners: `{}`\n",
                finding.subjects.cell_owners.join("`, `")
            ));
        }
        if let Some(note) = &finding.note {
            out.push_str(&format!("- Note: {}\n", note));
        }
        out.push_str("- Evidence:\n");
        for evidence in &finding.evidence {
            out.push_str(&format!(
                "  - {}: step {} pc `{}`",
                evidence.role, evidence.step, evidence.pc
            ));
            if let Some(source) = &evidence.source {
                out.push_str(&format!(" ({})", source_label(source)));
            }
            if let Some(note) = &evidence.note {
                out.push_str(&format!(" — {}", note));
            }
            out.push('\n');
        }
        out.push('\n');
    }
    out
}

fn contextual_evidence(
    result: &AnalysisResult,
    violation: &Violation,
    resolver: &mut SourceResolver,
) -> Vec<FcsEvidence> {
    let mut evidence = Vec::new();
    match violation.kind {
        ViolationKind::OutOfBoundsRead | ViolationKind::OutOfBoundsWrite => {
            if let Some(boundary) = previous_related_violation(
                &result.violations,
                violation,
                &[ViolationKind::CrossBoundary],
            ) {
                evidence.push(evidence_from_violation(
                    "cross-boundary",
                    boundary,
                    resolver,
                ));
            }
            if let Some(event) = related_event(result, violation, "allocation") {
                evidence.push(evidence_from_event("allocation-site", event, resolver));
            }
        }
        ViolationKind::UseAfterFreeRead
        | ViolationKind::UseAfterFreeWrite
        | ViolationKind::ExpiredPointerDereference
        | ViolationKind::DanglingPointer => {
            if let Some(event) = related_event(result, violation, "free") {
                evidence.push(evidence_from_event("free-site", event, resolver));
            }
            if let Some(copy) = previous_related_violation(
                &result.violations,
                violation,
                &[ViolationKind::DanglingPointer],
            ) {
                evidence.push(evidence_from_violation("pointer-copy", copy, resolver));
            }
        }
        ViolationKind::DoubleFree => {
            if let Some(event) = related_event(result, violation, "free") {
                evidence.push(evidence_from_event("first-free-site", event, resolver));
            }
        }
        ViolationKind::UninitializedRead => {
            if let Some(event) = related_event(result, violation, "allocation") {
                evidence.push(evidence_from_event("allocation-site", event, resolver));
            }
            if let Some(event) = related_event(result, violation, "stack-allocation") {
                evidence.push(evidence_from_event("stack-creation", event, resolver));
            }
        }
        ViolationKind::InvalidFree => {
            if let Some(event) = related_event(result, violation, "allocation") {
                evidence.push(evidence_from_event("allocation-context", event, resolver));
            }
        }
        _ => {}
    }
    evidence
}

fn previous_related_violation<'a>(
    violations: &'a [Violation],
    current: &Violation,
    kinds: &[ViolationKind],
) -> Option<&'a Violation> {
    violations.iter().rev().find(|candidate| {
        candidate.step < current.step
            && kinds.contains(&candidate.kind)
            && owners_intersect(&candidate.pointer_owners, &current.pointer_owners)
    })
}

fn related_event<'a>(
    result: &'a AnalysisResult,
    violation: &Violation,
    kind: &str,
) -> Option<&'a MemoryEvent> {
    result
        .memory_events
        .iter()
        .filter(|event| event.step <= violation.step && event.kind == kind)
        .rev()
        .find(|event| {
            event.subject.as_ref().is_some_and(|subject| {
                violation.pointer_owners.contains(subject)
                    || violation.cell_owners.contains(subject)
                    || violation.value_owners.contains(subject)
            })
        })
        .or_else(|| {
            result
                .memory_events
                .iter()
                .rfind(|event| event.step <= violation.step && event.kind == kind)
        })
}

fn evidence_from_violation(
    role: &str,
    violation: &Violation,
    resolver: &mut SourceResolver,
) -> FcsEvidence {
    FcsEvidence {
        role: role.into(),
        step: violation.step,
        pc: violation.pc.clone(),
        source: resolver.resolve_label(&violation.pc),
        note: violation.note.clone(),
    }
}

fn evidence_from_event(
    role: &str,
    event: &MemoryEvent,
    resolver: &mut SourceResolver,
) -> FcsEvidence {
    FcsEvidence {
        role: role.into(),
        step: event.step,
        pc: event.pc.clone(),
        source: resolver.resolve_label(&event.pc),
        note: event
            .symbol
            .as_ref()
            .map(|symbol| format!("{} {}", event.kind, symbol))
            .or_else(|| Some(event.kind.clone())),
    }
}

fn owners_intersect(a: &[String], b: &[String]) -> bool {
    a.iter().any(|owner| b.contains(owner))
}

fn alias_summary(violation: &Violation) -> Vec<String> {
    violation
        .pointer_owners
        .iter()
        .map(|owner| format!("pointee-owner:{owner}"))
        .collect()
}

fn is_fcs_kind(kind: ViolationKind) -> bool {
    matches!(
        kind,
        ViolationKind::UninitializedRead
            | ViolationKind::OutOfBoundsRead
            | ViolationKind::OutOfBoundsWrite
            | ViolationKind::UseAfterFreeRead
            | ViolationKind::UseAfterFreeWrite
            | ViolationKind::StackUseAfterScopeRead
            | ViolationKind::StackUseAfterScopeWrite
            | ViolationKind::DoubleFree
            | ViolationKind::InvalidFree
            | ViolationKind::CrossBoundary
            | ViolationKind::DanglingPointer
            | ViolationKind::ExpiredPointerDereference
            | ViolationKind::NullPointerDereference
            | ViolationKind::UntrustedPtr
    )
}

fn primary_role(kind: ViolationKind) -> &'static str {
    match kind {
        ViolationKind::CrossBoundary => "cross-boundary",
        ViolationKind::UninitializedRead => "uninitialized-read",
        ViolationKind::DoubleFree => "second-free-site",
        ViolationKind::InvalidFree => "invalid-free-site",
        _ => "invalid-access",
    }
}

fn finding_kind(kind: ViolationKind) -> &'static str {
    match kind {
        ViolationKind::UninitializedRead => "uninitialized-read",
        ViolationKind::OutOfBoundsRead => "out-of-bounds-read",
        ViolationKind::OutOfBoundsWrite => "out-of-bounds-write",
        ViolationKind::UseAfterFreeRead => "use-after-free-read",
        ViolationKind::UseAfterFreeWrite => "use-after-free-write",
        ViolationKind::StackUseAfterScopeRead => "stack-use-after-scope-read",
        ViolationKind::StackUseAfterScopeWrite => "stack-use-after-scope-write",
        ViolationKind::DoubleFree => "double-free",
        ViolationKind::InvalidFree => "invalid-free",
        ViolationKind::MemoryOverlap => "memory-overlap",
        ViolationKind::CrossBoundary => "cross-boundary",
        ViolationKind::DanglingPointer => "dangling-pointer",
        ViolationKind::ExpiredPointerDereference => "expired-pointer-dereference",
        ViolationKind::NullPointerDereference => "null-pointer-dereference",
        ViolationKind::UntrustedPtr => "untrusted-pointer-dereference",
    }
}

fn cwe_for_kind(kind: ViolationKind) -> &'static str {
    match kind {
        ViolationKind::UninitializedRead => "CWE-457",
        ViolationKind::OutOfBoundsRead => "CWE-125",
        ViolationKind::OutOfBoundsWrite => "CWE-787",
        ViolationKind::UseAfterFreeRead | ViolationKind::UseAfterFreeWrite => "CWE-416",
        ViolationKind::StackUseAfterScopeRead | ViolationKind::StackUseAfterScopeWrite => "CWE-562",
        ViolationKind::DoubleFree => "CWE-415",
        ViolationKind::InvalidFree => "CWE-590",
        ViolationKind::MemoryOverlap => "CWE-119",
        ViolationKind::CrossBoundary => "CWE-823",
        ViolationKind::DanglingPointer | ViolationKind::ExpiredPointerDereference => "CWE-825",
        ViolationKind::NullPointerDereference => "CWE-476",
        ViolationKind::UntrustedPtr => "CWE-822",
    }
}

fn severity_for_kind(kind: ViolationKind) -> &'static str {
    match kind {
        ViolationKind::CrossBoundary | ViolationKind::UninitializedRead => "medium",
        ViolationKind::UntrustedPtr | ViolationKind::NullPointerDereference => "medium",
        _ => "high",
    }
}

fn source_label(source: &SourceLocation) -> String {
    let mut out = String::new();
    if let Some(function) = &source.function {
        out.push_str(function);
    }
    if let Some(file) = &source.file {
        if !out.is_empty() {
            out.push_str(" at ");
        }
        out.push_str(file);
    }
    if let Some(line) = source.line {
        out.push(':');
        out.push_str(&line.to_string());
    }
    out
}
