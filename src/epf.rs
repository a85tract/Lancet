use serde::Serialize;

use crate::analyzer::AnalysisResult;
use crate::metadata::{SourceLocation, SourceResolver};
use crate::vuln::{Violation, ViolationKind};

#[derive(Debug, Serialize)]
pub struct EpfReport {
    pub version: u32,
    pub primitive_events: Vec<PrimitiveEvent>,
    pub transitions: Vec<PrimitiveTransition>,
    pub techniques: Vec<TechniqueSummary>,
}

#[derive(Debug, Serialize, Clone)]
pub struct PrimitiveEvent {
    pub id: String,
    pub step: u64,
    pub kind: String,
    pub cwe: String,
    pub pc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceLocation>,
    pub subjects: PrimitiveSubjects,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct PrimitiveSubjects {
    pub pointer_owners: Vec<String>,
    pub cell_owners: Vec<String>,
    pub value_owners: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PrimitiveTransition {
    pub from: String,
    pub to: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct TechniqueSummary {
    pub name: String,
    pub events: Vec<String>,
    pub confidence: String,
}

pub fn build_report(result: &AnalysisResult, resolver: &mut SourceResolver) -> EpfReport {
    let mut primitive_events = Vec::new();
    for violation in &result.violations {
        let Some(kind) = primitive_kind(violation.kind) else {
            continue;
        };
        if primitive_events
            .last()
            .is_some_and(|previous: &PrimitiveEvent| {
                previous.kind == kind
                    && previous.subjects.pointer_owners == violation.pointer_owners
                    && previous.subjects.cell_owners == violation.cell_owners
            })
        {
            continue;
        }
        primitive_events.push(PrimitiveEvent {
            id: format!("EPF-E{}", primitive_events.len() + 1),
            step: violation.step,
            kind: kind.into(),
            cwe: cwe_for_kind(violation.kind).into(),
            pc: violation.pc.clone(),
            source: resolver.resolve_label(&violation.pc),
            subjects: PrimitiveSubjects {
                pointer_owners: violation.pointer_owners.clone(),
                cell_owners: violation.cell_owners.clone(),
                value_owners: violation.value_owners.clone(),
            },
            note: violation.note.clone(),
        });
    }
    let transitions = build_transitions(&primitive_events);
    let techniques = recognize_techniques(&primitive_events);
    EpfReport {
        version: 1,
        primitive_events,
        transitions,
        techniques,
    }
}

pub fn render_markdown(report: &EpfReport) -> String {
    let mut out = String::new();
    out.push_str("# EPF Report\n\n");
    if report.primitive_events.is_empty() {
        out.push_str("No primitive events were generated.\n");
        return out;
    }
    out.push_str("## Primitive timeline\n\n");
    for event in &report.primitive_events {
        out.push_str(&format!(
            "- {} step {} `{}` {} ({})\n",
            event.id, event.step, event.pc, event.kind, event.cwe
        ));
    }
    if !report.transitions.is_empty() {
        out.push_str("\n## Transitions\n\n");
        for transition in &report.transitions {
            out.push_str(&format!(
                "- {} -> {}: {}\n",
                transition.from, transition.to, transition.reason
            ));
        }
    }
    if !report.techniques.is_empty() {
        out.push_str("\n## Techniques\n\n");
        for technique in &report.techniques {
            out.push_str(&format!(
                "- {} ({}) via `{}`\n",
                technique.name,
                technique.confidence,
                technique.events.join("`, `")
            ));
        }
    }
    out
}

fn build_transitions(events: &[PrimitiveEvent]) -> Vec<PrimitiveTransition> {
    let mut transitions = Vec::new();
    for window in events.windows(2) {
        let from = &window[0];
        let to = &window[1];
        if subjects_related(&from.subjects, &to.subjects) || transition_is_escalation(from, to) {
            transitions.push(PrimitiveTransition {
                from: from.id.clone(),
                to: to.id.clone(),
                reason: transition_reason(from, to).into(),
            });
        }
    }
    transitions
}

fn recognize_techniques(events: &[PrimitiveEvent]) -> Vec<TechniqueSummary> {
    let mut techniques = Vec::new();
    let house_events: Vec<_> = events
        .iter()
        .filter(|event| {
            event.kind == "InvalidFree"
                && event
                    .subjects
                    .pointer_owners
                    .iter()
                    .chain(event.subjects.cell_owners.iter())
                    .any(|owner| owner.contains("stack") || owner.contains("global"))
        })
        .map(|event| event.id.clone())
        .collect();
    if !house_events.is_empty() {
        techniques.push(TechniqueSummary {
            name: "HouseOfSpirit".into(),
            events: house_events,
            confidence: "high".into(),
        });
    }

    let has_invalid_free = events.iter().any(|event| event.kind == "InvalidFree");

    if let Some(chain) = find_chain4(
        events,
        &["CrossBoundary", "OOBW"],
        &["MemoryOverlap"],
        &["InvalidFree"],
        &["UAFR", "UAFW"],
    ) {
        techniques.push(TechniqueSummary {
            name: "EinherjarStyle".into(),
            events: chain,
            confidence: "high".into(),
        });
    }

    if !has_invalid_free
        && let Some(chain) = find_chain(events, &["OOBW"], &["MemoryOverlap"], &["UAFR", "UAFW"])
    {
        techniques.push(TechniqueSummary {
            name: "PoisonNullByteStyle".into(),
            events: chain,
            confidence: "medium".into(),
        });
    }

    if !has_invalid_free && let Some((chain, confidence)) = find_fastbin_reverse_into_tcache(events)
    {
        techniques.push(TechniqueSummary {
            name: "FastbinReverseIntoTcacheStyle".into(),
            events: chain,
            confidence,
        });
    }

    techniques
}

fn find_fastbin_reverse_into_tcache(events: &[PrimitiveEvent]) -> Option<(Vec<String>, String)> {
    let uafw = events.iter().find(|event| event.kind == "UAFW")?;
    let overlap = events.iter().find(|event| {
        event.step > uafw.step && event.kind == "MemoryOverlap" && has_static_owner(&event.subjects)
    })?;
    let mut chain = Vec::new();
    let dangling = events
        .iter()
        .find(|event| event.step < uafw.step && event.kind == "DanglingPtr");
    if let Some(dangling) = dangling {
        chain.push(dangling.id.clone());
    }
    chain.push(uafw.id.clone());
    chain.push(overlap.id.clone());
    let confidence = if dangling.is_some() { "high" } else { "medium" }.into();
    Some((chain, confidence))
}

fn has_static_owner(subjects: &PrimitiveSubjects) -> bool {
    subjects
        .pointer_owners
        .iter()
        .chain(subjects.cell_owners.iter())
        .chain(subjects.value_owners.iter())
        .any(|owner| owner.contains("stack") || owner.contains("global"))
}

fn find_chain(
    events: &[PrimitiveEvent],
    first_kinds: &[&str],
    middle_kinds: &[&str],
    last_kinds: &[&str],
) -> Option<Vec<String>> {
    let first = events
        .iter()
        .find(|event| first_kinds.contains(&event.kind.as_str()))?;
    let middle = events
        .iter()
        .find(|event| event.step > first.step && middle_kinds.contains(&event.kind.as_str()))?;
    let last = events
        .iter()
        .find(|event| event.step > middle.step && last_kinds.contains(&event.kind.as_str()))?;
    Some(vec![first.id.clone(), middle.id.clone(), last.id.clone()])
}

fn find_chain4(
    events: &[PrimitiveEvent],
    first_kinds: &[&str],
    second_kinds: &[&str],
    third_kinds: &[&str],
    fourth_kinds: &[&str],
) -> Option<Vec<String>> {
    let first = events
        .iter()
        .find(|event| first_kinds.contains(&event.kind.as_str()))?;
    let second = events
        .iter()
        .find(|event| event.step > first.step && second_kinds.contains(&event.kind.as_str()))?;
    let third = events
        .iter()
        .find(|event| event.step > second.step && third_kinds.contains(&event.kind.as_str()))?;
    let fourth = events
        .iter()
        .find(|event| event.step > third.step && fourth_kinds.contains(&event.kind.as_str()))?;
    Some(vec![
        first.id.clone(),
        second.id.clone(),
        third.id.clone(),
        fourth.id.clone(),
    ])
}

fn transition_is_escalation(from: &PrimitiveEvent, to: &PrimitiveEvent) -> bool {
    matches!(
        (from.kind.as_str(), to.kind.as_str()),
        ("CrossBoundary", "OOBW")
            | ("CrossBoundary", "OOBR")
            | ("OOBW", "InvalidFree")
            | ("OOBW", "MemoryOverlap")
            | ("InvalidFree", "MemoryOverlap")
            | ("MemoryOverlap", "UAFR")
            | ("MemoryOverlap", "UAFW")
    )
}

fn transition_reason(from: &PrimitiveEvent, to: &PrimitiveEvent) -> &'static str {
    if subjects_related(&from.subjects, &to.subjects) {
        "shared pointer/cell/value owner"
    } else {
        "known primitive escalation pattern"
    }
}

fn subjects_related(a: &PrimitiveSubjects, b: &PrimitiveSubjects) -> bool {
    intersects(&a.pointer_owners, &b.pointer_owners)
        || intersects(&a.pointer_owners, &b.cell_owners)
        || intersects(&a.cell_owners, &b.pointer_owners)
        || intersects(&a.cell_owners, &b.cell_owners)
        || intersects(&a.value_owners, &b.value_owners)
}

fn intersects(a: &[String], b: &[String]) -> bool {
    a.iter().any(|value| b.contains(value))
}

fn primitive_kind(kind: ViolationKind) -> Option<&'static str> {
    Some(match kind {
        ViolationKind::UninitializedRead => "UninitRead",
        ViolationKind::OutOfBoundsRead => "OOBR",
        ViolationKind::OutOfBoundsWrite => "OOBW",
        ViolationKind::UseAfterFreeRead => "UAFR",
        ViolationKind::UseAfterFreeWrite => "UAFW",
        ViolationKind::StackUseAfterScopeRead => "StackUAFR",
        ViolationKind::StackUseAfterScopeWrite => "StackUAFW",
        ViolationKind::DoubleFree => "DoubleFree",
        ViolationKind::InvalidFree => "InvalidFree",
        ViolationKind::MemoryOverlap => "MemoryOverlap",
        ViolationKind::CrossBoundary => "CrossBoundary",
        ViolationKind::DanglingPointer => "DanglingPtr",
        ViolationKind::ExpiredPointerDereference => "ExpiredPtr",
        ViolationKind::NullPointerDereference => "NullPtrDeref",
        ViolationKind::UntrustedPtr => "UntrustedPtr",
    })
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

#[allow(dead_code)]
fn _event_from_violation(violation: &Violation) -> (&'static str, &'static str) {
    (
        primitive_kind(violation.kind).unwrap_or("Unknown"),
        cwe_for_kind(violation.kind),
    )
}
