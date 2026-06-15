use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use serde::Serialize;

use crate::analyzer::AnalysisResult;
use crate::vuln::ViolationKind;

#[derive(Debug, Default, Serialize)]
pub struct ReportSummary {
    pub ownership_violations: usize,
    pub uninitialized_reads: usize,
    pub out_of_bounds_reads: usize,
    pub out_of_bounds_writes: usize,
    pub use_after_free_reads: usize,
    pub use_after_free_writes: usize,
    pub double_frees: usize,
    pub invalid_frees: usize,
    pub memory_overlaps: usize,
    pub cross_boundaries: usize,
    pub dangling_pointers: usize,
    pub expired_pointer_dereferences: usize,
    pub null_pointer_dereferences: usize,
    pub untrusted_ptrs: usize,
}

pub fn write_reports(result: &AnalysisResult, out_dir: &Path) -> std::io::Result<ReportSummary> {
    std::fs::create_dir_all(out_dir)?;
    let mut ownership = BufWriter::new(File::create(out_dir.join("ownership_details.jsonl"))?);
    let mut summary = ReportSummary {
        ownership_violations: result.violations.len(),
        ..Default::default()
    };
    for violation in &result.violations {
        match violation.kind {
            ViolationKind::UninitializedRead => summary.uninitialized_reads += 1,
            ViolationKind::OutOfBoundsRead => summary.out_of_bounds_reads += 1,
            ViolationKind::OutOfBoundsWrite => summary.out_of_bounds_writes += 1,
            ViolationKind::UseAfterFreeRead => summary.use_after_free_reads += 1,
            ViolationKind::UseAfterFreeWrite => summary.use_after_free_writes += 1,
            ViolationKind::DoubleFree => summary.double_frees += 1,
            ViolationKind::InvalidFree => summary.invalid_frees += 1,
            ViolationKind::MemoryOverlap => summary.memory_overlaps += 1,
            ViolationKind::CrossBoundary => summary.cross_boundaries += 1,
            ViolationKind::DanglingPointer => summary.dangling_pointers += 1,
            ViolationKind::ExpiredPointerDereference => summary.expired_pointer_dereferences += 1,
            ViolationKind::NullPointerDereference => summary.null_pointer_dereferences += 1,
            ViolationKind::UntrustedPtr => summary.untrusted_ptrs += 1,
        }
        serde_json::to_writer(&mut ownership, violation)?;
        ownership.write_all(b"\n")?;
    }
    ownership.flush()?;
    let mut events = BufWriter::new(File::create(out_dir.join("memory_events.jsonl"))?);
    for event in &result.memory_events {
        serde_json::to_writer(&mut events, event)?;
        events.write_all(b"\n")?;
    }
    events.flush()?;
    let mut summary_file = BufWriter::new(File::create(out_dir.join("summary.json"))?);
    serde_json::to_writer_pretty(&mut summary_file, &summary)?;
    summary_file.write_all(b"\n")?;
    Ok(summary)
}
