pub mod analyzer;
pub mod config;
pub mod decode;
pub mod legacy;
pub mod ownership;
pub mod qlt;
pub mod registers;
pub mod report;
pub mod trace;
pub mod varint;
pub mod vuln;
pub mod zstd_ffi;

use std::path::Path;

use analyzer::Analyzer;
use config::Config;
use report::ReportSummary;
use trace::TraceFormat;

pub fn run_klancet(
    trace_path: impl AsRef<Path>,
    config_path: impl AsRef<Path>,
    out_dir: impl AsRef<Path>,
    format: TraceFormat,
) -> Result<ReportSummary, Box<dyn std::error::Error>> {
    let config = Config::load(config_path)?;
    let mut analyzer = Analyzer::new(config);
    trace::for_each_trace_record(trace_path.as_ref(), format, |record| {
        analyzer.process_record(&record)?;
        Ok(())
    })?;
    let result = analyzer.finish();
    report::write_reports(&result, out_dir.as_ref()).map_err(|err| err.into())
}
