use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

use crate::config::MetadataConfig;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SourceLocation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
}

#[derive(Debug, Default)]
pub struct SourceResolver {
    binary: Option<PathBuf>,
    source_roots: Vec<PathBuf>,
    enabled: bool,
    cache: HashMap<u64, Option<SourceLocation>>,
}

impl SourceResolver {
    pub fn new(config: &MetadataConfig) -> Self {
        Self {
            binary: config.binary.as_ref().map(PathBuf::from),
            source_roots: config.source_roots.iter().map(PathBuf::from).collect(),
            enabled: config.enable_dwarf,
            cache: HashMap::new(),
        }
    }

    pub fn resolve_label(&mut self, pc: &str) -> Option<SourceLocation> {
        let pc = parse_hex_label(pc)?;
        self.resolve_pc(pc)
    }

    pub fn resolve_pc(&mut self, pc: u64) -> Option<SourceLocation> {
        if let Some(cached) = self.cache.get(&pc) {
            return cached.clone();
        }
        let resolved = self.resolve_pc_uncached(pc);
        self.cache.insert(pc, resolved.clone());
        resolved
    }

    fn resolve_pc_uncached(&self, pc: u64) -> Option<SourceLocation> {
        if !self.enabled {
            return None;
        }
        let binary = self.binary.as_ref()?;
        if !binary.exists() {
            return None;
        }
        let output = Command::new("addr2line")
            .arg("-f")
            .arg("-C")
            .arg("-e")
            .arg(binary)
            .arg(format!("0x{pc:x}"))
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut lines = stdout.lines();
        let function = clean_addr2line_field(lines.next());
        let (file, line) = parse_file_line(lines.next(), &self.source_roots);
        if function.is_none() && file.is_none() && line.is_none() {
            None
        } else {
            Some(SourceLocation {
                function,
                file,
                line,
            })
        }
    }
}

fn clean_addr2line_field(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty() || value == "??" {
        None
    } else {
        Some(value.into())
    }
}

fn parse_file_line(value: Option<&str>, source_roots: &[PathBuf]) -> (Option<String>, Option<u64>) {
    let Some(raw) = value.map(str::trim) else {
        return (None, None);
    };
    if raw.is_empty() || raw == "??:0" || raw == "??:?" || raw == "??" {
        return (None, None);
    }
    let (file, line) = raw
        .rsplit_once(':')
        .map(|(file, line)| (file, line.parse::<u64>().ok()))
        .unwrap_or((raw, None));
    let file = normalize_source_path(file, source_roots);
    (Some(file), line)
}

fn normalize_source_path(file: &str, source_roots: &[PathBuf]) -> String {
    let path = Path::new(file);
    for root in source_roots {
        if let Ok(stripped) = path.strip_prefix(root) {
            return stripped.display().to_string();
        }
    }
    file.into()
}

pub fn parse_hex_label(label: &str) -> Option<u64> {
    let trimmed = label.trim();
    let raw = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    u64::from_str_radix(raw, 16).ok()
}
