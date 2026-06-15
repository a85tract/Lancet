use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::registers::id_from_name;
use crate::trace::{TraceReader, TraceRecord};

pub struct LegacyReader {
    path: std::path::PathBuf,
}

impl LegacyReader {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        Ok(Self {
            path: path.as_ref().to_path_buf(),
        })
    }
}

impl TraceReader for LegacyReader {
    fn read_all(&mut self) -> Result<Vec<TraceRecord>, Box<dyn std::error::Error>> {
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut records = Vec::new();
        let mut step = 0u64;
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            step += 1;
            records.push(parse_line(&line, step)?);
        }
        Ok(records)
    }
}

fn parse_line(line: &str, step: u64) -> Result<TraceRecord, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = line.trim().split('|').collect();
    if parts.len() < 4 {
        return Err(format!("malformed legacy trace line: {line}").into());
    }
    let cpu_id = if parts[0].trim().is_empty() {
        0
    } else {
        parts[0].trim().parse::<u16>()?
    };
    let pc = parse_u64(parts[1])?;
    let asm = parts[2].trim();
    let bytecode = parse_bytecode(parts[3])?;
    let mut rec = TraceRecord::new(step, pc, bytecode);
    rec.cpu_id = cpu_id;
    rec.branch_target = parse_branch_target(asm);
    for segment in parts.iter().skip(4) {
        let s = segment.trim();
        if s.starts_with("regs:") {
            parse_regs(&mut rec, s.trim_start_matches("regs:"));
        } else if s.starts_with("value:") {
            rec.value = parse_value_segment(s);
        } else if s.starts_with("cr3=") {
            rec.cr3 = parse_u64(s.trim_start_matches("cr3=")).ok();
        }
    }
    Ok(rec)
}

fn parse_regs(rec: &mut TraceRecord, regs: &str) {
    for token in regs.split_whitespace() {
        let token = token.trim_end_matches(',');
        let Some((name, value)) = token.split_once('=') else {
            continue;
        };
        let Some(id) = id_from_name(name) else {
            continue;
        };
        if let Ok(parsed) = parse_u64(value) {
            if id.name() == "cr3" {
                rec.cr3 = Some(parsed);
            }
            rec.set_reg(id, parsed);
        }
    }
}

fn parse_value_segment(segment: &str) -> Option<u64> {
    let raw = segment.trim().strip_prefix("value:")?.trim();
    let raw = raw
        .split(|c: char| c.is_whitespace() || c == '(')
        .next()
        .unwrap_or("");
    parse_u64(raw.trim_end_matches(',')).ok()
}

fn parse_bytecode(bytes: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for tok in bytes.split_whitespace() {
        let tok = tok.trim();
        if tok.is_empty() || tok.starts_with('<') {
            continue;
        }
        out.push(u8::from_str_radix(tok.trim_start_matches("0x"), 16)?);
    }
    Ok(out)
}

fn parse_branch_target(asm: &str) -> Option<u64> {
    let lower = asm.trim().to_ascii_lowercase();
    if !(lower.starts_with("call") || lower.starts_with("jmp")) {
        return None;
    }
    for token in asm.split(|c: char| c.is_whitespace() || c == ',' || c == '*') {
        let token = token.trim();
        if token.starts_with("0x") {
            if let Ok(value) = parse_u64(token) {
                return Some(value);
            }
        }
    }
    None
}

fn parse_u64(raw: &str) -> Result<u64, std::num::ParseIntError> {
    let cleaned = raw.trim().trim_end_matches(',');
    if let Some(hex) = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        cleaned.parse::<u64>()
    }
}
