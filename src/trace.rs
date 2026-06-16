use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::registers::{CR3, RegId};

pub const TRACE_FLAG_HAS_BRANCH_TARGET: u32 = 1 << 0;
pub const TRACE_FLAG_HAS_VALUE: u32 = 1 << 1;
pub const TRACE_FLAG_HAS_CR3: u32 = 1 << 2;
pub const TRACE_FLAG_IS_CALL: u32 = 1 << 3;
pub const TRACE_FLAG_IS_RET: u32 = 1 << 4;
pub const TRACE_FLAG_IS_REP: u32 = 1 << 5;
pub const TRACE_FLAG_REGS_FALLBACK_ALL_GPR: u32 = 1 << 6;
pub const TRACE_FLAG_HAS_FS_BASE: u32 = 1 << 7;
pub const TRACE_FLAG_HAS_GS_BASE: u32 = 1 << 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceFormat {
    Auto,
    Qlt,
    Legacy,
}

impl FromStr for TraceFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "qlt" | "binary" | "bin" => Ok(Self::Qlt),
            "legacy" | "text" | "txt" => Ok(Self::Legacy),
            other => Err(format!("unknown trace format '{other}'")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRecord {
    pub step: u64,
    pub cpu_id: u16,
    pub pc: u64,
    pub flags: u32,
    pub bytecode: Vec<u8>,
    pub regs: BTreeMap<RegId, u64>,
    pub branch_target: Option<u64>,
    pub value: Option<u64>,
    pub cr3: Option<u64>,
    pub fs_base: Option<u64>,
    pub gs_base: Option<u64>,
}

impl TraceRecord {
    pub fn new(step: u64, pc: u64, bytecode: Vec<u8>) -> Self {
        Self {
            step,
            cpu_id: 0,
            pc,
            flags: 0,
            bytecode,
            regs: BTreeMap::new(),
            branch_target: None,
            value: None,
            cr3: None,
            fs_base: None,
            gs_base: None,
        }
    }

    pub fn reg(&self, reg: RegId) -> Option<u64> {
        self.regs
            .get(&reg)
            .copied()
            .or_else(|| if reg == CR3 { self.cr3 } else { None })
    }

    pub fn set_reg(&mut self, reg: RegId, value: u64) {
        self.regs.insert(reg, value);
    }
}

pub trait TraceReader {
    fn read_all(&mut self) -> Result<Vec<TraceRecord>, Box<dyn std::error::Error>>;
}

pub fn read_trace(
    path: &Path,
    format: TraceFormat,
) -> Result<Vec<TraceRecord>, Box<dyn std::error::Error>> {
    match format {
        TraceFormat::Qlt => crate::qlt::QltReader::open(path)?.read_all(),
        TraceFormat::Legacy => crate::legacy::LegacyReader::open(path)?.read_all(),
        TraceFormat::Auto => {
            let mut file = File::open(path)?;
            let mut magic = [0u8; 4];
            let n = file.read(&mut magic)?;
            if n == 4 && &magic == b"QLT1" {
                crate::qlt::QltReader::open(path)?.read_all()
            } else {
                crate::legacy::LegacyReader::open(path)?.read_all()
            }
        }
    }
}

pub fn for_each_trace_record(
    path: &Path,
    format: TraceFormat,
    f: impl FnMut(TraceRecord) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        TraceFormat::Qlt => crate::qlt::QltReader::open(path)?.for_each_record(f),
        TraceFormat::Legacy => crate::legacy::LegacyReader::open(path)?.for_each_record(f),
        TraceFormat::Auto => {
            let mut file = File::open(path)?;
            let mut magic = [0u8; 4];
            let n = file.read(&mut magic)?;
            if n == 4 && &magic == b"QLT1" {
                crate::qlt::QltReader::open(path)?.for_each_record(f)
            } else {
                crate::legacy::LegacyReader::open(path)?.for_each_record(f)
            }
        }
    }
}
