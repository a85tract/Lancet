use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::registers::{RegId, id_from_name};
use crate::vuln::ViolationKind;

#[derive(Debug, Clone)]
pub struct Config {
    pub malloc_addrs: HashSet<u64>,
    pub free_addrs: HashSet<u64>,
    pub symbols_by_addr: HashMap<u64, SymbolConfig>,
    pub enabled: HashSet<ViolationKind>,
    pub malloc_size: Option<u64>,
    pub skip_return_addrs: HashMap<u64, u64>,
    pub module_range: Option<(u64, u64)>,
    pub page_allocator: Option<PageAllocatorConfig>,
    pub metadata: MetadataConfig,
    pub report: ReportConfig,
    pub segment_bases: SegmentBases,
    pub field_subjects: Vec<FieldSubjectConfig>,
    pub allocation_type_hints: HashMap<u64, String>,
    pub type_layouts: HashMap<String, TypeLayoutConfig>,
}

#[derive(Debug, Clone)]
pub struct SymbolConfig {
    pub name: String,
    pub addr: u64,
    pub import_reg: Option<RegId>,
    pub offset: i64,
    pub use_value_to_size: bool,
    pub malloc_size: Option<u64>,
    pub value_size: Option<u8>,
    pub zero_initialized: bool,
    pub is_bulk: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct PageAllocatorConfig {
    pub vmemmap_start: u64,
    pub page_offset_base: u64,
}

#[derive(Debug, Clone, Default)]
pub struct MetadataConfig {
    pub binary: Option<String>,
    pub source_roots: Vec<String>,
    pub enable_dwarf: bool,
}

#[derive(Debug, Clone)]
pub struct ReportConfig {
    pub max_findings: usize,
    pub include_raw_evidence: bool,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            max_findings: 200,
            include_raw_evidence: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SegmentBases {
    pub fs: Option<u64>,
    pub gs: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct FieldSubjectConfig {
    pub start: u64,
    pub size: u64,
    pub name: String,
    pub fields: Vec<FieldConfig>,
}

#[derive(Debug, Clone)]
pub struct TypeLayoutConfig {
    pub size: Option<u64>,
    pub fields: Vec<FieldConfig>,
}

#[derive(Debug, Clone)]
pub struct FieldConfig {
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default)]
    malloc_addrs: Vec<String>,
    #[serde(default)]
    free_addrs: Vec<String>,
    #[serde(default)]
    vulnerability_types: Vec<String>,
    #[serde(default)]
    symbol_names: HashMap<String, RawSymbol>,
    #[serde(default, alias = "malloc-size", alias = "mallocSize")]
    malloc_size: Option<RawNum>,
    #[serde(default)]
    skip_addrs: Vec<HashMap<String, RawSkipRange>>,
    #[serde(default)]
    ctf_mode: bool,
    #[serde(default)]
    module_base: Option<String>,
    #[serde(default)]
    module_size: Option<RawNum>,
    #[serde(default)]
    page_allocator: Option<RawPageAllocator>,
    #[serde(default)]
    vmemmap_start: Option<String>,
    #[serde(default)]
    page_offset_base: Option<String>,
    #[serde(default)]
    metadata: Option<RawMetadata>,
    #[serde(default)]
    report: Option<RawReport>,
    #[serde(default)]
    segment_bases: Option<RawSegmentBases>,
    #[serde(default)]
    field_subjects: Vec<RawFieldSubject>,
    #[serde(default)]
    allocation_type_hints: HashMap<String, String>,
    #[serde(default)]
    type_layouts: HashMap<String, RawTypeLayout>,
}

#[derive(Debug, Deserialize)]
struct RawSymbol {
    addr: String,
    #[serde(default)]
    import_reg: Option<String>,
    #[serde(default)]
    offset: Option<String>,
    #[serde(default)]
    use_value_to_size: bool,
    #[serde(default, alias = "malloc-size", alias = "mallocSize")]
    malloc_size: Option<RawNum>,
    #[serde(default)]
    value_size: Option<u8>,
    #[serde(default)]
    zero_initialized: bool,
    #[serde(default)]
    is_bulk: bool,
}

#[derive(Debug, Deserialize)]
struct RawSkipRange {
    start_addr: String,
    ret_addr: String,
}

#[derive(Debug, Deserialize)]
struct RawPageAllocator {
    vmemmap_start: String,
    page_offset_base: String,
}

#[derive(Debug, Deserialize)]
struct RawMetadata {
    #[serde(default)]
    binary: Option<String>,
    #[serde(default)]
    source_roots: Vec<String>,
    #[serde(default)]
    enable_dwarf: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct RawReport {
    #[serde(default)]
    max_findings: Option<usize>,
    #[serde(default)]
    include_raw_evidence: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct RawSegmentBases {
    #[serde(default)]
    fs: Option<String>,
    #[serde(default)]
    gs: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawFieldSubject {
    start: String,
    size: RawNum,
    name: String,
    #[serde(default)]
    fields: Vec<RawField>,
}

#[derive(Debug, Deserialize)]
struct RawTypeLayout {
    #[serde(default)]
    size: Option<RawNum>,
    #[serde(default)]
    fields: Vec<RawField>,
}

#[derive(Debug, Deserialize)]
struct RawField {
    name: String,
    #[serde(default)]
    offset: Option<RawNum>,
    size: RawNum,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawNum {
    String(String),
    Number(u64),
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let raw: RawConfig = serde_json::from_str(&fs::read_to_string(path)?)?;
        let mut malloc_addrs = HashSet::new();
        for raw_addr in raw.malloc_addrs {
            malloc_addrs.insert(parse_u64(&raw_addr)?);
        }
        let mut free_addrs = HashSet::new();
        for raw_addr in raw.free_addrs {
            free_addrs.insert(parse_u64(&raw_addr)?);
        }
        let global_malloc_size = raw.malloc_size.map(parse_raw_num).transpose()?;
        let mut symbols_by_addr = HashMap::new();
        for (name, raw_sym) in raw.symbol_names {
            let addr = parse_u64(&raw_sym.addr)?;
            let offset = raw_sym
                .offset
                .as_deref()
                .map(parse_i64)
                .transpose()?
                .unwrap_or(0);
            let import_reg = raw_sym.import_reg.as_deref().and_then(id_from_name);
            let malloc_size = raw_sym
                .malloc_size
                .map(parse_raw_num)
                .transpose()?
                .or(global_malloc_size);
            symbols_by_addr.insert(
                addr,
                SymbolConfig {
                    zero_initialized: raw_sym.zero_initialized
                        || name.contains("kzalloc")
                        || name.contains("calloc")
                        || name.contains("zalloc"),
                    is_bulk: raw_sym.is_bulk || name.contains("_bulk"),
                    name,
                    addr,
                    import_reg,
                    offset,
                    use_value_to_size: raw_sym.use_value_to_size,
                    malloc_size,
                    value_size: raw_sym.value_size,
                },
            );
        }
        for &addr in &malloc_addrs {
            symbols_by_addr.entry(addr).or_insert(SymbolConfig {
                name: "malloc".into(),
                addr,
                import_reg: None,
                offset: 0,
                use_value_to_size: false,
                malloc_size: global_malloc_size,
                value_size: None,
                zero_initialized: false,
                is_bulk: false,
            });
        }
        for &addr in &free_addrs {
            symbols_by_addr.entry(addr).or_insert(SymbolConfig {
                name: "free".into(),
                addr,
                import_reg: None,
                offset: 0,
                use_value_to_size: false,
                malloc_size: None,
                value_size: None,
                zero_initialized: false,
                is_bulk: false,
            });
        }
        let mut skip_return_addrs = HashMap::new();
        for range in raw.skip_addrs {
            for (_, raw_range) in range {
                skip_return_addrs.insert(
                    parse_u64(&raw_range.start_addr)?,
                    parse_u64(&raw_range.ret_addr)?,
                );
            }
        }
        let module_range = if raw.ctf_mode {
            match (raw.module_base.as_deref(), raw.module_size) {
                (Some(base), Some(size)) => {
                    let base = parse_u64(base)?;
                    Some((base, parse_raw_num(size)?))
                }
                _ => None,
            }
        } else {
            None
        };
        let page_allocator = if let Some(page) = raw.page_allocator {
            Some(PageAllocatorConfig {
                vmemmap_start: parse_u64(&page.vmemmap_start)?,
                page_offset_base: parse_u64(&page.page_offset_base)?,
            })
        } else {
            match (
                raw.vmemmap_start.as_deref(),
                raw.page_offset_base.as_deref(),
            ) {
                (Some(vmemmap_start), Some(page_offset_base)) => Some(PageAllocatorConfig {
                    vmemmap_start: parse_u64(vmemmap_start)?,
                    page_offset_base: parse_u64(page_offset_base)?,
                }),
                _ => None,
            }
        };
        let enabled = if raw.vulnerability_types.is_empty() {
            ViolationKind::all().into_iter().collect()
        } else {
            raw.vulnerability_types
                .iter()
                .map(|s| s.parse())
                .collect::<Result<HashSet<_>, _>>()?
        };
        let metadata = raw
            .metadata
            .map(|raw| MetadataConfig {
                binary: raw.binary,
                source_roots: raw.source_roots,
                enable_dwarf: raw.enable_dwarf.unwrap_or(true),
            })
            .unwrap_or_default();
        let report = raw
            .report
            .map(|raw| ReportConfig {
                max_findings: raw.max_findings.unwrap_or(200),
                include_raw_evidence: raw.include_raw_evidence.unwrap_or(true),
            })
            .unwrap_or_default();
        let segment_bases = if let Some(raw) = raw.segment_bases {
            SegmentBases {
                fs: raw.fs.as_deref().map(parse_u64).transpose()?,
                gs: raw.gs.as_deref().map(parse_u64).transpose()?,
            }
        } else {
            SegmentBases::default()
        };
        let mut field_subjects = Vec::new();
        for raw_subject in raw.field_subjects {
            let start = parse_u64(&raw_subject.start)?;
            let size = parse_raw_num(raw_subject.size)?;
            let mut fields = Vec::new();
            for raw_field in raw_subject.fields {
                fields.push(parse_field(raw_field)?);
            }
            field_subjects.push(FieldSubjectConfig {
                start,
                size,
                name: raw_subject.name,
                fields,
            });
        }
        let mut allocation_type_hints = HashMap::new();
        for (addr, ty) in raw.allocation_type_hints {
            allocation_type_hints.insert(parse_u64(&addr)?, ty);
        }
        let mut type_layouts = HashMap::new();
        for (name, raw_layout) in raw.type_layouts {
            let mut fields = Vec::new();
            for raw_field in raw_layout.fields {
                fields.push(parse_field(raw_field)?);
            }
            type_layouts.insert(
                name,
                TypeLayoutConfig {
                    size: raw_layout.size.map(parse_raw_num).transpose()?,
                    fields,
                },
            );
        }
        Ok(Self {
            malloc_addrs,
            free_addrs,
            symbols_by_addr,
            enabled,
            malloc_size: global_malloc_size,
            skip_return_addrs,
            module_range,
            page_allocator,
            metadata,
            report,
            segment_bases,
            field_subjects,
            allocation_type_hints,
            type_layouts,
        })
    }

    pub fn symbol(&self, addr: u64) -> Option<&SymbolConfig> {
        self.symbols_by_addr.get(&addr)
    }
    pub fn skip_return_for(&self, target: u64) -> Option<u64> {
        self.skip_return_addrs.get(&target).copied()
    }
    pub fn violation_enabled(&self, kind: ViolationKind) -> bool {
        self.enabled.contains(&kind)
    }
}

fn parse_field(raw_field: RawField) -> Result<FieldConfig, Box<dyn std::error::Error>> {
    Ok(FieldConfig {
        name: raw_field.name,
        offset: raw_field
            .offset
            .map(parse_raw_num)
            .transpose()?
            .unwrap_or(0),
        size: parse_raw_num(raw_field.size)?,
    })
}

fn parse_raw_num(raw: RawNum) -> Result<u64, Box<dyn std::error::Error>> {
    Ok(match raw {
        RawNum::String(s) => parse_u64(&s)?,
        RawNum::Number(n) => n,
    })
}

fn parse_u64(raw: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let raw = raw.trim();
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        Ok(u64::from_str_radix(hex, 16)?)
    } else {
        Ok(raw.parse()?)
    }
}

fn parse_i64(raw: &str) -> Result<i64, Box<dyn std::error::Error>> {
    let raw = raw.trim();
    if let Some(hex) = raw.strip_prefix("+0x").or_else(|| raw.strip_prefix("+0X")) {
        Ok(i64::from_str_radix(hex, 16)?)
    } else if let Some(hex) = raw.strip_prefix("-0x").or_else(|| raw.strip_prefix("-0X")) {
        Ok(-i64::from_str_radix(hex, 16)?)
    } else if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        Ok(i64::from_str_radix(hex, 16)?)
    } else {
        Ok(raw.parse()?)
    }
}
