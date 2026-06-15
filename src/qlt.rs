use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;

use thiserror::Error;

use crate::registers::{REG_COUNT, REG_TABLE_ID_X86_64_V1, RegId};
use crate::trace::{
    TRACE_FLAG_HAS_BRANCH_TARGET, TRACE_FLAG_HAS_CR3, TRACE_FLAG_HAS_VALUE, TraceReader,
    TraceRecord,
};
use crate::varint;

const MAGIC: &[u8; 4] = b"QLT1";
const VERSION: u16 = 1;
const HEADER_SIZE: u64 = 32;
const DEFAULT_BLOCK_SIZE: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct BlockIndex {
    pub compressed_offset: u64,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub first_step: u64,
    pub record_count: u64,
}

#[derive(Debug, Error)]
pub enum QltError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid QLT magic")]
    InvalidMagic,
    #[error("unsupported QLT version {0}")]
    UnsupportedVersion(u16),
    #[error("unsupported register table id {0}")]
    UnsupportedRegisterTable(u16),
    #[error("invalid QLT data: {0}")]
    InvalidData(String),
}

pub struct QltWriter<W: Write + Seek> {
    writer: W,
    block_buf: Vec<u8>,
    indexes: Vec<BlockIndex>,
    prev_step: u64,
    first_step_in_block: Option<u64>,
    records_in_block: u64,
    block_size: usize,
    compression_level: i32,
}

impl QltWriter<File> {
    pub fn create(path: impl AsRef<Path>) -> Result<Self, QltError> {
        Self::new(File::create(path)?)
    }
}

impl<W: Write + Seek> QltWriter<W> {
    pub fn new(mut writer: W) -> Result<Self, QltError> {
        write_placeholder_header(&mut writer)?;
        Ok(Self {
            writer,
            block_buf: Vec::with_capacity(DEFAULT_BLOCK_SIZE),
            indexes: Vec::new(),
            prev_step: 0,
            first_step_in_block: None,
            records_in_block: 0,
            block_size: DEFAULT_BLOCK_SIZE,
            compression_level: 3,
        })
    }

    pub fn with_block_size(mut self, block_size: usize) -> Self {
        self.block_size = block_size.max(256);
        self
    }

    pub fn write_record(&mut self, record: &TraceRecord) -> Result<(), QltError> {
        if self.first_step_in_block.is_none() {
            self.first_step_in_block = Some(record.step);
        }
        encode_record(record, self.prev_step, &mut self.block_buf)?;
        self.prev_step = record.step;
        self.records_in_block += 1;
        if self.block_buf.len() >= self.block_size {
            self.flush_block()?;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<W, QltError> {
        self.flush_block()?;
        let index_offset = self.writer.stream_position()?;
        for index in &self.indexes {
            write_u64(&mut self.writer, index.compressed_offset)?;
            write_u64(&mut self.writer, index.compressed_size)?;
            write_u64(&mut self.writer, index.uncompressed_size)?;
            write_u64(&mut self.writer, index.first_step)?;
            write_u64(&mut self.writer, index.record_count)?;
        }
        self.writer.seek(SeekFrom::Start(0))?;
        write_header(&mut self.writer, self.indexes.len() as u64, index_offset)?;
        self.writer.seek(SeekFrom::End(0))?;
        Ok(self.writer)
    }

    fn flush_block(&mut self) -> Result<(), QltError> {
        if self.records_in_block == 0 {
            return Ok(());
        }
        let compressed = crate::zstd_ffi::compress(&self.block_buf, self.compression_level)?;
        let offset = self.writer.stream_position()?;
        self.writer.write_all(&compressed)?;
        self.indexes.push(BlockIndex {
            compressed_offset: offset,
            compressed_size: compressed.len() as u64,
            uncompressed_size: self.block_buf.len() as u64,
            first_step: self.first_step_in_block.unwrap_or(0),
            record_count: self.records_in_block,
        });
        self.block_buf.clear();
        self.first_step_in_block = None;
        self.records_in_block = 0;
        Ok(())
    }
}

pub struct QltReader {
    file: File,
    indexes: Vec<BlockIndex>,
}

impl QltReader {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, QltError> {
        let mut file = File::open(path)?;
        let (block_count, index_offset) = read_header(&mut file)?;
        file.seek(SeekFrom::Start(index_offset))?;
        let mut indexes = Vec::with_capacity(block_count as usize);
        for _ in 0..block_count {
            indexes.push(BlockIndex {
                compressed_offset: read_u64(&mut file)?,
                compressed_size: read_u64(&mut file)?,
                uncompressed_size: read_u64(&mut file)?,
                first_step: read_u64(&mut file)?,
                record_count: read_u64(&mut file)?,
            });
        }
        Ok(Self { file, indexes })
    }

    pub fn for_each_record(
        &mut self,
        mut f: impl FnMut(TraceRecord) -> Result<(), Box<dyn std::error::Error>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut prev_step = 0u64;
        for index in &self.indexes {
            self.file.seek(SeekFrom::Start(index.compressed_offset))?;
            let mut compressed = vec![0u8; index.compressed_size as usize];
            self.file.read_exact(&mut compressed)?;
            let data = crate::zstd_ffi::decompress(&compressed, index.uncompressed_size as usize)?;
            let mut cursor = Cursor::new(data);
            for _ in 0..index.record_count {
                let record = decode_record(&mut cursor, prev_step)?;
                prev_step = record.step;
                f(record)?;
            }
        }
        Ok(())
    }
}

impl TraceReader for QltReader {
    fn read_all(&mut self) -> Result<Vec<TraceRecord>, Box<dyn std::error::Error>> {
        let mut out = Vec::new();
        self.for_each_record(|record| {
            out.push(record);
            Ok(())
        })?;
        Ok(out)
    }
}

fn write_placeholder_header(writer: &mut impl Write) -> io::Result<()> {
    write_header(writer, 0, 0)
}

fn write_header(writer: &mut impl Write, block_count: u64, index_offset: u64) -> io::Result<()> {
    writer.write_all(MAGIC)?;
    write_u16(writer, VERSION)?;
    write_u16(writer, 0)?; // flags
    write_u16(writer, REG_TABLE_ID_X86_64_V1)?;
    write_u16(writer, 0)?; // reserved
    write_u64(writer, block_count)?;
    write_u64(writer, index_offset)?;
    write_u64(writer, HEADER_SIZE)?;
    Ok(())
}

fn read_header(reader: &mut impl Read) -> Result<(u64, u64), QltError> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(QltError::InvalidMagic);
    }
    let version = read_u16(reader)?;
    if version != VERSION {
        return Err(QltError::UnsupportedVersion(version));
    }
    let _flags = read_u16(reader)?;
    let reg_table_id = read_u16(reader)?;
    if reg_table_id != REG_TABLE_ID_X86_64_V1 {
        return Err(QltError::UnsupportedRegisterTable(reg_table_id));
    }
    let _reserved = read_u16(reader)?;
    let block_count = read_u64(reader)?;
    let index_offset = read_u64(reader)?;
    let _header_size = read_u64(reader)?;
    Ok((block_count, index_offset))
}

fn encode_record(
    record: &TraceRecord,
    prev_step: u64,
    out: &mut impl Write,
) -> Result<(), QltError> {
    let step_delta = record.step.saturating_sub(prev_step);
    varint::write_u64(step_delta, out)?;
    write_u16(out, record.cpu_id)?;
    write_u64(out, record.pc)?;
    let mut flags = record.flags;
    if record.branch_target.is_some() {
        flags |= TRACE_FLAG_HAS_BRANCH_TARGET;
    }
    if record.value.is_some() {
        flags |= TRACE_FLAG_HAS_VALUE;
    }
    if record.cr3.is_some() {
        flags |= TRACE_FLAG_HAS_CR3;
    }
    write_u32(out, flags)?;
    if record.bytecode.len() > u8::MAX as usize {
        return Err(QltError::InvalidData("bytecode too long".into()));
    }
    out.write_all(&[record.bytecode.len() as u8])?;
    out.write_all(&record.bytecode)?;
    let mut mask = 0u64;
    for reg in record.regs.keys() {
        if reg.0 as usize >= REG_COUNT {
            return Err(QltError::InvalidData(format!("unknown reg id {}", reg.0)));
        }
        mask |= reg.bit();
    }
    write_u64(out, mask)?;
    for idx in 0..REG_COUNT {
        let id = RegId(idx as u8);
        if mask & id.bit() != 0 {
            write_u64(out, record.regs.get(&id).copied().unwrap_or(0))?;
        }
    }
    if let Some(target) = record.branch_target {
        write_u64(out, target)?;
    }
    if let Some(value) = record.value {
        write_u64(out, value)?;
    }
    if let Some(cr3) = record.cr3 {
        write_u64(out, cr3)?;
    }
    Ok(())
}

fn decode_record(input: &mut impl Read, prev_step: u64) -> Result<TraceRecord, QltError> {
    let step = prev_step.saturating_add(varint::read_u64(input)?);
    let cpu_id = read_u16(input)?;
    let pc = read_u64(input)?;
    let flags = read_u32(input)?;
    let mut len = [0u8; 1];
    input.read_exact(&mut len)?;
    let mut bytecode = vec![0u8; len[0] as usize];
    input.read_exact(&mut bytecode)?;
    let mask = read_u64(input)?;
    let mut regs = std::collections::BTreeMap::new();
    for idx in 0..REG_COUNT {
        let id = RegId(idx as u8);
        if mask & id.bit() != 0 {
            regs.insert(id, read_u64(input)?);
        }
    }
    let branch_target = if flags & TRACE_FLAG_HAS_BRANCH_TARGET != 0 {
        Some(read_u64(input)?)
    } else {
        None
    };
    let value = if flags & TRACE_FLAG_HAS_VALUE != 0 {
        Some(read_u64(input)?)
    } else {
        None
    };
    let cr3 = if flags & TRACE_FLAG_HAS_CR3 != 0 {
        Some(read_u64(input)?)
    } else {
        None
    };
    Ok(TraceRecord {
        step,
        cpu_id,
        pc,
        flags,
        bytecode,
        regs,
        branch_target,
        value,
        cr3,
    })
}

fn write_u16(out: &mut impl Write, value: u16) -> io::Result<()> {
    out.write_all(&value.to_le_bytes())
}
fn write_u32(out: &mut impl Write, value: u32) -> io::Result<()> {
    out.write_all(&value.to_le_bytes())
}
fn write_u64(out: &mut impl Write, value: u64) -> io::Result<()> {
    out.write_all(&value.to_le_bytes())
}
fn read_u16(input: &mut impl Read) -> io::Result<u16> {
    let mut b = [0; 2];
    input.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}
fn read_u32(input: &mut impl Read) -> io::Result<u32> {
    let mut b = [0; 4];
    input.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}
fn read_u64(input: &mut impl Read) -> io::Result<u64> {
    let mut b = [0; 8];
    input.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}
