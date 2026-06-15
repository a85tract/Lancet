use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use a85_qlancet::qlt::QltWriter;
use a85_qlancet::registers::*;
use a85_qlancet::trace::TraceRecord;

fn temp_dir(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("a85_qlancet_{name}_{stamp}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_config(dir: &Path) -> PathBuf {
    let path = dir.join("config.json");
    fs::write(&path, default_config_json()).unwrap();
    path
}

fn default_config_json() -> &'static str {
    r#"{
        "malloc_addrs":["0x1000"],
        "free_addrs":["0x2000"],
        "vulnerability_types":["uninitializedread","outofboundsread","outofboundswrite","uafread","uafwrite","doublefree","invalidfree","memoryoverlap","crossboundary","nullpointerdereference"],
        "symbol_names":{
            "malloc":{"addr":"0x1000","import_reg":"rdi"},
            "free":{"addr":"0x2000","import_reg":"rdi"}
        }
    }"#
}

fn call(step: u64, pc: u64, target: u64, rdi: u64) -> TraceRecord {
    let mut r = TraceRecord::new(step, pc, vec![0xe8, 0, 0, 0, 0]);
    r.branch_target = Some(target);
    r.set_reg(RDI, rdi);
    r
}

fn nop(step: u64, pc: u64, rax: u64) -> TraceRecord {
    let mut r = TraceRecord::new(step, pc, vec![0x90]);
    r.set_reg(RAX, rax);
    r
}

fn mov_rbx_rax(step: u64, pc: u64, rax: u64, rbx: u64) -> TraceRecord {
    let mut r = TraceRecord::new(step, pc, vec![0x48, 0x89, 0xc3]);
    r.set_reg(RAX, rax);
    r.set_reg(RBX, rbx);
    r
}

fn mov_rdi_rax(step: u64, pc: u64, rax: u64, rdi: u64) -> TraceRecord {
    let mut r = TraceRecord::new(step, pc, vec![0x48, 0x89, 0xc7]);
    r.set_reg(RAX, rax);
    r.set_reg(RDI, rdi);
    r
}

fn write_ptr(step: u64, pc: u64, base: RegId, addr: u64) -> TraceRecord {
    let bytes = match base.name() {
        "rbx" => vec![0x89, 0x0b], // mov dword ptr [rbx], ecx
        "rax" => vec![0x89, 0x08], // mov dword ptr [rax], ecx
        _ => vec![0x89, 0x08],
    };
    let mut r = TraceRecord::new(step, pc, bytes);
    r.set_reg(base, addr);
    r.set_reg(RCX, 0x41414141);
    r
}

fn read_rax(step: u64, pc: u64, rax: u64) -> TraceRecord {
    let mut r = TraceRecord::new(step, pc, vec![0x8b, 0x00]); // mov eax, [rax]
    r.set_reg(RAX, rax);
    r
}

fn run_qlt(name: &str, records: &[TraceRecord]) -> serde_json::Value {
    run_qlt_with_config(name, records, default_config_json())
}

fn run_qlt_with_config(
    name: &str,
    records: &[TraceRecord],
    config_json: &str,
) -> serde_json::Value {
    let dir = temp_dir(name);
    let config = dir.join("config.json");
    fs::write(&config, config_json).unwrap();
    let trace = dir.join("trace.qlt");
    let file = fs::File::create(&trace).unwrap();
    let mut writer = QltWriter::new(file).unwrap().with_block_size(128);
    for record in records {
        writer.write_record(record).unwrap();
    }
    writer.finish().unwrap();
    let out = dir.join("out");
    a85_qlancet::run_klancet(&trace, &config, &out, a85_qlancet::trace::TraceFormat::Auto).unwrap();
    serde_json::from_str(&fs::read_to_string(out.join("summary.json")).unwrap()).unwrap()
}

#[test]
fn invalid_free_for_interior_pointer() {
    let records = vec![
        call(1, 0x400000, 0x1000, 0x10),
        nop(2, 0x400005, 0x5000),
        mov_rdi_rax(3, 0x400006, 0x5001, 0),
        call(4, 0x400009, 0x2000, 0x5001),
        nop(5, 0x40000e, 0),
    ];
    let summary = run_qlt("invalid_free", &records);
    assert_eq!(summary["invalid_frees"], 1);
}

#[test]
fn uaf_after_reuse_is_not_oob() {
    let records = vec![
        call(1, 0x400000, 0x1000, 0x10),
        nop(2, 0x400005, 0x5000),
        mov_rbx_rax(3, 0x400006, 0x5000, 0),
        mov_rdi_rax(4, 0x400009, 0x5000, 0),
        call(5, 0x40000c, 0x2000, 0x5000),
        nop(6, 0x400011, 0),
        call(7, 0x400012, 0x1000, 0x10),
        nop(8, 0x400017, 0x5000),
        write_ptr(9, 0x400018, RBX, 0x5000),
    ];
    let summary = run_qlt("uaf_reuse", &records);
    assert_eq!(summary["use_after_free_writes"], 1);
    assert_eq!(summary["out_of_bounds_writes"], 0);
}

#[test]
fn lea_cross_boundary() {
    let mut lea = TraceRecord::new(6, 0x40000f, vec![0x48, 0x8d, 0x4b, 0x10]); // lea rcx,[rbx+0x10]
    lea.set_reg(RBX, 0x5000);
    lea.set_reg(RCX, 0x5010);
    let records = vec![
        call(1, 0x400000, 0x1000, 0x10),
        nop(2, 0x400005, 0x5000),
        mov_rbx_rax(3, 0x400006, 0x5000, 0),
        call(4, 0x400009, 0x1000, 0x10),
        nop(5, 0x40000e, 0x5010),
        lea,
    ];
    let summary = run_qlt("lea_cross", &records);
    assert_eq!(summary["cross_boundaries"], 1);
}

#[test]
fn uninitialized_read_after_malloc() {
    let records = vec![
        call(1, 0x400000, 0x1000, 0x10),
        nop(2, 0x400005, 0x5000),
        read_rax(3, 0x400006, 0x5000),
    ];
    let summary = run_qlt("uninit", &records);
    assert_eq!(summary["uninitialized_reads"], 1);
}

#[test]
fn qlt_value_field_drives_malloc_size() {
    let mut alloc = TraceRecord::new(1, 0x400000, vec![0xe8, 0, 0, 0, 0]);
    alloc.branch_target = Some(0x1000);
    alloc.value = Some(0x10);
    let records = vec![
        alloc,
        nop(2, 0x400005, 0x5000),
        read_rax(3, 0x400006, 0x5000),
    ];
    let summary = run_qlt_with_config(
        "value_size",
        &records,
        r#"{
            "malloc_addrs":["0x1000"],
            "free_addrs":[],
            "vulnerability_types":["uninitializedread","outofboundsread"],
            "symbol_names":{
                "slab_alloc":{"addr":"0x1000","use_value_to_size":true}
            }
        }"#,
    );
    assert_eq!(summary["uninitialized_reads"], 1);
    assert_eq!(summary["out_of_bounds_reads"], 0);
}

#[test]
fn qlt_preserves_branch_value_and_cr3_fields() {
    let dir = temp_dir("qlt_fields");
    let trace = dir.join("trace.qlt");
    let mut record = TraceRecord::new(1, 0x400000, vec![0xe8, 0, 0, 0, 0]);
    record.branch_target = Some(0x1000);
    record.value = Some(0x20);
    record.cr3 = Some(0x12345000);
    record.set_reg(RDI, 0x40);
    let file = fs::File::create(&trace).unwrap();
    let mut writer = QltWriter::new(file).unwrap();
    writer.write_record(&record).unwrap();
    writer.finish().unwrap();

    let mut reader = a85_qlancet::qlt::QltReader::open(&trace).unwrap();
    let decoded = a85_qlancet::trace::TraceReader::read_all(&mut reader).unwrap();
    assert_eq!(decoded[0].branch_target, Some(0x1000));
    assert_eq!(decoded[0].value, Some(0x20));
    assert_eq!(decoded[0].cr3, Some(0x12345000));
    assert_eq!(decoded[0].reg(RDI), Some(0x40));
}

#[test]
fn memory_overlap_on_reused_active_cell() {
    let records = vec![
        call(1, 0x400000, 0x1000, 0x10),
        nop(2, 0x400005, 0x5000),
        call(3, 0x400006, 0x1000, 0x10),
        nop(4, 0x40000b, 0x5000),
    ];
    let summary = run_qlt("overlap", &records);
    assert_eq!(summary["memory_overlaps"], 1);
}

#[test]
fn qlt_block_index_handles_multiple_blocks() {
    let mut records = Vec::new();
    for i in 0..80u64 {
        let mut r = TraceRecord::new(i + 1, 0x500000 + i, vec![0x90]);
        r.set_reg(RAX, i);
        records.push(r);
    }
    let dir = temp_dir("multi_block");
    let trace = dir.join("trace.qlt");
    let file = fs::File::create(&trace).unwrap();
    let mut writer = QltWriter::new(file).unwrap().with_block_size(64);
    for record in &records {
        writer.write_record(record).unwrap();
    }
    writer.finish().unwrap();
    let mut reader = a85_qlancet::qlt::QltReader::open(&trace).unwrap();
    let decoded = a85_qlancet::trace::TraceReader::read_all(&mut reader).unwrap();
    assert_eq!(decoded.len(), records.len());
    assert_eq!(decoded.first().unwrap().step, 1);
    assert_eq!(decoded.last().unwrap().step, 80);
}

#[test]
fn qlt_and_legacy_are_equivalent_for_invalid_free() {
    let dir = temp_dir("legacy_equiv");
    let config = write_config(&dir);
    let legacy = dir.join("trace.txt");
    fs::write(&legacy, "0|0x400000|call 0x1000|e8 00 00 00 00|regs: rdi=0x10\n0|0x400005|nop|90|regs: rax=0x5000\n0|0x400009|call 0x2000|e8 00 00 00 00|regs: rdi=0x5001\n0|0x40000e|nop|90|regs: rax=0x0\n").unwrap();
    let out = dir.join("out");
    a85_qlancet::run_klancet(
        &legacy,
        &config,
        &out,
        a85_qlancet::trace::TraceFormat::Legacy,
    )
    .unwrap();
    let summary: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("summary.json")).unwrap()).unwrap();
    assert_eq!(summary["invalid_frees"], 1);
}
