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
        "vulnerability_types":["uninitializedread","outofboundsread","outofboundswrite","uafread","uafwrite","stackuseafterscoperead","stackuseafterscopewrite","doublefree","invalidfree","memoryoverlap","crossboundary","danglingptr","expiredptr","nullpointerdereference","untrustedptr"],
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

fn jmp_to_alloc(step: u64, pc: u64, target: u64, rdi: u64) -> TraceRecord {
    let mut r = TraceRecord::new(step, pc, vec![0xe9, 0, 0, 0, 0]);
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

fn mov_rcx_rbx(step: u64, pc: u64, rbx: u64, rcx: u64) -> TraceRecord {
    let mut r = TraceRecord::new(step, pc, vec![0x48, 0x89, 0xd9]);
    r.set_reg(RBX, rbx);
    r.set_reg(RCX, rcx);
    r
}

fn add_rbx_imm8(step: u64, pc: u64, rbx: u64, imm: u8) -> TraceRecord {
    let mut r = TraceRecord::new(step, pc, vec![0x48, 0x83, 0xc3, imm]);
    r.set_reg(RBX, rbx);
    r
}

fn sub_rsp_imm8(step: u64, pc: u64, rsp: u64, imm: u8) -> TraceRecord {
    let mut r = TraceRecord::new(step, pc, vec![0x48, 0x83, 0xec, imm]);
    r.set_reg(RSP, rsp);
    r
}

fn add_rsp_imm8(step: u64, pc: u64, rsp: u64, imm: u8) -> TraceRecord {
    let mut r = TraceRecord::new(step, pc, vec![0x48, 0x83, 0xc4, imm]);
    r.set_reg(RSP, rsp);
    r
}

fn lea_rax_rsp(step: u64, pc: u64, rsp: u64, rax: u64) -> TraceRecord {
    let mut r = TraceRecord::new(step, pc, vec![0x48, 0x8d, 0x04, 0x24]); // lea rax,[rsp]
    r.set_reg(RSP, rsp);
    r.set_reg(RAX, rax);
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

fn read_rbx(step: u64, pc: u64, rbx: u64) -> TraceRecord {
    let mut r = TraceRecord::new(step, pc, vec![0x8b, 0x03]); // mov eax,[rbx]
    r.set_reg(RBX, rbx);
    r
}

fn read_rax(step: u64, pc: u64, rax: u64) -> TraceRecord {
    let mut r = TraceRecord::new(step, pc, vec![0x8b, 0x00]); // mov eax, [rax]
    r.set_reg(RAX, rax);
    r
}

fn read_rsp(step: u64, pc: u64, rsp: u64) -> TraceRecord {
    let mut r = TraceRecord::new(step, pc, vec![0x48, 0x8b, 0x04, 0x24]); // mov rax,[rsp]
    r.set_reg(RSP, rsp);
    r
}

fn read_abs_rax(step: u64, pc: u64, addr: u64) -> TraceRecord {
    let mut r = TraceRecord::new(step, pc, vec![0x48, 0xa1, 0, 0, 0, 0, 0, 0, 0, 0]); // mov rax,moffs64
    r.bytecode[2..10].copy_from_slice(&addr.to_le_bytes());
    r
}

fn call_memset(step: u64, pc: u64, target: u64, dst: u64, len: u64) -> TraceRecord {
    let mut r = TraceRecord::new(step, pc, vec![0xe8, 0, 0, 0, 0]);
    r.branch_target = Some(target);
    r.set_reg(RDI, dst);
    r.set_reg(RDX, len);
    r
}

fn call_realloc(step: u64, pc: u64, target: u64, old: u64, size: u64) -> TraceRecord {
    let mut r = TraceRecord::new(step, pc, vec![0xe8, 0, 0, 0, 0]);
    r.branch_target = Some(target);
    r.set_reg(RDI, old);
    r.set_reg(RSI, size);
    r
}

fn call_calloc(step: u64, pc: u64, target: u64, nmemb: u64, size: u64) -> TraceRecord {
    let mut r = TraceRecord::new(step, pc, vec![0xe8, 0, 0, 0, 0]);
    r.branch_target = Some(target);
    r.set_reg(RDI, nmemb);
    r.set_reg(RSI, size);
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
fn value_size_masks_allocator_size() {
    let mut alloc = TraceRecord::new(1, 0x400000, vec![0xe8, 0, 0, 0, 0]);
    alloc.branch_target = Some(0x1000);
    alloc.value = Some(0x1_0000_0010);
    let records = vec![
        alloc,
        nop(2, 0x400005, 0x5000),
        read_rax(3, 0x400006, 0x5000),
    ];
    let summary = run_qlt_with_config(
        "value_size_mask",
        &records,
        r#"{
            "malloc_addrs":["0x1000"],
            "free_addrs":[],
            "vulnerability_types":["uninitializedread","outofboundsread"],
            "symbol_names":{
                "slab_alloc":{"addr":"0x1000","use_value_to_size":true,"value_size":4}
            }
        }"#,
    );
    assert_eq!(summary["out_of_bounds_reads"], 0);
    assert_eq!(summary["uninitialized_reads"], 1);
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
fn dangling_pointer_copy_after_free() {
    let records = vec![
        call(1, 0x400000, 0x1000, 0x10),
        nop(2, 0x400005, 0x5000),
        mov_rbx_rax(3, 0x400006, 0x5000, 0),
        mov_rdi_rax(4, 0x400009, 0x5000, 0),
        call(5, 0x40000c, 0x2000, 0x5000),
        nop(6, 0x400011, 0),
        mov_rcx_rbx(7, 0x400012, 0x5000, 0),
    ];
    let summary = run_qlt("dangling_copy", &records);
    assert_eq!(summary["dangling_pointers"], 1);
}

#[test]
fn expired_pointer_deref_after_pointer_leaves_freed_range() {
    let records = vec![
        call(1, 0x400000, 0x1000, 0x10),
        nop(2, 0x400005, 0x5000),
        mov_rbx_rax(3, 0x400006, 0x5000, 0),
        mov_rdi_rax(4, 0x400009, 0x5000, 0),
        call(5, 0x40000c, 0x2000, 0x5000),
        nop(6, 0x400011, 0),
        add_rbx_imm8(7, 0x400012, 0x5000, 0x20),
        read_rbx(8, 0x400016, 0x5020),
    ];
    let summary = run_qlt("expired_deref", &records);
    assert_eq!(summary["expired_pointer_dereferences"], 1);
    assert_eq!(summary["out_of_bounds_reads"], 0);
}

#[test]
fn stack_and_global_reads_are_modeled_subjects() {
    let records = vec![
        read_rsp(1, 0x400000, 0x7fff_ffff_f000),
        read_abs_rax(2, 0x400004, 0xffff_8880_0000_1000),
    ];
    let summary = run_qlt("static_subjects", &records);
    assert_eq!(summary["out_of_bounds_reads"], 0);
    assert_eq!(summary["uninitialized_reads"], 0);
}

#[test]
fn stack_use_after_scope_is_detected_after_rsp_restore() {
    let records = vec![
        sub_rsp_imm8(1, 0x400000, 0x7000, 0x20),
        lea_rax_rsp(2, 0x400004, 0x6fe0, 0x6fe0),
        add_rsp_imm8(3, 0x400008, 0x6fe0, 0x20),
        read_rax(4, 0x40000c, 0x6fe0),
    ];
    let summary = run_qlt("stack_after_scope", &records);
    assert_eq!(summary["stack_use_after_scope_reads"], 1);
    assert_eq!(summary["use_after_free_reads"], 0);
}

#[test]
fn heap_oob_into_unmodeled_cell_is_reported() {
    let records = vec![
        call(1, 0x400000, 0x1000, 0x10),
        nop(2, 0x400005, 0x5000),
        mov_rbx_rax(3, 0x400006, 0x5000, 0),
        read_rbx(4, 0x400009, 0x5010),
    ];
    let summary = run_qlt("heap_oob_unknown_cell", &records);
    assert_eq!(summary["out_of_bounds_reads"], 1);
}

#[test]
fn unknown_owner_dereference_is_untrusted_ptr() {
    let records = vec![read_abs_rax(1, 0x400000, 0x0040_0000)];
    let summary = run_qlt("untrusted_unknown", &records);
    assert_eq!(summary["untrusted_ptrs"], 1);
}

#[test]
fn memset_summary_marks_heap_bytes_initialized() {
    let records = vec![
        call(1, 0x400000, 0x1000, 0x8),
        nop(2, 0x400005, 0x5000),
        call_memset(3, 0x400006, 0x3000, 0x5000, 0x8),
        read_rax(4, 0x40000b, 0x5000),
    ];
    let summary = run_qlt_with_config(
        "memset_summary",
        &records,
        r#"{
            "malloc_addrs":["0x1000"],
            "free_addrs":[],
            "vulnerability_types":["uninitializedread","outofboundswrite","untrustedptr"],
            "symbol_names":{
                "malloc":{"addr":"0x1000","import_reg":"rdi"},
                "memset":{"addr":"0x3000"}
            }
        }"#,
    );
    assert_eq!(summary["uninitialized_reads"], 0);
    assert_eq!(summary["out_of_bounds_writes"], 0);
    assert_eq!(summary["untrusted_ptrs"], 0);
}

#[test]
fn realloc_invalidates_old_alias_even_when_address_is_reused() {
    let records = vec![
        call(1, 0x400000, 0x1000, 0x10),
        nop(2, 0x400005, 0x5000),
        mov_rbx_rax(3, 0x400006, 0x5000, 0),
        mov_rdi_rax(4, 0x400009, 0x5000, 0),
        call_realloc(5, 0x40000c, 0x3000, 0x5000, 0x20),
        nop(6, 0x400011, 0x5000),
        write_ptr(7, 0x400012, RBX, 0x5000),
    ];
    let summary = run_qlt_with_config(
        "realloc_alias",
        &records,
        r#"{
            "malloc_addrs":["0x1000"],
            "free_addrs":[],
            "vulnerability_types":["uafwrite","outofboundswrite"],
            "symbol_names":{
                "malloc":{"addr":"0x1000","import_reg":"rdi"},
                "realloc":{"addr":"0x3000"}
            }
        }"#,
    );
    assert_eq!(summary["use_after_free_writes"], 1);
    assert_eq!(summary["out_of_bounds_writes"], 0);
}

#[test]
fn calloc_uses_product_size_and_zero_initializes() {
    let records = vec![
        call_calloc(1, 0x400000, 0x3000, 2, 8),
        nop(2, 0x400005, 0x5000),
        read_rax(3, 0x400006, 0x5008),
    ];
    let summary = run_qlt_with_config(
        "calloc_product",
        &records,
        r#"{
            "malloc_addrs":[],
            "free_addrs":[],
            "vulnerability_types":["uninitializedread","outofboundsread"],
            "symbol_names":{"calloc":{"addr":"0x3000"}}
        }"#,
    );
    assert_eq!(summary["out_of_bounds_reads"], 0);
    assert_eq!(summary["uninitialized_reads"], 0);
}

#[test]
fn page_allocator_uaf_is_detected() {
    let mut alloc = TraceRecord::new(1, 0x400000, vec![0xe8, 0, 0, 0, 0]);
    alloc.branch_target = Some(0x3000);
    alloc.set_reg(RSI, 0);
    let mut ret = nop(2, 0x400005, 0xffff_ea00_0000_0000);
    ret.set_reg(RAX, 0xffff_ea00_0000_0000);
    let mut free = TraceRecord::new(3, 0x400006, vec![0xe8, 0, 0, 0, 0]);
    free.branch_target = Some(0x4000);
    free.set_reg(RDI, 0xffff_ea00_0000_0000);
    free.set_reg(RSI, 0);
    let mut after = nop(4, 0x40000b, 0);
    after.set_reg(RAX, 0);
    let mut read = read_rax(5, 0x40000c, 0xffff_8880_0000_0000);
    read.set_reg(RAX, 0xffff_8880_0000_0000);
    let summary = run_qlt_with_config(
        "page_uaf",
        &[alloc, ret, free, after, read],
        r#"{
            "malloc_addrs":[],
            "free_addrs":[],
            "vulnerability_types":["uafread"],
            "page_allocator":{"vmemmap_start":"0xffffea0000000000","page_offset_base":"0xffff888000000000"},
            "symbol_names":{
                "alloc_pages":{"addr":"0x3000"},
                "free_pages":{"addr":"0x4000"}
            }
        }"#,
    );
    assert_eq!(summary["use_after_free_reads"], 1);
}

#[test]
fn skip_return_range_applies_tail_call_allocation() {
    let records = vec![
        jmp_to_alloc(1, 0x400000, 0x1000, 0x10),
        nop(2, 0x400010, 0x5000),
        read_rax(3, 0x400011, 0x5000),
    ];
    let summary = run_qlt_with_config(
        "skip_return_alloc",
        &records,
        r#"{
            "malloc_addrs":["0x1000"],
            "free_addrs":[],
            "vulnerability_types":["uninitializedread"],
            "skip_addrs":[{"malloc":{"start_addr":"0x1000","ret_addr":"0x400010"}}],
            "symbol_names":{"malloc":{"addr":"0x1000","import_reg":"rdi"}}
        }"#,
    );
    assert_eq!(summary["uninitialized_reads"], 1);
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
fn missing_address_register_skips_unresolved_memory_operand() {
    let record = TraceRecord::new(1, 0x400000, vec![0x48, 0x8b, 0x04, 0x24]); // mov rax,[rsp]
    let summary = run_qlt("missing_addr_reg", &[record]);
    assert_eq!(summary["ownership_violations"], 0);
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
