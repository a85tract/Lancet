#!/usr/bin/env bash
set -euo pipefail

: "${EXP_IN:?missing EXP_IN}"
: "${EXP_OUT:?missing EXP_OUT}"

if [[ -n "${GLIBC_VERSION:-}" ]]; then
  source /work/a85/scripts/glibc_aio.sh
  compile_c_with_glibc "$EXP_IN" "$EXP_OUT" "$GLIBC_VERSION" \
    -no-pie -O0 -g -fno-stack-protector -fno-omit-frame-pointer
else
  gcc -static -no-pie -O0 -g -fno-stack-protector -fno-omit-frame-pointer \
    "$EXP_IN" -o "$EXP_OUT"
fi
chmod +x "$EXP_OUT"

case_dir=/work/a85/cases/fastbin_reverse_into_tcache
gen_dir="$case_dir/generated/user"
mkdir -p "$gen_dir"
cp "$EXP_OUT" "$gen_dir/exp"
nm -n "$EXP_OUT" > "$gen_dir/exp.nm" || true
objdump -d "$EXP_OUT" > "$gen_dir/exp.objdump" || true
readelf -W -l "$EXP_OUT" > "$gen_dir/exp.readelf" || true

python3 - "$gen_dir/exp.nm" "$gen_dir/exp.objdump" "$gen_dir/exp.readelf" "$gen_dir/analyzer_config.json" <<'PY'
import json
import re
import sys
from pathlib import Path

nm_path = Path(sys.argv[1])
objdump_path = Path(sys.argv[2])
readelf_path = Path(sys.argv[3])
out_path = Path(sys.argv[4])
symbols = {}
for line in nm_path.read_text(encoding="utf-8", errors="replace").splitlines():
    parts = line.split()
    if len(parts) >= 3:
        try:
            symbols[parts[2]] = int(parts[0], 16)
        except ValueError:
            pass

plt = {}
label_re = re.compile(r"^\s*([0-9a-fA-F]+)\s+<([^>]+)>:")
for line in objdump_path.read_text(encoding="utf-8", errors="replace").splitlines():
    m = label_re.match(line)
    if not m:
        continue
    addr = int(m.group(1), 16)
    label = m.group(2)
    base = label.split("@", 1)[0]
    if "@plt" in label:
        plt.setdefault(base, addr)

def resolve_func(name):
    if name in symbols and symbols[name] != 0:
        return symbols[name]
    if f"__libc_{name}" in symbols and symbols[f"__libc_{name}"] != 0:
        return symbols[f"__libc_{name}"]
    if name in plt:
        return plt[name]
    raise SystemExit(f"missing function/PLT symbol: {name}")

malloc_addr = resolve_func("malloc")
free_addr = resolve_func("free")
memset_addr = resolve_func("memset")
fmt = lambda value: f"0x{value:016x}"

loads = []
for line in readelf_path.read_text(encoding="utf-8", errors="replace").splitlines():
    parts = line.split()
    if len(parts) >= 6 and parts[0] == "LOAD":
        try:
            vaddr = int(parts[2], 16)
            memsz = int(parts[5], 16)
        except ValueError:
            continue
        if memsz:
            loads.append((vaddr, vaddr + memsz))

config = {
    "malloc_addrs": [fmt(malloc_addr)],
    "free_addrs": [fmt(free_addr)],
    "vulnerability_types": [
        "uninitializedread",
        "uafread",
        "uafwrite",
        "doublefree",
        "invalidfree",
        "outofboundsread",
        "outofboundswrite",
        "memoryoverlap",
        "danglingptr",
        "crossboundary",
        "expiredptr",
        "nullpointerdereference",
        "untrustedptr",
        "stackuseafterscoperead",
        "stackuseafterscopewrite",
    ],
    "symbol_names": {
        "malloc": {"addr": fmt(malloc_addr), "import_reg": "rdi"},
        "free": {"addr": fmt(free_addr), "import_reg": "rdi"},
        "memset": {"addr": fmt(memset_addr)},
    },
    "metadata": {
        "binary": "cases/fastbin_reverse_into_tcache/generated/user/exp",
        "source_roots": ["cases/fastbin_reverse_into_tcache"],
    },
}
if loads:
    module_base = min(start for start, _ in loads)
    module_end = max(end for _, end in loads)
    config["ctf_mode"] = True
    config["module_base"] = fmt(module_base)
    config["module_size"] = fmt(module_end - module_base)
out_path.write_text(json.dumps(config, indent=4) + "\n", encoding="utf-8")
print(f"[fastbin_reverse_into_tcache build] malloc={fmt(malloc_addr)} free={fmt(free_addr)}")
if loads:
    print(f"[fastbin_reverse_into_tcache build] module={fmt(module_base)}+{fmt(module_end - module_base)}")
print(f"[fastbin_reverse_into_tcache build] wrote {out_path}")
PY
