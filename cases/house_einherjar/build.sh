#!/usr/bin/env bash
set -euo pipefail

: "${EXP_IN:?missing EXP_IN}"
: "${EXP_OUT:?missing EXP_OUT}"

gcc -static -no-pie -O0 -g -fno-stack-protector -fno-omit-frame-pointer \
  "$EXP_IN" -o "$EXP_OUT"
chmod +x "$EXP_OUT"

case_dir=/work/a85/cases/house_einherjar
gen_dir="$case_dir/generated/user"
mkdir -p "$gen_dir"
cp "$EXP_OUT" "$gen_dir/exp"
nm -n "$EXP_OUT" > "$gen_dir/exp.nm"

python3 - "$gen_dir/exp.nm" "$gen_dir/analyzer_config.json" <<'PY'
import json
import sys
from pathlib import Path

nm_path = Path(sys.argv[1])
out_path = Path(sys.argv[2])
symbols = {}
for line in nm_path.read_text(encoding="utf-8", errors="replace").splitlines():
    parts = line.split()
    if len(parts) >= 3:
        try:
            symbols[parts[2]] = int(parts[0], 16)
        except ValueError:
            pass

malloc_name = "ql_malloc" if "ql_malloc" in symbols else "malloc"
free_name = "ql_free" if "ql_free" in symbols else "free"
required = [malloc_name, free_name]
missing = [name for name in required if name not in symbols]
if missing:
    raise SystemExit("missing symbols: " + ", ".join(missing))

fmt = lambda value: f"0x{value:016x}"
config = {
    "malloc_addrs": [fmt(symbols[malloc_name])],
    "free_addrs": [fmt(symbols[free_name])],
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
        malloc_name: {"addr": fmt(symbols[malloc_name]), "import_reg": "rdi"},
        free_name: {"addr": fmt(symbols[free_name]), "import_reg": "rdi"},
    },
    "metadata": {
        "binary": "cases/house_einherjar/generated/user/exp",
        "source_roots": ["cases/house_einherjar"],
    },
}
out_path.write_text(json.dumps(config, indent=4) + "\n", encoding="utf-8")
print(f"[house_einherjar build] wrote {out_path}")
PY
