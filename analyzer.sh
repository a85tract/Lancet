#!/usr/bin/env bash
# Run the Rust analyzer on traces/configs produced by get_trace.sh.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
CALLER_PWD=$(pwd -P)

usage() {
  cat <<'USAGE'
Usage:
  ./analyzer.sh <case-name-or-dir> [out-dir]
  ./analyzer.sh <trace-path> <analyzer-config.json> [out-dir] [trace-format]

Examples:
  ./analyzer.sh cve39682
  ./analyzer.sh cve39682 out/cve39682-rerun
  ./analyzer.sh qemu_tcg/traces/cve39682.qlt \
    cases/cve39682/generated/mitigation-v4-6.6/analyzer_config.json \
    out/cve39682 qlt

Environment:
  TRACE_FORMAT=auto|qlt|legacy   Override detected/case trace format.
  REGENERATE_CONFIG=1            Regenerate case analyzer config from vmlinux.
  CARGO='cargo'                  Cargo command to use.
USAGE
}

die() {
  echo "error: $*" >&2
  exit 1
}

truthy() {
  case "${1,,}" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

abs_existing_file() {
  local p=$1
  [[ -f "$p" ]] || die "missing file: $p"
  readlink -f "$p"
}

abs_dir_allow_new() {
  local p=$1
  if [[ "$p" != /* ]]; then
    p="$CALLER_PWD/$p"
  fi
  mkdir -p "$p"
  (cd "$p" && pwd -P)
}

trace_format_from_path() {
  case "$1" in
    *.qlt) echo qlt ;;
    *) echo auto ;;
  esac
}

case "$#" in
  0) usage >&2; exit 2 ;;
esac
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

CASE_MODE=0
CASE_ARG=${1:-}
CASES_DIR=${CASES_DIR:-$ROOT_DIR/cases}

if [[ $# -eq 1 || ($# -eq 2 && ! -f "$CASE_ARG") ]]; then
  if [[ -d "$CASE_ARG" || -d "$CASES_DIR/$CASE_ARG" ]]; then
    CASE_MODE=1
  fi
fi

if [[ "$CASE_MODE" == "1" ]]; then
  if [[ -d "$CASE_ARG" ]]; then
    CASE_DIR=$(cd "$CASE_ARG" && pwd -P)
  else
    CASE_DIR=$(cd "$CASES_DIR/$CASE_ARG" && pwd -P)
  fi
  CASE_JSON=${CASE_CONFIG:-$CASE_DIR/config.json}
  [[ -f "$CASE_JSON" ]] || die "missing case config: $CASE_JSON"

  eval "$(
    python3 - "$CASE_JSON" "$CASE_DIR" "$ROOT_DIR" <<'PY'
import json
import os
import shlex
import sys

cfg_path, case_dir, root_dir = sys.argv[1:4]
with open(cfg_path, "r", encoding="utf-8") as f:
    cfg = json.load(f)

def first(*names, default=""):
    for name in names:
        if name in cfg and cfg[name] is not None:
            return cfg[name]
    return default

def path_value(value, base=case_dir):
    if value in (None, ""):
        return ""
    value = str(value)
    if os.path.isabs(value):
        return os.path.normpath(value)
    return os.path.normpath(os.path.join(base, value))

def ref_value(value):
    if value in (None, ""):
        return "kernelctf"
    value = str(value)
    if os.path.isabs(value) or value.startswith(".") or "/" in value:
        return path_value(value)
    return value

def truthy(value):
    return str(value).strip().lower() in ("1", "true", "yes", "y", "on")

def simulator_releases_dir(ref):
    manifest = ""
    if not ref:
        ref = "kernelctf"
    if os.path.isfile(os.path.join(root_dir, "simulators", ref, "config.json")):
        manifest = os.path.join(root_dir, "simulators", ref, "config.json")
    elif os.path.isfile(ref):
        manifest = ref
    elif os.path.isdir(ref):
        if os.path.isfile(os.path.join(ref, "config.json")):
            manifest = os.path.join(ref, "config.json")
        else:
            return os.path.abspath(os.path.join(ref, "releases"))
    if manifest:
        base = os.path.dirname(os.path.abspath(manifest))
        with open(manifest, "r", encoding="utf-8") as mf:
            sim = json.load(mf)
        releases = sim.get("releases") or sim.get("releases_dir")
        if releases:
            return path_value(releases, base)
    return os.path.join(root_dir, "simulators", "kernelctf", "releases")

case_name = first("name", default=os.path.basename(case_dir))
release = first("release", "linux_kernel_version", "kernel")
fmt = first("trace_format", "format", default="qlt")
auto_config = first("auto_config", default=True)

trace_path = first("trace_path", "out", "output")
if trace_path:
    trace_path = path_value(trace_path)
else:
    output_dir = path_value(first("output_dir", "trace_dir", default="out"))
    trace_name = first("trace", "trace_name", default=f"{case_name}.{fmt}")
    trace_path = os.path.normpath(os.path.join(output_dir, str(trace_name)))

analyzer_config = path_value(first("analyzer_config", "qlancet_config"))
if not analyzer_config and truthy(auto_config):
    analyzer_config = os.path.join(case_dir, "generated", str(release), "analyzer_config.json")

qemu_config = path_value(first("qemu_config", "qemu_output"))
if not qemu_config and truthy(auto_config):
    qemu_config = os.path.join(case_dir, "generated", str(release), "qemu_config.json")

analysis_out = path_value(first("analysis_output", "analysis_out", "analyzer_output", "analyzer_out", default=""))
if not analysis_out:
    stem = os.path.basename(trace_path)
    if "." in stem:
        stem = stem.rsplit(".", 1)[0]
    analysis_out = os.path.join(root_dir, "out", stem)

values = {
    "CASE_NAME": case_name,
    "RELEASE": release,
    "TRACE_FORMAT_CASE": fmt,
    "TRACE_PATH": trace_path,
    "ANALYZER_CONFIG": analyzer_config,
    "QEMU_CONFIG": qemu_config,
    "AUTO_CONFIG": "1" if truthy(auto_config) else "0",
    "OUT_DIR": analysis_out,
    "RELEASES_DIR": simulator_releases_dir(ref_value(first("simulator", "sim", "sim_dir", "simulator_dir"))),
}
for key, value in values.items():
    print(f"{key}={shlex.quote(str(value))}")
PY
  )"
  if [[ $# -eq 2 ]]; then
    OUT_DIR=$(abs_dir_allow_new "$2")
  fi
  TRACE_FORMAT=${TRACE_FORMAT:-$TRACE_FORMAT_CASE}
else
  [[ $# -ge 2 && $# -le 4 ]] || { usage >&2; exit 2; }
  TRACE_PATH=$(abs_existing_file "$1")
  ANALYZER_CONFIG=$(abs_existing_file "$2")
  if [[ $# -ge 3 ]]; then
    OUT_DIR=$(abs_dir_allow_new "$3")
  else
    stem=$(basename "$TRACE_PATH")
    stem=${stem%.*}
    OUT_DIR="$ROOT_DIR/out/$stem"
  fi
  TRACE_FORMAT=${4:-${TRACE_FORMAT:-$(trace_format_from_path "$TRACE_PATH")}}
  AUTO_CONFIG=0
fi

case "$TRACE_FORMAT" in
  auto|qlt|legacy|text)
    if [[ "$TRACE_FORMAT" == "text" ]]; then TRACE_FORMAT=legacy; fi
    ;;
  *) die "unsupported trace format: $TRACE_FORMAT" ;;
esac

[[ -f "$TRACE_PATH" ]] || die "missing trace: $TRACE_PATH (run ./get_trace.sh first)"

if [[ ! -f "$ANALYZER_CONFIG" ]]; then
  if [[ "$CASE_MODE" == "1" ]] && truthy "$AUTO_CONFIG"; then
    [[ -n "${RELEASE:-}" ]] || die "case config has no release; cannot regenerate analyzer config"
    [[ -n "${QEMU_CONFIG:-}" ]] || QEMU_CONFIG="$CASE_DIR/generated/$RELEASE/qemu_config.json"
    echo "[*] analyzer config missing; generating for $RELEASE"
    python3 "$ROOT_DIR/scripts/gen_config.py" \
      --kernel "$RELEASE" \
      --releases-dir "$RELEASES_DIR" \
      --qlancet-output "$ANALYZER_CONFIG" \
      --qemu-output "$QEMU_CONFIG"
  else
    die "missing analyzer config: $ANALYZER_CONFIG"
  fi
elif [[ "$CASE_MODE" == "1" && "${REGENERATE_CONFIG:-0}" == "1" ]]; then
  echo "[*] regenerating analyzer config for $RELEASE"
  python3 "$ROOT_DIR/scripts/gen_config.py" \
    --kernel "$RELEASE" \
    --releases-dir "$RELEASES_DIR" \
    --qlancet-output "$ANALYZER_CONFIG" \
    --qemu-output "$QEMU_CONFIG"
fi

mkdir -p "$OUT_DIR"

echo "[*] trace        : $TRACE_PATH"
echo "[*] config       : $ANALYZER_CONFIG"
echo "[*] output       : $OUT_DIR"
echo "[*] trace format : $TRACE_FORMAT"

cd "$ROOT_DIR"
exec ${CARGO:-cargo} run -- klancet "$TRACE_PATH" "$ANALYZER_CONFIG" "$OUT_DIR" --trace-format "$TRACE_FORMAT"
