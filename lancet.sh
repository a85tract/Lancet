#!/usr/bin/env bash
# Unified QLancet entrypoint: collect traces and run the analyzer.
#
# Common usage:
#   ./lancet.sh <case-name-or-dir> [trace-path]          # collect + analyze
#   TRACE_ONLY=1 ./lancet.sh <case-name-or-dir>          # collect only
#   ./lancet.sh analyze <case-name-or-dir> [out-dir]     # analyze existing trace
#   ./lancet.sh user <case-or-exp.c> <trace-path> [...]  # direct user-mode collection
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)

list_supported_cases_unified() {
  local cases_dir=${CASES_DIR:-$ROOT_DIR/cases}
  if [[ -f "$ROOT_DIR/scripts/list_cases.py" ]]; then
    python3 "$ROOT_DIR/scripts/list_cases.py" "$cases_dir" "$ROOT_DIR" || true
  else
    echo "Supported cases:"
    find "$cases_dir" -mindepth 2 -maxdepth 2 -name config.json -printf '  %h\n' 2>/dev/null | sed "s#^  $cases_dir/#  #" || true
  fi
}

usage_unified() {
  cat <<'USAGE'
Usage:
  ./lancet.sh <case-name-or-dir> [trace-path]
  ./lancet.sh <linux-kernel-version> <trace-format> <exp-path> <trace-path> [sim-dir]
  ./lancet.sh analyze <case-name-or-dir> [out-dir]
  ./lancet.sh analyze <trace-path> <analyzer-config.json> [out-dir] [trace-format]
  ./lancet.sh user <case-name-or-dir> [trace-path]
  ./lancet.sh user <exp.c-or-bin> <trace-path> [start-symbol] [stop-symbol]

Default mode collects a trace and, for case runs, analyzes it immediately.
Use TRACE_ONLY=1 or ANALYZE=0 to skip the analyzer step. Use ANALYSIS_OUT=...
to override the analyzer output directory.

Subcommands:
  analyze       Rerun only the Rust analyzer on an existing trace/config.
  user          Direct user-mode trace collection via qemu-x86_64.
  collect/trace Explicit alias for the default collect + analyze mode.

Important environment overrides:
  IMAGE=a85_qlancet_qemu
  BUILD_IMAGE=auto|1|0
  DOCKER_PLATFORM=linux/amd64
  REQUIRED_IMAGE_REV=20260617-ql-user-binutils-v2
  GLIBC_AIO_RUNTIME_INSTALL=1   Allow one-off dependency install in stale images.
USAGE
  echo
  list_supported_cases_unified
}

cmd_analyze() (
# Run the Rust analyzer on traces/configs produced by lancet.sh.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
CALLER_PWD=$(pwd -P)

list_supported_cases() {
  local cases_dir=${CASES_DIR:-$ROOT_DIR/cases}
  if [[ -f "$ROOT_DIR/scripts/list_cases.py" ]]; then
    python3 "$ROOT_DIR/scripts/list_cases.py" "$cases_dir" "$ROOT_DIR" || true
  else
    echo "Supported cases:"
    find "$cases_dir" -mindepth 2 -maxdepth 2 -name config.json -printf '  %h\n' 2>/dev/null | sed "s#^  $cases_dir/#  #" || true
  fi
}

usage() {
  cat <<'USAGE'
Usage:
  ./lancet.sh analyze <case-name-or-dir> [out-dir]
  ./lancet.sh analyze <trace-path> <analyzer-config.json> [out-dir] [trace-format]

Examples:
  ./lancet.sh analyze house_einherjar
  ./lancet.sh analyze house_einherjar out/house_einherjar-rerun
  ./lancet.sh analyze qemu_tcg/traces/house_einherjar.qlt \
    cases/house_einherjar/generated/user/analyzer_config.json \
    out/house_einherjar qlt

Environment:
  TRACE_FORMAT=auto|qlt|legacy   Override detected/case trace format.
  REGENERATE_CONFIG=1            Regenerate case analyzer config from vmlinux.
  CARGO='cargo'                  Cargo command to use.
USAGE
  echo
  list_supported_cases
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
    "PLUGIN_MODE": first("plugin_mode", default=""),
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

collect_hint() {
  if [[ "${CASE_MODE:-0}" == "1" ]]; then
    if [[ "${PLUGIN_MODE:-}" == "user" ]]; then
      printf "run ./lancet.sh user '%s' first" "$CASE_ARG"
    else
      printf "run ./lancet.sh '%s' first" "$CASE_ARG"
    fi
  else
    printf "regenerate or recollect the trace"
  fi
}

validate_qlt_trace() {
  local trace=$1
  python3 - "$trace" <<'PY'
import os
import struct
import sys

path = sys.argv[1]
size = os.path.getsize(path)
if size < 36:
    raise SystemExit(
        f"trace '{path}' is only {size} bytes; QLT header is incomplete"
    )

with open(path, "rb") as f:
    header = f.read(36)
if header[:4] != b"QLT1":
    raise SystemExit(f"trace '{path}' does not start with QLT1 magic")

version, _flags, _regtab, _reserved = struct.unpack_from("<HHHH", header, 4)
blocks, index_off, header_size = struct.unpack_from("<QQQ", header, 12)
if header_size != 36:
    raise SystemExit(f"trace '{path}' has unexpected QLT header size {header_size}")
if version not in (1, 2):
    raise SystemExit(f"trace '{path}' has unsupported QLT version {version}")
if blocks == 0:
    raise SystemExit(f"trace '{path}' has no completed QLT blocks")
index_end = index_off + blocks * 40
if index_off > size or index_end > size:
    raise SystemExit(
        f"trace '{path}' has incomplete QLT index: index_end={index_end}, file_size={size}"
    )

with open(path, "rb") as f:
    f.seek(index_off)
    for i in range(blocks):
        data = f.read(40)
        if len(data) != 40:
            raise SystemExit(f"trace '{path}' ended inside QLT index entry {i}")
        comp_off, comp_size, _uncomp_size, _first_step, record_count = struct.unpack("<QQQQQ", data)
        if comp_off + comp_size > index_off:
            raise SystemExit(
                f"trace '{path}' has incomplete QLT data block {i}: "
                f"data_end={comp_off + comp_size}, index_off={index_off}"
            )
        if record_count == 0:
            raise SystemExit(f"trace '{path}' has empty QLT data block {i}")
PY
}

case "$TRACE_FORMAT" in
  auto|qlt|legacy|text)
    if [[ "$TRACE_FORMAT" == "text" ]]; then TRACE_FORMAT=legacy; fi
    ;;
  *) die "unsupported trace format: $TRACE_FORMAT" ;;
esac

[[ -f "$TRACE_PATH" ]] || die "missing trace: $TRACE_PATH ($(collect_hint))"

if [[ "$TRACE_FORMAT" == "qlt" || ( "$TRACE_FORMAT" == "auto" && "$TRACE_PATH" == *.qlt ) ]]; then
  if ! qlt_error=$(validate_qlt_trace "$TRACE_PATH" 2>&1); then
    die "$qlt_error; $(collect_hint)"
  fi
fi

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
)

cmd_user_trace() (
# Fast user-mode QEMU trace collector. It mirrors lancet.sh's Docker/plugin
# build flow but runs qemu-x86_64 instead of booting a full kernel simulator.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
CALLER_PWD=$(pwd -P)

usage() {
  cat <<'USAGE'
Usage:
  ./lancet.sh user <case-name-or-dir> [trace-path]
  ./lancet.sh user <exp.c-or-bin> <trace-path> [start-symbol] [stop-symbol]

Environment:
  IMAGE=a85_qlancet_qemu      Docker image containing qemu-x86_64 with plugins.
  BUILD_IMAGE=auto|1|0        Build Dockerfile if image is missing.
  DOCKER_PLATFORM=linux/amd64 Optional platform for docker build/run.
  TIMEOUT=120                 qemu-x86_64 timeout seconds.
  START_SYMBOL=name           Trigger symbol for case/direct mode.
  STOP_SYMBOL=name            Optional stop symbol for bounded traces.
  GLIBC_VERSION=2.32-0ubuntu3_amd64
                               Patch dynamic PoCs to this glibc-all-in-one id.
  EXTRA_PLUGIN_ARGS='...'     Extra plugin args appended after defaults.
USAGE
}

die() { echo "error: $*" >&2; exit 1; }
truthy() { case "${1,,}" in 1|true|yes|y|on) return 0;; *) return 1;; esac; }
abs_file() { local p=$1; [[ -e "$p" ]] || die "missing path: $p"; readlink -f "$p"; }

if [[ ${1:-} == "-h" || ${1:-} == "--help" || $# -lt 1 ]]; then
  usage
  exit $([[ $# -lt 1 ]] && echo 2 || echo 0)
fi

CASE_MODE=0
CASE_ARG=$1
CASES_DIR=${CASES_DIR:-$ROOT_DIR/cases}
EXP_PATH=""
TRACE_PATH=""
BUILD_REL=""
ANALYZER_CONFIG=""

if [[ $# -le 2 && ( -d "$CASE_ARG" || -d "$CASES_DIR/$CASE_ARG" ) ]]; then
  CASE_MODE=1
  if [[ -d "$CASE_ARG" ]]; then CASE_DIR=$(cd "$CASE_ARG" && pwd -P); else CASE_DIR=$(cd "$CASES_DIR/$CASE_ARG" && pwd -P); fi
  CASE_JSON=${CASE_CONFIG:-$CASE_DIR/config.json}
  [[ -f "$CASE_JSON" ]] || die "missing case config: $CASE_JSON"
  eval "$(python3 - "$CASE_JSON" "$CASE_DIR" <<'PY'
import json, os, shlex, sys
cfg_path, case_dir = sys.argv[1:3]
cfg = json.load(open(cfg_path, encoding='utf-8'))
def first(*names, default=''):
    for name in names:
        v = cfg.get(name)
        if v not in (None, ''):
            return v
    return default
def path_value(v):
    if v in (None, ''): return ''
    v = str(v)
    return os.path.normpath(v if os.path.isabs(v) else os.path.join(case_dir, v))
name = first('name', default=os.path.basename(case_dir))
fmt = first('trace_format', 'format', default='qlt')
exp = first('exp', 'exp_path', 'poc')
if not exp:
    for cand in ('exp.c', 'poc.c', 'exp'):
        if os.path.exists(os.path.join(case_dir, cand)):
            exp = cand; break
if not exp: raise SystemExit('case config requires exp or exp.c')
trace = first('trace_path', 'out', 'output')
if trace: trace = path_value(trace)
else:
    outdir = path_value(first('output_dir', 'trace_dir', default='out'))
    trace = os.path.normpath(os.path.join(outdir, first('trace', 'trace_name', default=f'{name}.{fmt}')))
build = first('build', 'build_script')
build_rel = ''
if build:
    bp = path_value(build)
    build_rel = os.path.relpath(bp, os.path.dirname(path_value(exp)))
vals = {
 'EXP_PATH': path_value(exp),
 'TRACE_PATH': trace,
 'BUILD_REL': build_rel,
 'START_SYMBOL_CASE': first('start_symbol', 'trigger_symbol', default='main'),
 'STOP_SYMBOL_CASE': first('stop_symbol', default=''),
 'ANALYZER_CONFIG': path_value(first('analyzer_config', 'qlancet_config')),
 'GLIBC_VERSION_CASE': first('glibc_version', 'glibc', default=''),
 'TIMEOUT_CASE': first('timeout', default=''),
 'EXTRA_PLUGIN_ARGS_CASE': first('extra_plugin_args', default=''),
}
for k,v in vals.items(): print(f'{k}={shlex.quote(str(v))}')
PY
)"
  if [[ $# -eq 2 ]]; then TRACE_PATH=$2; fi
  START_SYMBOL=${START_SYMBOL:-$START_SYMBOL_CASE}
  STOP_SYMBOL=${STOP_SYMBOL:-$STOP_SYMBOL_CASE}
  GLIBC_VERSION=${GLIBC_VERSION:-$GLIBC_VERSION_CASE}
  TIMEOUT=${TIMEOUT:-${TIMEOUT_CASE:-120}}
  EXTRA_PLUGIN_ARGS=${EXTRA_PLUGIN_ARGS:-${EXTRA_PLUGIN_ARGS_CASE:-}}
else
  [[ $# -ge 2 && $# -le 4 ]] || { usage >&2; exit 2; }
  EXP_PATH=$(abs_file "$1")
  TRACE_PATH=$2
  START_SYMBOL=${START_SYMBOL:-${3:-main}}
  STOP_SYMBOL=${STOP_SYMBOL:-${4:-}}
  GLIBC_VERSION=${GLIBC_VERSION:-}
  TIMEOUT=${TIMEOUT:-120}
  EXTRA_PLUGIN_ARGS=${EXTRA_PLUGIN_ARGS:-}
fi

if [[ "$TRACE_PATH" != /* ]]; then TRACE_PATH="$CALLER_PWD/$TRACE_PATH"; fi
TRACE_DIR=$(dirname "$TRACE_PATH")
TRACE_BASE=$(basename "$TRACE_PATH")
mkdir -p "$TRACE_DIR"
TRACE_DIR=$(cd "$TRACE_DIR" && pwd -P)
TRACE_PATH="$TRACE_DIR/$TRACE_BASE"
EXP_PATH=$(abs_file "$EXP_PATH")
EXP_DIR=$(dirname "$EXP_PATH")
EXP_BASE=$(basename "$EXP_PATH")

IMAGE=${IMAGE:-a85_qlancet_qemu}
BUILD_IMAGE=${BUILD_IMAGE:-auto}
DOCKERFILE=${DOCKERFILE:-$ROOT_DIR/Dockerfile}
DOCKER_PLATFORM=${DOCKER_PLATFORM:-${DOCKER_DEFAULT_PLATFORM:-}}
REQUIRED_IMAGE_REV=${REQUIRED_IMAGE_REV:-20260617-ql-user-binutils-v2}
CONTAINER_NAME=${CONTAINER_NAME:-a85_get_user_trace_$(date +%s)_$$}
DOCKER_NETWORK=${DOCKER_NETWORK:-}
if [[ -z "$DOCKER_NETWORK" ]]; then
  if [[ -n "$GLIBC_VERSION" ]]; then
    DOCKER_NETWORK=bridge
  else
    DOCKER_NETWORK=none
  fi
fi
if command -v docker >/dev/null 2>&1; then DOCKER_CMD=(docker); elif command -v sudo >/dev/null 2>&1; then DOCKER_CMD=(sudo docker); else die "docker not found"; fi
NEED_BUILD=0
if [[ "$BUILD_IMAGE" == "1" ]]; then
  NEED_BUILD=1
elif [[ "$BUILD_IMAGE" == "auto" ]]; then
  if ! "${DOCKER_CMD[@]}" image inspect "$IMAGE" >/dev/null 2>&1; then
    NEED_BUILD=1
  else
    if [[ -n "$REQUIRED_IMAGE_REV" && "$REQUIRED_IMAGE_REV" != "skip" ]]; then
      image_rev=$("${DOCKER_CMD[@]}" image inspect --format '{{index .Config.Labels "org.a85.qlancet.image-rev"}}' "$IMAGE" 2>/dev/null || true)
      if [[ "$image_rev" != "$REQUIRED_IMAGE_REV" ]]; then
        echo "[*] Docker image $IMAGE is stale (rev=${image_rev:-<none>}, need=$REQUIRED_IMAGE_REV); rebuilding"
        NEED_BUILD=1
      fi
    fi
    if [[ -n "$DOCKER_PLATFORM" ]]; then
      image_platform=$("${DOCKER_CMD[@]}" image inspect --format '{{.Os}}/{{.Architecture}}' "$IMAGE" 2>/dev/null || true)
      case "$DOCKER_PLATFORM" in
        "$image_platform"|"$image_platform"/*) ;;
        *) NEED_BUILD=1 ;;
      esac
    fi
  fi
fi
DOCKER_PLATFORM_ARGS=()
if [[ -n "$DOCKER_PLATFORM" ]]; then
  DOCKER_PLATFORM_ARGS=(--platform "$DOCKER_PLATFORM")
fi
if [[ "$NEED_BUILD" == "1" ]]; then
  echo "[*] building Docker image $IMAGE from $DOCKERFILE"
  "${DOCKER_CMD[@]}" build "${DOCKER_PLATFORM_ARGS[@]}" -t "$IMAGE" -f "$DOCKERFILE" "$ROOT_DIR"
fi

cleanup() { "${DOCKER_CMD[@]}" rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

echo "[*] exp          : $EXP_PATH"
echo "[*] start symbol : ${START_SYMBOL:-<none>}"
echo "[*] stop symbol  : ${STOP_SYMBOL:-<none>}"
echo "[*] glibc        : ${GLIBC_VERSION:-<system/static>}"
echo "[*] output       : $TRACE_PATH"
echo "[*] docker image : $IMAGE"
if [[ -n "$DOCKER_PLATFORM" ]]; then
  echo "[*] docker plat  : $DOCKER_PLATFORM"
fi

GLIBC_AIO_HOST_CACHE=${GLIBC_AIO_HOST_CACHE:-$ROOT_DIR/.cache/glibc-all-in-one}
if [[ -n "$GLIBC_VERSION" ]]; then
  mkdir -p "$GLIBC_AIO_HOST_CACHE"
fi

DOCKER_ARGS=(
  run --rm -i
  "${DOCKER_PLATFORM_ARGS[@]}"
  --name "$CONTAINER_NAME"
  --network "$DOCKER_NETWORK"
  --security-opt seccomp=unconfined
  -v "$ROOT_DIR":/work/a85
  -v "$EXP_DIR":/inputs/exp_dir:ro
  -v "$TRACE_DIR":/out
  -e EXP_BASE="$EXP_BASE"
  -e OUT_BASE="$TRACE_BASE"
  -e START_SYMBOL="${START_SYMBOL:-}"
  -e STOP_SYMBOL="${STOP_SYMBOL:-}"
  -e GLIBC_VERSION="${GLIBC_VERSION:-}"
  -e TIMEOUT="$TIMEOUT"
  -e BUILD_REL="$BUILD_REL"
  -e EXP_BUILD_CMD="${EXP_BUILD_CMD:-}"
  -e EXTRA_PLUGIN_ARGS="$EXTRA_PLUGIN_ARGS"
)
if [[ -n "$GLIBC_VERSION" ]]; then
  DOCKER_ARGS+=(-v "$GLIBC_AIO_HOST_CACHE":/opt/glibc-all-in-one -e GLIBC_AIO_DIR=/opt/glibc-all-in-one)
fi

"${DOCKER_CMD[@]}" "${DOCKER_ARGS[@]}" "$IMAGE" bash -s <<'IN_CONTAINER'
set -euo pipefail
cd /work/a85/qemu_tcg
./build.sh

source /work/a85/scripts/target_x86_64.sh
setup_x86_64_target_toolchain

EXP_IN="/inputs/exp_dir/$EXP_BASE"
EXP_OUT="/tmp/ql_user_exp"
if [[ -n "${EXP_BUILD_CMD:-}" ]]; then
  export EXP_IN EXP_OUT
  eval "$EXP_BUILD_CMD"
elif [[ -n "${BUILD_REL:-}" ]]; then
  build_exec="$BUILD_REL"
  [[ "$build_exec" == */* ]] || build_exec="./$build_exec"
  export EXP_IN EXP_OUT
  cd "$(dirname "$EXP_IN")"
  bash "$build_exec"
  cd /work/a85/qemu_tcg
else
  case "$EXP_IN" in
    *.c)
      if [[ -n "${GLIBC_VERSION:-}" ]]; then
        source /work/a85/scripts/glibc_aio.sh
        compile_c_with_glibc "$EXP_IN" "$EXP_OUT" "$GLIBC_VERSION" \
          -no-pie -O0 -g -fno-stack-protector -fno-omit-frame-pointer
      else
        "$TARGET_CC" -static -no-pie -O0 -g -fno-stack-protector -fno-omit-frame-pointer "$EXP_IN" -o "$EXP_OUT"
      fi
      ;;
    *) cp "$EXP_IN" "$EXP_OUT" ;;
  esac
fi
validate_x86_64_elf "$EXP_OUT" "PoC"
chmod +x "$EXP_OUT"
if [[ -n "${GLIBC_VERSION:-}" ]]; then
  source /work/a85/scripts/glibc_aio.sh
  patch_elf_to_glibc "$EXP_OUT" "$GLIBC_VERSION"
  validate_x86_64_elf "$EXP_OUT" "patched PoC"
fi

resolve_sym() {
  local sym=$1
  if [[ "$sym" == *:return ]]; then
    local func=${sym%:return}
    objdump -d "$EXP_OUT" 2>/dev/null | awk -v sym="$func" '
      $0 ~ "^[[:space:]]*[0-9a-fA-F]+[[:space:]]+<" sym ">:" {inside=1; next}
      inside && $0 ~ "^[[:space:]]*[0-9a-fA-F]+[[:space:]]+<[^>]+>:" {exit}
      inside && $0 ~ /[[:space:]]ret[q]?[[:space:]]*$/ {
        addr=$1
        sub(":", "", addr)
        last=addr
      }
      END {
        if (last != "") {
          print "0x" last
          exit 0
        }
        exit 1
      }'
    return
  fi
  nm "$EXP_OUT" 2>/dev/null | awk -v sym="$sym" '$2 ~ /^[Tt]$/ && $3 == sym {print "0x"$1; found=1} END {exit found ? 0 : 1}'
}
START_ADDR=""
if [[ -n "${START_SYMBOL:-}" ]]; then START_ADDR=$(resolve_sym "$START_SYMBOL"); else START_ADDR=$(resolve_sym main); fi
STOP_ADDR=""
if [[ -n "${STOP_SYMBOL:-}" ]]; then STOP_ADDR=$(resolve_sym "$STOP_SYMBOL"); fi

echo "[container] START_ADDR=$START_ADDR STOP_ADDR=${STOP_ADDR:-}"
nm -n "$EXP_OUT" 2>/dev/null | grep -E ' main$| ql_trace_start$| ql_trace_stop$| malloc$| free$' || true

PLUGIN_ARG="format=qlt,out=/out/$OUT_BASE,trigger=$START_ADDR,regs=insn,onlycpu=0,mode=user,trigger-mode=user,block-mb=4,zstd=1"
if [[ -n "$STOP_ADDR" ]]; then PLUGIN_ARG+=",stop=$STOP_ADDR"; fi
if [[ -n "${EXTRA_PLUGIN_ARGS:-}" ]]; then PLUGIN_ARG+=",$EXTRA_PLUGIN_ARGS"; fi
set +e
timeout --kill-after=5s "${TIMEOUT}s" qemu-x86_64 -plugin "./hello.so,$PLUGIN_ARG" "$EXP_OUT"
rc=$?
set -e
echo "[container] qemu-x86_64 rc=$rc"
exit 0
IN_CONTAINER

python3 - "$TRACE_PATH" <<'PY'
import os, struct, sys
p = sys.argv[1]
size = os.path.getsize(p) if os.path.exists(p) else 0
print('[*] qlt path:', p)
print('[*] qlt size:', size)
if size < 36:
    print('[!] qlt too small')
    sys.exit(3)
h = open(p, 'rb').read(36)
if h[:4] != b'QLT1':
    print('[!] invalid magic:', h[:4]); sys.exit(3)
version, flags, regtab, reserved = struct.unpack_from('<HHHH', h, 4)
blocks, index_off, header_size = struct.unpack_from('<QQQ', h, 12)
print(f'[*] qlt header: version={version} flags={flags} reg_table={regtab} blocks={blocks} index_offset={index_off} header_size={header_size}')
if blocks == 0 or size < index_off + blocks * 40:
    print('[!] qlt index incomplete')
    sys.exit(3)
total = 0
with open(p, 'rb') as f:
    f.seek(index_off)
    first = last = None
    for i in range(blocks):
        e = struct.unpack('<QQQQQ', f.read(40))
        first = first or e
        last = e
        total += e[4]
print('[*] qlt records:', total)
print('[*] first index:', first)
print('[*] last index :', last)
PY

if [[ -n "${ANALYZER_CONFIG:-}" && "${QL_SUPPRESS_ANALYZE_HINT:-0}" != "1" ]]; then
  echo "[*] analyze with: ./lancet.sh analyze '$TRACE_PATH' '$ANALYZER_CONFIG' '${TRACE_PATH%.qlt}.out' qlt"
fi
)

cmd_collect() (
# One-shot Docker wrapper for collecting QLancet QEMU traces and, in case mode,
# running the analyzer on the generated trace.
#
# Example:
#   ./lancet.sh mitigation-v4-6.6 qlt ./poc.c ./out/poc.qlt
#
# The container is started with --rm and a per-run name; it is removed
# automatically when collection finishes or this wrapper is interrupted.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
CALLER_PWD=$(pwd -P)

list_supported_cases() {
  local cases_dir=${CASES_DIR:-$ROOT_DIR/cases}
  if [[ -f "$ROOT_DIR/scripts/list_cases.py" ]]; then
    python3 "$ROOT_DIR/scripts/list_cases.py" "$cases_dir" "$ROOT_DIR" || true
  else
    echo "Supported cases:"
    find "$cases_dir" -mindepth 2 -maxdepth 2 -name config.json -printf '  %h\n' 2>/dev/null | sed "s#^  $cases_dir/#  #" || true
  fi
}

usage() {
  cat <<'USAGE'
Usage:
  ./lancet.sh <case-name-or-dir> [trace-path]
  ./lancet.sh <linux-kernel-version> <trace-format> <exp-path> <trace-path> [sim-dir]

Arguments:
  case-name-or-dir      Case under ./cases or a direct case directory containing config.json.
                        Case mode collects the trace and then runs the analyzer.
                        User-mode cases are dispatched to the user-mode collector first.
  linux-kernel-version  Release directory under simulator/releases, e.g. mitigation-v4-6.6.
  trace-format          qlt or text. qlt is the normal binary QLT format.
  exp-path              PoC source (.c, compiled static in Docker) or executable to place at /bin/exp.
  trace-path            Host output trace path. Serial log is written to <trace-path>.serial.
  sim-dir               Optional legacy simulator dir or simulator name.

Common environment overrides:
  IMAGE=a85_qlancet_qemu           Docker image name.
  BUILD_IMAGE=auto|1|0             Build Dockerfile if missing (default: auto).
  DOCKERFILE=./Dockerfile          Dockerfile used when building IMAGE.
  DOCKER_PLATFORM=linux/amd64      Optional platform for docker build/run.
  TIMEOUT=900                      QEMU timeout seconds.
  TRACE_CPU=1                      Guest CPU to trace.
  TASKSET_MASK=0x2                 CPU mask for running /bin/exp.
  FIFO_PRIO=99                     chrt FIFO priority.
  START_ADDR=0x...                 Override trigger address; default resolves exp::_start.
  START_SYMBOL=name                Resolve trigger from this symbol when START_ADDR is unset.
  STOP_ADDR=0x...                  Optional stop address to disarm tracing.
  STOP_SYMBOL=name                 Resolve stop address from this symbol when STOP_ADDR is unset.
  EXP_KIND=auto|c|bin              How to handle exp-path (default: auto).
  EXP_CFLAGS='...' EXP_LDFLAGS='...'  Extra flags for default .c compilation.
  EXP_BUILD_CMD='...'              Custom build command; uses EXP_IN and EXP_OUT variables.
  DOCKER_NETWORK=none              Docker network mode; use host if the PoC needs host networking.
  ANALYZE=1|0                      Run analyzer after successful case trace collection
                                   (default: 1 in case mode, 0 in direct release mode).
  TRACE_ONLY=1                     Alias for ANALYZE=0.
  ANALYSIS_OUT=out/<trace-stem>    Analyzer output directory.

Case config keys:
  release, trace_format, exp, build, simulator, output_dir, trace/trace_path,
  timeout, trace_cpu, taskset_mask, fifo_prio, analyzer_config, qemu_config,
  plugin_config, auto_config, start_addr, start_symbol.
  stop_addr and stop_symbol are also supported for bounded user-mode traces.
  Relative paths are resolved from the case directory.

Simulator manifests live under ./simulators/<name>/config.json and point to
shared core/, releases/, rootfs, flag, and plugin config assets.

Default collection policy:
  user-space _start trigger, kernel-only trace, regs=insn, only CPU1, zstd QLT blocks.
USAGE
  echo
  list_supported_cases
}

die() {
  echo "error: $*" >&2
  exit 1
}

abs_file() {
  local p=$1
  [[ -e "$p" ]] || die "missing path: $p"
  if command -v readlink >/dev/null 2>&1; then
    readlink -f "$p"
    return
  fi
  local d b
  d=$(dirname "$p")
  b=$(basename "$p")
  d=$(cd "$d" && pwd -P)
  printf '%s/%s\n' "$d" "$b"
}

abs_dir() {
  local p=$1
  [[ -d "$p" ]] || die "missing directory: $p"
  (cd "$p" && pwd -P)
}

set_env_default() {
  local k=$1
  local v=$2
  if [[ -n "$v" && -z "${!k+x}" ]]; then
    export "$k=$v"
  fi
}

truthy() {
  case "${1,,}" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

analysis_enabled() {
  if truthy "${TRACE_ONLY:-0}"; then
    return 1
  fi
  if [[ -n "${ANALYZE+x}" ]]; then
    truthy "$ANALYZE"
    return
  fi
  [[ "${CASE_MODE:-0}" == "1" || "${USER_CASE_DISPATCH:-0}" == "1" ]]
}

analyzer_trace_format() {
  case "$1" in
    text) echo legacy ;;
    "") echo auto ;;
    *) echo "$1" ;;
  esac
}

default_analysis_out() {
  local trace=$1
  local stem
  stem=$(basename "$trace")
  stem=${stem%.*}
  printf '%s/out/%s\n' "$ROOT_DIR" "$stem"
}

run_trace_analyzer() {
  local trace=$1
  local config=${2:-}
  local out=${3:-}
  local fmt=${4:-auto}

  if [[ -z "$config" ]]; then
    echo "[!] analyzer config is not set; skip analyzer" >&2
    return 0
  fi
  if [[ ! -s "$config" ]]; then
    echo "[!] analyzer config is missing or empty: $config; skip analyzer" >&2
    return 0
  fi
  if [[ -z "$out" ]]; then
    out=$(default_analysis_out "$trace")
  fi

  fmt=$(analyzer_trace_format "$fmt")
  echo "[*] analyzing trace : $trace"
  echo "[*] analyzer cfg    : $config"
  echo "[*] analyzer output : $out"
  echo "[*] analyzer format : $fmt"
  cmd_analyze "$trace" "$config" "$out" "$fmt"
}

resolve_simulator() {
  local ref=${1:-}
  local manifest=""

  if [[ -z "$ref" ]]; then
    if [[ -n "${SIMULATOR:-}" ]]; then
      ref=$SIMULATOR
    elif [[ -n "${SIM_DIR:-}" ]]; then
      ref=$SIM_DIR
    elif [[ -f "$ROOT_DIR/simulators/kernelctf/config.json" ]]; then
      ref=kernelctf
    else
      die "no simulator configured; set SIMULATOR/SIM_DIR or add simulators/<name>/config.json"
    fi
  fi

  if [[ -f "$ROOT_DIR/simulators/$ref/config.json" ]]; then
    manifest="$ROOT_DIR/simulators/$ref/config.json"
  elif [[ -f "$ref" ]]; then
    manifest=$(abs_file "$ref")
  elif [[ -d "$ref" ]]; then
    # A legacy simulator directory contains all assets directly. Do not treat
    # its plugin config.json as a simulator manifest.
    if [[ -d "$ref/core" && -d "$ref/releases" && -e "$ref/rootfs_v3.img" ]]; then
      SIM_DESC=$(abs_dir "$ref")
      CORE_DIR=$(abs_dir "$SIM_DESC/core")
      RELEASES_DIR=$(abs_dir "$SIM_DESC/releases")
      ROOTFS_PATH=$(abs_file "$SIM_DESC/rootfs_v3.img")
      FLAG_PATH=$(abs_file "$SIM_DESC/flag")
      CONFIG_PATH=""
      if [[ -e "$SIM_DESC/config.json" ]]; then
        CONFIG_PATH=$(abs_file "$SIM_DESC/config.json")
      fi
      return
    elif [[ -f "$ref/config.json" ]]; then
      manifest=$(abs_file "$ref/config.json")
    else
      die "invalid simulator directory: $ref"
    fi
  elif [[ -f "$ROOT_DIR/simulators/$ref.json" ]]; then
    manifest="$ROOT_DIR/simulators/$ref.json"
  else
    die "simulator not found: $ref"
  fi

  eval "$(
    python3 - "$manifest" <<'PY'
import json
import os
import shlex
import sys

manifest = os.path.abspath(sys.argv[1])
base = os.path.dirname(manifest)
with open(manifest, "r", encoding="utf-8") as f:
    cfg = json.load(f)

def first(*names, default=""):
    for name in names:
        if name in cfg and cfg[name] is not None:
            return cfg[name]
    return default

def path_value(value):
    if value in (None, ""):
        return ""
    value = str(value)
    if os.path.isabs(value):
        return os.path.normpath(value)
    return os.path.normpath(os.path.join(base, value))

values = {
    "SIM_DESC": first("name", default=os.path.basename(base)),
    "SIM_PREPARE_PATH": path_value(first("prepare", "prepare_script")),
    "SIM_CORE_DIR": path_value(first("core", "core_dir")),
    "SIM_RELEASES_DIR": path_value(first("releases", "releases_dir")),
    "SIM_ROOTFS_PATH": path_value(first("rootfs", "rootfs_img", "rootfs_v3")),
    "SIM_RAMDISK_PATH": path_value(first("ramdisk", "ramdisk_img", "ramdisk_v1")),
    "SIM_FLAG_PATH": path_value(first("flag", "flag_path")),
    "SIM_CONFIG_PATH": path_value(first("plugin_config", "qlt_config", "config_path", "config")),
}
missing = [k for k, v in values.items() if k not in ("SIM_DESC", "SIM_PREPARE_PATH", "SIM_RAMDISK_PATH", "SIM_CONFIG_PATH") and not v]
if missing:
    raise SystemExit("simulator manifest missing keys: " + ", ".join(missing))
for key, value in values.items():
    print(f"{key}={shlex.quote(str(value))}")
PY
  )"

  if [[ -n "${SIM_PREPARE_PATH:-}" ]]; then
    if [[ ! -d "$SIM_CORE_DIR" ||
          ! -d "$SIM_RELEASES_DIR" ||
          ! -f "$SIM_RELEASES_DIR/$RELEASE/bzImage" ||
          ! -f "$SIM_ROOTFS_PATH" ||
          ! -f "$SIM_FLAG_PATH" ]]; then
      echo "[*] preparing simulator assets via $SIM_PREPARE_PATH"
      bash "$SIM_PREPARE_PATH" "$RELEASE"
    fi
  fi

  CORE_DIR=$(abs_dir "$SIM_CORE_DIR")
  RELEASES_DIR=$(abs_dir "$SIM_RELEASES_DIR")
  ROOTFS_PATH=$(abs_file "$SIM_ROOTFS_PATH")
  FLAG_PATH=$(abs_file "$SIM_FLAG_PATH")
  CONFIG_PATH=""
  if [[ -n "${SIM_CONFIG_PATH:-}" ]]; then
    CONFIG_PATH=$(abs_file "$SIM_CONFIG_PATH")
  fi
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage
  exit 0
fi

maybe_dispatch_user_case() {
  if [[ $# -lt 1 || $# -gt 2 ]]; then
    return 0
  fi
  local case_arg=$1
  local cases_dir=${CASES_DIR:-$ROOT_DIR/cases}
  local case_dir=""
  if [[ -d "$case_arg" ]]; then
    case_dir=$(abs_dir "$case_arg")
  elif [[ -d "$cases_dir/$case_arg" ]]; then
    case_dir=$(abs_dir "$cases_dir/$case_arg")
  else
    return 0
  fi
  local case_json=${CASE_CONFIG:-$case_dir/config.json}
  [[ -f "$case_json" ]] || return 0
  local is_user
  is_user=$(python3 - "$case_json" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1], encoding="utf-8"))
def first(*names):
    for name in names:
        value = cfg.get(name)
        if value not in (None, ""):
            return str(value).lower()
    return ""
release = first("release", "linux_kernel_version", "kernel")
simulator = first("simulator", "sim", "sim_dir", "simulator_dir")
plugin_mode = first("plugin_mode")
print("1" if release == "user" or simulator == "user" or plugin_mode == "user" else "0")
PY
  )
  if [[ "$is_user" == "1" ]]; then
    USER_CASE_DISPATCH=1
    local trace_override="${2:-}"
    eval "$(
      python3 - "$case_json" "$case_dir" "$ROOT_DIR" "$CALLER_PWD" "$trace_override" <<'PY'
import json
import os
import shlex
import sys

cfg_path, case_dir, root_dir, caller_pwd, trace_override = sys.argv[1:6]
with open(cfg_path, "r", encoding="utf-8") as f:
    cfg = json.load(f)

def first(*names, default=""):
    for name in names:
        value = cfg.get(name)
        if value not in (None, ""):
            return value
    return default

def path_value(value, base=case_dir):
    if value in (None, ""):
        return ""
    value = str(value)
    if os.path.isabs(value):
        return os.path.normpath(value)
    return os.path.normpath(os.path.join(base, value))

case_name = first("name", default=os.path.basename(case_dir))
fmt = str(first("trace_format", "format", default="qlt"))
if trace_override:
    trace_path = trace_override
    if not os.path.isabs(trace_path):
        trace_path = os.path.normpath(os.path.join(caller_pwd, trace_path))
else:
    trace_path = first("trace_path", "out", "output")
    if trace_path:
        trace_path = path_value(trace_path)
    else:
        output_dir = path_value(first("output_dir", "trace_dir", default="out"))
        trace_name = first("trace", "trace_name", default=f"{case_name}.{fmt}")
        trace_path = os.path.normpath(os.path.join(output_dir, str(trace_name)))

analysis_out = first("analysis_output", "analysis_out", "analyzer_output", "analyzer_out", default="")
if analysis_out:
    analysis_out = path_value(analysis_out)
else:
    stem = os.path.basename(trace_path)
    if "." in stem:
        stem = stem.rsplit(".", 1)[0]
    analysis_out = os.path.join(root_dir, "out", stem)

values = {
    "USER_TRACE_PATH": trace_path,
    "USER_ANALYZER_CONFIG": path_value(first("analyzer_config", "qlancet_config")),
    "USER_ANALYSIS_OUT": analysis_out,
    "USER_TRACE_FORMAT": fmt,
}
for key, value in values.items():
    print(f"{key}={shlex.quote(str(value))}")
PY
    )"
    echo "[*] user-mode case detected; dispatching to lancet.sh user"
    QL_SUPPRESS_ANALYZE_HINT=1 cmd_user_trace "$@"
    if analysis_enabled; then
      run_trace_analyzer "$USER_TRACE_PATH" "$USER_ANALYZER_CONFIG" "${ANALYSIS_OUT:-$USER_ANALYSIS_OUT}" "$USER_TRACE_FORMAT"
    fi
    exit 0
  fi
}

maybe_dispatch_user_case "$@"

CASE_MODE=0
if [[ $# -eq 1 || $# -eq 2 ]]; then
  CASE_MODE=1
  CASE_ARG=$1
  CASES_DIR=${CASES_DIR:-$ROOT_DIR/cases}
  if [[ -d "$CASE_ARG" ]]; then
    CASE_DIR=$(abs_dir "$CASE_ARG")
  elif [[ -d "$CASES_DIR/$CASE_ARG" ]]; then
    CASE_DIR=$(abs_dir "$CASES_DIR/$CASE_ARG")
  else
    die "case not found: $CASE_ARG (looked in $CASES_DIR)"
  fi
  CASE_JSON=${CASE_CONFIG:-$CASE_DIR/config.json}
  [[ -f "$CASE_JSON" ]] || die "missing case config: $CASE_JSON"

  eval "$(
    python3 - "$CASE_JSON" "$CASE_DIR" "$ROOT_DIR" <<'PY'
import json
import os
import shlex
import sys

cfg_path, case_dir, root_dir = sys.argv[1], sys.argv[2], sys.argv[3]
with open(cfg_path, "r", encoding="utf-8") as f:
    cfg = json.load(f)

def first(*names, default=""):
    for name in names:
        if name in cfg and cfg[name] is not None:
            return cfg[name]
    return default

def path_value(value):
    if value in (None, ""):
        return ""
    value = str(value)
    if os.path.isabs(value):
        return os.path.normpath(value)
    return os.path.normpath(os.path.join(case_dir, value))

def ref_value(value):
    """Simulator references may be names (kernelctf) or paths."""
    if value in (None, ""):
        return ""
    value = str(value)
    if os.path.isabs(value) or value.startswith(".") or "/" in value:
        return path_value(value)
    return value

case_name = first("name", default=os.path.basename(case_dir))
release = first("release", "linux_kernel_version", "kernel")
if not release:
    raise SystemExit("case config requires 'release'")
fmt = first("trace_format", "format", default="qlt")

exp = first("exp", "exp_path", "poc")
if not exp:
    for candidate in ("exp.c", "poc.c", "exp"):
        if os.path.exists(os.path.join(case_dir, candidate)):
            exp = candidate
            break
if not exp:
    raise SystemExit("case config requires 'exp' or an exp.c/poc.c file")
exp_path = path_value(exp)

trace_path = first("trace_path", "out", "output")
if trace_path:
    trace_path = path_value(trace_path)
else:
    output_dir = path_value(first("output_dir", "trace_dir", default="out"))
    trace_name = first("trace", "trace_name", default=f"{case_name}.{fmt}")
    trace_path = os.path.normpath(os.path.join(output_dir, str(trace_name)))

analysis_out_cfg = path_value(first("analysis_output", "analysis_out", "analyzer_output", "analyzer_out", default=""))
analysis_out = analysis_out_cfg
if not analysis_out:
    stem = os.path.basename(trace_path)
    if "." in stem:
        stem = stem.rsplit(".", 1)[0]
    analysis_out = os.path.join(root_dir, "out", stem)

build = first("build", "build_script")
build_rel = ""
if build:
    build_path = path_value(build)
    exp_dir = os.path.dirname(exp_path)
    try:
        common = os.path.commonpath([os.path.abspath(build_path), os.path.abspath(exp_dir)])
    except ValueError:
        common = ""
    if common != os.path.abspath(exp_dir):
        raise SystemExit("case build script must live in the same directory as exp or below it")
    build_rel = os.path.relpath(build_path, exp_dir)

values = {
    "CASE_RELEASE": release,
    "CASE_TRACE_FORMAT": fmt,
    "CASE_EXP_PATH": exp_path,
    "CASE_TRACE_PATH": trace_path,
    "CASE_ANALYSIS_OUT": analysis_out,
    "CASE_ANALYSIS_OUT_EXPLICIT": "1" if analysis_out_cfg else "0",
    "CASE_SIM_REF": ref_value(first("simulator", "sim", "sim_dir", "simulator_dir")),
    "CASE_ANALYZER_CONFIG": path_value(first("analyzer_config", "qlancet_config")),
    "CASE_QEMU_CONFIG": path_value(first("qemu_config", "qemu_output")),
    "CASE_AUTO_CONFIG": first("auto_config", default="1"),
    "CASE_BUILD_REL": build_rel,
    "CASE_PLUGIN_CONFIG": path_value(first("plugin_config", "qlt_config")),
    "CASE_TIMEOUT": first("timeout"),
    "CASE_TRACE_CPU": first("trace_cpu", "cpu"),
    "CASE_TASKSET_MASK": first("taskset_mask"),
    "CASE_FIFO_PRIO": first("fifo_prio"),
    "CASE_START_ADDR": first("start_addr", "trigger"),
    "CASE_START_SYMBOL": first("start_symbol", "trigger_symbol"),
    "CASE_STOP_ADDR": first("stop_addr", "stop"),
    "CASE_STOP_SYMBOL": first("stop_symbol"),
    "CASE_QEMU_BIN": first("qemu_bin"),
    "CASE_MEMORY": first("memory"),
    "CASE_SMP": first("smp"),
    "CASE_QLT_BLOCK_MB": first("qlt_block_mb", "block_mb"),
    "CASE_QLT_ZSTD": first("qlt_zstd", "zstd"),
    "CASE_PLUGIN_MODE": first("plugin_mode"),
    "CASE_TRIGGER_MODE": first("trigger_mode"),
    "CASE_TRIGGER_PC_FROM_REG": first("trigger_pc_from_reg"),
    "CASE_TRIGGER_ONLYCPU": first("trigger_onlycpu"),
    "CASE_TRIGGER_WINDOW": first("trigger_window"),
    "CASE_EXTRA_PLUGIN_ARGS": first("extra_plugin_args"),
    "CASE_EXTRA_QEMU_ARGS": first("extra_qemu_args"),
    "CASE_DOCKER_NETWORK": first("docker_network"),
}
for key, value in values.items():
    if isinstance(value, bool):
        value = "1" if value else "0"
    elif value is None:
        value = ""
    else:
        value = str(value)
    print(f"{key}={shlex.quote(value)}")
PY
  )"

  set_env_default TIMEOUT "$CASE_TIMEOUT"
  set_env_default TRACE_CPU "$CASE_TRACE_CPU"
  set_env_default TASKSET_MASK "$CASE_TASKSET_MASK"
  set_env_default FIFO_PRIO "$CASE_FIFO_PRIO"
  set_env_default START_ADDR "$CASE_START_ADDR"
  set_env_default START_SYMBOL "$CASE_START_SYMBOL"
  set_env_default STOP_ADDR "$CASE_STOP_ADDR"
  set_env_default STOP_SYMBOL "$CASE_STOP_SYMBOL"
  set_env_default AUTO_CONFIG "$CASE_AUTO_CONFIG"
  set_env_default ANALYZER_CONFIG "$CASE_ANALYZER_CONFIG"
  set_env_default QEMU_CONFIG "$CASE_QEMU_CONFIG"
  set_env_default PLUGIN_CONFIG "$CASE_PLUGIN_CONFIG"
  set_env_default QEMU_BIN "$CASE_QEMU_BIN"
  set_env_default MEMORY "$CASE_MEMORY"
  set_env_default SMP "$CASE_SMP"
  set_env_default QLT_BLOCK_MB "$CASE_QLT_BLOCK_MB"
  set_env_default QLT_ZSTD "$CASE_QLT_ZSTD"
  set_env_default PLUGIN_MODE "$CASE_PLUGIN_MODE"
  set_env_default TRIGGER_MODE "$CASE_TRIGGER_MODE"
  set_env_default TRIGGER_PC_FROM_REG "$CASE_TRIGGER_PC_FROM_REG"
  set_env_default TRIGGER_ONLYCPU "$CASE_TRIGGER_ONLYCPU"
  set_env_default TRIGGER_WINDOW "$CASE_TRIGGER_WINDOW"
  set_env_default EXTRA_PLUGIN_ARGS "$CASE_EXTRA_PLUGIN_ARGS"
  set_env_default EXTRA_QEMU_ARGS "$CASE_EXTRA_QEMU_ARGS"
  set_env_default DOCKER_NETWORK "$CASE_DOCKER_NETWORK"

  if [[ -n "$CASE_BUILD_REL" && -z "${EXP_BUILD_CMD+x}" ]]; then
    build_exec=$CASE_BUILD_REL
    if [[ "$build_exec" != */* ]]; then
      build_exec="./$build_exec"
    fi
    printf -v build_exec_q '%q' "$build_exec"
    export EXP_BUILD_CMD="cd \"\$(dirname \"\$EXP_IN\")\" && bash $build_exec_q"
  fi

  if [[ $# -eq 2 ]]; then
    CASE_TRACE_PATH=$2
    if [[ "$CASE_ANALYSIS_OUT_EXPLICIT" != "1" ]]; then
      CASE_ANALYSIS_OUT=$(default_analysis_out "$CASE_TRACE_PATH")
    fi
  fi
  set_env_default ANALYSIS_OUT "$CASE_ANALYSIS_OUT"

  if [[ -n "$CASE_SIM_REF" ]]; then
    set -- "$CASE_RELEASE" "$CASE_TRACE_FORMAT" "$CASE_EXP_PATH" "$CASE_TRACE_PATH" "$CASE_SIM_REF"
  else
    set -- "$CASE_RELEASE" "$CASE_TRACE_FORMAT" "$CASE_EXP_PATH" "$CASE_TRACE_PATH"
  fi
fi

if [[ $# -lt 4 || $# -gt 5 ]]; then
  usage >&2
  exit 2
fi

RELEASE=$1
TRACE_FORMAT=$2
EXP_PATH=$(abs_file "$3")
TRACE_PATH=$4

case "$TRACE_FORMAT" in
  qlt|text) ;;
  *) die "unsupported trace-format '$TRACE_FORMAT' (expected qlt or text)" ;;
esac

SIM_REF=""
if [[ $# -eq 5 ]]; then
  SIM_REF=$5
fi

TRACE_DIR=$(dirname "$TRACE_PATH")
TRACE_BASE=$(basename "$TRACE_PATH")
mkdir -p "$TRACE_DIR"
TRACE_DIR=$(cd "$TRACE_DIR" && pwd -P)
TRACE_PATH="$TRACE_DIR/$TRACE_BASE"

resolve_simulator "$SIM_REF"

AUTO_CONFIG=${AUTO_CONFIG:-}
if [[ -z "$AUTO_CONFIG" ]]; then
  if [[ "$CASE_MODE" == "1" ]]; then
    AUTO_CONFIG=1
  else
    AUTO_CONFIG=0
  fi
fi

ANALYZER_CONFIG=${ANALYZER_CONFIG:-}
QEMU_CONFIG=${QEMU_CONFIG:-}
if truthy "$AUTO_CONFIG"; then
  if [[ -z "$ANALYZER_CONFIG" ]]; then
    if [[ -n "${CASE_DIR:-}" ]]; then
      ANALYZER_CONFIG="$CASE_DIR/generated/$RELEASE/analyzer_config.json"
    else
      ANALYZER_CONFIG="$TRACE_PATH.analyzer_config.json"
    fi
  fi
  if [[ -z "$QEMU_CONFIG" ]]; then
    if [[ -n "${CASE_DIR:-}" ]]; then
      QEMU_CONFIG="$CASE_DIR/generated/$RELEASE/qemu_config.json"
    else
      QEMU_CONFIG="$TRACE_PATH.qemu_config.json"
    fi
  fi
  ANALYZER_CONFIG=$(mkdir -p "$(dirname "$ANALYZER_CONFIG")" && cd "$(dirname "$ANALYZER_CONFIG")" && pwd -P)/$(basename "$ANALYZER_CONFIG")
  QEMU_CONFIG=$(mkdir -p "$(dirname "$QEMU_CONFIG")" && cd "$(dirname "$QEMU_CONFIG")" && pwd -P)/$(basename "$QEMU_CONFIG")
  if [[ "${REGENERATE_CONFIG:-0}" == "1" || ! -s "$ANALYZER_CONFIG" || ! -s "$QEMU_CONFIG" ]]; then
    echo "[*] generating analyzer/qemu configs for $RELEASE"
    python3 "$ROOT_DIR/scripts/gen_config.py" \
      --kernel "$RELEASE" \
      --releases-dir "$RELEASES_DIR" \
      --qlancet-output "$ANALYZER_CONFIG" \
      --qemu-output "$QEMU_CONFIG"
  fi
  CONFIG_PATH="$QEMU_CONFIG"
fi

if [[ -n "${PLUGIN_CONFIG:-}" ]]; then
  CONFIG_PATH=$(abs_file "$PLUGIN_CONFIG")
fi

[[ -f "$RELEASES_DIR/$RELEASE/bzImage" ]] || die "missing kernel: $RELEASES_DIR/$RELEASE/bzImage"

EXP_DIR=$(dirname "$EXP_PATH")
EXP_BASE=$(basename "$EXP_PATH")
ROOTFS_DIR=$(dirname "$ROOTFS_PATH")
ROOTFS_BASE=$(basename "$ROOTFS_PATH")
FLAG_DIR=$(dirname "$FLAG_PATH")
FLAG_BASE=$(basename "$FLAG_PATH")
CONFIG_DIR=""
CONFIG_BASE=""
if [[ -n "$CONFIG_PATH" ]]; then
  CONFIG_DIR=$(dirname "$CONFIG_PATH")
  CONFIG_BASE=$(basename "$CONFIG_PATH")
fi

IMAGE=${IMAGE:-a85_qlancet_qemu}
BUILD_IMAGE=${BUILD_IMAGE:-auto}
DOCKERFILE=${DOCKERFILE:-$ROOT_DIR/Dockerfile}
DOCKER_PLATFORM=${DOCKER_PLATFORM:-${DOCKER_DEFAULT_PLATFORM:-}}
REQUIRED_IMAGE_REV=${REQUIRED_IMAGE_REV:-20260617-ql-user-binutils-v2}
TIMEOUT=${TIMEOUT:-900}
TRACE_CPU=${TRACE_CPU:-1}
TASKSET_MASK=${TASKSET_MASK:-0x2}
FIFO_PRIO=${FIFO_PRIO:-99}
EXP_KIND=${EXP_KIND:-auto}
START_ADDR=${START_ADDR:-}
DOCKER_NETWORK=${DOCKER_NETWORK:-none}
CONTAINER_NAME=${CONTAINER_NAME:-a85_get_trace_$(date +%s)_$$}

case "$EXP_KIND" in
  auto|c|bin) ;;
  *) die "invalid EXP_KIND=$EXP_KIND (expected auto, c, or bin)" ;;
esac

if command -v docker >/dev/null 2>&1; then
  DOCKER_CMD=(docker)
elif command -v sudo >/dev/null 2>&1; then
  DOCKER_CMD=(sudo docker)
else
  die "docker not found"
fi

NEED_BUILD=0
if [[ "$BUILD_IMAGE" == "1" ]]; then
  NEED_BUILD=1
elif [[ "$BUILD_IMAGE" == "auto" ]]; then
  if ! "${DOCKER_CMD[@]}" image inspect "$IMAGE" >/dev/null 2>&1; then
    NEED_BUILD=1
  else
    if [[ -n "$REQUIRED_IMAGE_REV" && "$REQUIRED_IMAGE_REV" != "skip" ]]; then
      image_rev=$("${DOCKER_CMD[@]}" image inspect --format '{{index .Config.Labels "org.a85.qlancet.image-rev"}}' "$IMAGE" 2>/dev/null || true)
      if [[ "$image_rev" != "$REQUIRED_IMAGE_REV" ]]; then
        echo "[*] Docker image $IMAGE is stale (rev=${image_rev:-<none>}, need=$REQUIRED_IMAGE_REV); rebuilding"
        NEED_BUILD=1
      fi
    fi
    if [[ -n "$DOCKER_PLATFORM" ]]; then
      image_platform=$("${DOCKER_CMD[@]}" image inspect --format '{{.Os}}/{{.Architecture}}' "$IMAGE" 2>/dev/null || true)
      case "$DOCKER_PLATFORM" in
        "$image_platform"|"$image_platform"/*) ;;
        *) NEED_BUILD=1 ;;
      esac
    fi
  fi
fi

DOCKER_PLATFORM_ARGS=()
if [[ -n "$DOCKER_PLATFORM" ]]; then
  DOCKER_PLATFORM_ARGS=(--platform "$DOCKER_PLATFORM")
fi

if [[ "$NEED_BUILD" == "1" ]]; then
  [[ -f "$DOCKERFILE" ]] || die "missing Dockerfile: $DOCKERFILE"
  echo "[*] building Docker image $IMAGE from $DOCKERFILE"
  "${DOCKER_CMD[@]}" build "${DOCKER_PLATFORM_ARGS[@]}" -t "$IMAGE" -f "$DOCKERFILE" "$ROOT_DIR"
fi

cleanup() {
  "${DOCKER_CMD[@]}" rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "[*] release       : $RELEASE"
echo "[*] trace format  : $TRACE_FORMAT"
echo "[*] exp           : $EXP_PATH"
echo "[*] simulator     : $SIM_DESC"
echo "[*] simulator core: $CORE_DIR"
if [[ -n "${ANALYZER_CONFIG:-}" ]]; then
  echo "[*] analyzer cfg  : $ANALYZER_CONFIG"
fi
if [[ -n "${CONFIG_PATH:-}" ]]; then
  echo "[*] qemu cfg      : $CONFIG_PATH"
fi
echo "[*] output        : $TRACE_PATH"
echo "[*] serial        : $TRACE_PATH.serial"
echo "[*] docker image  : $IMAGE"
if [[ -n "$DOCKER_PLATFORM" ]]; then
  echo "[*] docker plat   : $DOCKER_PLATFORM"
fi
echo "[*] container     : $CONTAINER_NAME (--rm)"

DOCKER_ARGS=(
  run --rm -i
  "${DOCKER_PLATFORM_ARGS[@]}"
  --name "$CONTAINER_NAME"
  --network "$DOCKER_NETWORK"
  --security-opt seccomp=unconfined
  -v "$ROOT_DIR":/work/a85
  -v "$CORE_DIR":/inputs/core:ro
  -v "$RELEASES_DIR":/inputs/releases:ro
  -v "$ROOTFS_DIR":/inputs/rootfs_dir:ro
  -v "$FLAG_DIR":/inputs/flag_dir:ro
  -v "$EXP_DIR":/inputs/exp_dir:ro
  -v "$TRACE_DIR":/out
  -e RELEASE="$RELEASE"
  -e TRACE_FORMAT="$TRACE_FORMAT"
  -e OUT_BASE="$TRACE_BASE"
  -e TIMEOUT="$TIMEOUT"
  -e TRACE_CPU="$TRACE_CPU"
  -e TASKSET_MASK="$TASKSET_MASK"
  -e FIFO_PRIO="$FIFO_PRIO"
  -e EXP_BASE="$EXP_BASE"
  -e EXP_KIND="$EXP_KIND"
  -e ROOTFS_BASE="$ROOTFS_BASE"
  -e FLAG_BASE="$FLAG_BASE"
  -e START_ADDR="$START_ADDR"
  -e START_SYMBOL="${START_SYMBOL:-}"
  -e STOP_ADDR="${STOP_ADDR:-}"
  -e STOP_SYMBOL="${STOP_SYMBOL:-}"
  -e EXP_CFLAGS="${EXP_CFLAGS:-}"
  -e EXP_LDFLAGS="${EXP_LDFLAGS:-}"
  -e EXP_BUILD_CMD="${EXP_BUILD_CMD:-}"
  -e QLT_BLOCK_MB="${QLT_BLOCK_MB:-16}"
  -e QLT_ZSTD="${QLT_ZSTD:-1}"
  -e MEMORY="${MEMORY:-3.5G}"
  -e SMP="${SMP:-2}"
  -e QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
  -e PLUGIN_MODE="${PLUGIN_MODE:-kernel}"
  -e TRIGGER_MODE="${TRIGGER_MODE:-user}"
  -e TRIGGER_PC_FROM_REG="${TRIGGER_PC_FROM_REG:-1}"
  -e TRIGGER_ONLYCPU="${TRIGGER_ONLYCPU:-all}"
  -e TRIGGER_WINDOW="${TRIGGER_WINDOW:-0}"
  -e EXTRA_PLUGIN_ARGS="${EXTRA_PLUGIN_ARGS:-}"
  -e EXTRA_QEMU_ARGS="${EXTRA_QEMU_ARGS:-}"
)

if [[ -n "$CONFIG_PATH" ]]; then
  DOCKER_ARGS+=(-v "$CONFIG_DIR":/inputs/config_dir:ro -e CONFIG_BASE="$CONFIG_BASE")
else
  DOCKER_ARGS+=(-e CONFIG_BASE="")
fi

set +e
"${DOCKER_CMD[@]}" "${DOCKER_ARGS[@]}" "$IMAGE" bash -s <<'IN_CONTAINER'
set -euo pipefail

echo "[container] building QEMU plugin"
cd /work/a85/qemu_tcg
if ! printf '#include <zstd.h>\n' | gcc -E - >/dev/null 2>&1; then
  echo "container image is missing libzstd-dev; rebuild with: BUILD_IMAGE=1 ./lancet.sh ..." >&2
  exit 1
fi
./build.sh

source /work/a85/scripts/target_x86_64.sh
setup_x86_64_target_toolchain

echo "[container] preparing simulator overlay"
rm -rf /run_sim
mkdir -p /run_sim
cp -a /inputs/core /run_sim/core
ln -s /inputs/releases /run_sim/releases
ln -s "/inputs/rootfs_dir/$ROOTFS_BASE" /run_sim/rootfs_v3.img
ln -s "/inputs/flag_dir/$FLAG_BASE" /run_sim/flag
if [[ -n "${CONFIG_BASE:-}" ]]; then
  ln -s "/inputs/config_dir/$CONFIG_BASE" /run_sim/config.json
fi

EXP_IN="/inputs/exp_dir/$EXP_BASE"
EXP_OUT="/run_sim/core/exp"
if [[ -n "${EXP_BUILD_CMD:-}" ]]; then
  echo "[container] building exp with custom EXP_BUILD_CMD"
  export EXP_IN EXP_OUT
  eval "$EXP_BUILD_CMD"
else
  kind=$EXP_KIND
  if [[ "$kind" == "auto" ]]; then
    case "$EXP_IN" in
      *.c) kind=c ;;
      *) kind=bin ;;
    esac
  fi
  case "$kind" in
    c)
      echo "[container] compiling C PoC -> /run_sim/core/exp"
      # shellcheck disable=SC2086 # EXP_CFLAGS/LDFLAGS are intentionally shell-split.
      "$TARGET_CC" -static -no-pie -O0 -g -I"$(dirname "$EXP_IN")" $EXP_CFLAGS "$EXP_IN" -o "$EXP_OUT" $EXP_LDFLAGS
      ;;
    bin)
      echo "[container] copying executable PoC -> /run_sim/core/exp"
      cp "$EXP_IN" "$EXP_OUT"
      ;;
    *)
      echo "invalid EXP_KIND=$kind" >&2
      exit 2
      ;;
  esac
fi
chmod +x "$EXP_OUT"
validate_x86_64_elf "$EXP_OUT" "guest PoC"

cat > /run_sim/core/test.sh <<EOS
#!/bin/bash
set -x
echo "[run.sh] cmdline: \$(cat /proc/cmdline 2>/dev/null || true)"
mount -t tmpfs -o size=100M,mode=1777 tmp /tmp || true
ifconfig ens3 10.0.2.15 netmask 255.255.255.0 up || true
ifconfig enp0s3 10.0.2.15 netmask 255.255.255.0 up || true
ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up || true
ifconfig lo 127.0.0.1 netmask 255.0.0.0 up || true
route add default gw 10.0.2.2 || true
cd /
echo "[run.sh] launching exp pinned to CPU$TRACE_CPU mask=$TASKSET_MASK FIFO=$FIFO_PRIO"
if command -v taskset >/dev/null 2>&1 && command -v chrt >/dev/null 2>&1; then
  taskset "$TASKSET_MASK" chrt -f "$FIFO_PRIO" /bin/exp
else
  /bin/exp
fi
rc=\$?
echo "[run.sh] exp exited rc=\$rc"
poweroff -f || reboot -f || halt -f || exit "\$rc"
EOS
chmod +x /run_sim/core/test.sh

if [[ -z "${START_ADDR:-}" ]]; then
  if [[ -n "${START_SYMBOL:-}" ]] && START_ADDR=$(nm "$EXP_OUT" 2>/dev/null | awk -v sym="$START_SYMBOL" '$2 ~ /^[Tt]$/ && $3 == sym {print "0x"$1; found=1} END {exit found ? 0 : 1}'); then
    :
  elif START_ADDR=$(nm "$EXP_OUT" 2>/dev/null | awk '/ T _start$/ {print "0x"$1; found=1} END {exit found ? 0 : 1}'); then
    :
  else
    START_ADDR=$(readelf -h "$EXP_OUT" | awk '/Entry point address:/ {print $4; found=1} END {exit found ? 0 : 1}')
  fi
fi
if [[ -n "${START_SYMBOL:-}" ]]; then
  echo "[container] trigger START_SYMBOL=$START_SYMBOL"
fi
echo "[container] trigger START_ADDR=$START_ADDR"
if [[ -z "${STOP_ADDR:-}" && -n "${STOP_SYMBOL:-}" ]]; then
  if STOP_ADDR=$(nm "$EXP_OUT" 2>/dev/null | awk -v sym="$STOP_SYMBOL" '$2 ~ /^[Tt]$/ && $3 == sym {print "0x"$1; found=1} END {exit found ? 0 : 1}'); then
    :
  else
    echo "failed to resolve STOP_SYMBOL=$STOP_SYMBOL from $EXP_OUT" >&2
    exit 1
  fi
fi
if [[ -n "${STOP_SYMBOL:-}" ]]; then
  echo "[container] stop STOP_SYMBOL=$STOP_SYMBOL"
fi
if [[ -n "${STOP_ADDR:-}" ]]; then
  echo "[container] stop STOP_ADDR=$STOP_ADDR"
fi
echo "[container] exp symbols:"
nm -n "$EXP_OUT" 2>/dev/null | grep -E ' _start$| main$| ql_trace_start$| ql_trace_stop$' || true

echo "[container] rebuilding initramfs"
(cd /run_sim/core && find . | cpio -o --format=newc > /run_sim/ramdisk_v1)

echo "[container] collecting trace"
cd /work/a85/qemu_tcg
STOP_ARGS=()
if [[ -n "${STOP_ADDR:-}" ]]; then
  STOP_ARGS=(--stop "$STOP_ADDR")
fi
TRACE_FORMAT="$TRACE_FORMAT" \
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}" \
PLUGIN_MODE="${PLUGIN_MODE:-kernel}" \
TRIGGER_MODE="${TRIGGER_MODE:-user}" \
TRIGGER_PC_FROM_REG="${TRIGGER_PC_FROM_REG:-1}" \
TRIGGER_ONLYCPU="${TRIGGER_ONLYCPU:-all}" \
TRIGGER_WINDOW="${TRIGGER_WINDOW:-0}" \
ONLYCPU="$TRACE_CPU" \
QLT_BLOCK_MB="$QLT_BLOCK_MB" \
QLT_ZSTD="$QLT_ZSTD" \
MEMORY="$MEMORY" \
SMP="$SMP" \
EXTRA_PLUGIN_ARGS="$EXTRA_PLUGIN_ARGS" \
EXTRA_QEMU_ARGS="$EXTRA_QEMU_ARGS" \
SERIAL_LOG="/out/$OUT_BASE.serial" \
./collect_kernel_trace.sh --timeout "$TIMEOUT" --start "$START_ADDR" "${STOP_ARGS[@]}" --init /home/user/run.sh /run_sim "$RELEASE" "/out/$OUT_BASE"
IN_CONTAINER
docker_rc=$?
set -e

if [[ $docker_rc -ne 0 ]]; then
  echo "[!] docker/qemu exited with status $docker_rc; validating output anyway" >&2
fi

echo "[*] output files:"
ls -lh "$TRACE_PATH"* 2>/dev/null || true

if [[ "$TRACE_FORMAT" == "qlt" && -f "$TRACE_PATH" ]]; then
  set +e
  python3 - "$TRACE_PATH" <<'PY'
import os
import struct
import sys

p = sys.argv[1]
size = os.path.getsize(p)
print("[*] qlt path:", p)
print("[*] qlt size:", size)
if size < 36:
    print("[!] qlt too small; QEMU probably did not finalize the writer")
    sys.exit(3)

with open(p, "rb") as f:
    h = f.read(36)
magic = h[:4]
if magic != b"QLT1":
    print("[!] invalid magic:", magic)
    sys.exit(3)
version, flags, regtab, reserved = struct.unpack_from("<HHHH", h, 4)
blocks, index_off, header_size = struct.unpack_from("<QQQ", h, 12)
print("[*] qlt header: version=%d flags=%d reg_table=%d blocks=%d index_offset=%d header_size=%d" %
      (version, flags, regtab, blocks, index_off, header_size))
if blocks == 0:
    print("[!] block_count is 0; trace is not useful/finalized")
    sys.exit(3)
if size < index_off + blocks * 40:
    print("[!] index is incomplete")
    sys.exit(3)
total = 0
first = last = None
with open(p, "rb") as f:
    f.seek(index_off)
    for i in range(blocks):
        e = struct.unpack("<QQQQQ", f.read(40))
        if first is None:
            first = e
        last = e
        total += e[4]
print("[*] qlt records:", total)
print("[*] first index:", first)
print("[*] last index :", last)
PY
  validate_rc=$?
  set -e
else
  validate_rc=0
fi

if [[ $docker_rc -ne 0 && ( ! -s "$TRACE_PATH" || ${validate_rc:-0} -ne 0 ) ]]; then
  exit "$docker_rc"
fi

if [[ ${validate_rc:-0} -eq 0 ]] && analysis_enabled; then
  run_trace_analyzer "$TRACE_PATH" "${ANALYZER_CONFIG:-}" "${ANALYSIS_OUT:-}" "$TRACE_FORMAT"
elif [[ -n "${ANALYZER_CONFIG:-}" ]]; then
  echo "[*] analyzer skipped; run manually with:"
  echo "    ./lancet.sh analyze '$TRACE_PATH' '$ANALYZER_CONFIG' '$(default_analysis_out "$TRACE_PATH")' $(analyzer_trace_format "$TRACE_FORMAT")"
fi
exit "${validate_rc:-0}"
)

main() {
  case "${1:-}" in
    "")
      usage_unified >&2
      exit 2
      ;;
    -h|--help)
      usage_unified
      exit 0
      ;;
    analyze)
      shift
      cmd_analyze "$@"
      ;;
    user|user-trace)
      shift
      cmd_user_trace "$@"
      ;;
    collect|trace|run)
      shift
      cmd_collect "$@"
      ;;
    trace-only|collect-only)
      shift
      TRACE_ONLY=1 cmd_collect "$@"
      ;;
    *)
      cmd_collect "$@"
      ;;
  esac
}

main "$@"
