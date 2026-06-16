#!/usr/bin/env bash
# Fast user-mode QEMU trace collector. It mirrors get_trace.sh's Docker/plugin
# build flow but runs qemu-x86_64 instead of booting a full kernel simulator.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
CALLER_PWD=$(pwd -P)

usage() {
  cat <<'USAGE'
Usage:
  ./get_user_trace.sh <case-name-or-dir> [trace-path]
  ./get_user_trace.sh <exp.c-or-bin> <trace-path> [start-symbol] [stop-symbol]

Environment:
  IMAGE=a85_qlancet_qemu      Docker image containing qemu-x86_64 with plugins.
  BUILD_IMAGE=auto|1|0        Build Dockerfile if image is missing.
  TIMEOUT=120                 qemu-x86_64 timeout seconds.
  START_SYMBOL=name           Trigger symbol for case/direct mode.
  STOP_SYMBOL=name            Optional stop symbol for bounded traces.
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
 'TIMEOUT_CASE': first('timeout', default=''),
 'EXTRA_PLUGIN_ARGS_CASE': first('extra_plugin_args', default=''),
}
for k,v in vals.items(): print(f'{k}={shlex.quote(str(v))}')
PY
)"
  if [[ $# -eq 2 ]]; then TRACE_PATH=$2; fi
  START_SYMBOL=${START_SYMBOL:-$START_SYMBOL_CASE}
  STOP_SYMBOL=${STOP_SYMBOL:-$STOP_SYMBOL_CASE}
  TIMEOUT=${TIMEOUT:-${TIMEOUT_CASE:-120}}
  EXTRA_PLUGIN_ARGS=${EXTRA_PLUGIN_ARGS:-${EXTRA_PLUGIN_ARGS_CASE:-}}
else
  [[ $# -ge 2 && $# -le 4 ]] || { usage >&2; exit 2; }
  EXP_PATH=$(abs_file "$1")
  TRACE_PATH=$2
  START_SYMBOL=${START_SYMBOL:-${3:-main}}
  STOP_SYMBOL=${STOP_SYMBOL:-${4:-}}
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
CONTAINER_NAME=${CONTAINER_NAME:-a85_get_user_trace_$(date +%s)_$$}
if command -v docker >/dev/null 2>&1; then DOCKER_CMD=(docker); elif command -v sudo >/dev/null 2>&1; then DOCKER_CMD=(sudo docker); else die "docker not found"; fi
NEED_BUILD=0
if [[ "$BUILD_IMAGE" == "1" ]]; then NEED_BUILD=1; elif [[ "$BUILD_IMAGE" == "auto" ]]; then if ! "${DOCKER_CMD[@]}" image inspect "$IMAGE" >/dev/null 2>&1; then NEED_BUILD=1; fi; fi
if [[ "$NEED_BUILD" == "1" ]]; then
  echo "[*] building Docker image $IMAGE from $DOCKERFILE"
  "${DOCKER_CMD[@]}" build -t "$IMAGE" -f "$DOCKERFILE" "$ROOT_DIR"
fi

cleanup() { "${DOCKER_CMD[@]}" rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

echo "[*] exp          : $EXP_PATH"
echo "[*] start symbol : ${START_SYMBOL:-<none>}"
echo "[*] stop symbol  : ${STOP_SYMBOL:-<none>}"
echo "[*] output       : $TRACE_PATH"
echo "[*] docker image : $IMAGE"

DOCKER_ARGS=(
  run --rm -i --name "$CONTAINER_NAME"
  --network none
  --security-opt seccomp=unconfined
  -v "$ROOT_DIR":/work/a85
  -v "$EXP_DIR":/inputs/exp_dir:ro
  -v "$TRACE_DIR":/out
  -e EXP_BASE="$EXP_BASE"
  -e OUT_BASE="$TRACE_BASE"
  -e START_SYMBOL="${START_SYMBOL:-}"
  -e STOP_SYMBOL="${STOP_SYMBOL:-}"
  -e TIMEOUT="$TIMEOUT"
  -e BUILD_REL="$BUILD_REL"
  -e EXP_BUILD_CMD="${EXP_BUILD_CMD:-}"
  -e EXTRA_PLUGIN_ARGS="$EXTRA_PLUGIN_ARGS"
)

"${DOCKER_CMD[@]}" "${DOCKER_ARGS[@]}" "$IMAGE" bash -s <<'IN_CONTAINER'
set -euo pipefail
cd /work/a85/qemu_tcg
./build.sh

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
    *.c) gcc -static -no-pie -O0 -g -fno-stack-protector -fno-omit-frame-pointer "$EXP_IN" -o "$EXP_OUT" ;;
    *) cp "$EXP_IN" "$EXP_OUT" ;;
  esac
fi
chmod +x "$EXP_OUT"

resolve_sym() {
  local sym=$1
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

if [[ -n "${ANALYZER_CONFIG:-}" ]]; then
  echo "[*] analyze with: ./analyzer.sh '$TRACE_PATH' '$ANALYZER_CONFIG' '${TRACE_PATH%.qlt}.out' qlt"
fi
