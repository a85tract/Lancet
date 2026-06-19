#!/bin/bash
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PIN_ROOT="${1:-}"
if [ -z "$PIN_ROOT" ]; then
    for p in "$HOME/Code/pin-4.2" "$HOME/Code/pin-3.28"; do
        [ -x "$p/pin" ] && { PIN_ROOT="$p"; break; }
    done
fi
[ -z "$PIN_ROOT" ] && { echo "ERROR: PIN not found."; exit 1; }
LANCET=""
for d in "$SCRIPT_DIR/../.." "$SCRIPT_DIR/../../.."; do
    [ -f "$d/obj-intel64/lancet.so" ] && { LANCET="$d/obj-intel64/lancet.so"; break; }
done
[ -z "$LANCET" ] && { echo "ERROR: lancet.so not found."; exit 1; }
mkdir -p "$SCRIPT_DIR/lancet"
timeout 15 "$PIN_ROOT/pin" -t "$LANCET" -nolog 0 -noreason 0 -logdir "$SCRIPT_DIR/lancet" -- "$SCRIPT_DIR/bin/round_trip_fuzzer" "$SCRIPT_DIR/poc/poc.bin" </dev/null 2>&1 | tail -5
cp "$SCRIPT_DIR/lancet/ownership.log" "$SCRIPT_DIR/lancet/raw.log"
wc -l "$SCRIPT_DIR/lancet/raw.log"
