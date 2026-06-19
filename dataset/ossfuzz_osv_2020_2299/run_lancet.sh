#!/bin/bash
# This case requires Docker (Ubuntu 24.04) because the binary links libasan.so.6
# which is not natively available on Ubuntu 26.04.
#
# Usage: ./run_lancet.sh
# Requires: docker, PIN at ~/Code/pin-4.2, lancet.so built

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

docker run --rm \
    -v "$REPO_ROOT:/workspace" \
    -v "$HOME/Code/pin-4.2:/pin" \
    ubuntu:24.04 \
    bash -c "
apt-get update -qq && apt-get install -y -qq libasan6 >/dev/null 2>&1
timeout 15 /pin/pin -t /workspace/obj-intel64/lancet.so -nolog 0 -noreason 0 \
    -logdir $SCRIPT_DIR/lancet \
    -- $SCRIPT_DIR/bin/fuzz_client_asan \
    $SCRIPT_DIR/poc/poc.bin </dev/null >/dev/null 2>&1
cp $SCRIPT_DIR/lancet/ownership.log $SCRIPT_DIR/lancet/raw.log
wc -l $SCRIPT_DIR/lancet/raw.log
"
