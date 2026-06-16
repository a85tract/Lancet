#!/usr/bin/env bash
set -euo pipefail
: "${EXP_IN:=exp.c}"
: "${EXP_OUT:=exp}"
gcc -static -no-pie -O0 -g "$EXP_IN" -o "$EXP_OUT"
