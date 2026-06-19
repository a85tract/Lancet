#!/bin/bash
# Usage: ./run.sh [lancet_args] -- <target_binary> [target_args]
# Example: ./run.sh -targetlib libgpac.so -skip "strchr,strncmp" -- ./vulnerable_app
# Example: ./run.sh -- ./unittests/double_free
PIN_ROOT=/home/seondst/Desktop/Code/pin-4.2
$PIN_ROOT/pin -t ./obj-intel64/lancet.so "$@"
