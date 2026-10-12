#!/bin/sh
set -eu
cd "$(dirname "$0")"
cargo build --offline
cc -std=c11 -O2 -Wall -Wextra -Werror -D_FORTIFY_SOURCE=2 -o target/harness tests/harness.c -Wl,-l:libudev.so.1 -ldl -pthread
python3 tests/run.py
