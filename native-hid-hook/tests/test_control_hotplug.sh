#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
cargo build --offline --features simulation
cargo clippy --offline --features simulation -- -D warnings
cargo test --offline --features simulation
cc -std=c11 -O2 -Wall -Wextra -Werror -D_FORTIFY_SOURCE=2 -o target/control-hotplug-native tests/control_hotplug_native.c -Wl,-l:libudev.so.1 -ldl -pthread
python3 tests/run_control_hotplug.py
cargo build --offline
cargo clippy --offline -- -D warnings
cargo test --offline
python3 tests/run_control_production.py
cc -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared -o target/mock-udev-monitor.so tests/mock_udev_monitor.c -Wl,-l:libudev.so.1 -ldl
cc -std=c11 -O2 -Wall -Wextra -Werror -D_FORTIFY_SOURCE=2 -o target/monitor-adapter-native tests/monitor_adapter_native.c -Wl,-l:libudev.so.1 -ldl -pthread
python3 tests/run_monitor_adapter.py
