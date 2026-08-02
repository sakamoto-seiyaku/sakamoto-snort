#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
  "") transitions=5000 ;;
  --long) transitions=1000000 ;;
  --transitions)
    if [[ $# -ne 2 ]]; then
      echo "usage: $0 [--long | --transitions N]" >&2
      exit 2
    fi
    transitions=$2
    ;;
  *) echo "usage: $0 [--long | --transitions N]" >&2; exit 2 ;;
esac

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
build_dir=$(mktemp -d /tmp/sakamoto-p6c.XXXXXX)
trap 'rm -rf -- "$build_dir"' EXIT
seed=0x5A4B20260802

run_case() {
  local name=$1
  shift
  if "$@"; then
    echo "P6c $name PASS"
  else
    local status=$?
    echo "P6c $name FAIL (exit $status)" >&2
    return "$status"
  fi
}

run_case exhaustive python3 "$here/p6c_exhaustive.py"
run_case fault-coalescing-teardown python3 "$here/fault_scenarios.py"

cc -std=c11 -O2 -pthread -Wall -Wextra -Wpedantic -Werror \
  "$here/p6c_litmus.c" -o "$build_dir/p6c_litmus"
echo "P6c c11-build PASS"
run_case litmus "$build_dir/p6c_litmus" --transitions "$transitions" --seed "$seed"

cc -std=c11 -O1 -g -pthread -Wall -Wextra -Wpedantic -Werror \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  "$here/p6c_litmus.c" -o "$build_dir/p6c_litmus_san"
echo "P6c asan-ubsan-build PASS"
# This harness performs no heap allocation. LeakSanitizer's exit-time scan is
# disabled because it recursively faults under this WSL runtime; ASan's memory
# checks and UBSan remain enabled.
# WSL2's crash-capture path also intermittently recurses with ASan under ASLR
# (the kernel reports an overflowing signal alternate stack). A process-local
# ADDR_NO_RANDOMIZE personality makes both GCC and Clang ASan reproducible
# without changing the harness or the unsanitized million-transition run.
sanitizer_command=("$build_dir/p6c_litmus_san")
if grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null; then
  sanitizer_command=(setarch "$(uname -m)" -R "${sanitizer_command[@]}")
fi
ASAN_OPTIONS=detect_leaks=0 \
  run_case asan-ubsan-smoke "${sanitizer_command[@]}" --transitions 200 --seed "$seed"

echo "P6c local-suite PASS transitions=$transitions seed=$seed"
