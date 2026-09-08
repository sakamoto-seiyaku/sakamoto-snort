#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="$(mktemp -d /tmp/sakamoto-s210-capacity.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cc -std=c11 -Wall -Wextra -Werror -pedantic \
  -I"$repo_root/src/product/vpp" \
  "$repo_root/src/product/vpp/product_packet.c" \
  "$repo_root/tests/host/s210_capacity_bypass_test.c" \
  -o "$work_dir/capacity-test"
"$work_dir/capacity-test"
python3 "$repo_root/tests/host/s210-capacity-source-contract.py"
