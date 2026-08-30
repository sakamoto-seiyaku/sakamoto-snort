#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="$(mktemp -d /tmp/sakamoto-s174-packet-kernel.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

cc -std=c11 -Wall -Wextra -Werror -pedantic \
  -I"$repo_root/src/product/vpp" \
  "$repo_root/src/product/vpp/product_packet.c" \
  "$repo_root/tests/host/s174_product_packet_kernel_test.c" \
  -o "$work_dir/s174-product-packet-kernel-test"

"$work_dir/s174-product-packet-kernel-test"
