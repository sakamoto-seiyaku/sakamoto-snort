#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
test_dir=$(mktemp -d /tmp/sakamoto-fragment-test.XXXXXX)
trap 'rm -f "$test_dir/contract"; rmdir "$test_dir"' EXIT HUP INT TERM
cc -std=c11 -Wall -Wextra -Werror -pedantic \
  -I"$repo/src/product/vpp" \
  "$repo/tests/host/product_fragment_contract.c" \
  "$repo/src/product/vpp/product_fragment.c" \
  "$repo/src/product/vpp/product_packet.c" -o "$test_dir/contract"
"$test_dir/contract"
