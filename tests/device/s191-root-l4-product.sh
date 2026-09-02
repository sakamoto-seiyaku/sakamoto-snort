#!/usr/bin/env bash
set -euo pipefail

# Compatibility entry for the shorter SAKAMOTO-191 Root L4 runner name.
# The maintained implementation is the explicit Root IPv4/TCP runner.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
exec "${repo_root}/tests/device/s191-root-tcp4-l4-product.sh" "$@"
