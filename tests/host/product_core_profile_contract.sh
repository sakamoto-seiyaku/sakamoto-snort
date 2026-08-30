#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

# The default test profile must compile and run the Rust test harness without
# requiring a caller-supplied profile override.
cargo test -p sakamoto-product-core --all-targets

# Ask rustc for the effective release cfg instead of checking Cargo.toml text.
# This proves the compiled Product Core release artifact uses a non-unwinding
# panic strategy even though the test harness uses unwind.
panic_cfg="$(cargo rustc --release -p sakamoto-product-core --lib -- --print cfg \
  | grep -Fx 'panic="abort"')"
if [[ "$panic_cfg" != 'panic="abort"' ]]; then
  echo "release Product Core must compile with panic=abort" >&2
  exit 1
fi

echo "sakamoto product core profile contract: PASS"
