#!/usr/bin/env bash
set -euo pipefail

# Compatibility contract for the historical short SAKAMOTO-191 Root L4 name.
# The explicit Root IPv4/TCP contract owns the acceptance semantics.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
current_contract="$repo_root/tests/android/s191-root-tcp4-l4-contract-test.sh"

test -x "$current_contract"
exec bash "$current_contract" "$@"
