#!/usr/bin/env bash
set -euo pipefail

# Exercise the residue checker with generation-owned state. This test is not a
# process-name scan and does not pretend that a process-local VAPI handle can
# be observed after the owner exits.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
residue_script="$repo_root/tools/product/host-residue-check.sh"
runtime_dir="$repo_root/build-output/product-vpp-runtime-residue-contract-$$"
cleanup() {
  rm -rf -- "$runtime_dir"
}
trap cleanup EXIT
mkdir -p "$runtime_dir"

empty_output="$(PRODUCT_RUNTIME_DIR="$runtime_dir" "$residue_script")"
printf '%s\n' "$empty_output" | grep -Fqx 'runtime_directory=empty'
printf '%s\n' "$empty_output" | grep -Fqx 'residue=clean'

printf '%s\n' 9 > "$runtime_dir/generation"
set +e
generation_output="$(PRODUCT_RUNTIME_DIR="$runtime_dir" "$residue_script" 2>&1)"
generation_status=$?
set -e
if [[ "$generation_status" -ne 1 ]]; then
  echo "residue checker did not fail for a live generation marker" >&2
  exit 1
fi
printf '%s\n' "$generation_output" | grep -Fqx 'generation_marker=present(9)'
printf '%s\n' "$generation_output" | grep -Fqx 'residue=present'
if printf '%s\n' "$generation_output" | grep -q 'vapi_handle=retired'; then
  echo "residue checker emitted an unobservable handle claim" >&2
  exit 1
fi

rm -f "$runtime_dir/generation"
if python3 - "$runtime_dir/api.sock" <<'PY'
import socket
import sys

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    server.bind(sys.argv[1])
except PermissionError:
    sys.exit(77)
server.close()
PY
then
  set +e
  socket_output="$(PRODUCT_RUNTIME_DIR="$runtime_dir" "$residue_script" 2>&1)"
  socket_status=$?
  set -e
  if [[ "$socket_status" -ne 1 ]]; then
    echo "residue checker did not fail for an active API socket" >&2
    exit 1
  fi
  printf '%s\n' "$socket_output" | grep -Fqx 'api_socket=present'
else
  socket_status=$?
  if [[ "$socket_status" -ne 77 ]]; then
    exit "$socket_status"
  fi
fi

echo "sakamoto product residue contract: PASS"
