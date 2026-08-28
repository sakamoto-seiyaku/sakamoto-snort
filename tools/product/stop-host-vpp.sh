#!/usr/bin/env bash
set -euo pipefail

# Stop exactly the VPP process owned by one Host generation, then remove only
# that generation's sockets/configuration. A stale or mismatched PID is a
# hard error; this helper never searches for or kills an unrelated process.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$repo_root/tools/product/path-helpers.sh"
product_prepare_build_output || exit 2
artifact_root="$(product_validate_artifact_root \
  "${PRODUCT_ARTIFACT_DIR:-$repo_root/build-output/product-vpp-host}")" || exit 2
runtime_dir="$(product_validate_runtime_root \
  "${PRODUCT_RUNTIME_DIR:-$repo_root/build-output/product-vpp-runtime}")" || exit 2
if [[ ! -d "$runtime_dir" ]]; then
  echo "product VPP runtime directory is missing" >&2
  exit 2
fi
vpp_bin="$artifact_root/bin/vpp"
if [[ -n "${VPP_BIN:-}" &&
      "$(product_canonical_for_write "$VPP_BIN")" != "$vpp_bin" ]]; then
  echo "VPP_BIN must resolve to the verified artifact executable" >&2
  exit 2
fi
pid_file="$(product_validate_owned_child "$runtime_dir" owner.pid)" || exit 2
generation_file="$(product_validate_owned_child "$runtime_dir" generation)" || exit 2
api_socket="$(product_validate_owned_child "$runtime_dir" api.sock)" || exit 2
cli_socket="$(product_validate_owned_child "$runtime_dir" cli.sock)" || exit 2
stats_socket="$(product_validate_owned_child "$runtime_dir" stats.sock)" || exit 2
config="$(product_validate_owned_child "$runtime_dir" startup.conf)" || exit 2
while IFS= read -r entry; do
  case "$entry" in
    api.sock|cli.sock|stats.sock|owner.pid|generation|startup.conf) ;;
    *)
      echo "runtime contains an unowned entry; refusing cleanup: $entry" >&2
      exit 2
      ;;
  esac
done < <(find "$runtime_dir" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
if [[ ! -f "$pid_file" ]]; then
  echo "missing product VPP owner pid; refuse to guess a process" >&2
  exit 2
fi
if [[ ! -f "$generation_file" ]]; then
  echo "missing product VPP generation marker; refuse to stop an unowned runtime" >&2
  exit 2
fi
generation="$(tr -d '[:space:]' < "$generation_file")"
if [[ ! "$generation" =~ ^[1-9][0-9]*$ ]]; then
  echo "invalid product VPP generation marker" >&2
  exit 2
fi
pid="$(tr -d '[:space:]' < "$pid_file")"
if [[ ! "$pid" =~ ^[1-9][0-9]*$ || ! -r "/proc/$pid/exe" ]]; then
  echo "product VPP owner is not alive" >&2
  exit 1
fi
actual_exe="$(readlink -f "/proc/$pid/exe")"
expected_exe="$(product_canonical_existing "$vpp_bin")" || exit 2
if [[ "$actual_exe" != "$expected_exe" ]]; then
  echo "owner pid does not belong to VPP_BIN; refusing to stop it" >&2
  exit 2
fi
kill -TERM "$pid"
for _ in {1..50}; do
  if ! kill -0 "$pid" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if kill -0 "$pid" 2>/dev/null; then
  kill -KILL "$pid"
  for _ in {1..20}; do
    if ! kill -0 "$pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
fi
if kill -0 "$pid" 2>/dev/null; then
  echo "VPP process did not stop" >&2
  exit 1
fi

rm -f "$api_socket" "$cli_socket" "$stats_socket" "$pid_file" \
  "$generation_file" "$config"
rmdir "$runtime_dir"
echo "stopped_generation=$generation"
