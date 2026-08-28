#!/usr/bin/env bash
set -euo pipefail

# Inspect only the generation owner and its runtime directory.  This checker
# intentionally does not use process-name/command-line matching: an unrelated VPP
# process must never be treated as product residue or stopped by this lane.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$repo_root/tools/product/path-helpers.sh"
product_prepare_build_output || exit 2
artifact_root="$(product_validate_artifact_root \
  "${PRODUCT_ARTIFACT_DIR:-$repo_root/build-output/product-vpp-host}")" || exit 2
runtime_dir="$(product_validate_runtime_root \
  "${PRODUCT_RUNTIME_DIR:-$repo_root/build-output/product-vpp-runtime}")" || exit 2
vpp_bin="$artifact_root/bin/vpp"
if [[ -n "${VPP_BIN:-}" &&
      "$(product_canonical_for_write "$VPP_BIN")" != "$vpp_bin" ]]; then
  echo "VPP_BIN must resolve to the verified artifact executable" >&2
  exit 2
fi
expected_exe="$(product_canonical_for_write "$vpp_bin")" || exit 2

if [[ ! -e "$runtime_dir" ]]; then
  echo "vpp_process=absent"
  echo "runtime_directory=absent"
  echo "residue=clean"
  exit 0
fi
if [[ ! -d "$runtime_dir" ]]; then
  echo "runtime path is not a directory: $runtime_dir" >&2
  exit 1
fi

pid_file="$(product_validate_owned_child "$runtime_dir" owner.pid)" || exit 2
generation_file="$(product_validate_owned_child "$runtime_dir" generation)" || exit 2
api_socket="$(product_validate_owned_child "$runtime_dir" api.sock)" || exit 2
cli_socket="$(product_validate_owned_child "$runtime_dir" cli.sock)" || exit 2
stats_socket="$(product_validate_owned_child "$runtime_dir" stats.sock)" || exit 2
config="$(product_validate_owned_child "$runtime_dir" startup.conf)" || exit 2

residue=0
process_state=absent
owner_pid_state=absent
if [[ -e "$pid_file" ]]; then
  owner_pid_state=present
  residue=1
  pid="$(tr -d '[:space:]' < "$pid_file")"
  if [[ "$pid" =~ ^[1-9][0-9]*$ && -r "/proc/$pid/exe" ]]; then
    actual_exe="$(readlink -f "/proc/$pid/exe")"
    if [[ "$actual_exe" == "$expected_exe" ]]; then
      process_state="live(pid=$pid)"
    else
      process_state="foreign(pid=$pid)"
    fi
  elif [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then
    process_state="owner-pid-stale(pid=$pid)"
  else
    process_state=owner-pid-invalid
  fi
fi

generation_state=absent
if [[ -e "$generation_file" ]]; then
  generation="$(tr -d '[:space:]' < "$generation_file")"
  if [[ "$generation" =~ ^[1-9][0-9]*$ ]]; then
    generation_state="present($generation)"
  else
    generation_state=invalid
  fi
  residue=1
fi

socket_state() {
  local path="$1"
  if [[ ! -e "$path" ]]; then
    printf 'absent\n'
    return
  fi
  if [[ -S "$path" ]]; then
    printf 'present\n'
  else
    printf 'wrong-type\n'
  fi
}

api_state="$(socket_state "$api_socket")"
cli_state="$(socket_state "$cli_socket")"
stats_state="$(socket_state "$stats_socket")"
for state in "$api_state" "$cli_state" "$stats_state"; do
  if [[ "$state" != absent ]]; then
    residue=1
  fi
done
config_state=absent
if [[ -e "$config" ]]; then
  residue=1
  if [[ -f "$config" ]]; then
    config_state=present
  else
    config_state=wrong-type
  fi
fi

unknown_entries=()
while IFS= read -r entry; do
  case "$entry" in
    api.sock|cli.sock|stats.sock|owner.pid|generation|startup.conf) ;;
    '') ;;
    *) unknown_entries+=("$entry") ;;
  esac
done < <(find "$runtime_dir" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
if [[ "${#unknown_entries[@]}" -ne 0 ]]; then
  residue=1
fi
if [[ "$residue" -eq 0 ]]; then
  runtime_state=empty
else
  runtime_state=nonempty
fi

echo "vpp_process=$process_state"
echo "owner_pid=$owner_pid_state"
echo "generation_marker=$generation_state"
echo "api_socket=$api_state"
echo "cli_socket=$cli_state"
echo "stats_socket=$stats_state"
echo "startup_config=$config_state"
echo "runtime_directory=$runtime_state"
if [[ "${#unknown_entries[@]}" -ne 0 ]]; then
  printf 'unknown_runtime_entries=%s\n' "${unknown_entries[*]}"
fi
if [[ "$residue" -ne 0 ]]; then
  echo "residue=present" >&2
  exit 1
fi
echo "residue=clean"
