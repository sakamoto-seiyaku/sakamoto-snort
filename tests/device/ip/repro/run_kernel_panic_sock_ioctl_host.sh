#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

# Prefer an explicit Linux adb to avoid wrappers that call adb.exe (WSL interop off).
if [[ -z "${ADB:-}" && -x "$HOME/.local/android/platform-tools/adb" ]]; then
  export ADB="$HOME/.local/android/platform-tools/adb"
fi

source "$SNORT_ROOT/dev/dev-android-device-lib.sh"

device_preflight

serial="$(adb_target_desc)"
run_id="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
records_dir="$SNORT_ROOT/tests/device/ip/records"
prefix="${run_id}_${serial}"

remote_path="/data/local/tmp/iptest_kernel_panic_sock_ioctl_repro.sh"
log_dir="${LOG_DIR:-/data/local/tmp/iptest_panic_repro}"

mkdir -p "$records_dir"

remote_env=""
append_remote_env_var() {
  local name="$1"
  if [[ -n "${!name+x}" ]]; then
    printf -v remote_env '%s %s=%q' "$remote_env" "$name" "${!name}"
  fi
}

for name in \
  REPRO_MODE SKIP_RULES STOP_SNORT SERVER_MODE \
  SNORT_SOCKET SNORT_BIN SNORT_PROC_NAME \
  IPTEST_NS IPTEST_VETH0 IPTEST_VETH1 IPTEST_NET_CIDR IPTEST_HOST_IP IPTEST_PEER_IP IPTEST_UID \
  IPTEST_PERF_PORT IPTEST_PERF_SECONDS IPTEST_PERF_CHUNK_BYTES IPTEST_PERF_COMPARE \
  IPTEST_PERF_TRAFFIC_RULES IPTEST_PERF_BG_TOTAL IPTEST_PERF_BG_UIDS IPTEST_PERF_BG_UID_BASE \
  LOAD_WRAPPER LOAD_MODE LOAD_HEAD_BYTES LOAD_TIMEOUT_SECONDS LOAD_MAX_ITERS LOG_SYNC_EVERY
do
  append_remote_env_var "$name"
done

echo "== push device-side repro =="
adb_push_file "$SNORT_ROOT/tests/archive/device/ip/repro/kernel_panic_sock_ioctl_device_repro.sh" "$remote_path" >/dev/null
adb_su "chmod 755 \"$remote_path\""

echo "== run on-device repro (serial=$serial run_id=$run_id) =="
set +e
adb_su "${remote_env# } RUN_ID=\"$run_id\" LOG_DIR=\"$log_dir\" \"$remote_path\""
rc=$?
set -e
echo "device repro rc=$rc (non-zero is expected if device rebooted mid-run)"

echo "== wait for device to come back (if rebooted) =="
deadline=$((SECONDS + 300))
while :; do
  state="$(adb_cmd get-state 2>/dev/null | tr -d '\r\n' || true)"
  if [[ "$state" == "device" ]]; then
    break
  fi
  if (( SECONDS >= deadline )); then
    echo "FATAL: timeout waiting for device to reconnect (serial=$serial)" >&2
    exit 1
  fi
  sleep 2
done

deadline=$((SECONDS + 120))
while :; do
  if adb_su "id" 2>/dev/null | tr -d '\r' | grep -q "uid=0(root)"; then
    break
  fi
  if (( SECONDS >= deadline )); then
    echo "FATAL: timeout waiting for root su after reconnect (serial=$serial)" >&2
    exit 1
  fi
  sleep 2
done

echo "== collect logs =="
{
  echo "serial=$serial"
  echo "run_id=$run_id"
  echo "sys.boot.reason=$(adb_cmd shell getprop sys.boot.reason 2>/dev/null | tr -d '\r\n' || true)"
  echo "sys.boot.reason.last=$(adb_cmd shell getprop sys.boot.reason.last 2>/dev/null | tr -d '\r\n' || true)"
  echo "fingerprint=$(adb_cmd shell getprop ro.build.fingerprint 2>/dev/null | tr -d '\r\n' || true)"
  echo "uname=$(adb_cmd shell uname -a 2>/dev/null | tr -d '\r' || true)"
} >"$records_dir/${prefix}_boot.txt"

adb_su "cat /sys/fs/pstore/console-ramoops-0 2>/dev/null || true" >"$records_dir/${prefix}_console-ramoops-0.txt"

set +e
adb_cmd exec-out "su 0 sh -c 'cat /sys/fs/pstore/pmsg-ramoops-0 2>/dev/null || true'" >"$records_dir/${prefix}_pmsg-ramoops-0.bin"
set -e

{
  echo "== $log_dir/last_step.txt =="
  adb_su "cat \"$log_dir/last_step.txt\" 2>/dev/null || true"
  echo ""
  echo "== $log_dir/last_iter.txt =="
  adb_su "cat \"$log_dir/last_iter.txt\" 2>/dev/null || true"
  echo ""
  echo "== $log_dir/last_cmd.txt =="
  adb_su "cat \"$log_dir/last_cmd.txt\" 2>/dev/null || true"
  echo ""
  echo "== $log_dir/last_load.txt =="
  adb_su "cat \"$log_dir/last_load.txt\" 2>/dev/null || true"
} >"$records_dir/${prefix}_device-last.txt"

adb_su "cat \"$log_dir/latest.log\" 2>/dev/null || true" >"$records_dir/${prefix}_device-repro.log"

echo "OK: wrote records:"
echo "  - $records_dir/${prefix}_boot.txt"
echo "  - $records_dir/${prefix}_console-ramoops-0.txt"
echo "  - $records_dir/${prefix}_pmsg-ramoops-0.bin"
echo "  - $records_dir/${prefix}_device-last.txt"
echo "  - $records_dir/${prefix}_device-repro.log"
