#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

# Prefer an explicit Linux adb to avoid wrappers that call adb.exe (WSL interop off).
if [[ -z "${ADB:-}" && -x "$HOME/.local/android/platform-tools/adb" ]]; then
  export ADB="$HOME/.local/android/platform-tools/adb"
fi

source "$SNORT_ROOT/dev/dev-android-device-lib.sh"

PROBE_ITERS="${PROBE_ITERS:-1}"
PROBE_IPV6="${PROBE_IPV6:-1}"

show_help() {
  cat <<EOF
Usage: $0 [options]

Options:
  --serial <serial>    Target device serial (required if multiple devices)
  --iters <n>          Probe iterations (default: \$PROBE_ITERS or 1)
  --ipv6 <0|1>         Enable IPv6 steps (default: \$PROBE_IPV6 or 1)
  -h, --help           Show help

Env:
  PROBE_ITERS, PROBE_IPV6  Same as flags
  ADB, ADB_SERIAL          Standard adb envs
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial)
      ADB_SERIAL="$2"
      export ADB_SERIAL
      shift 2
      ;;
    --iters)
      PROBE_ITERS="$2"
      shift 2
      ;;
    --ipv6)
      PROBE_IPV6="$2"
      shift 2
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      show_help >&2
      exit 1
      ;;
  esac
done

device_preflight

serial="$(adb_target_desc)"
run_id="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
records_dir="$SNORT_ROOT/tests/device/ip/records"
prefix="${run_id}_${serial}"

device_script_src="$SNORT_ROOT/tests/archive/device/ip/repro/ip_sock_ioctl_tier1_probe_device.sh"
remote_path="/data/local/tmp/iptest_ip_sock_ioctl_tier1_probe.sh"
remote_log_dir="/data/local/tmp/iptest_sock_ioctl_probe_${run_id}"

mkdir -p "$records_dir"

echo "== push device-side probe =="
adb_push_file "$device_script_src" "$remote_path" >/dev/null
adb_su "chmod 755 \"$remote_path\""

echo "== run on-device probe (serial=$serial run_id=$run_id iters=$PROBE_ITERS ipv6=$PROBE_IPV6) =="
set +e
adb_su "RUN_ID=\"$run_id\" LOG_DIR=\"$remote_log_dir\" PROBE_ITERS=\"$PROBE_ITERS\" PROBE_IPV6=\"$PROBE_IPV6\" \"$remote_path\""
rc=$?
set -e
echo "device probe rc=$rc (non-zero is expected if device rebooted mid-run)"

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
  echo "probe_rc=$rc"
  echo "probe_iters=$PROBE_ITERS"
  echo "probe_ipv6=$PROBE_IPV6"
  echo "sys.boot.reason=$(adb_cmd shell getprop sys.boot.reason 2>/dev/null | tr -d '\r\n' || true)"
  echo "sys.boot.reason.last=$(adb_cmd shell getprop sys.boot.reason.last 2>/dev/null | tr -d '\r\n' || true)"
  echo "fingerprint=$(adb_cmd shell getprop ro.build.fingerprint 2>/dev/null | tr -d '\r\n' || true)"
  echo "uname=$(adb_cmd shell uname -a 2>/dev/null | tr -d '\r' || true)"
  echo "uptime=$(adb_cmd shell cat /proc/uptime 2>/dev/null | tr -d '\r\n' || true)"
} >"$records_dir/${prefix}_boot.txt"

adb_su "cat /sys/fs/pstore/console-ramoops-0 2>/dev/null || true" >"$records_dir/${prefix}_console-ramoops-0.txt"

set +e
adb_cmd exec-out "su 0 sh -c 'cat /sys/fs/pstore/pmsg-ramoops-0 2>/dev/null || true'" >"$records_dir/${prefix}_pmsg-ramoops-0.bin"
set -e

adb_su "cat \"$remote_log_dir/last_step.txt\" 2>/dev/null || true" >"$records_dir/${prefix}_probe-last_step.txt"
adb_su "cat \"$remote_log_dir/last_cmd.txt\" 2>/dev/null || true" >"$records_dir/${prefix}_probe-last_cmd.txt"
adb_su "tail -200 \"$remote_log_dir/latest.log\" 2>/dev/null || true" >"$records_dir/${prefix}_probe.log.tail.txt"

echo "OK: wrote records:"
echo "  - $records_dir/${prefix}_boot.txt"
echo "  - $records_dir/${prefix}_console-ramoops-0.txt"
echo "  - $records_dir/${prefix}_pmsg-ramoops-0.bin"
echo "  - $records_dir/${prefix}_probe-last_step.txt"
echo "  - $records_dir/${prefix}_probe-last_cmd.txt"
echo "  - $records_dir/${prefix}_probe.log.tail.txt"

