#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-69 product VPN RuntimeService evidence matrix.
#
# This matrix verifies the product app path, not the historical vpn-lite POC:
# APK build/install, VPN profile start, native control surface, adapter
# counters, Android VPN/tun0 presence, and final no-residue cleanup.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

# Force device operations through the repo-local wrapper.
export ADB="${repo_root}/dev/adb"
source "${repo_root}/dev/dev-android-device-lib.sh"

PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s69-product-vpn-runtime-matrix}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"
S69_APK_VARIANT="${S69_APK_VARIANT:-${ANDROID_RUNTIME_APK_VARIANT:-debug}}"
case "$S69_APK_VARIANT" in
  debug)
    APK="${APK:-${repo_root}/app/android-runtime/build/outputs/sakamoto-runtime-debug.apk}"
    S69_BUILD_SCRIPT="${S69_BUILD_SCRIPT:-app/android-runtime/scripts/build-debug-apk.sh}"
    ;;
  release-candidate)
    APK="${APK:-${repo_root}/app/android-runtime/build/outputs/sakamoto-runtime-release-candidate.apk}"
    S69_BUILD_SCRIPT="${S69_BUILD_SCRIPT:-app/android-runtime/scripts/build-release-candidate-apk.sh}"
    ;;
  *)
    echo "unsupported S69_APK_VARIANT: $S69_APK_VARIANT" >&2
    exit 1
    ;;
esac
S69_PRODUCT_BUILD_APK="${S69_PRODUCT_BUILD_APK:-1}"
S69_PRODUCT_INSTALL_APK="${S69_PRODUCT_INSTALL_APK:-1}"
S69_PRODUCT_FORWARD_PORT="${S69_PRODUCT_FORWARD_PORT:-60619}"
S69_PRODUCT_RESTART_CYCLES="${S69_PRODUCT_RESTART_CYCLES:-2}"
S69_PRODUCT_CLEANUP_ON_EXIT="${S69_PRODUCT_CLEANUP_ON_EXIT:-1}"
STATE_PATH="files/runtime-state/snapshot.properties"
LOG_PATH="files/logs/runtime-service.log"
VPN_HEV_LOG_PATH="files/profiles/vpn/vpp/logs/vpn-hev.log"
VPN_HEV_PROTECT_LOG_PATH="files/profiles/vpn/vpp/logs/vpn-hev-protect.log"
CONTROL_SOCKET="sucre-snort-control-vnext"

mkdir -p "$RESULT_DIR"

kv() {
  printf '%s=%s\n' "$1" "$2"
}

section() {
  printf '\n## %s\n' "$1"
}

cleanup() {
  if [[ "$S69_PRODUCT_CLEANUP_ON_EXIT" != "1" ]]; then
    return
  fi
  adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStop true >/dev/null 2>&1 || true
}
trap cleanup EXIT

read_snapshot() {
  app_file_cat "$STATE_PATH" | tr -d '\r' || true
}

app_file_path() {
  printf '/data/user/0/%s/%s\n' "$PACKAGE" "$1"
}

app_file_cat() {
  local relative_path="$1"
  adb_cmd shell run-as "$PACKAGE" cat "$relative_path" 2>/dev/null \
    || adb_su "cat $(shell_single_quote "$(app_file_path "$relative_path")") 2>/dev/null" \
    || true
}

snapshot_value() {
  local key="$1"
  awk -F= -v key="$key" '$1 == key { print $2; found=1 } END { if (!found) exit 1 }'
}

wait_for_snapshot_field() {
  local key="$1"
  local expected="$2"
  local out_file="$3"
  local attempts="${4:-30}"
  local state=""
  for _ in $(seq 1 "$attempts"); do
    state="$(read_snapshot)"
    printf '%s\n' "$state" >"$out_file"
    if grep -Fxq "${key}=${expected}" <<<"$state"; then
      printf '%s\n' "$state"
      return 0
    fi
    sleep 1
  done
  return 1
}

assert_no_native_residue() {
  local out_file="$1"
  local native=""
  native="$(adb_cmd shell pidof sucre-snortd libsucre_snortd.so vpp hev-socks5-tunnel 2>/dev/null \
    | tr -d '\r' || true)"
  printf '%s\n' "$native" >"$out_file"
  [[ -z "$native" ]]
}

assert_no_tun0_residue() {
  local out_file="$1"
  adb_cmd shell su 0 ip link show tun0 >"$out_file" 2>&1 || true
  if grep -Eq '^[0-9]+: tun0[:@]' "$out_file"; then
    return 1
  fi
  return 0
}

assert_tun0_present() {
  local out_file="$1"
  adb_cmd shell dumpsys connectivity >"$out_file" 2>&1
  grep -Eq "VPN:${PACKAGE}" "$out_file"
  grep -Eq "InterfaceName: tun0" "$out_file"
}

assert_no_connectivity_residue() {
  local out_file="$1"
  adb_cmd shell dumpsys connectivity >"$out_file" 2>&1
  ! grep -Eq "VPN:${PACKAGE}|InterfaceName: tun0" "$out_file"
}

section "matrix_contract"
require_adb_device
kv "matrix" "SAKAMOTO-69-product-vpn-runtime"
kv "resultDir" "${RESULT_DIR#${repo_root}/}"
kv "adbWrapper" "./dev/adb"
kv "device" "$(adb_target_desc)"
kv "package" "$PACKAGE"
kv "activity" "$ACTIVITY"
kv "apkVariant" "$S69_APK_VARIANT"
kv "productRuntimeServiceVpnAdapter" "claimed"
kv "POC_ONLY" "false"
kv "s69Done" "not_claimed"

section "build_install"
if [[ "$S69_PRODUCT_BUILD_APK" == "1" ]]; then
  kv "build.command" "bash $S69_BUILD_SCRIPT"
  (cd "$repo_root" && bash "$S69_BUILD_SCRIPT") \
    >"${RESULT_DIR}/build-apk.log" 2>&1
  kv "build.result" "PASS"
fi
[[ -f "$APK" ]] || {
  kv "apk.exists" "false"
  echo "missing APK: $APK" >&2
  exit 1
}
kv "apk" "${APK#${repo_root}/}"
kv "apk.sha256" "$(sha256sum "$APK" | awk '{print $1}')"
if [[ "$S69_PRODUCT_INSTALL_APK" == "1" ]]; then
  adb_cmd install -r "$APK" >"${RESULT_DIR}/install.log" 2>&1
  kv "install.result" "PASS"
fi

section "start_vpn"
adb_cmd shell am force-stop "$PACKAGE" >/dev/null
adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStart true --es runtimeProfile vpn \
  >"${RESULT_DIR}/start.intent.log" 2>&1
state="$(wait_for_snapshot_field state running "${RESULT_DIR}/snapshot.running" 45)" || {
  kv "start.result" "FAIL"
  cat "${RESULT_DIR}/snapshot.running" >&2
  exit 1
}
printf '%s\n' "$state" | grep -Fxq "profile=vpn"
printf '%s\n' "$state" | grep -Fxq "health=ok"
printf '%s\n' "$state" | grep -Fxq "coreHealth=ok"
printf '%s\n' "$state" | grep -Fxq "adapterReadiness=vpn-tun-hev"
kv "start.result" "PASS"
kv "snapshot.state" "running"
kv "snapshot.profile" "vpn"
kv "snapshot.adapterReadiness" "vpn-tun-hev"
kv "snapshot.pid" "$(printf '%s\n' "$state" | snapshot_value pid)"

section "android_vpn_network"
assert_tun0_present "${RESULT_DIR}/tun0.running"
kv "tun0.running" "PASS"
adb_cmd shell dumpsys connectivity >"${RESULT_DIR}/connectivity.running" 2>&1
grep -q "VPN:${PACKAGE}" "${RESULT_DIR}/connectivity.running"
grep -q "InterfaceName: tun0" "${RESULT_DIR}/connectivity.running"
kv "connectivity.vpnNetwork" "PASS"

section "runtime_log"
app_file_cat "$LOG_PATH" >"${RESULT_DIR}/runtime-service.log"
grep -q "vpn_tun_control_ready=ok" "${RESULT_DIR}/runtime-service.log"
grep -q "vpn_tun_control_attach=ok adapter=vpn-tun-hev" "${RESULT_DIR}/runtime-service.log"
grep -q "vpn_hev_transport=ok" "${RESULT_DIR}/runtime-service.log"
grep -q "runtime_state=running profile=vpn health=ok" "${RESULT_DIR}/runtime-service.log"
kv "runtimeLog.vpnStartup" "PASS"

section "control_socket"
adb_cmd forward "tcp:${S69_PRODUCT_FORWARD_PORT}" "localabstract:${CONTROL_SOCKET}" \
  >"${RESULT_DIR}/adb-forward.log" 2>&1
python3 - "$S69_PRODUCT_FORWARD_PORT" "$RESULT_DIR" <<'PY'
import json
import pathlib
import socket
import sys

port = int(sys.argv[1])
result_dir = pathlib.Path(sys.argv[2])

def frame(obj):
    payload = json.dumps(obj, separators=(",", ":")).encode()
    return str(len(payload)).encode() + b":" + payload + b","

def read_netstring(sock):
    digits = bytearray()
    while True:
        byte = sock.recv(1)
        if not byte:
            raise RuntimeError("eof before length")
        if byte == b":":
            break
        digits += byte
    length = int(digits)
    payload = bytearray()
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            raise RuntimeError("eof in payload")
        payload += chunk
    if sock.recv(1) != b",":
        raise RuntimeError("missing netstring comma")
    return json.loads(payload.decode())

with socket.create_connection(("127.0.0.1", port), timeout=2.5) as sock:
    responses = {}
    for name, request in {
        "hello": {"id": 1, "cmd": "HELLO", "args": {}},
        "vpn_tun_status": {"id": 2, "cmd": "VPN_TUN.STATUS", "args": {}},
        "policy_status": {"id": 3, "cmd": "POLICY.STATUS", "args": {}},
    }.items():
        sock.sendall(frame(request))
        response = read_netstring(sock)
        responses[name] = response
        (result_dir / f"{name}.json").write_text(
            json.dumps(response, indent=2, sort_keys=True) + "\n")

hello = responses["hello"]
assert hello["ok"] is True
capabilities = set(hello["result"]["capabilities"])
for capability in [
    "snort10-base",
    "packet-adapter-vpn-tun-hev",
    "vpn-tun-fd-handoff",
    "vpn-tun-transport-fd-handoff",
    "vpn-tun-runtime-counters",
    "packet-policy-control",
]:
    assert capability in capabilities, capability

status = responses["vpn_tun_status"]
assert status["ok"] is True
counters = status["result"]
assert counters["packetsSeen"] > 0
assert counters["forwardedPackets"] > 0
assert counters["uidUnknownFallbackPackets"] > 0

policy = responses["policy_status"]
assert policy["ok"] is True
PY
kv "control.HELLO" "PASS"
kv "control.VPN_TUN.STATUS" "PASS"
kv "control.POLICY.STATUS" "PASS"

section "protect_anti_loop"
protect_ok=0
for _ in $(seq 1 20); do
  app_file_cat "$VPN_HEV_PROTECT_LOG_PATH" >"${RESULT_DIR}/vpn-hev-protect.log"
  app_file_cat "$VPN_HEV_LOG_PATH" >"${RESULT_DIR}/vpn-hev.log"
  if grep -Eq 'protect fd=[0-9]+ result=1' "${RESULT_DIR}/vpn-hev-protect.log" \
      && grep -q 'protect callback enabled' "${RESULT_DIR}/vpn-hev.log"; then
    protect_ok=1
    break
  fi
  sleep 1
done
if [[ "$protect_ok" != "1" ]]; then
  kv "protect.result" "FAIL"
  echo "missing product HEV VpnService.protect success evidence" >&2
  exit 1
fi
kv "protect.callback" "PASS"
kv "protect.fdResult" "PASS"
kv "protect.result" "PASS"

section "cleanup"
adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStop true >"${RESULT_DIR}/stop.intent.log" 2>&1
stopped="$(wait_for_snapshot_field state stopped "${RESULT_DIR}/snapshot.stopped" 30)" || {
  kv "cleanup.result" "FAIL"
  cat "${RESULT_DIR}/snapshot.stopped" >&2
  exit 1
}
printf '%s\n' "$stopped" | grep -Fxq "mayBeActive=false"
printf '%s\n' "$stopped" | grep -Fxq "adapterReadiness=unavailable"
assert_no_native_residue "${RESULT_DIR}/native-residue.after-stop"
assert_no_tun0_residue "${RESULT_DIR}/tun0.after-stop"
assert_no_connectivity_residue "${RESULT_DIR}/connectivity.after-stop"
kv "cleanup.result" "PASS"

section "restart_cleanup_loop"
kv "restart.cycles" "$S69_PRODUCT_RESTART_CYCLES"
for cycle in $(seq 1 "$S69_PRODUCT_RESTART_CYCLES"); do
  cycle_dir="${RESULT_DIR}/restart-cycle-${cycle}"
  mkdir -p "$cycle_dir"
  adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStart true --es runtimeProfile vpn \
    >"${cycle_dir}/start.intent.log" 2>&1
  cycle_running="$(wait_for_snapshot_field state running "${cycle_dir}/snapshot.running" 45)" || {
    kv "restart.${cycle}.start" "FAIL"
    cat "${cycle_dir}/snapshot.running" >&2
    exit 1
  }
  printf '%s\n' "$cycle_running" | grep -Fxq "profile=vpn"
  printf '%s\n' "$cycle_running" | grep -Fxq "health=ok"
  printf '%s\n' "$cycle_running" | grep -Fxq "adapterReadiness=vpn-tun-hev"
  assert_tun0_present "${cycle_dir}/tun0.running"
  adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStop true \
    >"${cycle_dir}/stop.intent.log" 2>&1
  cycle_stopped="$(wait_for_snapshot_field state stopped "${cycle_dir}/snapshot.stopped" 30)" || {
    kv "restart.${cycle}.stop" "FAIL"
    cat "${cycle_dir}/snapshot.stopped" >&2
    exit 1
  }
  printf '%s\n' "$cycle_stopped" | grep -Fxq "mayBeActive=false"
  printf '%s\n' "$cycle_stopped" | grep -Fxq "adapterReadiness=unavailable"
  assert_no_native_residue "${cycle_dir}/native-residue.after-stop"
  assert_no_tun0_residue "${cycle_dir}/tun0.after-stop"
  assert_no_connectivity_residue "${cycle_dir}/connectivity.after-stop"
  kv "restart.${cycle}.result" "PASS"
done
kv "restart.result" "PASS"

section "matrix_result"
kv "matrix.result" "PASS"
kv "matrix.s69Done" "not_claimed"
