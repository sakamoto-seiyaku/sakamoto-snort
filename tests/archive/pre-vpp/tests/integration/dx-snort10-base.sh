#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$SCRIPT_DIR/../.."

VNEXT_PORT="${VNEXT_PORT:-60607}"
SNORT_CTL="${SNORT_CTL:-}"
SNORT_PROC_NAMES=("sucre-snort-dev" "libsucre_snortd.so" "sucre-snort-ndk")

show_help() {
  cat <<'USAGE'
Usage: dx-snort10-base.sh [options]

Options:
  --serial <serial>  Select Android device serial.
  --ctl <path>       Use a specific sucre-snort-ctl binary.
  --port <port>      Host TCP port forwarded to sucre-snort-control-vnext.
  -h, --help         Show this help.

This gate deploys and starts the NDK daemon, verifies the pre-SNORT-12
NFQUEUE pass-through base, sends QUIT, asserts no stale daemon remains, then
redeploys and verifies restart readiness.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial)
      ADB_SERIAL="$2"
      export ADB_SERIAL
      shift 2
      ;;
    --ctl)
      SNORT_CTL="$2"
      shift 2
      ;;
    --port)
      VNEXT_PORT="$2"
      shift 2
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      show_help >&2
      exit 1
      ;;
  esac
done

source "$SNORT_ROOT/dev/dev-android-device-lib.sh"

blocked() {
  echo "BLOCKED: $1" >&2
  exit 77
}

find_snort_ctl() {
  if [[ -n "$SNORT_CTL" ]]; then
    [[ -x "$SNORT_CTL" ]] && printf '%s\n' "$SNORT_CTL" && return 0
    return 1
  fi

  local candidate
  for candidate in \
    "$SNORT_ROOT/build-output/cmake/dev-debug/tests/host/sucre-snort-ctl" \
    "$SNORT_ROOT/build-output/cmake/dev-relwithdebinfo/tests/host/sucre-snort-ctl" \
    "$SNORT_ROOT/build-output/cmake/host-asan-clang/tests/host/sucre-snort-ctl"
  do
    [[ -x "$candidate" ]] && printf '%s\n' "$candidate" && return 0
  done
  return 1
}

if ! command -v python3 >/dev/null 2>&1; then
  blocked "python3 not found"
fi

SNORT_CTL="$(find_snort_ctl)" || {
  blocked "sucre-snort-ctl not found; build dev-debug or pass --ctl"
}

device_preflight
echo "PASS: device preflight ($(adb_target_desc))"

bash "$SNORT_ROOT/dev/dev-deploy.sh" --serial "$(adb_target_desc)"

setup_control_vnext_forward "$VNEXT_PORT"
trap 'remove_control_vnext_forward "$VNEXT_PORT" >/dev/null 2>&1 || true' EXIT

ctl_cmd() {
  "$SNORT_CTL" --tcp "127.0.0.1:${VNEXT_PORT}" --compact "$@"
}

assert_ok() {
  local label="$1"
  local json="$2"
  JSON="$json" python3 - <<'PY' || {
import json
import os
data = os.environ["JSON"]
j = json.loads(data)
assert j.get("ok") is True
PY
    echo "FAIL: $label" >&2
    printf '%s\n' "$json" >&2
    exit 1
  }
  echo "PASS: $label"
}

daemon_pids() {
  local name
  for name in "${SNORT_PROC_NAMES[@]}"; do
    adb_su "pidof $name 2>/dev/null || true" | tr -d '\r'
  done | tr ' ' '\n' | awk 'NF' | sort -u
}

assert_single_daemon_running() {
  local label="$1"
  local -n out_pid_ref="$2"
  local pids
  mapfile -t pids < <(daemon_pids)
  if [[ ${#pids[@]} -ne 1 ]]; then
    echo "FAIL: $label expected exactly one daemon process, found ${#pids[@]}" >&2
    printf '  pid=%s\n' "${pids[@]}" >&2
    exit 1
  fi
  out_pid_ref="${pids[0]}"
  echo "PASS: $label daemon pid=${out_pid_ref}"
}

assert_no_daemon_process() {
  local label="$1"
  local pids=""
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    pids="$(daemon_pids | paste -sd ' ' -)"
    [[ -z "$pids" ]] && {
      echo "PASS: $label no stale daemon process"
      return 0
    }
    sleep 1
  done

  echo "FAIL: $label stale daemon process remains: $pids" >&2
  exit 1
}

assert_family_hooks() {
  local executable="$1"
  local label="$2"
  local rules missing=0
  rules="$(adb_su "$executable -S 2>/dev/null" | tr -d '\r')"

  for rule in \
    "-N sucre-snort_INPUT" \
    "-N sucre-snort_OUTPUT" \
    "-A INPUT -j sucre-snort_INPUT" \
    "-A OUTPUT -j sucre-snort_OUTPUT" \
    "-A sucre-snort_INPUT -i lo -j RETURN" \
    "-A sucre-snort_OUTPUT -o lo -j RETURN"
  do
    if ! printf '%s\n' "$rules" | grep -Fqx -- "$rule"; then
      echo "missing $executable rule: $rule" >&2
      missing=1
    fi
  done

  for rule in \
    "-A sucre-snort_INPUT -p udp -m udp --sport 53 -j RETURN" \
    "-A sucre-snort_OUTPUT -p udp -m udp --dport 53 -j RETURN" \
    "-A sucre-snort_INPUT -p tcp -m tcp --sport 53 -j RETURN" \
    "-A sucre-snort_OUTPUT -p tcp -m tcp --dport 53 -j RETURN" \
    "-A sucre-snort_INPUT -p udp -m udp --sport 853 -j RETURN" \
    "-A sucre-snort_OUTPUT -p udp -m udp --dport 853 -j RETURN" \
    "-A sucre-snort_INPUT -p tcp -m tcp --sport 853 -j RETURN" \
    "-A sucre-snort_OUTPUT -p tcp -m tcp --dport 853 -j RETURN" \
    "-A sucre-snort_INPUT -p udp -m udp --sport 5353 -j RETURN" \
    "-A sucre-snort_OUTPUT -p udp -m udp --dport 5353 -j RETURN" \
    "-A sucre-snort_INPUT -p tcp -m tcp --sport 5353 -j RETURN" \
    "-A sucre-snort_OUTPUT -p tcp -m tcp --dport 5353 -j RETURN"
  do
    if ! printf '%s\n' "$rules" | grep -Fqx -- "$rule"; then
      echo "missing $label DNS bypass rule: $rule" >&2
      missing=1
    fi
  done

  if ! printf '%s\n' "$rules" | grep -Eq -- '^-A sucre-snort_INPUT -j NFQUEUE .*--queue-bypass' ||
     ! printf '%s\n' "$rules" | grep -Eq -- '^-A sucre-snort_OUTPUT -j NFQUEUE .*--queue-bypass'; then
    echo "missing $label NFQUEUE queue-bypass rules" >&2
    missing=1
  fi

  if [[ $missing -ne 0 ]]; then
    echo "FAIL: $label hooks" >&2
    printf '%s\n' "$rules" | grep sucre-snort >&2 || true
    exit 1
  fi
  echo "PASS: $label hooks"
}

assert_dual_stack_hooks() {
  assert_family_hooks "iptables" "IPv4"
  if adb_su "command -v ip6tables >/dev/null 2>&1"; then
    assert_family_hooks "ip6tables" "IPv6"
  else
    echo "SKIP: IPv6 hooks (ip6tables unavailable on device)"
  fi
}

assert_ipv4_traffic_best_effort() {
  if ! adb_cmd shell "command -v ping >/dev/null 2>&1"; then
    echo "BLOCKED: IPv4 traffic smoke needs ping on device" >&2
    exit 77
  fi

  if adb_cmd shell "ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1"; then
    echo "PASS: IPv4 traffic"
    return 0
  fi

  echo "BLOCKED: IPv4 traffic smoke could not reach 1.1.1.1 from device" >&2
  exit 77
}

assert_ipv6_traffic_best_effort() {
  if ! adb_su "command -v ip6tables >/dev/null 2>&1"; then
    echo "SKIP: IPv6 traffic (ip6tables unavailable on device)"
    return 0
  fi
  local route
  route="$(adb_cmd shell "ip -6 route show default 2>/dev/null" | tr -d '\r')"
  if [[ -z "$route" ]]; then
    echo "SKIP: IPv6 traffic (no default IPv6 route on device)"
    return 0
  fi

  local ping_cmd=""
  if adb_cmd shell "command -v ping6 >/dev/null 2>&1"; then
    ping_cmd="ping6 -c 1 -W 2 2606:4700:4700::1111"
  elif adb_cmd shell "command -v ping >/dev/null 2>&1"; then
    ping_cmd="ping -6 -c 1 -W 2 2606:4700:4700::1111"
  else
    echo "BLOCKED: IPv6 traffic smoke needs ping or ping6 on device" >&2
    exit 77
  fi

  if adb_cmd shell "$ping_cmd >/dev/null 2>&1"; then
    echo "PASS: IPv6 traffic"
    return 0
  fi

  echo "BLOCKED: IPv6 traffic smoke could not reach 2606:4700:4700::1111 from device" >&2
  exit 77
}

assert_hello_shape() {
  local label="$1"
  local hello
  hello="$(ctl_cmd HELLO)"
JSON="$hello" python3 - <<'PY' || {
import json
import os
j = json.loads(os.environ["JSON"])
assert j.get("ok") is True
r = j["result"]
assert r["protocol"] == "control-vnext"
assert r["protocolVersion"] == 1
assert r["framing"] == "netstring"
assert "snort10-base" in r.get("capabilities", [])
assert "nfqueue-pass-through" in r.get("capabilities", [])
assert r["maxRequestBytes"] > 0
assert r["maxResponseBytes"] > 0
PY
    echo "FAIL: $label HELLO shape" >&2
    printf '%s\n' "$hello" >&2
    exit 1
  }
  echo "PASS: $label HELLO shape"
}

first_pid=""
second_pid=""
assert_single_daemon_running "initial deploy/start" first_pid
assert_hello_shape "initial"
assert_dual_stack_hooks
assert_ipv4_traffic_best_effort
assert_ipv6_traffic_best_effort
assert_ok "RESETALL pass-through runtime" "$(ctl_cmd RESETALL)"
assert_ok "QUIT" "$(ctl_cmd QUIT)"
assert_no_daemon_process "QUIT"

bash "$SNORT_ROOT/dev/dev-deploy.sh" --serial "$(adb_target_desc)"
assert_single_daemon_running "restart" second_pid
assert_hello_shape "restart"

echo "dx-snort10-base: PASS"
