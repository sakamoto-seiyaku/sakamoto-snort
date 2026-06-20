#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$SCRIPT_DIR/../.."
source "$SNORT_ROOT/dev/dev-android-device-lib.sh"

VNEXT_PORT="${VNEXT_PORT:-60607}"
SNORT_CTL="${SNORT_CTL:-$SNORT_ROOT/build-output/cmake/dev-debug/tests/host/sucre-snort-ctl}"

if [[ ! -x "$SNORT_CTL" ]]; then
  echo "BLOCKED: sucre-snort-ctl not found at $SNORT_CTL" >&2
  exit 1
fi

device_preflight
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
  echo "FAIL: HELLO shape" >&2
  printf '%s\n' "$hello" >&2
  exit 1
}
echo "PASS: HELLO shape"

assert_dual_stack_hooks
assert_ipv4_traffic_best_effort
assert_ok "RESETALL pass-through runtime" "$(ctl_cmd RESETALL)"
assert_ok "QUIT" "$(ctl_cmd QUIT)"
echo "dx-snort10-base: PASS"
