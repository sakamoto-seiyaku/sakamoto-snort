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
assert r["maxRequestBytes"] > 0
assert r["maxResponseBytes"] > 0
PY
  echo "FAIL: HELLO shape" >&2
  printf '%s\n' "$hello" >&2
  exit 1
}
echo "PASS: HELLO shape"

assert_ok "RESETALL no-op" "$(ctl_cmd RESETALL)"
assert_ok "QUIT" "$(ctl_cmd QUIT)"
echo "dx-snort10-base: PASS"
