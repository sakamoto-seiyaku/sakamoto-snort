#!/bin/bash

set -euo pipefail

CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$CASE_DIR/../lib.sh"

log_section "iprules vNext smoke (tier1)"

VNEXT_PORT="${VNEXT_PORT:-60607}"
SNORT_CTL="${SNORT_CTL:-}"

find_snort_ctl() {
  if [[ -n "$SNORT_CTL" ]]; then
    if [[ -x "$SNORT_CTL" ]]; then
      printf '%s\n' "$SNORT_CTL"
      return 0
    fi
    echo "❌ sucre-snort-ctl 不可执行: $SNORT_CTL" >&2
    return 1
  fi

  local candidates=(
    "$SNORT_ROOT/build-output/cmake/dev-debug/tests/host/sucre-snort-ctl"
    "$SNORT_ROOT/build-output/cmake/dev-relwithdebinfo/tests/host/sucre-snort-ctl"
    "$SNORT_ROOT/build-output/cmake/host-asan-clang/tests/host/sucre-snort-ctl"
  )

  local c
  for c in "${candidates[@]}"; do
    if [[ -x "$c" ]]; then
      printf '%s\n' "$c"
      return 0
    fi
  done

  echo "❌ 未找到 sucre-snort-ctl；请先构建 clang host preset（例如: cmake --build --preset dev-debug --target sucre-snort-ctl）" >&2
  return 1
}

ctl_cmd() {
  local cmd="$1"
  local args_json="${2:-}"
  if [[ -n "$args_json" ]]; then
    "$SNORT_CTL" --tcp "127.0.0.1:${VNEXT_PORT}" --compact "$cmd" "$args_json"
  else
    "$SNORT_CTL" --tcp "127.0.0.1:${VNEXT_PORT}" --compact "$cmd"
  fi
}

assert_json_pred() {
  local desc="$1"
  local json="$2"
  local py="$3"
  if printf '%s\n' "$json" | python3 -c "$py" >/dev/null 2>&1; then
    log_pass "$desc"
    return 0
  fi
  log_fail "$desc"
  printf '%s\n' "$json" | head -n 3 | sed 's/^/    /'
  return 1
}

if ! init_test_env; then
  exit 2
fi

if ! check_control_vnext_forward "$VNEXT_PORT"; then
  log_info "设置 vNext adb forward..."
  setup_control_vnext_forward "$VNEXT_PORT"
fi

SNORT_CTL="$(find_snort_ctl)" || exit 2
log_info "sucre-snort-ctl: $SNORT_CTL"

hello="$(ctl_cmd HELLO 2>/dev/null || true)"
assert_json_pred "VNX-01 HELLO ok" "$hello" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert j["result"]["protocol"]=="control-vnext"'

apps="$(ctl_cmd APPS.LIST '{"query":"com.","limit":50}' 2>/dev/null || true)"
app_uid="$(APPS_JSON="$apps" python3 - <<'PY'
import os, json
j = json.loads(os.environ["APPS_JSON"])
apps = j.get("result", {}).get("apps", [])
print(apps[0]["uid"] if apps else "")
PY
)" || app_uid=""

if [[ -z "$app_uid" ]]; then
  echo "SKIP: no apps found for selector" >&2
  exit 10
fi
log_info "target uid=$app_uid"

resetall="$(ctl_cmd RESETALL 2>/dev/null || true)"
assert_json_pred "VNX-02 RESETALL ok" "$resetall" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

preflight="$(ctl_cmd IPRULES.PREFLIGHT 2>/dev/null || true)"
assert_json_pred "VNX-03 IPRULES.PREFLIGHT shape" "$preflight" \
  'import sys,json; j=json.load(sys.stdin); r=j["result"]; assert j["ok"] is True; assert "summary" in r and "limits" in r and "warnings" in r and "violations" in r'

apply="$(ctl_cmd IPRULES.APPLY "{\"app\":{\"uid\":${app_uid}},\"rules\":[{\"clientRuleId\":\"g1:r1\",\"action\":\"block\",\"priority\":10,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"1.2.3.4/24\",\"sport\":\"any\",\"dport\":\"443\"},{\"clientRuleId\":\"g1:r2\",\"action\":\"block\",\"priority\":11,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"2.3.4.5/24\",\"sport\":\"any\",\"dport\":\"443\"}]}" 2>/dev/null || true)"
assert_json_pred "VNX-04 IPRULES.APPLY returns mapping" "$apply" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; rules=j["result"]["rules"]; assert len(rules)==2; assert set([r["clientRuleId"] for r in rules])==set(["g1:r1","g1:r2"]); assert all(isinstance(r["ruleId"], int) for r in rules); assert all(isinstance(r["matchKey"], str) for r in rules)'

printed="$(ctl_cmd IPRULES.PRINT "{\"app\":{\"uid\":${app_uid}}}" 2>/dev/null || true)"
assert_json_pred "VNX-05 IPRULES.PRINT sorted + canonical CIDR" "$printed" \
  'import sys,json; j=json.load(sys.stdin); rules=j["result"]["rules"]; ids=[r["ruleId"] for r in rules]; assert len(rules)==2; assert ids==sorted(ids); assert any(r["dst"]=="1.2.3.0/24" for r in rules); assert any("dst=1.2.3.0/24" in r["matchKey"] for r in rules)'

log_pass "iprules vNext smoke ok"
exit 0

