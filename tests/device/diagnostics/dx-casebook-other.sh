#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
EXPLICIT_IPTEST_UID="${IPTEST_UID-}"
EXPLICIT_IPTEST_APP_UID="${IPTEST_APP_UID-}"
source "$SNORT_ROOT/tests/device/ip/lib.sh"

DO_DEPLOY=1
CLEANUP_FORWARD=0
RUN_PERFMETRICS=1
RUN_LIMITS=1

VNEXT_PORT="${VNEXT_PORT:-60607}"
SNORT_CTL="${SNORT_CTL:-}"

PAYLOAD_PORT="${DX_OTHER_PAYLOAD_PORT:-4443}"
PAYLOAD_BYTES="${DX_OTHER_PAYLOAD_BYTES:-65536}"
DOMAIN_UNDER_COUNT="${DX_OTHER_DOMAIN_UNDER_COUNT:-3}"
DOMAIN_OVER_COUNT="${DX_OTHER_DOMAIN_OVER_COUNT:-1000001}"
DOMAIN_OVER_VALUE="${DX_OTHER_DOMAIN_OVER_VALUE:-x}"
IPRULES_UNDER_COUNT="${DX_OTHER_IPRULES_UNDER_COUNT:-1100}"
IPRULES_OVER_COUNT="${DX_OTHER_IPRULES_OVER_COUNT:-5001}"

PASSED=0
FAILED=0
SKIPPED=0
ORIG_PERF=""
TIER1_TABLE=""
MUTATED=0
CASEBOOK_IPRULES_UID=""

show_help() {
  cat <<USAGE
用法: dx-casebook-other.sh [选项]

选项:
  --serial <serial>       指定目标真机 serial
  --skip-deploy           跳过部署，复用当前真机守护进程
  --cleanup-forward       结束后移除 vNext adb forward
  --case <name>           perfmetrics|limits|all（默认: all）
  --ctl <path>            指定 sucre-snort-ctl 路径（默认自动探测）
  --port <port>           指定 host tcp port（默认: $VNEXT_PORT -> localabstract:sucre-snort-control-vnext）
  -h, --help              显示帮助

环境变量:
  IPTEST_UID                     指定 perfmetrics Tier-1 payload uid（默认: 2000/shell）
  IPTEST_APP_UID                 指定 IPRULES limits app uid；未设置时从 APPS.LIST 自动挑选
  DX_OTHER_PAYLOAD_BYTES          perfmetrics payload bytes（默认: $PAYLOAD_BYTES）
  DX_OTHER_DOMAIN_OVER_COUNT      DOMAINLISTS.IMPORT over-limit domains 数量（默认: $DOMAIN_OVER_COUNT）
  DX_OTHER_IPRULES_UNDER_COUNT    IPRULES warning rules 数量（默认: $IPRULES_UNDER_COUNT）
  DX_OTHER_IPRULES_OVER_COUNT     IPRULES hard-limit rules 数量（默认: $IPRULES_OVER_COUNT）

说明:
  - Optional Device Smoke Casebook / 其他：不属于默认 dx-smoke 主链。
  - Case 1 使用 Tier-1 payload 流量验证 perfmetrics.enabled。
  - Case 2 验证 DOMAINLISTS.IMPORT 与 IPRULES.APPLY limits 的结构化失败与恢复性。
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial)
      ADB_SERIAL="$2"
      export ADB_SERIAL
      shift 2
      ;;
    --skip-deploy)
      DO_DEPLOY=0
      shift
      ;;
    --cleanup-forward)
      CLEANUP_FORWARD=1
      shift
      ;;
    --case)
      case "$2" in
        perfmetrics)
          RUN_PERFMETRICS=1
          RUN_LIMITS=0
          ;;
        limits)
          RUN_PERFMETRICS=0
          RUN_LIMITS=1
          ;;
        all)
          RUN_PERFMETRICS=1
          RUN_LIMITS=1
          ;;
        *)
          echo "未知 case: $2" >&2
          show_help >&2
          exit 1
          ;;
      esac
      shift 2
      ;;
    --ctl)
      SNORT_CTL="$2"
      export SNORT_CTL
      shift 2
      ;;
    --port)
      VNEXT_PORT="$2"
      export VNEXT_PORT
      shift 2
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      echo "未知选项: $1" >&2
      show_help >&2
      exit 1
      ;;
  esac
done

log_pass() { echo -e "${GREEN}✓${NC} $1"; PASSED=$((PASSED + 1)); }
log_fail() { echo -e "${RED}✗${NC} $1"; FAILED=$((FAILED + 1)); }
log_skip() { echo -e "${YELLOW}⊘${NC} $1"; SKIPPED=$((SKIPPED + 1)); }

assert_json_pred() {
  local desc="$1"
  local json="$2"
  local py="$3"
  if printf '%s\n' "$json" | python3 -c "$py" >/dev/null 2>&1; then
    log_pass "$desc"
    return 0
  fi
  log_fail "$desc"
  printf '%s\n' "$json" | head -n 4 | sed 's/^/    /'
  return 1
}

ctl_json_or_block() {
  local out_var="$1"
  local cmd="$2"
  local args_json="${3:-}"
  local block_msg="${4:-$cmd failed}"
  local response st

  set +e
  if [[ -n "$args_json" ]]; then
    response="$(vnext_ctl_cmd "$cmd" "$args_json" 2>/dev/null)"
  else
    response="$(vnext_ctl_cmd "$cmd" 2>/dev/null)"
  fi
  st=$?
  set -e
  if [[ $st -ne 0 ]]; then
    echo "BLOCKED: $block_msg" >&2
    return 77
  fi
  printf -v "$out_var" '%s' "$response"
}

ctl_expect_ok() {
  local desc="$1"
  local cmd="$2"
  local args_json="${3:-}"
  local out
  ctl_json_or_block out "$cmd" "$args_json" "$cmd failed" || return $?
  assert_json_pred "$desc" "$out" 'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'
}

read_perf_enabled() {
  local out
  ctl_json_or_block out CONFIG.GET '{"scope":"device","keys":["perfmetrics.enabled"]}' \
    "CONFIG.GET(perfmetrics.enabled) failed" || return $?
  JSON="$out" python3 - <<'PY'
import json
import os
j = json.loads(os.environ["JSON"])
print(int(j["result"]["values"]["perfmetrics.enabled"]))
PY
}

perf_samples_from_json() {
  local json="$1"
  local metric="$2"
  JSON="$json" METRIC="$metric" python3 - <<'PY'
import json
import os
j = json.loads(os.environ["JSON"])
print(int(j["result"]["perf"][os.environ["METRIC"]]["samples"]))
PY
}

vnext_large_rpc() {
  local mode="$1"
  shift
  python3 - "$VNEXT_PORT" "$mode" "$@" <<'PY'
import json
import socket
import sys

port = int(sys.argv[1])
mode = sys.argv[2]
args = sys.argv[3:]


def make_domain_request(list_id: str, count: int, value: str) -> dict:
    if count <= 1000 and "." in value:
        domains = [f"d{i}.{value}" for i in range(count)]
    else:
        domains = [value] * count
    return {
        "id": 1,
        "cmd": "DOMAINLISTS.IMPORT",
        "args": {
            "listId": list_id,
            "listKind": "block",
            "mask": 1,
            "clear": 1,
            "domains": domains,
        },
    }


def make_rule(index: int) -> dict:
    third = (index >> 8) & 0xFF
    fourth = index & 0xFF
    return {
        "clientRuleId": f"dx-other:{index}",
        "action": "allow",
        "priority": 100,
        "enabled": 1,
        "enforce": 1,
        "log": 0,
        "dir": "out",
        "iface": "any",
        "ifindex": 0,
        "proto": "tcp",
        "ct": {"state": "any", "direction": "any"},
        "src": "any",
        "dst": f"10.42.{third}.{fourth}/32",
        "sport": "any",
        "dport": str(10000 + index),
    }


def make_iprules_request(uid: int, count: int) -> dict:
    return {
        "id": 1,
        "cmd": "IPRULES.APPLY",
        "args": {"app": {"uid": uid}, "rules": [make_rule(i) for i in range(count)]},
    }


def encode_request(req: dict) -> bytes:
    return json.dumps(req, separators=(",", ":")).encode("utf-8")


def read_exact(sock: socket.socket, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RuntimeError("connection closed while reading frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def rpc(req: dict) -> dict:
    payload = encode_request(req)
    frame = str(len(payload)).encode("ascii") + b":" + payload + b","
    with socket.create_connection(("127.0.0.1", port), timeout=60) as sock:
        sock.settimeout(120)
        sock.sendall(frame)
        header = bytearray()
        while True:
            b = sock.recv(1)
            if not b:
                raise RuntimeError("connection closed before response header")
            if b == b":":
                break
            if not b.isdigit():
                raise RuntimeError(f"invalid netstring header byte: {b!r}")
            header.extend(b)
        length = int(header.decode("ascii"))
        payload = read_exact(sock, length)
        comma = read_exact(sock, 1)
        if comma != b",":
            raise RuntimeError("invalid netstring terminator")
    return json.loads(payload.decode("utf-8"))


if mode == "domain-over-len":
    req = make_domain_request(args[0], int(args[1]), args[2])
    print(len(encode_request(req)))
elif mode == "domain-import":
    req = make_domain_request(args[0], int(args[1]), args[2])
    print(json.dumps(rpc(req), separators=(",", ":")))
elif mode == "iprules-apply":
    req = make_iprules_request(int(args[0]), int(args[1]))
    print(json.dumps(rpc(req), separators=(",", ":")))
else:
    raise SystemExit(f"unknown mode: {mode}")
PY
}

pick_casebook_uid() {
  if [[ -n "$EXPLICIT_IPTEST_APP_UID" ]]; then
    printf '%s\n' "$EXPLICIT_IPTEST_APP_UID"
    return 0
  fi
  if [[ -n "$EXPLICIT_IPTEST_UID" ]]; then
    printf '%s\n' "$EXPLICIT_IPTEST_UID"
    return 0
  fi

  local apps_json
  ctl_json_or_block apps_json APPS.LIST '{"limit":500}' "vNext APPS.LIST failed" || return $?

  APPS_JSON="$apps_json" python3 - <<'PY'
import json
import os
j = json.loads(os.environ["APPS_JSON"])
for app in j.get("result", {}).get("apps", []):
    uid = app.get("uid")
    name = app.get("app", "")
    if isinstance(uid, int) and uid >= 10000 and isinstance(name, str) and name:
        print(uid)
        raise SystemExit(0)
raise SystemExit(1)
PY
}

trigger_payload_or_skip() {
  local count
  count="$(iptest_tier1_tcp_count_bytes "$PAYLOAD_PORT" "$PAYLOAD_BYTES" "$IPTEST_UID" | tr -d '\r\n ' || true)"
  if [[ "$count" =~ ^[0-9]+$ && "$count" -eq "$PAYLOAD_BYTES" ]]; then
    return 0
  fi
  echo "SKIP: dx-casebook-other Tier-1 payload trigger read ${count:-0}/${PAYLOAD_BYTES} bytes"
  return 10
}

run_perfmetrics_case() {
  log_section "dx-casebook-other / perfmetrics.enabled"

  ORIG_PERF="$(read_perf_enabled)" || return $?
  log_pass "VNXOTH-01a CONFIG.GET perfmetrics.enabled orig=$ORIG_PERF"

  if ! iptest_require_tier1_prereqs; then
    echo "SKIP: dx-casebook-other Tier-1 prerequisites unavailable"
    return 10
  fi

  set +e
  TIER1_TABLE="$(iptest_tier1_setup)"
  local setup_rc=$?
  set -e
  if [[ $setup_rc -eq 10 ]]; then
    echo "SKIP: dx-casebook-other Tier-1 setup skipped"
    return 10
  fi
  if [[ $setup_rc -ne 0 ]]; then
    echo "BLOCKED: dx-casebook-other Tier-1 setup failed" >&2
    return 77
  fi

  iptest_tier1_start_tcp_zero_server "$PAYLOAD_PORT" >/dev/null || {
    echo "SKIP: dx-casebook-other Tier-1 TCP payload server unavailable"
    return 10
  }

  ctl_expect_ok "VNXOTH-01b CONFIG.SET perfmetrics.enabled=0" \
    CONFIG.SET '{"scope":"device","set":{"perfmetrics.enabled":0}}' || return $?
  ctl_expect_ok "VNXOTH-01c METRICS.RESET perf before disabled traffic" \
    METRICS.RESET '{"name":"perf"}' || return $?
  trigger_payload_or_skip || return $?

  local perf0
  ctl_json_or_block perf0 METRICS.GET '{"name":"perf"}' "METRICS.GET(perf disabled) failed" || return $?
  assert_json_pred "VNXOTH-01d perfmetrics.enabled=0 keeps nfq_total_us.samples==0" "$perf0" \
    'import sys,json; j=json.load(sys.stdin); assert int(j["result"]["perf"]["nfq_total_us"]["samples"]) == 0' || return 1

  ctl_expect_ok "VNXOTH-01e CONFIG.SET perfmetrics.enabled=1" \
    CONFIG.SET '{"scope":"device","set":{"perfmetrics.enabled":1}}' || return $?
  ctl_expect_ok "VNXOTH-01f METRICS.RESET perf before enabled traffic" \
    METRICS.RESET '{"name":"perf"}' || return $?
  trigger_payload_or_skip || return $?

  local perf1 samples1
  ctl_json_or_block perf1 METRICS.GET '{"name":"perf"}' "METRICS.GET(perf enabled) failed" || return $?
  assert_json_pred "VNXOTH-01g perfmetrics.enabled=1 grows nfq_total_us.samples" "$perf1" \
    'import sys,json; j=json.load(sys.stdin); assert int(j["result"]["perf"]["nfq_total_us"]["samples"]) >= 1' || return 1
  samples1="$(perf_samples_from_json "$perf1" nfq_total_us)"

  ctl_expect_ok "VNXOTH-01h CONFIG.SET perfmetrics.enabled=1 idempotent ack" \
    CONFIG.SET '{"scope":"device","set":{"perfmetrics.enabled":1}}' || return $?
  local perf2 samples2
  ctl_json_or_block perf2 METRICS.GET '{"name":"perf"}' "METRICS.GET(perf idempotent) failed" || return $?
  samples2="$(perf_samples_from_json "$perf2" nfq_total_us)"
  if [[ "$samples2" -ge "$samples1" ]]; then
    log_pass "VNXOTH-01i perfmetrics.enabled 1->1 does not clear nfq_total_us (before=$samples1 after=$samples2)"
  else
    log_fail "VNXOTH-01i perfmetrics.enabled 1->1 does not clear nfq_total_us"
    return 1
  fi

  local invalid invalid_rc
  set +e
  invalid="$(vnext_ctl_cmd CONFIG.SET '{"scope":"device","set":{"perfmetrics.enabled":2}}' 2>/dev/null)"
  invalid_rc=$?
  set -e
  if [[ $invalid_rc -ne 0 ]] && printf '%s\n' "$invalid" | python3 -c 'import sys,json; j=json.load(sys.stdin); assert j["ok"] is False; assert j["error"]["code"]=="INVALID_ARGUMENT"' >/dev/null 2>&1; then
    log_pass "VNXOTH-01j CONFIG.SET perfmetrics.enabled=2 rejects INVALID_ARGUMENT"
  else
    log_fail "VNXOTH-01j CONFIG.SET perfmetrics.enabled=2 rejects INVALID_ARGUMENT"
    printf '%s\n' "$invalid" | head -n 3 | sed 's/^/    /'
    return 1
  fi

  local after_invalid
  after_invalid="$(read_perf_enabled)" || return $?
  if [[ "$after_invalid" -eq 1 ]]; then
    log_pass "VNXOTH-01k invalid perfmetrics value leaves current valid value unchanged"
  else
    log_fail "VNXOTH-01k invalid perfmetrics value leaves current valid value unchanged"
    echo "    current=$after_invalid expected=1"
    return 1
  fi

  log_info "VNXOTH-01l dns_decision_us optional; not hard-gated without explicit active netd resolver hook"
  return 0
}

run_domain_limits_case() {
  log_section "dx-casebook-other / DOMAINLISTS.IMPORT limits"

  local hello max_request
  ctl_json_or_block hello HELLO "" "HELLO before domain limits failed" || return $?
  assert_json_pred "VNXOTH-02a HELLO exposes maxRequestBytes" "$hello" \
    'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert int(j["result"]["maxRequestBytes"]) > 0' || return 1
  max_request="$(JSON="$hello" python3 - <<'PY'
import json
import os
j = json.loads(os.environ["JSON"])
print(int(j["result"]["maxRequestBytes"]))
PY
)"

  local list_id="00000000-0000-0000-0000-0000000000c1"
  local apply_args
  apply_args="{\"upsert\":[{\"listId\":\"${list_id}\",\"listKind\":\"block\",\"mask\":1,\"enabled\":0,\"url\":\"https://example.test/dx-casebook-other\",\"name\":\"dx-casebook-other\",\"updatedAt\":\"2026-04-25_00:00:00\",\"etag\":\"dx-casebook-other\",\"outdated\":0,\"domainsCount\":0}],\"remove\":[]}"
  ctl_expect_ok "VNXOTH-02b DOMAINLISTS.APPLY creates disabled test list" DOMAINLISTS.APPLY "$apply_args" || return $?
  MUTATED=1

  local under_resp
  under_resp="$(vnext_large_rpc domain-import "$list_id" "$DOMAIN_UNDER_COUNT" "dx-other-under.example.test")" || {
    echo "BLOCKED: DOMAINLISTS.IMPORT under-limit transport failed" >&2
    return 77
  }
  assert_json_pred "VNXOTH-02c DOMAINLISTS.IMPORT under-limit ok" "$under_resp" \
    'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert int(j["result"]["imported"]) >= 1' || return 1

  local lists_get
  ctl_json_or_block lists_get DOMAINLISTS.GET "" "DOMAINLISTS.GET after under import failed" || return $?
  LIST_ID="$list_id" EXPECT="$DOMAIN_UNDER_COUNT" assert_json_pred "VNXOTH-02d DOMAINLISTS.GET reports domainsCount after under-limit import" "$lists_get" \
    'import os,sys,json; j=json.load(sys.stdin); want=os.environ["LIST_ID"]; expect=int(os.environ["EXPECT"]); lists=j["result"]["lists"]; matches=[it for it in lists if it.get("listId")==want]; assert matches; assert int(matches[0].get("domainsCount", -1)) == expect' || return 1

  local over_len
  over_len="$(vnext_large_rpc domain-over-len "$list_id" "$DOMAIN_OVER_COUNT" "$DOMAIN_OVER_VALUE")" || return 1
  if [[ "$over_len" -ge "$max_request" ]]; then
    echo "SKIP: dx-casebook-other DOMAINLISTS over-limit payload (${over_len} bytes) exceeds HELLO maxRequestBytes=${max_request}"
    return 10
  fi

  local over_resp
  over_resp="$(vnext_large_rpc domain-import "$list_id" "$DOMAIN_OVER_COUNT" "$DOMAIN_OVER_VALUE")" || {
    log_fail "VNXOTH-02e DOMAINLISTS.IMPORT over-limit returns structured error"
    return 1
  }
  assert_json_pred "VNXOTH-02e DOMAINLISTS.IMPORT over-limit rejects with limits" "$over_resp" \
    'import sys,json; j=json.load(sys.stdin); err=j["error"]; assert j["ok"] is False; assert err["code"]=="INVALID_ARGUMENT"; assert int(err["limits"]["maxImportDomains"]) == 1000000; assert int(err["limits"]["maxImportBytes"]) == 16777216; assert "hint" in err' || return 1

  ctl_expect_ok "VNXOTH-02f HELLO succeeds after DOMAINLISTS.IMPORT rejection" HELLO || return $?
  return 0
}

run_iprules_limits_case() {
  log_section "dx-casebook-other / IPRULES.APPLY limits"

  ctl_expect_ok "VNXOTH-02g RESETALL before IPRULES limits" RESETALL || return $?
  MUTATED=1
  ctl_expect_ok "VNXOTH-02h CONFIG.SET device block/iprules enabled" \
    CONFIG.SET '{"scope":"device","set":{"block.enabled":1,"iprules.enabled":1}}' || return $?

  local under_resp
  under_resp="$(vnext_large_rpc iprules-apply "$CASEBOOK_IPRULES_UID" "$IPRULES_UNDER_COUNT")" || {
    echo "BLOCKED: IPRULES.APPLY under-limit transport failed" >&2
    return 77
  }
  assert_json_pred "VNXOTH-02i IPRULES.APPLY under-hard-limit ruleset ok" "$under_resp" \
    'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert len(j["result"]["rules"]) >= 1' || return 1

  local preflight
  ctl_json_or_block preflight IPRULES.PREFLIGHT "" "IPRULES.PREFLIGHT after under-limit apply failed" || return $?
  EXPECT="$IPRULES_UNDER_COUNT" assert_json_pred "VNXOTH-02j IPRULES.PREFLIGHT reports rulesTotal warning" "$preflight" \
    'import os,sys,json; j=json.load(sys.stdin); r=j["result"]; assert int(r["summary"]["rulesTotal"]) == int(os.environ["EXPECT"]); assert any(it.get("metric")=="rulesTotal" for it in r["warnings"])' || return 1

  local over_resp
  over_resp="$(vnext_large_rpc iprules-apply "$CASEBOOK_IPRULES_UID" "$IPRULES_OVER_COUNT")" || {
    log_fail "VNXOTH-02k IPRULES.APPLY over-hard-limit returns structured error"
    return 1
  }
  assert_json_pred "VNXOTH-02k IPRULES.APPLY over-hard-limit rejects with preflight violations" "$over_resp" \
    'import sys,json; j=json.load(sys.stdin); err=j["error"]; assert j["ok"] is False; assert err["code"]=="INVALID_ARGUMENT"; pf=err["preflight"]; assert any(it.get("metric")=="rulesTotal" for it in pf["violations"])' || return 1

  local preflight_after
  ctl_json_or_block preflight_after IPRULES.PREFLIGHT "" "IPRULES.PREFLIGHT after rejected apply failed" || return $?
  EXPECT="$IPRULES_UNDER_COUNT" assert_json_pred "VNXOTH-02l rejected IPRULES.APPLY is all-or-nothing" "$preflight_after" \
    'import os,sys,json; j=json.load(sys.stdin); assert int(j["result"]["summary"]["rulesTotal"]) == int(os.environ["EXPECT"])' || return 1
  ctl_expect_ok "VNXOTH-02m HELLO succeeds after IPRULES.APPLY rejection" HELLO || return $?
  assert_json_pred "VNXOTH-02n IPRULES.PREFLIGHT remains parseable after rejection" "$preflight_after" \
    'import sys,json; j=json.load(sys.stdin); r=j["result"]; assert "summary" in r and "limits" in r and "warnings" in r and "violations" in r' || return 1
  return 0
}

cleanup() {
  local rc=$?
  set +e
  if [[ -n "$TIER1_TABLE" ]]; then
    iptest_tier1_teardown "$TIER1_TABLE" >/dev/null 2>&1 || true
  fi
  if [[ "$MUTATED" -eq 1 ]]; then
    vnext_ctl_cmd RESETALL >/dev/null 2>&1 || true
  fi
  if [[ -n "$ORIG_PERF" ]]; then
    vnext_ctl_cmd CONFIG.SET "{\"scope\":\"device\",\"set\":{\"perfmetrics.enabled\":${ORIG_PERF}}}" >/dev/null 2>&1 || true
  fi
  if [[ "$CLEANUP_FORWARD" -eq 1 ]]; then
    remove_control_vnext_forward "$VNEXT_PORT" >/dev/null 2>&1 || true
  fi
  exit "$rc"
}

run_case() {
  local name="$1"
  shift
  set +e
  "$@"
  local rc=$?
  case "$rc" in
    0) return 0 ;;
    10) return 10 ;;
    77) return 77 ;;
    *) return 1 ;;
  esac
}

main() {
  trap cleanup EXIT

  if [[ $DO_DEPLOY -eq 1 ]]; then
    log_info "deploy via dev/dev-deploy.sh"
    local -a deploy_cmd=(bash "$SNORT_ROOT/dev/dev-deploy.sh")
    if [[ -n "${ADB_SERIAL:-}" ]]; then
      deploy_cmd+=(--serial "$ADB_SERIAL")
    fi
    "${deploy_cmd[@]}"
  fi

  vnext_preflight || exit $?
  log_info "sucre-snort-ctl: $SNORT_CTL"

  local uid uid_rc
  set +e
  uid="$(pick_casebook_uid)"
  uid_rc=$?
  set -e
  if [[ $uid_rc -ne 0 || ! "$uid" =~ ^[0-9]+$ ]]; then
    echo "BLOCKED: unable to select a valid test app uid" >&2
    exit 77
  fi
  export IPTEST_APP_UID="$uid"
  CASEBOOK_IPRULES_UID="$uid"
  log_info "payload uid=$IPTEST_UID iprules uid=$CASEBOOK_IPRULES_UID"

  local failed=0 blocked=0 skipped=0 rc

  if [[ $RUN_PERFMETRICS -eq 1 ]]; then
    set +e
    run_case perfmetrics run_perfmetrics_case
    rc=$?
    set -e
    case "$rc" in
      0) ;;
      10) skipped=1 ;;
      77) blocked=1 ;;
      *) failed=1 ;;
    esac
  fi

  if [[ $RUN_LIMITS -eq 1 && $blocked -eq 0 && $failed -eq 0 ]]; then
    set +e
    run_case domain-limits run_domain_limits_case
    rc=$?
    set -e
    case "$rc" in
      0) ;;
      10) skipped=1 ;;
      77) blocked=1 ;;
      *) failed=1 ;;
    esac
  fi

  if [[ $RUN_LIMITS -eq 1 && $blocked -eq 0 && $failed -eq 0 ]]; then
    set +e
    run_case iprules-limits run_iprules_limits_case
    rc=$?
    set -e
    case "$rc" in
      0) ;;
      10) skipped=1 ;;
      77) blocked=1 ;;
      *) failed=1 ;;
    esac
  fi

  echo ""
  echo "== SUMMARY =="
  echo "passed=$PASSED failed=$FAILED skipped=$SKIPPED"

  if [[ $failed -ne 0 || $FAILED -ne 0 ]]; then
    return 1
  fi
  if [[ $blocked -ne 0 ]]; then
    return 77
  fi
  if [[ $skipped -ne 0 || $SKIPPED -ne 0 ]]; then
    echo "SKIP: dx-casebook-other completed with optional skipped checks"
  fi
  echo "dx-casebook-other: PASS"
  return 0
}

main "$@"
