#!/bin/bash

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/lib.sh"

DO_DEPLOY=1
CLEANUP_FORWARD=0
RESTORE_INETCONTROL=0

VNEXT_PORT="${VNEXT_PORT:-60607}"
SNORT_CTL="${SNORT_CTL:-}"

show_help() {
    cat <<EOF
用法: $0 [选项]

选项:
  --serial <serial>       指定目标真机 serial
  --skip-deploy           跳过部署，直接复用当前真机上的守护进程
  --cleanup-forward       结束后移除 vNext adb forward
  --ctl <path>            指定 sucre-snort-ctl 路径（默认自动探测）
  --port <port>           指定 host tcp port（默认: 60607 -> localabstract:sucre-snort-control-vnext）
  -h, --help              显示帮助
EOF
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
            echo "未知选项: $1" >&2
            show_help >&2
            exit 1
            ;;
    esac
done

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

assert_ctl_ok() {
    local desc="$1"
    shift
    local out
    out=$("$@" 2>&1)
    local status=$?
    if [[ $status -ne 0 ]]; then
        log_fail "$desc"
        printf '    cmd: %q\n' "$*" | sed 's/^/    /'
        printf '    out: %s\n' "$out" | head -n 5 | sed 's/^/    /'
        return 1
    fi
    log_pass "$desc"
    return 0
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

two_client_last_write_wins() {
    VNEXT_PORT="$VNEXT_PORT" PERF_ORIG="$perf_orig" python3 - <<'PY'
import json
import os
import socket
import sys

PORT = int(os.environ["VNEXT_PORT"])
PERF_ORIG = int(os.environ["PERF_ORIG"])


def encode_netstring(payload: bytes) -> bytes:
    return str(len(payload)).encode("ascii") + b":" + payload + b","


def read_exact(sock: socket.socket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise EOFError("eof while reading payload")
        out += chunk
    return bytes(out)


def read_netstring(sock: socket.socket) -> bytes:
    header = bytearray()
    while True:
        ch = sock.recv(1)
        if not ch:
            raise EOFError("eof while reading netstring header")
        if ch == b":":
            break
        header += ch
        if len(header) > 32:
            raise ValueError("netstring header too long")
    if not header:
        raise ValueError("empty netstring length")
    if header.startswith(b"0") and header != b"0":
        raise ValueError("leading zero in netstring length")
    length = int(header.decode("ascii"))
    payload = read_exact(sock, length)
    comma = read_exact(sock, 1)
    if comma != b",":
        raise ValueError("netstring missing trailing comma")
    return payload


def rpc(sock: socket.socket, req_id: int, cmd: str, args: dict) -> dict:
    req = {"id": req_id, "cmd": cmd, "args": args}
    payload = json.dumps(req, separators=(",", ":")).encode("utf-8")
    sock.sendall(encode_netstring(payload))
    resp = json.loads(read_netstring(sock))
    if resp.get("id") != req_id:
        raise RuntimeError(f"id mismatch: expected={req_id} got={resp.get('id')}")
    if not resp.get("ok", False):
        raise RuntimeError(f"rpc failed: {resp}")
    return resp


sock1 = socket.create_connection(("127.0.0.1", PORT), timeout=5)
sock2 = socket.create_connection(("127.0.0.1", PORT), timeout=5)
sock1.settimeout(5)
sock2.settimeout(5)

rpc(sock1, 100, "HELLO", {})
rpc(sock2, 200, "HELLO", {})

# Two clients connected concurrently; serialize two CONFIG.SET operations across connections.
rpc(sock1, 101, "CONFIG.SET", {"scope": "device", "set": {"perfmetrics.enabled": 0}})
rpc(sock2, 201, "CONFIG.SET", {"scope": "device", "set": {"perfmetrics.enabled": 1}})

resp1 = rpc(sock1, 102, "CONFIG.GET", {"scope": "device", "keys": ["perfmetrics.enabled"]})
val1 = resp1["result"]["values"]["perfmetrics.enabled"]
if val1 != 1:
    raise RuntimeError(f"expected perfmetrics.enabled==1 after last-write-wins, got {val1}")

resp2 = rpc(sock2, 202, "CONFIG.GET", {"scope": "device", "keys": ["perfmetrics.enabled"]})
val2 = resp2["result"]["values"]["perfmetrics.enabled"]
if val2 != 1:
    raise RuntimeError(f"expected perfmetrics.enabled==1 (client2 view), got {val2}")

# Restore original value to avoid affecting later tests/runs.
rpc(sock1, 103, "CONFIG.SET", {"scope": "device", "set": {"perfmetrics.enabled": PERF_ORIG}})
rpc(sock1, 104, "QUIT", {})
rpc(sock2, 203, "QUIT", {})

sock1.close()
sock2.close()

print("OK")
PY
}

main() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║ sucre-snort vNext Integration Tests (baseline)            ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""

    device_preflight || exit 1
    echo "目标真机: $(adb_target_desc)"

    SNORT_CTL="$(find_snort_ctl)" || exit 1
    echo "sucre-snort-ctl: $SNORT_CTL"

    local had_telnet
    had_telnet="$(adb_su "test -f /data/snort/telnet && echo 1 || echo 0" | tr -d '\r\n')" || had_telnet=0

    if [[ $DO_DEPLOY -eq 1 ]]; then
        # For gating tests we want a deterministic inetControl()==false baseline.
        # inetControl() is latched at startup, so ensure /data/snort/telnet is absent before deploy.
        if [[ "$had_telnet" == "1" ]]; then
            RESTORE_INETCONTROL=1
        fi
        adb_su "rm -f /data/snort/telnet" >/dev/null 2>&1 || true

        bash "$SCRIPT_DIR/../../dev/dev-deploy.sh" --serial "$(adb_target_desc)" || exit 1
    fi

    log_section "Gating (inetControl)"

    if [[ $DO_DEPLOY -eq 1 ]]; then
        local host_port=60618
        adb_cmd forward "tcp:${host_port}" "tcp:60607" >/dev/null 2>&1 || {
            log_fail "VNT-00 adb forward tcp:60607 failed"
            return 1
        }

        # inetControl()==false MUST NOT expose TCP:60607.
        if "$SNORT_CTL" --tcp "127.0.0.1:${host_port}" --compact HELLO >/dev/null 2>&1; then
            log_fail "VNT-00 inetControl() gating off (tcp:60607 should be unreachable)"
            adb_cmd forward --remove "tcp:${host_port}" >/dev/null 2>&1 || true
            return 1
        fi
        log_pass "VNT-00 inetControl() gating off (tcp:60607 unreachable)"
        adb_cmd forward --remove "tcp:${host_port}" >/dev/null 2>&1 || true
    else
        log_skip "VNT-00 inetControl() gating off skipped (--skip-deploy)"
    fi

    if ! check_control_vnext_forward "$VNEXT_PORT"; then
        log_info "设置 vNext adb forward..."
        setup_control_vnext_forward "$VNEXT_PORT"
    fi

    log_section "Meta"

    local hello
    hello=$(ctl_cmd HELLO) || true
    assert_json_pred "VNT-01 HELLO has handshake fields" "$hello" \
        'import sys,json; j=json.load(sys.stdin); r=j["result"]; assert j["ok"] is True; assert r["protocol"]=="control-vnext"; assert r["protocolVersion"]==1; assert r["framing"]=="netstring"; assert "maxRequestBytes" in r and "maxResponseBytes" in r'

    assert_ctl_ok "VNT-02 QUIT closes cleanly" ctl_cmd QUIT

    assert_ctl_ok "VNT-03 reconnect HELLO" ctl_cmd HELLO

    log_section "Inventory"

    local apps
    apps=$(ctl_cmd APPS.LIST '{"query":"com.","limit":50}') || true
    assert_json_pred "VNT-04 APPS.LIST has apps[] + truncated" "$apps" \
        'import sys,json; j=json.load(sys.stdin); r=j["result"]; assert j["ok"] is True; assert isinstance(r["apps"], list); assert isinstance(r["truncated"], bool)'

    assert_json_pred "VNT-04b APPS.LIST apps[] sorted by uid" "$apps" \
        'import sys,json; j=json.load(sys.stdin); apps=j["result"]["apps"]; u=[a["uid"] for a in apps]; assert u==sorted(u)'

    local apps_count
    apps_count=$(APPS_JSON="$apps" python3 - <<'PY'
import os, json
j = json.loads(os.environ["APPS_JSON"])
apps = j.get("result", {}).get("apps", [])
print(len(apps))
PY
) || apps_count=0

    if [[ "$apps_count" -ge 2 ]]; then
        local apps_limit1
        apps_limit1=$(ctl_cmd APPS.LIST '{"limit":1}') || true
        assert_json_pred "VNT-04c APPS.LIST limit=1 sets truncated=true when more apps exist" "$apps_limit1" \
            'import sys,json; j=json.load(sys.stdin); r=j["result"]; assert j["ok"] is True; assert len(r["apps"])<=1; assert r["truncated"] is True'
    else
        log_skip "VNT-04c APPS.LIST limit=1 truncated skipped (insufficient apps)"
    fi

    local ifaces
    ifaces=$(ctl_cmd IFACES.LIST) || true
    assert_json_pred "VNT-05 IFACES.LIST has ifaces[]" "$ifaces" \
        'import sys,json; j=json.load(sys.stdin); r=j["result"]; assert j["ok"] is True; assert isinstance(r["ifaces"], list)'

    assert_json_pred "VNT-05b IFACES.LIST ifaces[] sorted by ifindex" "$ifaces" \
        'import sys,json; j=json.load(sys.stdin); ifs=j["result"]["ifaces"]; idx=[i["ifindex"] for i in ifs]; assert idx==sorted(idx)'

    log_section "Config (device)"

    local device_get device_set device_get2
    device_get=$(ctl_cmd CONFIG.GET '{"scope":"device","keys":["block.enabled","rdns.enabled","perfmetrics.enabled"]}') || true
    assert_json_pred "VNT-06 CONFIG.GET device returns values" "$device_get" \
        'import sys,json; j=json.load(sys.stdin); v=j["result"]["values"]; assert set(["block.enabled","rdns.enabled","perfmetrics.enabled"]).issubset(v.keys())'

    local perf_orig
    perf_orig=$(DEVICE_GET_JSON="$device_get" python3 - <<'PY'
import os, json
j = json.loads(os.environ["DEVICE_GET_JSON"])
print(j["result"]["values"]["perfmetrics.enabled"])
PY
) || perf_orig=0

    device_set=$(DEVICE_GET_JSON="$device_get" python3 - <<'PY'
import os, json
j = json.loads(os.environ["DEVICE_GET_JSON"])
v = j["result"]["values"]
payload = {"scope":"device","set":{
  "block.enabled": v["block.enabled"],
  "rdns.enabled": v["rdns.enabled"],
  "perfmetrics.enabled": v["perfmetrics.enabled"],
}}
print(json.dumps(payload, separators=(",",":")))
PY
) || true

    assert_ctl_ok "VNT-07 CONFIG.SET device (idempotent)" ctl_cmd CONFIG.SET "$device_set"

    device_get2=$(ctl_cmd CONFIG.GET '{"scope":"device","keys":["block.enabled","rdns.enabled","perfmetrics.enabled"]}') || true
    assert_json_pred "VNT-08 CONFIG roundtrip device stable" "$device_get2" \
        'import sys,json; j=json.load(sys.stdin); v=j["result"]["values"]; assert set(["block.enabled","rdns.enabled","perfmetrics.enabled"]).issubset(v.keys())'

    local device_unknown
    device_unknown=$(ctl_cmd CONFIG.SET '{"scope":"device","set":{"vnext.unknown":1}}' || true)
    assert_json_pred "VNT-08b CONFIG.SET rejects unknown key" "$device_unknown" \
        'import sys,json; j=json.load(sys.stdin); assert j["ok"] is False; assert j["error"]["code"]=="INVALID_ARGUMENT"'

    local perf_toggle=$((1 - perf_orig))
    local device_atomic_fail
    device_atomic_fail=$(ctl_cmd CONFIG.SET "{\"scope\":\"device\",\"set\":{\"perfmetrics.enabled\":${perf_toggle},\"block.enabled\":2}}" || true)
    assert_json_pred "VNT-08c CONFIG.SET all-or-nothing (no partial apply)" "$device_atomic_fail" \
        'import sys,json; j=json.load(sys.stdin); assert j["ok"] is False; assert j["error"]["code"]=="INVALID_ARGUMENT"'

    local perf_after
    perf_after=$(ctl_cmd CONFIG.GET '{"scope":"device","keys":["perfmetrics.enabled"]}') || true
    assert_json_pred "VNT-08d CONFIG.SET validation failure does not change state" "$perf_after" \
        "import sys,json; j=json.load(sys.stdin); assert j['result']['values']['perfmetrics.enabled'] == ${perf_orig}"

    log_section "Config (app)"

    local app_uid
    app_uid=$(APPS_JSON="$apps" python3 - <<'PY'
import os, json
j = json.loads(os.environ["APPS_JSON"])
apps = j.get("result", {}).get("apps", [])
print(apps[0]["uid"] if apps else "")
PY
) || true

    if [[ -z "$app_uid" ]]; then
        log_skip "VNT-09 CONFIG app skipped (no apps)"
    else
        local app_get app_set
        app_get=$(ctl_cmd CONFIG.GET "{\"scope\":\"app\",\"app\":{\"uid\":${app_uid}},\"keys\":[\"tracked\",\"domain.custom.enabled\"]}") || true
        assert_json_pred "VNT-09 CONFIG.GET app returns values" "$app_get" \
            'import sys,json; j=json.load(sys.stdin); v=j["result"]["values"]; assert set(["tracked","domain.custom.enabled"]).issubset(v.keys())'

        app_set=$(APP_GET_JSON="$app_get" APP_UID="$app_uid" python3 - <<'PY'
import os, json
j = json.loads(os.environ["APP_GET_JSON"])
v = j["result"]["values"]
payload = {"scope":"app","app":{"uid": int(os.environ["APP_UID"])},"set":{
  "tracked": v["tracked"],
  "domain.custom.enabled": v["domain.custom.enabled"],
}}
print(json.dumps(payload, separators=(",",":")))
PY
) || true

        assert_ctl_ok "VNT-10 CONFIG.SET app (idempotent)" ctl_cmd CONFIG.SET "$app_set"
    fi

    log_section "Last-write-wins (device)"

    assert_ctl_ok "VNT-11 SET perfmetrics.enabled=0" ctl_cmd CONFIG.SET '{"scope":"device","set":{"perfmetrics.enabled":0}}'
    assert_ctl_ok "VNT-12 SET perfmetrics.enabled=1" ctl_cmd CONFIG.SET '{"scope":"device","set":{"perfmetrics.enabled":1}}'

    local perf_check
    perf_check=$(ctl_cmd CONFIG.GET '{"scope":"device","keys":["perfmetrics.enabled"]}') || true
    assert_json_pred "VNT-13 last write wins (perfmetrics.enabled==1)" "$perf_check" \
        'import sys,json; j=json.load(sys.stdin); assert j["result"]["values"]["perfmetrics.enabled"] == 1'

    assert_ctl_ok "VNT-14 restore perfmetrics.enabled" ctl_cmd CONFIG.SET "{\"scope\":\"device\",\"set\":{\"perfmetrics.enabled\":${perf_orig}}}"

    assert_ctl_ok "VNT-14b two clients concurrent (last-write-wins)" two_client_last_write_wins

    log_section "Resetall"

    local resetall
    resetall=$(ctl_cmd RESETALL) || true
    assert_json_pred "VNT-15 RESETALL ok=true" "$resetall" \
        'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'
    assert_ctl_ok "VNT-16 HELLO after RESETALL" ctl_cmd HELLO

    print_summary
    local status=$?

    if [[ $RESTORE_INETCONTROL -eq 1 ]]; then
        log_info "恢复 inetControl() 环境（/data/snort/telnet）..."
        adb_su "mkdir -p /data/snort && touch /data/snort/telnet" >/dev/null 2>&1 || true
        # Best-effort restore: inetControl() is latched at startup.
        bash "$SCRIPT_DIR/../../dev/dev-deploy.sh" --serial "$(adb_target_desc)" >/dev/null 2>&1 || true
    fi

    if [[ $CLEANUP_FORWARD -eq 1 ]]; then
        log_info "移除 vNext adb forward..."
        remove_control_vnext_forward "$VNEXT_PORT"
    fi

    return $status
}

main "$@"
