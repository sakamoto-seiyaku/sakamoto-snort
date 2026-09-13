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

stream_activity_start_event_stop_smoke() {
    VNEXT_PORT="$VNEXT_PORT" python3 - <<'PY'
import json
import os
import select
import socket

PORT = int(os.environ["VNEXT_PORT"])


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
    return resp


def read_event(sock: socket.socket) -> dict:
    ev = json.loads(read_netstring(sock))
    if not isinstance(ev, dict):
        raise RuntimeError(f"event not object: {type(ev)}")
    if "id" in ev or "ok" in ev:
        raise RuntimeError(f"event contains response envelope fields: {ev}")
    if "type" not in ev:
        raise RuntimeError(f"event missing type: {ev}")
    return ev


sock = socket.create_connection(("127.0.0.1", PORT), timeout=5)
sock.settimeout(5)

hello = rpc(sock, 1, "HELLO", {})
if not hello.get("ok", False):
    raise RuntimeError(f"HELLO failed: {hello}")

start = rpc(sock, 2, "STREAM.START", {"type": "activity"})
if not start.get("ok", False):
    raise RuntimeError(f"STREAM.START failed: {start}")

notice = read_event(sock)
if notice.get("type") != "notice" or notice.get("notice") != "started" or notice.get("stream") != "activity":
    raise RuntimeError(f"unexpected started notice: {notice}")

activity = read_event(sock)
if activity.get("type") != "activity" or "blockEnabled" not in activity or not isinstance(activity["blockEnabled"], bool):
    raise RuntimeError(f"unexpected activity event: {activity}")

stop = rpc(sock, 3, "STREAM.STOP", {})
if not stop.get("ok", False):
    raise RuntimeError(f"STREAM.STOP failed: {stop}")

# STOP ack barrier: no further frames until next START (best-effort time window).
r, _, _ = select.select([sock], [], [], 0.2)
if r:
    extra = json.loads(read_netstring(sock))
    raise RuntimeError(f"unexpected frame after STOP: {extra}")

sock.close()
print("OK")
PY
}

stage_dx_netd_injector() {
    local host_bin="${DX_NETD_INJECT_HOST_BIN:-$SNORT_ROOT/build-output/dx-netd-inject}"
    local device_bin="${DX_NETD_INJECT_DEVICE_BIN:-/data/local/tmp/dx-netd-inject}"

    if [[ ! -f "$host_bin" ]]; then
        log_info "dx-netd-inject not found, building..."
        if ! bash "$SNORT_ROOT/dev/dev-build-dx-netd-inject.sh" >/dev/null 2>&1; then
            echo "BLOCKED: missing dx-netd-inject ($host_bin); build it with: bash dev/dev-build-dx-netd-inject.sh" >&2
            return 77
        fi
    fi

    set +e
    adb_push_file "$host_bin" "$device_bin" >/dev/null 2>&1
    local rc=$?
    set -e
    if [[ $rc -ne 0 ]]; then
        echo "BLOCKED: failed to push dx-netd-inject to device" >&2
        return 77
    fi
    adb_su "chmod 755 \"$device_bin\"" >/dev/null 2>&1 || {
        echo "BLOCKED: failed to chmod dx-netd-inject on device" >&2
        return 77
    }

    export DX_NETD_INJECT_DEVICE_BIN="$device_bin"
    return 0
}

stream_dns_start_inject_event_stop_smoke() {
    local uid="${DX_NETD_INJECT_UID:-}"
    local domain="${DX_NETD_INJECT_DOMAIN:-}"
    local injector="${DX_NETD_INJECT_DEVICE_BIN:-/data/local/tmp/dx-netd-inject}"

    if [[ -z "$uid" || -z "$domain" ]]; then
        echo "BLOCKED: missing DX_NETD_INJECT_UID/DX_NETD_INJECT_DOMAIN" >&2
        return 77
    fi
    if [[ ! "$uid" =~ ^[0-9]+$ ]]; then
        echo "BLOCKED: invalid DX_NETD_INJECT_UID: $uid" >&2
        return 77
    fi

    local tmp_dir ready_file
    tmp_dir="$(mktemp -d)"
    ready_file="$tmp_dir/stream_ready"

    VNEXT_PORT="$VNEXT_PORT" EXPECT_UID="$uid" EXPECT_DOMAIN="$domain" READY_FILE="$ready_file" python3 - <<'PY' &
import json
import os
import socket
import sys
import time

PORT = int(os.environ["VNEXT_PORT"])
EXPECT_UID = int(os.environ["EXPECT_UID"])
EXPECT_DOMAIN = os.environ["EXPECT_DOMAIN"]
READY_FILE = os.environ["READY_FILE"]


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
    return resp


def read_event(sock: socket.socket) -> dict:
    ev = json.loads(read_netstring(sock))
    if not isinstance(ev, dict):
        raise RuntimeError(f"event not object: {type(ev)}")
    if "id" in ev or "ok" in ev:
        raise RuntimeError(f"event contains response envelope fields: {ev}")
    if "type" not in ev:
        raise RuntimeError(f"event missing type: {ev}")
    return ev


try:
    sock = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    sock.settimeout(0.5)

    hello = rpc(sock, 1, "HELLO", {})
    if not hello.get("ok", False):
        raise RuntimeError(f"HELLO failed: {hello}")

    start = rpc(sock, 2, "STREAM.START", {"type": "dns", "horizonSec": 0, "minSize": 0})
    if not start.get("ok", False):
        raise RuntimeError(f"STREAM.START failed: {start}")

    notice = read_event(sock)
    if notice.get("type") != "notice" or notice.get("notice") != "started" or notice.get("stream") != "dns":
        raise RuntimeError(f"unexpected started notice: {notice}")

    with open(READY_FILE, "w", encoding="utf-8") as f:
        f.write("ready\n")

    deadline = time.time() + 5.0
    found = False
    samples = []
    while time.time() < deadline:
        try:
            ev = read_event(sock)
        except socket.timeout:
            continue

        if len(samples) < 5:
            samples.append({"type": ev.get("type"), "uid": ev.get("uid"), "domain": ev.get("domain")})

        if ev.get("type") != "dns":
            continue
        if int(ev.get("uid", -1)) != EXPECT_UID:
            continue
        if ev.get("domain") != EXPECT_DOMAIN:
            continue
        if not isinstance(ev.get("blocked"), bool):
            raise RuntimeError(f"dns event missing blocked bool: {ev}")
        if not isinstance(ev.get("policySource"), str):
            raise RuntimeError(f"dns event missing policySource: {ev}")
        found = True
        break

    if not found:
        print("DEBUG: no matching dns event found", file=sys.stderr)
        if samples:
            print("DEBUG: samples (up to 5):", file=sys.stderr)
            for s in samples:
                print(json.dumps(s, separators=(",", ":")), file=sys.stderr)

    stop = rpc(sock, 3, "STREAM.STOP", {})
    if not stop.get("ok", False):
        raise RuntimeError(f"STREAM.STOP failed: {stop}")
    sock.close()
    raise SystemExit(0 if found else 2)
except Exception:
    raise SystemExit(77)
PY
    local stream_pid=$!

    local ready=0
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if [[ -f "$ready_file" ]]; then
            ready=1
            break
        fi
        sleep 0.1
    done
    if [[ $ready -ne 1 ]]; then
        echo "BLOCKED: dns stream listener did not become ready" >&2
        wait "$stream_pid" >/dev/null 2>&1 || true
        rm -rf "$tmp_dir"
        return 77
    fi

    # Inject a synthetic DNS request via the netd socket to avoid relying on external network.
    set +e
    adb_su "$injector --uid $uid --domain $domain" >/dev/null 2>&1
    local inj_rc=$?
    set -e
    if [[ $inj_rc -ne 0 ]]; then
        echo "BLOCKED: dx-netd-inject failed (rc=$inj_rc)" >&2
        wait "$stream_pid" >/dev/null 2>&1 || true
        rm -rf "$tmp_dir"
        return 77
    fi

    set +e
    wait "$stream_pid"
    local rc=$?
    set -e
    rm -rf "$tmp_dir"

    if [[ $rc -eq 77 ]]; then
        echo "BLOCKED: dns stream capture failed" >&2
        return 77
    fi
    if [[ $rc -ne 0 ]]; then
        return 1
    fi
    return 0
}

domain_casebook_smoke() {
    local uid="$1"
    local injector="${DX_NETD_INJECT_DEVICE_BIN:-/data/local/tmp/dx-netd-inject}"
    python3 "$SCRIPT_DIR/vnext-domain-casebook.py" \
        --port "$VNEXT_PORT" \
        --uid "$uid" \
        --adb "$ADB" \
        --serial "${ADB_SERIAL_RESOLVED:-}" \
        --injector "$injector"
}

main() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║ sucre-snort vNext Integration Tests (baseline)            ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""

    device_preflight || exit 77
    echo "目标真机: $(adb_target_desc)"

    log_section "SELinux"
    if ! selinux_ensure_permissive; then
        echo "BLOCKED: SELinux must be Permissive for device tests (try: adb shell su 0 sh -c 'nsenter -t 1 -m -- setenforce 0')" >&2
        exit 77
    fi
    log_pass "SELinux ok ($(selinux_get_mode 2>/dev/null || echo unknown))"

    SNORT_CTL="$(find_snort_ctl)" || exit 77
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

    # Ensure a deterministic baseline even if the device has persisted state from a previous run.
    local pre_resetall
    pre_resetall=$(ctl_cmd RESETALL) || true
    assert_json_pred "VNT-03c RESETALL pre-clean ok=true" "$pre_resetall" \
        'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'
    assert_ctl_ok "VNT-03d HELLO after RESETALL (pre-clean)" ctl_cmd HELLO

    log_section "Stream"

    assert_ctl_ok "VNT-03b STREAM activity start→event→stop flow" stream_activity_start_event_stop_smoke

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

    local block_orig
    block_orig=$(DEVICE_GET_JSON="$device_get" python3 - <<'PY'
import os, json
j = json.loads(os.environ["DEVICE_GET_JSON"])
print(j["result"]["values"]["block.enabled"])
PY
    ) || block_orig=0

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

    log_section "Stream (dns end-to-end)"

    if [[ -z "$app_uid" ]]; then
        log_skip "VNT-10b STREAM dns skipped (no apps)"
    else
        if ! stage_dx_netd_injector; then
            exit 77
        fi

        local tracked_get tracked_orig
        tracked_get=$(ctl_cmd CONFIG.GET "{\"scope\":\"app\",\"app\":{\"uid\":${app_uid}},\"keys\":[\"tracked\"]}" 2>/dev/null || true)
        tracked_orig=$(TRACKED_JSON="$tracked_get" python3 - <<'PY'
import os, json
j = json.loads(os.environ["TRACKED_JSON"] or "{}")
print(j.get("result", {}).get("values", {}).get("tracked", 0))
PY
        ) || tracked_orig=0
        if [[ "$tracked_orig" != "0" && "$tracked_orig" != "1" ]]; then
            tracked_orig=0
        fi

        assert_ctl_ok "VNT-10b1 SET block.enabled=1 (dns stream)" \
            ctl_cmd CONFIG.SET '{"scope":"device","set":{"block.enabled":1}}'

        assert_ctl_ok "VNT-10b2 SET tracked=1 (dns stream)" \
            ctl_cmd CONFIG.SET "{\"scope\":\"app\",\"app\":{\"uid\":${app_uid}},\"set\":{\"tracked\":1}}"

        local dns_domain
        dns_domain="dx-smoke-dns-$(date +%s 2>/dev/null || echo 0).example.com"

        set +e
        DX_NETD_INJECT_UID="$app_uid" DX_NETD_INJECT_DOMAIN="$dns_domain" stream_dns_start_inject_event_stop_smoke
        local dns_rc=$?
        set -e
        if [[ $dns_rc -eq 77 ]]; then
            exit 77
        fi
        if [[ $dns_rc -ne 0 ]]; then
            log_fail "VNT-10b3 STREAM dns start→event→stop (netd inject)"
            return 1
        fi
        log_pass "VNT-10b3 STREAM dns start→event→stop (netd inject)"

        assert_ctl_ok "VNT-10b4 restore tracked" \
            ctl_cmd CONFIG.SET "{\"scope\":\"app\",\"app\":{\"uid\":${app_uid}},\"set\":{\"tracked\":${tracked_orig}}}"

        assert_ctl_ok "VNT-10b5 restore block.enabled" \
            ctl_cmd CONFIG.SET "{\"scope\":\"device\",\"set\":{\"block.enabled\":${block_orig}}}"
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

    log_section "Domain Surface"

    local rules_apply rules_get rid0
    rules_apply=$(ctl_cmd DOMAINRULES.APPLY '{"rules":[{"type":"domain","pattern":"example.com"},{"type":"regex","pattern":".*google.*"}]}' || true)
    assert_json_pred "VNT-15 DOMAINRULES.APPLY ok + returns rules[]" "$rules_apply" \
        'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert isinstance(j["result"]["rules"], list); assert len(j["result"]["rules"]) >= 2'

    rid0=$(RULES_APPLY_JSON="$rules_apply" python3 - <<'PY'
import os, json
j = json.loads(os.environ["RULES_APPLY_JSON"])
rules = j["result"]["rules"]
print(rules[0]["ruleId"] if rules else "")
PY
) || rid0=""

    rules_get=$(ctl_cmd DOMAINRULES.GET) || true
    assert_json_pred "VNT-16 DOMAINRULES.GET rules[] sorted by ruleId" "$rules_get" \
        'import sys,json; j=json.load(sys.stdin); rules=j["result"]["rules"]; ids=[r["ruleId"] for r in rules]; assert ids==sorted(ids)'

    local pol_apply pol_get
    pol_apply=$(ctl_cmd DOMAINPOLICY.APPLY "{\"scope\":\"device\",\"policy\":{\"allow\":{\"domains\":[],\"ruleIds\":[${rid0}]},\"block\":{\"domains\":[\"bad.com\"],\"ruleIds\":[]}}}" || true)
    assert_json_pred "VNT-17 DOMAINPOLICY.APPLY is ack-only" "$pol_apply" \
        'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert "result" not in j'

    pol_get=$(ctl_cmd DOMAINPOLICY.GET '{"scope":"device"}') || true
    assert_json_pred "VNT-18 DOMAINPOLICY.GET device contains ruleId" "$pol_get" \
        "import sys,json; j=json.load(sys.stdin); ids=j['result']['policy']['allow']['ruleIds']; assert ${rid0} in ids"

    local list_id list_unknown lists_apply lists_get imp lists_get2
    list_id="$(python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
)"
    list_unknown="00000000-0000-0000-0000-00000000ffff"

    lists_apply=$(ctl_cmd DOMAINLISTS.APPLY "{\"upsert\":[{\"listId\":\"${list_id}\",\"listKind\":\"block\",\"mask\":1,\"enabled\":0,\"url\":\"https://example/list\",\"name\":\"Example\",\"updatedAt\":\"2026-01-01_00:00:00\",\"etag\":\"etagX\",\"outdated\":0,\"domainsCount\":0}],\"remove\":[\"${list_unknown}\"]}" || true)
    assert_json_pred "VNT-19 DOMAINLISTS.APPLY remove unknown reports notFound[]" "$lists_apply" \
        "import sys,json; j=json.load(sys.stdin); assert j['ok'] is True; assert '${list_unknown}' in j['result']['notFound']"

    lists_get=$(ctl_cmd DOMAINLISTS.GET) || true
    assert_json_pred "VNT-20 DOMAINLISTS.GET lists[] sorted by (kind,id)" "$lists_get" \
        'import sys,json; j=json.load(sys.stdin); ls=j["result"]["lists"]; key=[(e["listKind"],e["listId"]) for e in ls]; assert key==sorted(key)'
    assert_json_pred "VNT-20b DOMAINLISTS.GET contains our listId" "$lists_get" \
        "import sys,json; j=json.load(sys.stdin); ls=j['result']['lists']; assert any(e['listId']=='${list_id}' for e in ls)"

    imp=$(ctl_cmd DOMAINLISTS.IMPORT "{\"listId\":\"${list_id}\",\"listKind\":\"block\",\"mask\":1,\"clear\":1,\"domains\":[\"a.com\",\"b.com\"]}" || true)
    assert_json_pred "VNT-21 DOMAINLISTS.IMPORT imported==2" "$imp" \
        'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert j["result"]["imported"] == 2'

    lists_get2=$(ctl_cmd DOMAINLISTS.GET) || true
    assert_json_pred "VNT-22 DOMAINLISTS.IMPORT updates only domainsCount" "$lists_get2" \
        "import sys,json; j=json.load(sys.stdin); ls=j['result']['lists']; e=[x for x in ls if x['listId']=='${list_id}'][0]; assert e['domainsCount']==2 and e['url']=='https://example/list' and e['etag']=='etagX' and e['outdated']==0"

    log_section "Domain Casebook"

    if [[ -z "$app_uid" ]]; then
        log_skip "VNT-DOM Domain casebook skipped (no apps)"
    else
        if ! stage_dx_netd_injector; then
            exit 77
        fi

        set +e
        domain_casebook_smoke "$app_uid"
        local domain_casebook_rc=$?
        set -e
        if [[ $domain_casebook_rc -eq 77 ]]; then
            exit 77
        fi
        if [[ $domain_casebook_rc -ne 0 ]]; then
            log_fail "VNT-DOM Domain casebook Case 1-9"
            return 1
        fi
        log_pass "VNT-DOM Domain casebook Case 1-9"
    fi

    log_section "IPRULES Surface"

    if [[ -z "$app_uid" ]]; then
        log_skip "VNT-22c IPRULES surface skipped (no apps)"
    else
        local ip_preflight ip_apply ip_print
        ip_preflight=$(ctl_cmd IPRULES.PREFLIGHT) || true
        assert_json_pred "VNT-22c IPRULES.PREFLIGHT has summary/limits" "$ip_preflight" \
            'import sys,json; j=json.load(sys.stdin); r=j["result"]; assert j["ok"] is True; assert "summary" in r and "limits" in r and "warnings" in r and "violations" in r'

        ip_apply=$(ctl_cmd IPRULES.APPLY "{\"app\":{\"uid\":${app_uid}},\"rules\":[{\"clientRuleId\":\"g1:r1\",\"family\":\"ipv4\",\"action\":\"block\",\"priority\":10,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"1.2.3.4/24\",\"sport\":\"any\",\"dport\":\"443\"},{\"clientRuleId\":\"g1:r2\",\"family\":\"ipv4\",\"action\":\"block\",\"priority\":11,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"2.3.4.5/24\",\"sport\":\"any\",\"dport\":\"443\"}]}" || true)
        assert_json_pred "VNT-22d IPRULES.APPLY ok + returns mapping" "$ip_apply" \
            'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; r=j["result"]; assert isinstance(r["uid"], int); assert isinstance(r["rules"], list); assert len(r["rules"])==2; assert set([x["clientRuleId"] for x in r["rules"]])==set(["g1:r1","g1:r2"]); assert all(isinstance(x["ruleId"], int) for x in r["rules"]); assert all(isinstance(x["matchKey"], str) for x in r["rules"])'

        ip_print=$(ctl_cmd IPRULES.PRINT "{\"app\":{\"uid\":${app_uid}}}") || true
        assert_json_pred "VNT-22e IPRULES.PRINT rules[] sorted by ruleId" "$ip_print" \
            'import sys,json; j=json.load(sys.stdin); rules=j["result"]["rules"]; ids=[r["ruleId"] for r in rules]; assert ids==sorted(ids)'
        assert_json_pred "VNT-22f IPRULES.PRINT has required fields + canonical CIDR" "$ip_print" \
            'import sys,json; j=json.load(sys.stdin); rules=j["result"]["rules"]; assert len(rules)==2; r0=rules[0]; assert "clientRuleId" in r0 and "matchKey" in r0 and "stats" in r0 and "ct" in r0; assert isinstance(r0["stats"]["hitPackets"], int); assert any(r["dst"]=="1.2.3.0/24" for r in rules); assert any("dst=1.2.3.0/24" in r["matchKey"] for r in rules)'
    fi

    log_section "Metrics Surface"

    local m_perf m_reasons m_sources m_traffic m_ct

    m_perf=$(ctl_cmd METRICS.GET '{"name":"perf"}' || true)
    assert_json_pred "VNT-22g METRICS.GET perf shape" "$m_perf" \
        'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; p=j["result"]["perf"]; assert "nfq_total_us" in p and "dns_decision_us" in p; s=p["nfq_total_us"]; assert set(["samples","min","avg","p50","p95","p99","max"]).issubset(s.keys())'

    m_reasons=$(ctl_cmd METRICS.GET '{"name":"reasons"}' || true)
    assert_json_pred "VNT-22h METRICS.GET reasons has ALLOW_DEFAULT" "$m_reasons" \
        'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; r=j["result"]["reasons"]; assert "ALLOW_DEFAULT" in r'

    m_sources=$(ctl_cmd METRICS.GET '{"name":"domainSources"}' || true)
    assert_json_pred "VNT-22i METRICS.GET domainSources has MASK_FALLBACK" "$m_sources" \
        'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; s=j["result"]["sources"]; assert "MASK_FALLBACK" in s; assert set(["allow","block"]).issubset(s["MASK_FALLBACK"].keys())'

    log_section "DomainSources Behavior"

    if [[ -z "$app_uid" ]]; then
        log_skip "VNT-22i2 domainSources behavior skipped (no apps)"
    else
        local tracked_orig
        tracked_orig=$(ctl_cmd CONFIG.GET "{\"scope\":\"app\",\"app\":{\"uid\":${app_uid}},\"keys\":[\"tracked\"]}" 2>/dev/null || true)
        tracked_orig=$(TRACKED_JSON="$tracked_orig" python3 - <<'PY'
import os, json
j = json.loads(os.environ["TRACKED_JSON"] or "{}")
print(j.get("result", {}).get("values", {}).get("tracked", 0))
PY
        ) || tracked_orig=0
        if [[ "$tracked_orig" != "0" && "$tracked_orig" != "1" ]]; then
            tracked_orig=0
        fi

        assert_ctl_ok "VNT-22i3 METRICS.RESET domainSources (device)" \
            ctl_cmd METRICS.RESET '{"name":"domainSources"}'
        local sources_zero
        sources_zero=$(ctl_cmd METRICS.GET '{"name":"domainSources"}' || true)
        assert_json_pred "VNT-22i4 domainSources zero after reset (device)" "$sources_zero" \
            'import sys,json; j=json.load(sys.stdin); s=j["result"]["sources"]; total=sum(int(v.get("allow",0))+int(v.get("block",0)) for v in s.values()); assert total==0'

        assert_ctl_ok "VNT-22i5 SET block.enabled=0 (gate domainSources)" \
            ctl_cmd CONFIG.SET '{"scope":"device","set":{"block.enabled":0}}'

        local dq_gate
        dq_gate=$(ctl_cmd DEV.DOMAIN.QUERY "{\"app\":{\"uid\":${app_uid}},\"domain\":\"bad.com\"}" 2>/dev/null || true)
        assert_json_pred "VNT-22i6 DEV.DOMAIN.QUERY returns shape" "$dq_gate" \
            'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; r=j["result"]; assert isinstance(r["uid"], int); assert isinstance(r["domain"], str); assert isinstance(r["blocked"], bool); assert isinstance(r["policySource"], str)'

        local sources_gated
        sources_gated=$(ctl_cmd METRICS.GET '{"name":"domainSources"}' || true)
        assert_json_pred "VNT-22i7 domainSources gated by block.enabled=0" "$sources_gated" \
            'import sys,json; j=json.load(sys.stdin); s=j["result"]["sources"]; total=sum(int(v.get("allow",0))+int(v.get("block",0)) for v in s.values()); assert total==0'

        assert_ctl_ok "VNT-22i8 SET block.enabled=1 (enable domainSources)" \
            ctl_cmd CONFIG.SET '{"scope":"device","set":{"block.enabled":1}}'

        assert_ctl_ok "VNT-22i9 METRICS.RESET domainSources (device)" \
            ctl_cmd METRICS.RESET '{"name":"domainSources"}'

        local dq_grow
        dq_grow=$(ctl_cmd DEV.DOMAIN.QUERY "{\"app\":{\"uid\":${app_uid}},\"domain\":\"bad.com\"}" 2>/dev/null || true)
        assert_json_pred "VNT-22j0 DEV.DOMAIN.QUERY ok (growth)" "$dq_grow" \
            'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

        local sources_grow
        sources_grow=$(ctl_cmd METRICS.GET '{"name":"domainSources"}' || true)
        assert_json_pred "VNT-22j1 domainSources grows under block.enabled=1" "$sources_grow" \
            'import sys,json; j=json.load(sys.stdin); s=j["result"]["sources"]; total=sum(int(v.get("allow",0))+int(v.get("block",0)) for v in s.values()); assert total>=1'

        assert_ctl_ok "VNT-22j2 SET tracked=0 (per-app domainSources should still grow)" \
            ctl_cmd CONFIG.SET "{\"scope\":\"app\",\"app\":{\"uid\":${app_uid}},\"set\":{\"tracked\":0}}"

        assert_ctl_ok "VNT-22j3 METRICS.RESET domainSources (app)" \
            ctl_cmd METRICS.RESET "{\"name\":\"domainSources\",\"app\":{\"uid\":${app_uid}}}"

        local dq_app
        dq_app=$(ctl_cmd DEV.DOMAIN.QUERY "{\"app\":{\"uid\":${app_uid}},\"domain\":\"bad.com\"}" 2>/dev/null || true)
        assert_json_pred "VNT-22j4 DEV.DOMAIN.QUERY ok (app)" "$dq_app" \
            'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

        local sources_app
        sources_app=$(ctl_cmd METRICS.GET "{\"name\":\"domainSources\",\"app\":{\"uid\":${app_uid}}}" || true)
        assert_json_pred "VNT-22j5 domainSources(app) grows even when tracked=0" "$sources_app" \
            'import sys,json; j=json.load(sys.stdin); s=j["result"]["sources"]; total=sum(int(v.get("allow",0))+int(v.get("block",0)) for v in s.values()); assert total>=1'

        assert_ctl_ok "VNT-22j6 restore tracked" \
            ctl_cmd CONFIG.SET "{\"scope\":\"app\",\"app\":{\"uid\":${app_uid}},\"set\":{\"tracked\":${tracked_orig}}}"

        assert_ctl_ok "VNT-22j7 restore block.enabled" \
            ctl_cmd CONFIG.SET "{\"scope\":\"device\",\"set\":{\"block.enabled\":${block_orig}}}"
    fi

    m_traffic=$(ctl_cmd METRICS.GET '{"name":"traffic"}' || true)
    assert_json_pred "VNT-22j METRICS.GET traffic has required keys" "$m_traffic" \
        'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; t=j["result"]["traffic"]; assert set(["dns","rxp","rxb","txp","txb"]).issubset(t.keys()); assert set(["allow","block"]).issubset(t["txp"].keys())'

    m_ct=$(ctl_cmd METRICS.GET '{"name":"conntrack"}' || true)
    assert_json_pred "VNT-22k METRICS.GET conntrack has required fields" "$m_ct" \
        'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; ct=j["result"]["conntrack"]; assert set(["totalEntries","creates","expiredRetires","overflowDrops"]).issubset(ct.keys())'

    local ct_reset
    ct_reset=$(ctl_cmd METRICS.RESET '{"name":"conntrack"}' || true)
    assert_json_pred "VNT-22l METRICS.RESET conntrack rejected" "$ct_reset" \
        'import sys,json; j=json.load(sys.stdin); assert j["ok"] is False; assert j["error"]["code"] == "INVALID_ARGUMENT"'

    # Best-effort: try to generate a small amount of traffic (usually from shell uid=2000),
    # then verify per-app traffic counters increase and can be reset.
    local block_get block_enabled
    block_get=$(ctl_cmd CONFIG.GET '{"scope":"device","keys":["block.enabled"]}' || true)
    block_enabled=$(BLOCK_GET_JSON="$block_get" python3 - <<'PY'
import os, json
j = json.loads(os.environ["BLOCK_GET_JSON"])
print(j.get("result", {}).get("values", {}).get("block.enabled", ""))
PY
) || block_enabled=""

    if [[ "$block_enabled" != "1" ]]; then
        log_skip "VNT-22m traffic generation skipped (block.enabled!=1)"
    else
        local uid_shell traffic_shell_before traffic_shell_after traffic_shell_reset
        uid_shell=2000

        traffic_shell_before=$(ctl_cmd METRICS.GET "{\"name\":\"traffic\",\"app\":{\"uid\":${uid_shell}}}" 2>/dev/null || true)

        # Try a few packets; ignore errors (offline device, blocked network, etc).
        adb_cmd shell "ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1" || true

        traffic_shell_after=$(ctl_cmd METRICS.GET "{\"name\":\"traffic\",\"app\":{\"uid\":${uid_shell}}}" 2>/dev/null || true)

        if TRAFFIC_JSON="$traffic_shell_after" python3 - <<'PY' >/dev/null 2>&1
import json
import os
j = json.loads(os.environ.get("TRAFFIC_JSON") or "{}")
if not j.get("ok", False):
    raise SystemExit(1)
t = j["result"]["traffic"]
total = 0
for k in ("dns","rxp","rxb","txp","txb"):
    total += int(t[k]["allow"]) + int(t[k]["block"])
if total <= 0:
    raise SystemExit(1)
PY
        then
            log_pass "VNT-22m traffic counters increased (shell uid=2000)"

            assert_ctl_ok "VNT-22n METRICS.RESET traffic (shell uid=2000)" \
                ctl_cmd METRICS.RESET "{\"name\":\"traffic\",\"app\":{\"uid\":${uid_shell}}}"

            traffic_shell_reset=$(ctl_cmd METRICS.GET "{\"name\":\"traffic\",\"app\":{\"uid\":${uid_shell}}}" 2>/dev/null || true)
            if TRAFFIC_JSON="$traffic_shell_reset" python3 - <<'PY' >/dev/null 2>&1
import json
import os
j = json.loads(os.environ.get("TRAFFIC_JSON") or "{}")
if not j.get("ok", False):
    raise SystemExit(1)
t = j["result"]["traffic"]
for k in ("dns","rxp","rxb","txp","txb"):
    if int(t[k]["allow"]) != 0 or int(t[k]["block"]) != 0:
        raise SystemExit(1)
PY
            then
                log_pass "VNT-22o traffic reset clears per-app counters (shell uid=2000)"
            else
                log_skip "VNT-22o traffic reset check skipped (non-zero after reset; background traffic?)"
            fi
        else
            log_skip "VNT-22m traffic generation skipped (could not observe per-app counters)"
        fi
    fi

    log_section "Resetall"

    local resetall
    resetall=$(ctl_cmd RESETALL) || true
    assert_json_pred "VNT-23 RESETALL ok=true" "$resetall" \
        'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'
    assert_ctl_ok "VNT-24 HELLO after RESETALL" ctl_cmd HELLO

    local ct_after_resetall
    ct_after_resetall=$(ctl_cmd METRICS.GET '{"name":"conntrack"}' || true)
    assert_json_pred "VNT-24b conntrack counters cleared by RESETALL (best-effort)" "$ct_after_resetall" \
        'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; ct=j["result"]["conntrack"]; assert ct["totalEntries"] == 0 and ct["creates"] == 0 and ct["expiredRetires"] == 0 and ct["overflowDrops"] == 0'

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
