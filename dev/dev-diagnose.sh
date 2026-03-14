#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/dev-android-device-lib.sh"

PROC_NAME="sucre-snort-dev"
TARGET="/data/local/tmp/sucre-snort-dev"
LOG="/data/local/tmp/sucre-snort-dev.log"
CONTROL_FORWARD_PORT="${CONTROL_FORWARD_PORT:-60618}"

show_help() {
    cat <<EOF
用法: $0 [选项]

选项:
  --serial <serial>   指定目标真机 serial
  -h, --help          显示帮助
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --serial)
            ADB_SERIAL="$2"
            export ADB_SERIAL
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "未知选项: $1" >&2
            show_help
            exit 1
            ;;
    esac
done

print_section() {
    echo ""
    echo "【$1】"
}

resolve_pid() {
    adb_su "pidof $PROC_NAME 2>/dev/null | awk '{print \$1}'" | tr -d '\r\n' || true
}

control_hello() {
    if ! adb_su "ls /dev/socket/sucre-snort-control" >/dev/null 2>&1; then
        return 1
    fi
    adb_cmd forward "tcp:${CONTROL_FORWARD_PORT}" localabstract:sucre-snort-control >/dev/null 2>&1
    python3 - <<PY
import socket, sys
port = int(${CONTROL_FORWARD_PORT})
try:
    sock = socket.create_connection(("127.0.0.1", port), timeout=2)
    sock.sendall(b"HELLO\0")
    sock.settimeout(3)
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if data.endswith(b"\0"):
            break
    sock.close()
    if data.endswith(b"\0"):
        data = data[:-1]
    print(data.decode("utf-8", errors="replace"), end="")
except Exception as exc:
    print(f"ERROR: {exc}", end="")
    sys.exit(1)
PY
    local status=$?
    adb_cmd forward --remove "tcp:${CONTROL_FORWARD_PORT}" >/dev/null 2>&1 || true
    return $status
}

echo "╔═══════════════════════════════════════╗"
echo "║ Sucre-Snort 当前真机诊断             ║"
echo "╚═══════════════════════════════════════╝"

device_preflight

print_section "1. 设备与 root"
echo "设备: $(adb_target_desc)"
echo "root: $(adb_su "id" | tr -d '\r')"
echo "SELinux: $(adb_su "getenforce" | tr -d '\r\n')"

print_section "2. 进程与 tracer"
PID="$(resolve_pid)"
if [[ -n "$PID" ]]; then
    echo "PID: $PID"
    adb_su "ps -AZ | grep $PROC_NAME || true" | sed 's/^/  /'
    TRACER_PID="$(adb_su "awk '/^TracerPid:/ {print \$2}' /proc/$PID/status" | tr -d '\r\n')"
    echo "TracerPid: ${TRACER_PID:-0}"
    if [[ -n "$TRACER_PID" && "$TRACER_PID" != "0" ]]; then
        echo "⚠️  检测到遗留 debugger；重新 deploy 会自动清理。"
    fi
else
    echo "❌ $PROC_NAME 未运行"
fi

print_section "3. 控制面与 socket"
HELLO_RESULT="$(control_hello || true)"
echo "HELLO: ${HELLO_RESULT:-<no-response>}"
adb_su "ls -lZ /dev/socket/sucre-snort-control /dev/socket/sucre-snort-netd 2>/dev/null || true" | sed 's/^/  /'

print_section "4. 二进制与日志"
adb_su "ls -lh $TARGET 2>/dev/null || true" | sed 's/^/  /'
adb_su "tail -20 $LOG 2>/dev/null || true" | sed 's/^/  /'

print_section "5. 平台依赖"
echo "libnetd_resolv.so 挂载:"
adb_su "mount | grep libnetd_resolv.so || true" | sed 's/^/  /'
echo "iptables / ip6tables (sucre-snort):"
adb_su "iptables -S 2>/dev/null | grep sucre-snort || true" | sed 's/^/  /'
adb_su "ip6tables -S 2>/dev/null | grep sucre-snort || true" | sed 's/^/  /'

echo ""
echo "建议："
echo "  重新部署: bash dev/dev-deploy.sh --serial $(adb_target_desc)"
echo "  P1 baseline: bash tests/integration/run.sh --serial $(adb_target_desc)"
echo "  P2 smoke:    bash tests/integration/device-smoke.sh --serial $(adb_target_desc)"
echo "  P3 debug:    python3 dev/dev-vscode-debug-task.py prepare attach"
