#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$SCRIPT_DIR/.."
source "$SCRIPT_DIR/dev-android-device-lib.sh"

BINARY="$SNORT_ROOT/build-output/sucre-snort"
TARGET=/data/local/tmp/sucre-snort-dev
PROC_NAME=$(basename "$TARGET")
LOG_DIR=/data/local/tmp
LOG=$LOG_DIR/sucre-snort-dev.log
CLEAR_LOG=1
STAGE_ONLY=0
CONTROL_FORWARD_PORT="${CONTROL_FORWARD_PORT:-60616}"

control_socket_roundtrip() {
    local request="$1"
    local expected="$2"

    if ! adb_su "ls /dev/socket/sucre-snort-control" >/dev/null 2>&1; then
        return 1
    fi

    adb_cmd forward "tcp:${CONTROL_FORWARD_PORT}" localabstract:sucre-snort-control >/dev/null 2>&1 || return 1
    python3 - <<PY >/dev/null 2>&1
import socket, sys
port = int(${CONTROL_FORWARD_PORT})
request = ${request@Q}.encode("utf-8") + b"\0"
expected = ${expected@Q}
try:
    sock = socket.create_connection(("127.0.0.1", port), timeout=2)
    sock.sendall(request)
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
    sys.exit(0 if data.decode("utf-8", errors="replace").strip() == expected else 1)
except Exception:
    sys.exit(1)
PY
    local status=$?
    adb_cmd forward --remove "tcp:${CONTROL_FORWARD_PORT}" >/dev/null 2>&1 || true
    return $status
}

request_dev_shutdown() {
    control_socket_roundtrip "DEV.SHUTDOWN" "OK"
}

request_dev_hello() {
    control_socket_roundtrip "HELLO" "OK"
}

clear_debugger_residue() {
    local pid="$1"
    local tracer_pid

    tracer_pid=$(adb_su "awk '/^TracerPid:/ {print \$2}' /proc/$pid/status 2>/dev/null || true" | tr -d '\r\n')
    if [[ -n "$tracer_pid" && "$tracer_pid" != "0" ]]; then
        echo "  检测到残留 debugger (TracerPid: $tracer_pid)，先清理..."
        adb_su "kill -9 $tracer_pid 2>/dev/null || true"
        adb_su "kill -CONT $pid 2>/dev/null || true"
        sleep 1
    fi
}

show_help() {
    cat <<EOF
用法: $0 [选项]

选项:
  --serial <serial>   指定目标真机 serial
  --no-clear-log      保留原有日志，不清空 dev.log
  --stage-only        仅停止旧进程、推送并准备二进制，不启动守护进程
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
        --no-clear-log)
            CLEAR_LOG=0
            shift
            ;;
        --stage-only)
            STAGE_ONLY=1
            shift
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

echo "=== Sucre-Snort Development Deploy ==="
echo ""

if [[ ! -f "$BINARY" ]]; then
    echo "❌ 二进制文件不存在: $BINARY"
    echo "运行: bash dev/dev-build.sh"
    exit 1
fi

device_preflight

echo "目标真机: $(adb_target_desc)"
echo "二进制: $BINARY"
echo "目标路径: $TARGET"
echo ""

echo "[1/6] 停止现有进程..."
CURRENT_PID=$(adb_su "pidof $PROC_NAME 2>/dev/null | awk '{print \$1}'" | tr -d '\r\n' || true)
if [[ -n "$CURRENT_PID" ]]; then
    clear_debugger_residue "$CURRENT_PID"
fi
if request_dev_shutdown; then
    echo "  已通过 DEV.SHUTDOWN 请求优雅退出"
else
    adb_su "killall $PROC_NAME 2>/dev/null || true"
fi
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if ! adb_su "pidof $PROC_NAME >/dev/null 2>&1" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
if adb_su "pidof $PROC_NAME >/dev/null 2>&1" >/dev/null 2>&1; then
    CURRENT_PID=$(adb_su "pidof $PROC_NAME 2>/dev/null | awk '{print \$1}'" | tr -d '\r\n' || true)
    if [[ -n "$CURRENT_PID" ]]; then
        clear_debugger_residue "$CURRENT_PID"
    fi
    echo "⚠️  进程未能在宽限期内退出，强制终止..."
    adb_su "killall -9 $PROC_NAME 2>/dev/null || true"
    sleep 1
fi
adb_su "rm -f /dev/socket/sucre-snort-control /dev/socket/sucre-snort-netd 2>/dev/null || true"

echo "[2/6] 推送二进制文件..."
adb_push_file "$BINARY" "$TARGET" 2>&1 | grep -E "pushed|[0-9]+ KB/s|[0-9]+ MB/s" || true

echo "[3/6] 设置权限..."
adb_su "chmod 755 $TARGET"

if [[ $CLEAR_LOG -eq 1 ]]; then
    echo "[4/6] 清理旧日志..."
    adb_su "mkdir -p $LOG_DIR && : > $LOG"
else
    echo "[4/6] 保留现有日志..."
    adb_su "mkdir -p $LOG_DIR"
fi

if [[ $STAGE_ONLY -eq 1 ]]; then
    echo "[5/5] 设备预部署完成（未启动守护进程）"
    echo ""
    echo "✅ 已完成 stage-only，可直接进入 run-under-debugger"
    exit 0
fi

echo "[5/6] 启动守护进程..."
adb_su "$TARGET >> $LOG 2>&1 &"

echo "[6/6] 健康检查..."
sleep 2

ERRORS=0

echo -n "  进程状态: "
if adb_su "pidof $PROC_NAME" >/dev/null 2>&1; then
    PID=$(adb_su "pidof $PROC_NAME" | tr -d '\r\n')
    echo "✓ 运行中 (PID: $PID)"
else
    echo "❌ 未运行"
    ERRORS=$((ERRORS + 1))
fi

echo -n "  控制 Socket: "
if adb_su "ls /dev/socket/sucre-snort-control" >/dev/null 2>&1; then
    echo "✓ 已创建"
else
    echo "❌ 未创建"
    ERRORS=$((ERRORS + 1))
fi

echo -n "  DNS Socket: "
if adb_su "ls /dev/socket/sucre-snort-netd" >/dev/null 2>&1; then
    echo "✓ 已创建"
else
    echo "❌ 未创建"
    ERRORS=$((ERRORS + 1))
fi

echo -n "  控制协议 HELLO: "
if request_dev_hello; then
    echo "✓ OK"
else
    echo "❌ 未响应"
    ERRORS=$((ERRORS + 1))
fi

echo -n "  SELinux: "
CONTEXT=$(adb_su "ps -AZ | grep $PROC_NAME | awk '{print \$1}' | head -1" | tr -d '\r\n' || true)
if [[ -n "$CONTEXT" ]]; then
    echo "$CONTEXT"
else
    echo "⚠️  无法获取"
fi

echo ""
echo "=== 最近日志 (最后10行) ==="
adb_su "tail -10 $LOG" 2>/dev/null || echo "日志为空或无法读取"

echo ""
if [[ $ERRORS -eq 0 ]]; then
    echo "✅ 部署成功"
else
    echo "❌ 部署完成，但有 $ERRORS 个检查失败"
    exit 1
fi

echo ""
echo "=== 快速命令 ==="
echo "实时日志:    ${ADB_BIN} -s $(adb_target_desc) shell su -c \"tail -f $LOG\""
echo "进程状态:    ${ADB_BIN} -s $(adb_target_desc) shell su -c \"ps -AZ | grep sucre\""
echo "Socket状态:  ${ADB_BIN} -s $(adb_target_desc) shell su -c \"ls -lZ /dev/socket/sucre*\""
echo "诊断工具:    bash dev/dev-diagnose.sh --serial $(adb_target_desc)"
