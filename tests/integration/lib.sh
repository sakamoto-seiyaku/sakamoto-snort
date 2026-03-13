#!/bin/bash
# tests/integration/lib.sh - sucre-snort 测试工具库
# 用于 tests/integration/full-smoke.sh / tests/integration/run.sh 的辅助函数

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../dev/dev-android-device-lib.sh"

# ============================================================================
# 配置
# ============================================================================
SNORT_HOST="${SNORT_HOST:-127.0.0.1}"
SNORT_PORT="${SNORT_PORT:-60606}"
SNORT_TIMEOUT="${SNORT_TIMEOUT:-5}"
ADB="${ADB:-$ADB_BIN}"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# 统计
PASSED=0
FAILED=0
SKIPPED=0

# ============================================================================
# 输出辅助
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((PASSED++))
}

log_fail() {
    echo -e "${RED}✗${NC} $1"
    ((FAILED++))
}

log_skip() {
    echo -e "${YELLOW}⊘${NC} $1"
    ((SKIPPED++))
}

log_section() {
    echo ""
    echo -e "${BOLD}${CYAN}═══ $1 ═══${NC}"
}

# ============================================================================
# 核心函数：发送命令
# ============================================================================

# 发送命令到 sucre-snort，返回响应
# 用法: result=$(send_cmd "HELLO")
# 用法: result=$(send_cmd "HELP" 10)  # 10秒超时
send_cmd() {
    local cmd="$1"
    local timeout="${2:-$SNORT_TIMEOUT}"

    python3 -c "
import socket
import sys
import time

try:
    s = socket.create_connection(('$SNORT_HOST', $SNORT_PORT), timeout=$timeout)
    s.sendall(b'$cmd\x00')
    s.settimeout(0.5)  # 短超时用于非阻塞读取

    # 读取响应，限制最大时间
    data = b''
    end_time = time.time() + $timeout
    max_size = 100000  # 最大 100KB

    while time.time() < end_time and len(data) < max_size:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            # 如果收到 NUL 结尾，响应完整
            if data.endswith(b'\x00'):
                break
        except socket.timeout:
            # 短暂无数据，继续等待
            if data:
                # 已有数据且无更多数据，可能完成
                break
            continue

    s.close()
    # 去掉结尾的 NUL
    if data.endswith(b'\x00'):
        data = data[:-1]
    sys.stdout.write(data.decode('utf-8', errors='replace'))
except Exception as e:
    sys.stderr.write(f'ERROR: {e}\n')
    sys.exit(1)
" 2>&1
}

# 发送命令并获取原始字节（用于调试）
send_cmd_raw() {
    local cmd="$1"
    local timeout="${2:-$SNORT_TIMEOUT}"

    python3 -c "
import socket
import sys

try:
    s = socket.create_connection(('$SNORT_HOST', $SNORT_PORT), timeout=$timeout)
    s.sendall(b'$cmd\x00')
    s.settimeout($timeout)

    data = b''
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if data.endswith(b'\x00'):
                break
        except socket.timeout:
            break

    s.close()
    print(repr(data))
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
" 2>&1
}

# ============================================================================
# 断言函数
# ============================================================================

# 断言返回 OK
# 用法: assert_ok "HELLO" "连接测试"
assert_ok() {
    local cmd="$1"
    local desc="$2"

    local result
    result=$(send_cmd "$cmd")
    local status=$?

    if [[ $status -ne 0 ]]; then
        log_fail "$desc: 命令执行失败"
        echo "    命令: $cmd"
        echo "    错误: $result"
        return 1
    fi

    if [[ "$result" == "OK" ]]; then
        log_pass "$desc"
        return 0
    else
        log_fail "$desc: 预期 OK，实际 '$result'"
        echo "    命令: $cmd"
        return 1
    fi
}

# 断言返回非空
# 用法: assert_not_empty "HELP" "帮助文本"
assert_not_empty() {
    local cmd="$1"
    local desc="$2"

    local result
    result=$(send_cmd "$cmd")
    local status=$?

    if [[ $status -ne 0 ]]; then
        log_fail "$desc: 命令执行失败"
        echo "    命令: $cmd"
        echo "    错误: $result"
        return 1
    fi

    if [[ -n "$result" ]]; then
        log_pass "$desc (${#result} bytes)"
        return 0
    else
        log_fail "$desc: 返回为空"
        echo "    命令: $cmd"
        return 1
    fi
}

# 断言返回有效 JSON
# 用法: assert_json "ALL.A" "全局统计"
assert_json() {
    local cmd="$1"
    local desc="$2"

    local result
    result=$(send_cmd "$cmd")
    local status=$?

    if [[ $status -ne 0 ]]; then
        log_fail "$desc: 命令执行失败"
        echo "    命令: $cmd"
        echo "    错误: $result"
        return 1
    fi

    # 验证 JSON
    if echo "$result" | python3 -c "import sys, json; json.load(sys.stdin)" 2>/dev/null; then
        log_pass "$desc"
        return 0
    else
        log_fail "$desc: 无效 JSON"
        echo "    命令: $cmd"
        echo "    响应: ${result:0:200}..."
        return 1
    fi
}

# 断言返回匹配正则
# 用法: assert_match "BLOCK" "^[01]$" "全局开关查询"
assert_match() {
    local cmd="$1"
    local pattern="$2"
    local desc="$3"

    local result
    result=$(send_cmd "$cmd")
    local status=$?

    if [[ $status -ne 0 ]]; then
        log_fail "$desc: 命令执行失败"
        echo "    命令: $cmd"
        echo "    错误: $result"
        return 1
    fi

    if echo "$result" | grep -qE "$pattern"; then
        log_pass "$desc: $result"
        return 0
    else
        log_fail "$desc: 不匹配 '$pattern'"
        echo "    命令: $cmd"
        echo "    响应: $result"
        return 1
    fi
}

# 断言设置后查询返回预期值
# 用法: assert_set_get "BLOCK" "0" "1" "全局开关设置"
assert_set_get() {
    local cmd_base="$1"
    local set_val="$2"
    local restore_val="$3"
    local desc="$4"

    # 设置
    local set_result
    set_result=$(send_cmd "$cmd_base $set_val")
    if [[ "$set_result" != "OK" ]]; then
        log_fail "$desc: 设置失败"
        echo "    命令: $cmd_base $set_val"
        echo "    响应: $set_result"
        return 1
    fi

    # 查询
    local get_result
    get_result=$(send_cmd "$cmd_base")
    if [[ "$get_result" != "$set_val" ]]; then
        log_fail "$desc: 查询值不匹配"
        echo "    设置: $set_val"
        echo "    查询: $get_result"
        # 恢复
        send_cmd "$cmd_base $restore_val" >/dev/null
        return 1
    fi

    # 恢复
    local restore_result
    restore_result=$(send_cmd "$cmd_base $restore_val")
    if [[ "$restore_result" != "OK" ]]; then
        log_fail "$desc: 恢复失败"
        return 1
    fi

    log_pass "$desc"
    return 0
}

# ============================================================================
# JSON 查询辅助
# ============================================================================

# 从 JSON 提取字段
# 用法: json_get '{"a":1}' '.a' -> 1
json_get() {
    local json="$1"
    local path="$2"
    echo "$json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
path = '$path'.split('.')
for p in path:
    if p:
        if p.isdigit():
            data = data[int(p)]
        else:
            data = data[p]
print(json.dumps(data) if isinstance(data, (dict, list)) else data)
" 2>/dev/null
}

# 检查 JSON 是否包含某个键
# 用法: json_has '{"a":1}' 'a' && echo "has a"
json_has() {
    local json="$1"
    local key="$2"
    echo "$json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
sys.exit(0 if '$key' in data else 1)
" 2>/dev/null
}

# ============================================================================
# 流式测试辅助
# ============================================================================

# 采样流式数据（指定时间）
# 用法: stream_sample "DNSSTREAM.START" "DNSSTREAM.STOP" 2
stream_sample() {
    local start_cmd="$1"
    local stop_cmd="$2"
    local duration="${3:-1}"

    python3 -c "
import socket
import time
import sys

try:
    s = socket.create_connection(('$SNORT_HOST', $SNORT_PORT), timeout=10)
    s.sendall(b'$start_cmd\x00')
    s.settimeout(0.5)

    data = b''
    end_time = time.time() + $duration

    while time.time() < end_time:
        try:
            chunk = s.recv(4096)
            if chunk:
                data += chunk
        except socket.timeout:
            pass

    # 发送停止命令
    s.sendall(b'$stop_cmd\x00')
    time.sleep(0.1)
    s.close()

    # 输出采样数据（将控制协议里的 NUL 转成换行，便于逐条解析 JSON 事件）
    sys.stdout.write(data.replace(b'\x00', b'\n').decode('utf-8', errors='replace'))
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
" 2>&1
}

# ============================================================================
# 环境检查
# ============================================================================

# 检查守护进程是否运行
check_daemon() {
    local result
    result=$(send_cmd "HELLO" 2)
    if [[ "$result" == "OK" ]]; then
        return 0
    else
        return 1
    fi
}

# 检查 adb forward
check_forward() {
    check_control_forward "$SNORT_PORT"
}

# 设置 adb forward
setup_forward() {
    setup_control_forward "$SNORT_PORT"
}

# ============================================================================
# 报告
# ============================================================================

print_summary() {
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════${NC}"
    echo -e "${BOLD}测试汇总${NC}"
    echo -e "${BOLD}═══════════════════════════════════════${NC}"
    echo -e "  ${GREEN}通过${NC}: $PASSED"
    echo -e "  ${RED}失败${NC}: $FAILED"
    echo -e "  ${YELLOW}跳过${NC}: $SKIPPED"
    echo -e "  总计: $((PASSED + FAILED + SKIPPED))"
    echo ""

    if [[ $FAILED -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}所有测试通过!${NC}"
        return 0
    else
        echo -e "${RED}${BOLD}有 $FAILED 个测试失败${NC}"
        return 1
    fi
}

# ============================================================================
# 初始化
# ============================================================================

init_test_env() {
    log_info "初始化测试环境..."

    if ! device_preflight; then
        echo -e "${RED}错误: 真机 preflight 失败${NC}"
        return 1
    fi

    log_info "目标真机: $(adb_target_desc)"

    if ! check_forward; then
        log_info "设置 adb forward..."
        setup_forward
    fi

    if ! check_daemon; then
        echo -e "${RED}错误: 守护进程未响应${NC}"
        echo "请确保守护进程正在运行:"
        echo "  ${ADB} -s $(adb_target_desc) shell \"su -c '/data/local/tmp/sucre-snort-dev &'\""
        return 1
    fi

    log_info "守护进程连接正常"
    return 0
}
