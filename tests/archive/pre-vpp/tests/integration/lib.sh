#!/bin/bash
# tests/integration/lib.sh - sucre-snort vNext-only 测试工具库
#
# 约束：
# - 本文件 **只** 提供 vNext 主线测试需要的通用能力（adb + 日志 + JSON helper）。
# - 任何 legacy 文本协议能力必须位于归档目录：`tests/archive/integration/lib_legacy.sh`。

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
if ! source "$SNORT_ROOT/dev/dev-android-device-lib.sh"; then
  echo "BLOCKED: adb/device helper unavailable; install adb or set ADB/ADB_SERIAL" >&2
  exit 77
fi

# Prefer a stable adb path if the caller set it; otherwise use dev lib's ADB_BIN.
ADB="${ADB:-$ADB_BIN}"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# 统计（vNext 脚本通常不依赖，但保留以兼容旧的 log_* 习惯）
PASSED=0
FAILED=0
SKIPPED=0

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_pass() { echo -e "${GREEN}✓${NC} $1"; PASSED=$((PASSED + 1)); }
log_fail() { echo -e "${RED}✗${NC} $1"; FAILED=$((FAILED + 1)); }
log_skip() { echo -e "${YELLOW}⊘${NC} $1"; SKIPPED=$((SKIPPED + 1)); }

log_section() {
  echo ""
  echo -e "${BOLD}${CYAN}═══ $1 ═══${NC}"
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
# 用法: json_has '{"a":1}' 'a' && echo \"has a\"
json_has() {
  local json="$1"
  local key="$2"
  echo "$json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
sys.exit(0 if '$key' in data else 1)
" 2>/dev/null
}

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
  fi

  echo -e "${RED}${BOLD}有 $FAILED 个测试失败${NC}"
  return 1
}
