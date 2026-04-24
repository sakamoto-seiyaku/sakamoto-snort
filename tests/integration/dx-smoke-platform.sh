#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

DO_DEPLOY=1
CLEANUP_FORWARD=0

VNEXT_PORT="${VNEXT_PORT:-60607}"
SNORT_CTL="${SNORT_CTL:-}"

show_help() {
  cat <<'USAGE'
用法: dx-smoke-platform.sh [选项]

选项:
  --serial <serial>       指定目标真机 serial
  --skip-deploy           跳过部署，直接复用当前真机上的守护进程
  --cleanup-forward       结束后移除 adb forward
  --ctl <path>            指定 sucre-snort-ctl 路径（默认自动探测）
  --port <port>           指定 host tcp port（默认: 60607 -> localabstract:sucre-snort-control-vnext）
  -h, --help              显示帮助

说明:
  - DX smoke 平台 gate（vNext-only）：root/环境、socket、iptables/ip6tables hooks、NFQUEUE 规则、SELinux AVC。
  - 本入口不调用 legacy 控制协议命令。
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

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_pass() { echo -e "${GREEN}✓${NC} $1"; }
log_fail() { echo -e "${RED}✗${NC} $1"; }
log_skip() { echo -e "${YELLOW}⊘${NC} $1"; }
log_section() { echo ""; echo -e "${BOLD}${CYAN}═══ $1 ═══${NC}"; }

blocked() {
  echo -e "${YELLOW}BLOCKED:${NC} $1" >&2
  exit 77
}

require_python3() {
  if ! command -v python3 >/dev/null 2>&1; then
    blocked "未找到 python3（脚本断言依赖）；请先安装/配置 python3"
  fi
}

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

ensure_vnext_forward() {
  if check_control_vnext_forward "$VNEXT_PORT"; then
    return 0
  fi
  log_info "设置 vNext adb forward..."
  if ! setup_control_vnext_forward "$VNEXT_PORT"; then
    return 1
  fi
  return 0
}

vnext_hello_sanity() {
  local attempts="$1"
  local delay_sec="$2"
  local on_fail="${3:-fail}" # fail|blocked

  local i out err rc tmp_err
  for i in $(seq 1 "$attempts"); do
    tmp_err="$(mktemp)"
    set +e
    out="$(ctl_cmd HELLO 2>"$tmp_err")"
    rc=$?
    set -e
    err="$(cat "$tmp_err" 2>/dev/null || true)"
    rm -f "$tmp_err"
    if [[ $rc -eq 0 ]] && printf '%s\n' "$out" | python3 -c \
      'import sys,json; j=json.load(sys.stdin); r=j["result"]; assert j["ok"] is True; assert r["protocol"]=="control-vnext"; assert r["protocolVersion"]==1; assert r["framing"]=="netstring"; assert "maxRequestBytes" in r and "maxResponseBytes" in r' \
      >/dev/null 2>&1; then
      log_pass "vNext HELLO ok"
      return 0
    fi
    if [[ $i -lt $attempts ]]; then
      sleep "$delay_sec"
    fi
  done

  if [[ "$on_fail" == "blocked" ]]; then
    log_skip "vNext HELLO not ready (--skip-deploy)"
  else
    log_fail "vNext HELLO sanity"
  fi
  if [[ -n "$out" ]]; then
    echo "    stdout:"
    printf '%s\n' "$out" | head -n 8 | sed 's/^/      /'
  fi
  if [[ -n "$err" ]]; then
    echo "    stderr:"
    printf '%s\n' "$err" | head -n 8 | sed 's/^/      /'
  fi
  return 1
}

log_section "Host Tools"
require_python3
SNORT_CTL="$(find_snort_ctl)" || blocked "未找到/无法使用 sucre-snort-ctl；请先构建（例如: cmake --build --preset dev-debug --target sucre-snort-ctl），或用 --ctl 指定路径"
log_info "sucre-snort-ctl: $SNORT_CTL"

source "$SNORT_ROOT/dev/dev-android-device-lib.sh" || blocked "未找到/无法初始化 adb"

device_preflight || blocked "device_preflight 失败（adb/设备/root 不满足）"
log_info "目标真机: $(adb_target_desc)"

if [[ $DO_DEPLOY -eq 1 ]]; then
  log_section "Deploy"
  bash "$SNORT_ROOT/dev/dev-deploy.sh" --serial "$(adb_target_desc)" || exit 1
else
  log_info "skip deploy (--skip-deploy)"
fi

log_section "Daemon"
pid="$(adb_su "pidof sucre-snort-dev 2>/dev/null || true" | tr -d '\r\n')"
if [[ -n "$pid" ]]; then
  log_pass "daemon running (pid=$pid)"
else
  if [[ $DO_DEPLOY -eq 0 ]]; then
    blocked "skip-deploy 但设备上无 sucre-snort-dev；去掉 --skip-deploy 或先 deploy"
  fi
  log_fail "daemon running"
  exit 1
fi

log_section "Sockets"
sock_ls="$(adb_su "ls -lZ /dev/socket/sucre-snort-control-vnext /dev/socket/sucre-snort-netd 2>/dev/null || true" | tr -d '\r')"
if printf '%s\n' "$sock_ls" | grep -q "/dev/socket/sucre-snort-control-vnext" && \
   printf '%s\n' "$sock_ls" | grep -q "/dev/socket/sucre-snort-netd"; then
  log_pass "socket namespace ok"
else
  if [[ $DO_DEPLOY -eq 0 ]]; then
    log_skip "socket namespace missing (--skip-deploy)"
    printf '%s\n' "$sock_ls" | sed 's/^/    /'
    blocked "skip-deploy 但 socket namespace 不就绪；去掉 --skip-deploy 或先 deploy"
  fi
  log_fail "socket namespace"
  printf '%s\n' "$sock_ls" | sed 's/^/    /'
  exit 1
fi

log_section "vNext"
if ! ensure_vnext_forward; then
  if [[ $DO_DEPLOY -eq 0 ]]; then
    blocked "skip-deploy 且 vNext adb forward 失败；去掉 --skip-deploy 或先 deploy"
  fi
  log_fail "vNext adb forward"
  exit 1
fi

if [[ $DO_DEPLOY -eq 1 ]]; then
  vnext_hello_sanity 5 0.5 || exit 1
else
  vnext_hello_sanity 1 0 blocked || blocked "skip-deploy 但 vNext 控制面不可用；去掉 --skip-deploy 或先 deploy"
fi

log_section "Netd Prereq"
mount_line="$(adb_su "nsenter -t 1 -m -- mount 2>/dev/null | grep libnetd_resolv.so || mount | grep libnetd_resolv.so || true" | tr -d '\r')"
if [[ -n "$mount_line" ]]; then
  log_pass "netd prerequisite ok"
else
  log_skip "netd prerequisite missing (libnetd_resolv.so 未挂载；需要时先跑 bash dev/dev-netd-resolv.sh status / prepare)"
fi

log_section "Firewall Hooks"
iptables_rules="$(adb_su "iptables -S 2>/dev/null" | tr -d '\r')"
ip6tables_rules="$(adb_su "ip6tables -S 2>/dev/null" | tr -d '\r')"

need_v4=(
  "-A INPUT -j sucre-snort_INPUT"
  "-A OUTPUT -j sucre-snort_OUTPUT"
  "-N sucre-snort_INPUT"
  "-N sucre-snort_OUTPUT"
)
need_v6=(
  "-A INPUT -j sucre-snort_INPUT"
  "-A OUTPUT -j sucre-snort_OUTPUT"
  "-N sucre-snort_INPUT"
  "-N sucre-snort_OUTPUT"
)

missing=0
for r in "${need_v4[@]}"; do
  if ! printf '%s\n' "$iptables_rules" | grep -Fqx -- "$r"; then
    echo "missing iptables rule: $r" >&2
    missing=1
  fi
done
if ! printf '%s\n' "$iptables_rules" | grep -Eq -- '^-A sucre-snort_INPUT( .*)? -j NFQUEUE' || \
   ! printf '%s\n' "$iptables_rules" | grep -Eq -- '^-A sucre-snort_OUTPUT( .*)? -j NFQUEUE'; then
  echo "missing iptables NFQUEUE rules" >&2
  missing=1
fi

for r in "${need_v6[@]}"; do
  if ! printf '%s\n' "$ip6tables_rules" | grep -Fqx -- "$r"; then
    echo "missing ip6tables rule: $r" >&2
    missing=1
  fi
done
if ! printf '%s\n' "$ip6tables_rules" | grep -Eq -- '^-A sucre-snort_INPUT( .*)? -j NFQUEUE' || \
   ! printf '%s\n' "$ip6tables_rules" | grep -Eq -- '^-A sucre-snort_OUTPUT( .*)? -j NFQUEUE'; then
  echo "missing ip6tables NFQUEUE rules" >&2
  missing=1
fi

if [[ $missing -eq 0 ]]; then
  log_pass "iptables/ip6tables hooks + NFQUEUE rules ok"
else
  log_fail "iptables/ip6tables hooks + NFQUEUE rules"
  adb_su "iptables -S 2>/dev/null | grep sucre-snort || true" | sed 's/^/    /'
  adb_su "ip6tables -S 2>/dev/null | grep sucre-snort || true" | sed 's/^/    /'
  exit 1
fi

log_section "SELinux"
mode="$(adb_su "getenforce" | tr -d '\r\n')"
context="$(adb_su "ps -AZ | grep sucre-snort-dev | head -1 || true" | tr -d '\r')"
denials="$(adb_su "logcat -d -s AVC 2>/dev/null | grep -i sucre | tail -20 || true" | tr -d '\r')"

if [[ -z "$mode" || -z "$context" ]]; then
  log_fail "SELinux runtime"
  echo "    mode=$mode"
  echo "    context=${context:-<empty>}"
  exit 1
fi
if [[ -n "$denials" ]]; then
  log_fail "SELinux AVC denials"
  printf '%s\n' "$denials" | sed 's/^/    /'
  exit 1
fi
log_pass "SELinux runtime ok ($mode)"

if [[ $DO_DEPLOY -eq 1 ]]; then
  log_section "Lifecycle Restart"
  adb_su "killall sucre-snort-dev 2>/dev/null || true"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    pid_after="$(adb_su "pidof sucre-snort-dev 2>/dev/null || true" | tr -d '\r\n')"
    [[ -z "$pid_after" ]] && break
    sleep 1
  done
  bash "$SNORT_ROOT/dev/dev-deploy.sh" --serial "$(adb_target_desc)" || exit 1
  log_pass "lifecycle restart ok"
else
  log_skip "lifecycle restart skipped (--skip-deploy)"
fi

if [[ $CLEANUP_FORWARD -eq 1 ]]; then
  log_info "移除 adb forward..."
  remove_control_vnext_forward "$VNEXT_PORT"
fi

log_pass "dx-smoke-platform ok"
exit 0
