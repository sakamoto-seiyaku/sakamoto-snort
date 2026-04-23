#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

DO_DEPLOY=1
CLEANUP_FORWARD=0

show_help() {
  cat <<'USAGE'
用法: dx-smoke-platform.sh [选项]

选项:
  --serial <serial>       指定目标真机 serial
  --skip-deploy           跳过部署，直接复用当前真机上的守护进程
  --cleanup-forward       结束后移除 adb forward
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

source "$SNORT_ROOT/dev/dev-android-device-lib.sh" || blocked "未找到/无法初始化 adb"

device_preflight || blocked "device_preflight 失败（adb/设备/root 不满足）"
log_info "目标真机: $(adb_target_desc)"

if [[ $DO_DEPLOY -eq 1 ]]; then
  log_section "Deploy"
  bash "$SNORT_ROOT/dev/dev-deploy.sh" --serial "$(adb_target_desc)" || exit 1
else
  log_info "skip deploy (--skip-deploy)"
fi

log_section "Sockets"
sock_ls="$(adb_su "ls -lZ /dev/socket/sucre-snort-control /dev/socket/sucre-snort-netd 2>/dev/null || true" | tr -d '\r')"
if printf '%s\n' "$sock_ls" | grep -q "/dev/socket/sucre-snort-control" && \
   printf '%s\n' "$sock_ls" | grep -q "/dev/socket/sucre-snort-netd"; then
  log_pass "socket namespace ok"
else
  log_fail "socket namespace"
  printf '%s\n' "$sock_ls" | sed 's/^/    /'
  exit 1
fi

log_section "Netd Prereq"
mount_line="$(adb_su "mount | grep libnetd_resolv.so || true" | tr -d '\r')"
if [[ -n "$mount_line" ]]; then
  log_pass "netd prerequisite ok"
else
  log_skip "netd prerequisite missing (libnetd_resolv.so 未挂载；需要时先跑 bash dev/dev-netd-resolv.sh prepare)"
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
  remove_control_forward 60606
  remove_control_vnext_forward 60607
fi

log_pass "dx-smoke-platform ok"
exit 0

