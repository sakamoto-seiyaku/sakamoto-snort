#!/bin/bash

set -euo pipefail

IPMOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$IPMOD_DIR/../../../.." && pwd)"

DO_DEPLOY=1
CLEANUP_FORWARD=0

show_help() {
  cat <<'EOF'
用法: run_legacy.sh [选项]

选项:
  --serial <serial>       指定目标真机 serial（等价于设置 ADB_SERIAL）
  --skip-deploy           跳过 deploy，直接复用当前真机守护进程
  --cleanup-forward       结束后移除 adb forward
  -h, --help              显示帮助

说明:
  - 该入口为 legacy 文本协议回查用途（仅归档）。
  - 主线真机测试请使用 vNext-only 的 `dx-smoke*` / `dx-diagnostics*` 或 `tests/device/ip/run.sh`。
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

source "$IPMOD_DIR/lib_legacy.sh"

if [[ $DO_DEPLOY -eq 1 ]]; then
  deploy_cmd=(bash "$SNORT_ROOT/dev/dev-deploy.sh")
  if [[ -n "${ADB_SERIAL:-}" ]]; then
    deploy_cmd+=(--serial "$ADB_SERIAL")
  fi
  "${deploy_cmd[@]}"
fi

case_dir="$IPMOD_DIR/cases"

echo ""
echo "=== CASE: 10_iprules_smoke ==="
bash "$case_dir/10_iprules_smoke.sh"

echo ""
echo "=== CASE: 12_native_replay_poc ==="
bash "$case_dir/12_native_replay_poc.sh"

if [[ $CLEANUP_FORWARD -eq 1 ]]; then
  remove_control_forward 60606 >/dev/null 2>&1 || true
fi

echo ""
echo "legacy ip smoke: PASS"
exit 0

