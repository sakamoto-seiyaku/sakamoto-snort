#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DO_DEPLOY=1
CLEANUP_FORWARD=0

show_help() {
  cat <<'USAGE'
用法: dx-smoke.sh [选项]

选项:
  --serial <serial>       指定目标真机 serial
  --skip-deploy           跳过部署，直接复用当前真机上的守护进程
  --cleanup-forward       结束后移除 adb forward
  -h, --help              显示帮助

说明:
  - DX smoke 总入口：固定顺序 `platform -> control -> datapath`，fail-fast。
  - BLOCKED 使用退出码 77（供 CTest/VS Code Testing 标记为 skipped）。
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

run_stage() {
  local name="$1"
  shift

  echo ""
  echo "=== $name ==="

  set +e
  "$@"
  local rc=$?
  set -e

  if [[ $rc -ne 0 ]]; then
    return $rc
  fi
  return 0
}

platform_cmd=(bash "$SCRIPT_DIR/dx-smoke-platform.sh")
control_cmd=(bash "$SCRIPT_DIR/dx-smoke-control.sh")
datapath_cmd=(bash "$SCRIPT_DIR/dx-smoke-datapath.sh")

if [[ -n "${ADB_SERIAL:-}" ]]; then
  platform_cmd+=(--serial "$ADB_SERIAL")
  control_cmd+=(--serial "$ADB_SERIAL")
  datapath_cmd+=(--serial "$ADB_SERIAL")
fi

if [[ $DO_DEPLOY -eq 0 ]]; then
  platform_cmd+=(--skip-deploy)
  control_cmd+=(--skip-deploy)
  datapath_cmd+=(--skip-deploy)
else
  # platform 已 deploy 后，后续两段固定复用当前守护进程
  control_cmd+=(--skip-deploy)
  datapath_cmd+=(--skip-deploy)
fi

if [[ $CLEANUP_FORWARD -eq 1 ]]; then
  platform_cmd+=(--cleanup-forward)
  control_cmd+=(--cleanup-forward)
  datapath_cmd+=(--cleanup-forward)
fi

run_stage "dx-smoke-platform" "${platform_cmd[@]}" || exit $?
run_stage "dx-smoke-control" "${control_cmd[@]}" || exit $?
run_stage "dx-smoke-datapath" "${datapath_cmd[@]}" || exit $?

echo ""
echo "dx-smoke: PASS"
exit 0

