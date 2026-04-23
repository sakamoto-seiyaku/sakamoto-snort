#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

DO_DEPLOY=1
CLEANUP_FORWARD=0
GROUP_FILTER=""
CASE_FILTER=""

show_help() {
  cat <<'USAGE'
用法: dx-smoke-datapath.sh [选项]

选项:
  --serial <serial>       指定目标真机 serial
  --skip-deploy           跳过部署，直接复用当前真机上的守护进程
  --cleanup-forward       结束后移除 adb forward
  --group <token>         透传给 IP 模组（按 case 文件名推导的 group）
  --case <token>          透传给 IP 模组（按 case 文件名子串匹配）
  -h, --help              显示帮助

说明:
  - DX smoke datapath gate（vNext-only）：调用 IP 模组 `--profile smoke`。
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
    --group)
      GROUP_FILTER="$2"
      shift 2
      ;;
    --case)
      CASE_FILTER="$2"
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

cmd=(bash "$SNORT_ROOT/tests/device-modules/ip/run.sh" --profile smoke)
if [[ -n "${ADB_SERIAL:-}" ]]; then
  cmd+=(--serial "$ADB_SERIAL")
fi
if [[ $DO_DEPLOY -eq 0 ]]; then
  cmd+=(--skip-deploy)
fi
if [[ $CLEANUP_FORWARD -eq 1 ]]; then
  cmd+=(--cleanup-forward)
fi
if [[ -n "$GROUP_FILTER" ]]; then
  cmd+=(--group "$GROUP_FILTER")
fi
if [[ -n "$CASE_FILTER" ]]; then
  cmd+=(--case "$CASE_FILTER")
fi

"${cmd[@]}"
