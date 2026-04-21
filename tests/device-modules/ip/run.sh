#!/bin/bash

set -euo pipefail

IPMOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$IPMOD_DIR/../../.." && pwd)"

DO_DEPLOY=1
CLEANUP_FORWARD=0
PROFILE="smoke"
GROUP_FILTER=""
CASE_FILTER=""

show_help() {
  cat <<EOF
用法: $0 [选项]

选项:
  --serial <serial>        指定目标真机 serial（等价于设置 ADB_SERIAL）
  --skip-deploy            跳过 deploy，复用当前真机上的守护进程
  --cleanup-forward        结束后移除 adb forward
  --profile <name>         smoke|vnext|perf|matrix|stress|longrun（默认: smoke；后 3 者当前为 staged，缺 case 时会 SKIP）
  --group <token>          只运行指定 group（按 case 文件名推导，如 iprules/perf）
  --case <token>           只运行指定 case（按 case 文件名子串匹配）
  -h, --help               显示帮助

环境变量:
  ADB, ADB_SERIAL          指定 adb 与目标设备
  SNORT_HOST, SNORT_PORT   控制协议连接（默认 127.0.0.1:60606，经 adb forward）
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
    --profile)
      PROFILE="$2"
      shift 2
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
      show_help
      exit 1
      ;;
  esac
done

case_dir="$IPMOD_DIR/cases"

case_group_from_path() {
  local p="$1"
  local b
  b="$(basename "$p" .sh)" # e.g. 10_iprules_smoke
  b="${b#*_}"              # iprules_smoke
  printf '%s\n' "${b%%_*}" # iprules
}

case_matches_filters() {
  local p="$1"
  local b g
  b="$(basename "$p" .sh)"
  g="$(case_group_from_path "$p")"

  if [[ -n "$GROUP_FILTER" && "$g" != "$GROUP_FILTER" ]]; then
    return 1
  fi
  if [[ -n "$CASE_FILTER" && "$b" != *"$CASE_FILTER"* ]]; then
    return 1
  fi
  return 0
}

collect_cases_for_profile() {
  local profile="$1"
  local -a out=()

  case "$profile" in
    smoke)
      out+=("$case_dir/00_env.sh")
      out+=("$case_dir/10_iprules_smoke.sh")
      out+=("$case_dir/12_native_replay_poc.sh")
      ;;
    vnext)
      out+=("$case_dir/00_env.sh")
      out+=("$case_dir/14_iprules_vnext_smoke.sh")
      ;;
    matrix)
      out+=("$case_dir/00_env.sh")
      out+=("$case_dir/20_matrix_l3l4.sh")
      out+=("$case_dir/22_conntrack_ct.sh")
      out+=("$case_dir/30_ip_leak.sh")
      out+=("$case_dir/40_iface_block.sh")
      ;;
    stress)
      out+=("$case_dir/00_env.sh")
      out+=("$case_dir/50_stress.sh")
      ;;
    perf)
      out+=("$case_dir/00_env.sh")
      out+=("$case_dir/60_perf.sh")
      out+=("$case_dir/62_perf_ct_compare.sh")
      ;;
    longrun)
      out+=("$case_dir/00_env.sh")
      out+=("$case_dir/70_longrun.sh")
      ;;
    *)
      echo "未知 profile: $profile" >&2
      exit 1
      ;;
  esac

  printf '%s\n' "${out[@]}"
}

run_case() {
  local path="$1"
  local name
  name="$(basename "$path" .sh)"

  echo ""
  echo "=== CASE: $name ==="

  if [[ ! -f "$path" ]]; then
    echo "SKIP: missing case script: $path"
    return 10
  fi

  bash "$path"
}

main() {
  if [[ $DO_DEPLOY -eq 1 ]]; then
    echo "== deploy =="
    local -a deploy_cmd=(bash "$SNORT_ROOT/dev/dev-deploy.sh")
    if [[ -n "${ADB_SERIAL:-}" ]]; then
      deploy_cmd+=(--serial "$ADB_SERIAL")
    fi
    "${deploy_cmd[@]}"
  fi

  # Preflight once (forward + HELLO). Individual cases still do their own baseline resets.
  source "$IPMOD_DIR/lib.sh"
  init_test_env

  local passed=0 failed=0 skipped=0

  mapfile -t cases < <(collect_cases_for_profile "$PROFILE")
  local c
  for c in "${cases[@]}"; do
    if ! case_matches_filters "$c"; then
      continue
    fi

    set +e
    run_case "$c"
    local rc=$?
    set -e

    if [[ $rc -eq 0 ]]; then
      ((passed += 1))
    elif [[ $rc -eq 10 ]]; then
      ((skipped += 1))
    else
      ((failed += 1))
    fi
  done

  echo ""
  echo "== SUMMARY =="
  echo "passed=$passed failed=$failed skipped=$skipped"

  if [[ $CLEANUP_FORWARD -eq 1 ]]; then
    remove_control_forward "${SNORT_PORT:-60606}" >/dev/null 2>&1 || true
  fi

  if [[ $failed -ne 0 ]]; then
    return 1
  fi
  return 0
}

main "$@"
