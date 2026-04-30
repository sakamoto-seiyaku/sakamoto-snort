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
  printf '用法: %s [选项]\n\n' "$0"
  cat <<'EOF'
选项:
  --serial <serial>        指定目标真机 serial（等价于设置 ADB_SERIAL）
  --skip-deploy            跳过 deploy，复用当前真机上的守护进程
  --cleanup-forward        结束后移除 adb forward
  --profile <name>         smoke|perf|matrix|stress|longrun（默认: smoke；后 4 者当前为 staged，缺 case 时会 SKIP）
  --group <token>          只运行指定 group（按 case 文件名推导，如 iprules/perf）
  --case <token>           只运行指定 case（按 case 文件名子串匹配）
  -h, --help               显示帮助

环境变量:
  ADB, ADB_SERIAL          指定 adb 与目标设备
  VNEXT_PORT, SNORT_CTL    vNext 控制面（默认 127.0.0.1:60607，经 adb forward；ctl 默认自动探测）
  IPTEST_APP_UID           profile 运行时使用的目标 uid（默认：从 `APPS.LIST` 自动选择一个 `uid>=10000` 的 app uid；优先挑选具备 `INTERNET` 权限的包）
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
      out+=("$case_dir/14_iprules_vnext_smoke.sh")
      out+=("$case_dir/16_iprules_vnext_datapath_smoke.sh")
      out+=("$case_dir/18_flow_telemetry_smoke.sh")
      out+=("$case_dir/22_conntrack_ct.sh")
      ;;
    matrix)
      out+=("$case_dir/00_env.sh")
      out+=("$case_dir/20_matrix_l3l4.sh")
      out+=("$case_dir/22_conntrack_ct.sh")
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
  local explicit_iptest_uid="${IPTEST_UID-}"
  local explicit_iptest_app_uid="${IPTEST_APP_UID-}"

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
  if ! vnext_preflight; then
    exit 77
  fi

  pick_iptest_uid() {
    if [[ -n "$explicit_iptest_app_uid" ]]; then
      printf '%s\n' "$explicit_iptest_app_uid"
      return 0
    fi
    if [[ -n "$explicit_iptest_uid" ]]; then
      printf '%s\n' "$explicit_iptest_uid"
      return 0
    fi

    # Pick a stable uid for vNext CONFIG.SET(scope=app).
    #
    # Notes:
    # - vNext app selector is best-effort based on AppManager snapshots. For the
    #   device module we intentionally prefer real "app uids" (uid>=10000).
    # - Some package entries returned by APPS.LIST are overlays/RRO; those may not
    #   have network permission and will make Tier-1 traffic tests fail.
    set +e
    local apps_json
    apps_json="$(vnext_ctl_cmd APPS.LIST '{"limit":500}' 2>/dev/null)"
    local rc=$?
    set -e
    if [[ $rc -ne 0 ]]; then
      echo "BLOCKED: vNext APPS.LIST failed" >&2
      return 77
    fi

    local candidates
    candidates="$(APPS_JSON="$apps_json" python3 - <<'PY'
import os, json
j = json.loads(os.environ["APPS_JSON"])
apps = j.get("result", {}).get("apps", [])
for it in apps:
    uid = it.get("uid")
    name = it.get("app", "")
    if not isinstance(uid, int):
        continue
    if uid < 10000:
        continue
    if not isinstance(name, str) or not name:
        continue
    print(f"{uid}\t{name}")
PY
)" || candidates=""

    if [[ -z "$candidates" ]]; then
      echo "BLOCKED: APPS.LIST returned empty app list" >&2
      return 77
    fi

    local picked_uid="" fallback_uid=""
    local cand_uid cand_app
    while IFS=$'\t' read -r cand_uid cand_app; do
      [[ -n "$cand_uid" && -n "$cand_app" ]] || continue

      # Basic sanity: ensure we can switch to the uid.
      set +e
      local u
      u="$(adb_cmd shell "su $cand_uid sh -c 'id -u' 2>/dev/null" </dev/null | tr -d '\r\n')"
      rc=$?
      set -e
      if [[ $rc -ne 0 || "$u" != "$cand_uid" ]]; then
        continue
      fi

      # Some app uids exist in APPS.LIST but do not have network permission
      # (common for overlay/RRO packages). Probe socket creation to reject
      # those uids early; this avoids Tier-1 tests failing with EPERM.
      set +e
      local sock_probe
      sock_probe="$(adb_cmd shell "su $cand_uid sh -c 'nc -n -z -w 1 127.0.0.1 1 2>&1 || true'" </dev/null | tr -d '\r')"
      rc=$?
      set -e
      if [[ $rc -ne 0 ]]; then
        continue
      fi
      if echo "$sock_probe" | grep -qiE "Operation not permitted|Permission denied"; then
        continue
      fi

      # Keep the first usable uid as fallback.
      if [[ -z "$fallback_uid" ]]; then
        fallback_uid="$cand_uid"
      fi

      # Prefer packages with INTERNET permission (best-effort).
      set +e
      adb_cmd shell "dumpsys package \"$cand_app\" 2>/dev/null | grep -q \"android.permission.INTERNET\"" </dev/null >/dev/null 2>&1
      local has_internet=$?
      set -e
      if [[ $has_internet -eq 0 ]]; then
        picked_uid="$cand_uid"
        break
      fi
    done <<<"$candidates"

    if [[ -z "$picked_uid" ]]; then
      picked_uid="$fallback_uid"
    fi
    if [[ -z "$picked_uid" ]]; then
      echo "BLOCKED: unable to find a usable app uid via APPS.LIST" >&2
      return 77
    fi

    printf '%s\n' "$picked_uid"
    return 0
  }

  set +e
  uid="$(pick_iptest_uid)"
  rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    exit $rc
  fi
  export IPTEST_APP_UID="$uid"
  export IPTEST_UID="$uid"
  log_info "target uid=$uid"

  local passed=0 failed=0 skipped=0 blocked=0

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
    elif [[ $rc -eq 77 ]]; then
      ((blocked += 1))
      break
    else
      ((failed += 1))
    fi
  done

  echo ""
  echo "== SUMMARY =="
  echo "passed=$passed failed=$failed skipped=$skipped blocked=$blocked"

  if [[ $CLEANUP_FORWARD -eq 1 ]]; then
    remove_control_vnext_forward "${VNEXT_PORT:-60607}" >/dev/null 2>&1 || true
  fi

  if [[ $failed -ne 0 ]]; then
    return 1
  fi
  if [[ $blocked -ne 0 ]]; then
    return 77
  fi
  return 0
}

main "$@"
