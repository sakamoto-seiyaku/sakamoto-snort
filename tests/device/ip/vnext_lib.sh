#!/bin/bash

# Shared vNext helpers for the IP device module.
#
# Assumptions:
# - Caller already sourced `tests/integration/lib.sh` (for adb + forward helpers).
# - Caller defines `SNORT_ROOT` (repo root).

VNEXT_PORT="${VNEXT_PORT:-60607}"
SNORT_CTL="${SNORT_CTL:-}"

vnext_find_snort_ctl() {
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

vnext_ctl_cmd() {
  local cmd="$1"
  local args_json="${2:-}"
  if [[ -n "$args_json" ]]; then
    "$SNORT_CTL" --tcp "127.0.0.1:${VNEXT_PORT}" --compact "$cmd" "$args_json"
  else
    "$SNORT_CTL" --tcp "127.0.0.1:${VNEXT_PORT}" --compact "$cmd"
  fi
}

vnext_ctl_follow() {
  local cmd="$1"
  local args_json="${2:-}"
  shift || true
  if [[ -n "$args_json" ]]; then
    "$SNORT_CTL" --tcp "127.0.0.1:${VNEXT_PORT}" --compact --follow "$cmd" "$args_json" "$@"
  else
    "$SNORT_CTL" --tcp "127.0.0.1:${VNEXT_PORT}" --compact --follow "$cmd" "$@"
  fi
}

vnext_json_get() {
  local json="$1"
  local path="$2"
  json_get "$json" "$path"
}

vnext_assert_ok() {
  local desc="$1"
  local json="$2"
  if printf '%s\n' "$json" | python3 -c 'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True' >/dev/null 2>&1; then
    log_pass "$desc"
    return 0
  fi
  log_fail "$desc"
  printf '%s\n' "$json" | head -n 3 | sed 's/^/    /'
  return 1
}

vnext_preflight() {
  if ! device_preflight; then
    echo "BLOCKED: device_preflight failed (need adb + rooted device)" >&2
    return 77
  fi

  if ! check_control_vnext_forward "$VNEXT_PORT"; then
    setup_control_vnext_forward "$VNEXT_PORT" || {
      echo "BLOCKED: setup_control_vnext_forward failed (port=$VNEXT_PORT)" >&2
      return 77
    }
  fi

  SNORT_CTL="$(vnext_find_snort_ctl)" || return 77
  export SNORT_CTL

  set +e
  local hello
  hello="$(vnext_ctl_cmd HELLO 2>/dev/null)"
  local st=$?
  set -e
  if [[ $st -ne 0 ]]; then
    echo "BLOCKED: vNext control HELLO failed (port=$VNEXT_PORT)" >&2
    return 77
  fi

  if ! printf '%s\n' "$hello" | python3 -c 'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert j["result"]["protocol"]=="control-vnext"' >/dev/null 2>&1; then
    echo "BLOCKED: vNext HELLO response invalid" >&2
    printf '%s\n' "$hello" | head -n 3 | sed 's/^/    /' >&2
    return 77
  fi

  return 0
}

