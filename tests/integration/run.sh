#!/bin/bash

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

GROUP_FILTER=""
CASE_FILTER=""
DO_DEPLOY=1
RESET_BEFORE=0
CLEANUP_FORWARD=0

show_help() {
    cat <<EOF
用法: $0 [选项]

选项:
  --serial <serial>       指定目标真机 serial
  --group <csv>           只运行指定 group（core,config,app,streams,reset）
  --case <csv>            只运行指定 case（如 IT-01,IT-05）
  --skip-deploy           跳过部署，直接复用当前真机上的守护进程
  --reset-before          运行前先执行 RESETALL
  --cleanup-forward       结束后移除 adb forward
  -h, --help              显示帮助

示例:
  $0
  $0 --group core,app
  $0 --case IT-01,IT-07 --serial 28201JEGR0XPAJ
  $0 --skip-deploy --group reset
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --serial)
            ADB_SERIAL="$2"
            export ADB_SERIAL
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
        --skip-deploy)
            DO_DEPLOY=0
            shift
            ;;
        --reset-before)
            RESET_BEFORE=1
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
            show_help
            exit 1
            ;;
    esac
done

group_selected() {
    local group="$1"
    if [[ -z "$GROUP_FILTER" ]]; then
        return 0
    fi

    local token
    IFS=',' read -ra tokens <<< "$GROUP_FILTER"
    for token in "${tokens[@]}"; do
        if [[ "$token" == "$group" ]]; then
            return 0
        fi
    done
    return 1
}

case_selected() {
    local case_id="$1"
    if [[ -z "$CASE_FILTER" ]]; then
        return 0
    fi

    local token
    IFS=',' read -ra tokens <<< "$CASE_FILTER"
    for token in "${tokens[@]}"; do
        if [[ "$token" == "$case_id" ]]; then
            return 0
        fi
    done
    return 1
}

should_run_case() {
    local group="$1"
    local case_id="$2"
    group_selected "$group" || return 1
    case_selected "$case_id" || return 1
    return 0
}

skip_case() {
    local case_id="$1"
    local desc="$2"
    log_skip "$case_id $desc (filtered)"
}

case_it_01_hello() {
    local group="core"
    local case_id="IT-01"
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "HELLO"; return 0; }
    assert_ok "HELLO" "$case_id HELLO"
}

case_it_02_help() {
    local group="core"
    local case_id="IT-02"
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "HELP"; return 0; }
    assert_not_empty "HELP" "$case_id HELP"
}

case_it_03_block_roundtrip() {
    local group="config"
    local case_id="IT-03"
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "BLOCK roundtrip"; return 0; }

    local original
    original=$(send_cmd "BLOCK")
    if [[ "$original" =~ ^[01]$ ]]; then
        local toggled=$((1 - original))
        assert_set_get "BLOCK" "$toggled" "$original" "$case_id BLOCK roundtrip"
    else
        log_fail "$case_id BLOCK 查询格式错误"
    fi
}

case_it_04_blockipleaks_roundtrip() {
    local group="config"
    local case_id="IT-04"
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "BLOCKIPLEAKS roundtrip"; return 0; }

    local original
    original=$(send_cmd "BLOCKIPLEAKS")
    if [[ "$original" =~ ^[01]$ ]]; then
        local toggled=$((1 - original))
        assert_set_get "BLOCKIPLEAKS" "$toggled" "$original" "$case_id BLOCKIPLEAKS roundtrip"
    else
        log_fail "$case_id BLOCKIPLEAKS 查询格式错误"
    fi
}

case_it_05_app_lookup() {
    local group="app"
    local case_id="IT-05"
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "APP.NAME lookup"; return 0; }

    local result
    result=$(send_cmd "APP.NAME com.android")
    if echo "$result" | python3 -c "import sys, json; data = json.load(sys.stdin); raise SystemExit(0 if len(data) > 0 else 1)" 2>/dev/null; then
        log_pass "$case_id APP.NAME lookup"
    else
        log_fail "$case_id APP.NAME lookup"
        echo "    响应: ${result:0:200}..."
    fi
}

case_it_06_dnsstream_health() {
    local group="streams"
    local case_id="IT-06"
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "DNSSTREAM health"; return 0; }

    local result
    result=$(stream_sample "DNSSTREAM.START" "DNSSTREAM.STOP" 1)
    if [[ $? -eq 0 && "$result" != ERROR:* ]]; then
        log_pass "$case_id DNSSTREAM health (${#result} bytes)"
    else
        log_fail "$case_id DNSSTREAM health"
        echo "    响应: $result"
    fi
}

case_it_07_pktstream_health() {
    local group="streams"
    local case_id="IT-07"
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "PKTSTREAM health"; return 0; }

    local result
    result=$(stream_sample "PKTSTREAM.START" "PKTSTREAM.STOP" 1)
    if [[ $? -eq 0 && "$result" != ERROR:* ]]; then
        log_pass "$case_id PKTSTREAM health (${#result} bytes)"
    else
        log_fail "$case_id PKTSTREAM health"
        echo "    响应: $result"
    fi
}

case_it_08_activitystream_health() {
    local group="streams"
    local case_id="IT-08"
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "ACTIVITYSTREAM health"; return 0; }

    local result
    result=$(stream_sample "ACTIVITYSTREAM.START" "ACTIVITYSTREAM.STOP" 1)
    if [[ $? -eq 0 && "$result" != ERROR:* ]]; then
        log_pass "$case_id ACTIVITYSTREAM health (${#result} bytes)"
    else
        log_fail "$case_id ACTIVITYSTREAM health"
        echo "    响应: $result"
    fi
}

case_it_09_resetall() {
    local group="reset"
    local case_id="IT-09"
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "RESETALL"; return 0; }

    local result hello_after
    result=$(send_cmd "RESETALL" 10)
    if [[ "$result" != "OK" ]]; then
        log_fail "$case_id RESETALL returns OK"
        echo "    响应: $result"
        return 1
    fi

    sleep 1
    if ! adb_su "pidof sucre-snort-dev" >/dev/null 2>&1; then
        log_fail "$case_id daemon remains alive"
        return 1
    fi

    hello_after=$(send_cmd "HELLO")
    if [[ "$hello_after" == "OK" ]]; then
        log_pass "$case_id RESETALL baseline"
    else
        log_fail "$case_id RESETALL baseline"
        echo "    HELLO after reset: $hello_after"
    fi
}

run_all_cases() {
    case_it_01_hello
    case_it_02_help
    case_it_03_block_roundtrip
    case_it_04_blockipleaks_roundtrip
    case_it_05_app_lookup
    case_it_06_dnsstream_health
    case_it_07_pktstream_health
    case_it_08_activitystream_health
    case_it_09_resetall
}

main() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║ sucre-snort Host-driven Integration Tests (baseline)   ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""

    device_preflight || exit 1
    echo "目标真机: $(adb_target_desc)"

    if [[ $DO_DEPLOY -eq 1 ]]; then
        bash "$SCRIPT_DIR/../../dev/dev-deploy.sh" --serial "$(adb_target_desc)" || exit 1
    fi

    if ! init_test_env; then
        exit 1
    fi

    if [[ $RESET_BEFORE -eq 1 ]]; then
        log_info "运行前执行 RESETALL..."
        local reset_result
        reset_result=$(send_cmd "RESETALL" 10)
        if [[ "$reset_result" != "OK" ]]; then
            echo -e "${RED}错误: 预重置失败: $reset_result${NC}"
            exit 1
        fi
        sleep 1
    fi

    run_all_cases
    print_summary
    local status=$?

    if [[ $CLEANUP_FORWARD -eq 1 ]]; then
        log_info "移除 adb forward..."
        remove_control_forward "$SNORT_PORT"
    fi

    return $status
}

main "$@"
