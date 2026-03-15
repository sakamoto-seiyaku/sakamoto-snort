#!/bin/bash

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

DO_DEPLOY=1
CLEANUP_FORWARD=0

TEST_UID="${TEST_UID:-2000}" # shell user (stable on Android)

show_help() {
    cat <<EOF
用法: $0 [选项]

选项:
  --serial <serial>       指定目标真机 serial
  --skip-deploy           跳过部署，直接复用当前真机上的守护进程
  --cleanup-forward       结束后移除 adb forward
  -h, --help              显示帮助

环境变量:
  TEST_UID                触发流量的目标 UID（默认: 2000 / shell）
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
            show_help
            exit 1
            ;;
    esac
done

adb_shell() {
    local command="$1"
    local quoted
    quoted="$(shell_single_quote "$command")"
    adb_cmd shell "sh -c $quoted"
}

expect_ok() {
    local cmd="$1"
    local desc="$2"
    local result
    result="$(send_cmd "$cmd")"
    if [[ "$result" == "OK" ]]; then
        log_pass "$desc"
        return 0
    fi
    log_fail "$desc"
    echo "    命令: $cmd"
    echo "    响应: $result"
    return 1
}

expect_nok() {
    local cmd="$1"
    local desc="$2"
    local result
    result="$(send_cmd "$cmd")"
    if [[ "$result" == "NOK" ]]; then
        log_pass "$desc"
        return 0
    fi
    log_fail "$desc"
    echo "    命令: $cmd"
    echo "    响应: $result"
    return 1
}

expect_uint() {
    local cmd="$1"
    local desc="$2"
    local result
    result="$(send_cmd "$cmd")"
    if [[ "$result" =~ ^[0-9]+$ ]]; then
        log_pass "$desc (value=$result)" >&2
        echo "$result"
        return 0
    fi
    log_fail "$desc" >&2
    echo "    命令: $cmd" >&2
    echo "    响应: $result" >&2
    return 1
}

get_reason_packets() {
    local reason="$1"
    local json
    json="$(send_cmd "METRICS.REASONS")"
    json_get "$json" "reasons.${reason}.packets"
}

get_rule_stat() {
    local rid="$1"
    local stat="$2"
    local json
    json="$(send_cmd "IPRULES.PRINT RULE ${rid}")"
    json_get "$json" "rules.0.stats.${stat}"
}

ping4_once() {
    local target="$1"
    if adb_shell "command -v ping >/dev/null 2>&1"; then
        adb_shell "ping -4 -c 1 -W 1 \"$target\" >/dev/null 2>&1 || ping -c 1 -W 1 \"$target\" >/dev/null 2>&1 || true" >/dev/null 2>&1
        return 0
    fi
    return 1
}

main() {
    log_section "IP rules engine (IPRULES.* / IFACES.PRINT)"

    if [[ $DO_DEPLOY -eq 1 ]]; then
        log_info "先执行 deploy，确保真机处于干净可测状态..."
        if ! bash dev/dev-deploy.sh >/dev/null; then
            log_fail "deploy failed"
            print_summary
            exit 1
        fi
        log_pass "deploy ok"
    fi

    if ! init_test_env; then
        log_fail "init_test_env"
        print_summary
        exit 1
    fi

    expect_ok "RESETALL" "RESETALL"
    expect_ok "BLOCK 1" "BLOCK enable"
    expect_ok "BLOCKIPLEAKS 0" "BLOCKIPLEAKS baseline off"

    assert_match "IPRULES" "^[01]$" "IPRULES toggle query"
    expect_nok "IPRULES 2" "IPRULES rejects invalid value"
    expect_ok "IPRULES 1" "IPRULES enable"
    expect_ok "IPRULES 1" "IPRULES idempotent (1->1)"

    assert_json "IFACES.PRINT" "IFACES.PRINT JSON"
    assert_json "IPRULES.PREFLIGHT" "IPRULES.PREFLIGHT JSON"
    assert_json "IPRULES.PRINT" "IPRULES.PRINT JSON (empty ruleset)"

    log_section "Control plane validation"
    expect_nok "IPRULES.ADD ${TEST_UID} action=allow" "ADD rejects missing priority (does not consume ruleId)"
    expect_nok "IPRULES.ADD ${TEST_UID} action=allow priority=10 bogus=1" "ADD rejects unknown keys atomically"
    local rid0
    rid0="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10" "ADD ok after prior failures")"
    if [[ "$rid0" != "0" ]]; then
        log_fail "ruleId should start at 0 after RESETALL"
        echo "    got: $rid0"
    else
        log_pass "ruleId starts at 0 after RESETALL"
    fi

    expect_nok "IPRULES.ADD ${TEST_UID} action=allow priority=11 enforce=0" "ADD rejects action=allow,enforce=0"
    expect_nok "IPRULES.ADD ${TEST_UID} action=block priority=11 enforce=0" "ADD rejects action=block,enforce=0 without log=1"
    expect_nok "IPRULES.ADD ${TEST_UID} action=block priority=11 enforce=0 log=0" "ADD rejects enforce=0,log=0"
    local wouldRid
    wouldRid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=block priority=11 enforce=0 log=1 proto=icmp" "ADD would-block rule")"
    expect_nok "IPRULES.ADD ${TEST_UID} action=block priority=12 ct=foo" "ADD rejects ct token"

    log_section "UPDATE patch semantics"
    local updRid
    updRid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=5 log=1 dport=80" "ADD rule for UPDATE")"
    expect_ok "IPRULES.UPDATE ${updRid} dport=443" "UPDATE ok"
    local printed
    printed="$(send_cmd "IPRULES.PRINT RULE ${updRid}")"
    if [[ "$(json_get "$printed" "rules.0.log")" != "1" ]]; then
        log_fail "UPDATE preserves omitted fields (log)"
    else
        log_pass "UPDATE preserves omitted fields (log)"
    fi
    if [[ "$(json_get "$printed" "rules.0.dport")" != "443" ]]; then
        log_fail "UPDATE changed dport"
        echo "    dport: $(json_get "$printed" "rules.0.dport")"
    else
        log_pass "UPDATE changed dport"
    fi
    expect_nok "IPRULES.UPDATE ${updRid} bogus=1" "UPDATE rejects unknown key without mutation"
    local printed2
    printed2="$(send_cmd "IPRULES.PRINT RULE ${updRid}")"
    if [[ "$(json_get "$printed2" "rules.0.dport")" != "443" ]]; then
        log_fail "NOK UPDATE is atomic"
    else
        log_pass "NOK UPDATE is atomic"
    fi

    log_section "Runtime stats & verdict integration"
    expect_ok "METRICS.REASONS.RESET" "METRICS.REASONS.RESET"

    if ! ping4_once "1.1.1.1"; then
        log_skip "ping not available; skip traffic-dependent checks"
        print_summary
        exit 0
    fi

    local allowRid
    allowRid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=100 proto=icmp" "ADD enforce allow rule")"

    local allowBefore
    allowBefore="$(get_reason_packets "IP_RULE_ALLOW")"
    ping4_once "1.1.1.1"
    local allowAfter
    allowAfter="$(get_reason_packets "IP_RULE_ALLOW")"
    if [[ "$allowAfter" -gt "$allowBefore" ]]; then
        log_pass "reason IP_RULE_ALLOW grows under traffic ($allowBefore -> $allowAfter)"
    else
        log_fail "reason IP_RULE_ALLOW did not grow under traffic ($allowBefore -> $allowAfter)"
    fi
    local hits
    hits="$(get_rule_stat "$allowRid" "hitPackets")"
    if [[ "$hits" -ge 1 ]]; then
        log_pass "per-rule hitPackets grows (hitPackets=$hits)"
    else
        log_fail "per-rule hitPackets did not grow (hitPackets=$hits)"
    fi

    expect_ok "IPRULES.UPDATE ${allowRid} priority=101" "UPDATE clears stats"
    local hitsCleared
    hitsCleared="$(get_rule_stat "$allowRid" "hitPackets")"
    if [[ "$hitsCleared" -eq 0 ]]; then
        log_pass "UPDATE clears stats (hitPackets=0)"
    else
        log_fail "UPDATE did not clear stats (hitPackets=$hitsCleared)"
    fi

    ping4_once "1.1.1.1"
    local hitsAfterUpdate
    hitsAfterUpdate="$(get_rule_stat "$allowRid" "hitPackets")"
    if [[ "$hitsAfterUpdate" -ge 1 ]]; then
        log_pass "stats updated after UPDATE (hitPackets=$hitsAfterUpdate)"
    else
        log_fail "stats not updated after UPDATE (hitPackets=$hitsAfterUpdate)"
    fi

    expect_ok "IPRULES.ENABLE ${allowRid} 0" "ENABLE 1->0"
    local hitsBeforeDisabled
    hitsBeforeDisabled="$(get_rule_stat "$allowRid" "hitPackets")"
    ping4_once "1.1.1.1"
    local hitsAfterDisabled
    hitsAfterDisabled="$(get_rule_stat "$allowRid" "hitPackets")"
    if [[ "$hitsAfterDisabled" -eq "$hitsBeforeDisabled" ]]; then
        log_pass "disabled rule does not update stats"
    else
        log_fail "disabled rule updated stats unexpectedly ($hitsBeforeDisabled -> $hitsAfterDisabled)"
    fi

    expect_ok "IPRULES.ENABLE ${allowRid} 1" "ENABLE 0->1"
    local hitsAfterReenable
    hitsAfterReenable="$(get_rule_stat "$allowRid" "hitPackets")"
    if [[ "$hitsAfterReenable" -eq 0 ]]; then
        log_pass "ENABLE 0->1 clears stats"
    else
        log_fail "ENABLE 0->1 did not clear stats (hitPackets=$hitsAfterReenable)"
    fi

    ping4_once "1.1.1.1"
    local hitsAfterReenableTraffic
    hitsAfterReenableTraffic="$(get_rule_stat "$allowRid" "hitPackets")"
    if [[ "$hitsAfterReenableTraffic" -ge 1 ]]; then
        log_pass "stats updated after re-enable (hitPackets=$hitsAfterReenableTraffic)"
    else
        log_fail "stats not updated after re-enable (hitPackets=$hitsAfterReenableTraffic)"
    fi

    log_section "IFACE_BLOCK precedence"
    expect_ok "METRICS.REASONS.RESET" "METRICS.REASONS.RESET"
    expect_ok "BLOCKIFACE ${TEST_UID} 255" "BLOCKIFACE all"
    local ifaceBefore
    ifaceBefore="$(get_reason_packets "IFACE_BLOCK")"
    ping4_once "1.1.1.1"
    local ifaceAfter
    ifaceAfter="$(get_reason_packets "IFACE_BLOCK")"
    if [[ "$ifaceAfter" -gt "$ifaceBefore" ]]; then
        log_pass "IFACE_BLOCK grows under traffic ($ifaceBefore -> $ifaceAfter)"
    else
        log_fail "IFACE_BLOCK did not grow under traffic ($ifaceBefore -> $ifaceAfter)"
    fi

    log_section "Would-block overlay (accept-only)"
    expect_ok "RESETALL" "RESETALL (would-block test)"
    expect_ok "BLOCK 1" "BLOCK enable"
    expect_ok "IPRULES 1" "IPRULES enable"
    expect_ok "BLOCKIPLEAKS 0" "BLOCKIPLEAKS off (accept case)"
    local wouldOnlyRid
    wouldOnlyRid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=block priority=10 enforce=0 log=1 proto=icmp" "ADD would-block rule")"
    ping4_once "1.1.1.1"
    local wouldAccepted
    wouldAccepted="$(get_rule_stat "$wouldOnlyRid" "wouldHitPackets")"
    if [[ "$wouldAccepted" -ge 1 ]]; then
        log_pass "wouldHitPackets grows when accepted (wouldHitPackets=$wouldAccepted)"
    else
        log_fail "wouldHitPackets did not grow when accepted (wouldHitPackets=$wouldAccepted)"
    fi

    log_section "BLOCK=0 bypasses all processing"
    expect_ok "RESETALL" "RESETALL (BLOCK=0 test)"
    expect_ok "BLOCK 0" "BLOCK disable"
    expect_ok "IPRULES 1" "IPRULES enabled while BLOCK=0"
    expect_ok "METRICS.REASONS.RESET" "METRICS.REASONS.RESET"
    ping4_once "1.1.1.1"
    local reasonsJson
    reasonsJson="$(send_cmd "METRICS.REASONS")"
    local total=0
    total="$(echo "$reasonsJson" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(sum(v.get("packets",0) for v in d.get("reasons",{}).values()))' 2>/dev/null || echo 0)"
    if [[ "$total" -eq 0 ]]; then
        log_pass "METRICS.REASONS does not grow under traffic when BLOCK=0"
    else
        log_fail "METRICS.REASONS grew under traffic when BLOCK=0 (totalPackets=$total)"
    fi

    if [[ $CLEANUP_FORWARD -eq 1 ]]; then
        log_info "移除 adb forward..."
        remove_control_forward "$SNORT_PORT"
    fi

    print_summary
}

main "$@"
