#!/bin/bash

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib_legacy.sh"

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

ping4_async() {
    local target="$1"
    local delay="${2:-1}"
    if adb_shell "command -v ping >/dev/null 2>&1"; then
        adb_shell "sleep \"$delay\"; ping -4 -c 1 -W 1 \"$target\" >/dev/null 2>&1 || ping -c 1 -W 1 \"$target\" >/dev/null 2>&1 || true" >/dev/null 2>&1 &
        echo "$!"
        return 0
    fi
    return 1
}

resolve_ipv4_via_ping() {
    local host="$1"
    if ! adb_shell "command -v ping >/dev/null 2>&1"; then
        return 1
    fi
    local line
    line="$(adb_shell "ping -4 -c 1 -W 1 \"$host\" 2>/dev/null | head -n 1" 2>/dev/null || true)"
    echo "$line" | sed -n 's/.*(\([0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+\)).*/\1/p' | head -n 1
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
    expect_nok "IPRULES.ADD ${TEST_UID} action=allow priority=10 ct.state=foo" "ADD rejects invalid ct.state atomically"
    expect_nok "IPRULES.ADD ${TEST_UID} action=allow priority=10 ct.direction=foo" "ADD rejects invalid ct.direction atomically"
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
    expect_nok "IPRULES.ADD ${TEST_UID} action=block priority=12 ct=foo" "ADD rejects legacy ct token"
    expect_nok "IPRULES.ADD ${TEST_UID} action=allow priority=13 proto=icmp dport=53" "ADD rejects proto=icmp with port predicates"

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
    expect_nok "IPRULES.UPDATE ${updRid} ct.state=foo" "UPDATE rejects invalid ct.state without mutation"
    local printed3
    printed3="$(send_cmd "IPRULES.PRINT RULE ${updRid}")"
    if [[ "$(json_get "$printed3" "rules.0.ct.state")" != "any" ]]; then
        log_fail "NOK UPDATE is atomic (ct.state)"
    else
        log_pass "NOK UPDATE is atomic (ct.state)"
    fi
    if [[ "$(json_get "$printed3" "rules.0.dport")" != "443" ]]; then
        log_fail "NOK UPDATE is atomic (dport)"
    else
        log_pass "NOK UPDATE is atomic (dport)"
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

    log_section "PKTSTREAM schema: ruleId for enforce decisions"
    local targetIp
    targetIp="1.1.1.1"
    local pingPid
    pingPid="$(ping4_async "$targetIp" 1)"
    local pktSample
    pktSample="$(stream_sample "PKTSTREAM.START 0 0" "PKTSTREAM.STOP" 3)"
    wait "$pingPid" >/dev/null 2>&1 || true
    if echo "$pktSample" | python3 -c "$(cat <<PY
import sys, json
uid = int('${TEST_UID}')
target = '${targetIp}'
expected = int('${allowRid}')
found = False
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
    except Exception:
        continue
    if obj.get('uid') != uid or obj.get('direction') != 'out' or obj.get('dstIp') != target or obj.get('protocol') != 'icmp':
        continue
    assert bool(obj.get('accepted')) is True
    assert obj.get('reasonId') == 'IP_RULE_ALLOW'
    assert obj.get('ruleId') == expected
    found = True
    break
assert found, 'no matching pktstream event'
PY
)" 2>/dev/null; then
        log_pass "PKTSTREAM carries ruleId for IP_RULE_ALLOW (ruleId=$allowRid)"
    else
        log_fail "PKTSTREAM missing/incorrect ruleId for enforce decision"
        echo "    sample: ${pktSample:0:200}..."
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
    expect_ok "RESETALL" "RESETALL (IFACE_BLOCK test)"
    expect_ok "BLOCK 1" "BLOCK enable"
    expect_ok "IPRULES 1" "IPRULES enable"
    expect_ok "BLOCKIPLEAKS 0" "BLOCKIPLEAKS baseline off"
    local ifaceAllowRid
    ifaceAllowRid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=100 proto=icmp" "ADD enforce allow rule (IFACE precedence)")"
    expect_ok "BLOCKIFACE ${TEST_UID} 255" "BLOCKIFACE all"
    local ifaceBefore
    ifaceBefore="$(get_reason_packets "IFACE_BLOCK")"
    local ifaceTargetIp
    ifaceTargetIp="93.184.216.34" # example.com (stable) - low chance of background traffic
    ping4_once "$ifaceTargetIp"
    local ifaceAfter
    ifaceAfter="$(get_reason_packets "IFACE_BLOCK")"
    if [[ "$ifaceAfter" -gt "$ifaceBefore" ]]; then
        log_pass "IFACE_BLOCK grows under traffic ($ifaceBefore -> $ifaceAfter)"
    else
        log_fail "IFACE_BLOCK did not grow under traffic ($ifaceBefore -> $ifaceAfter)"
    fi
    local hostsJson
    hostsJson="$(send_cmd "HOSTS")"
    if [[ -n "$hostsJson" ]] && ! echo "$hostsJson" | grep -q "$ifaceTargetIp"; then
        log_pass "IFACE_BLOCK does not materialize host cache entries for blocked traffic"
    else
        log_fail "IFACE_BLOCK traffic polluted HOSTS cache (unexpected remote IP present)"
        echo "    hosts: ${hostsJson:0:200}..."
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
    pingPid="$(ping4_async "1.1.1.1" 1)"
    pktSample="$(stream_sample "PKTSTREAM.START 0 0" "PKTSTREAM.STOP" 3)"
    wait "$pingPid" >/dev/null 2>&1 || true
    if echo "$pktSample" | python3 -c "$(cat <<PY
import sys, json
uid = int('${TEST_UID}')
target = '1.1.1.1'
expected = int('${wouldOnlyRid}')
found = False
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
    except Exception:
        continue
    if obj.get('uid') != uid or obj.get('direction') != 'out' or obj.get('dstIp') != target or obj.get('protocol') != 'icmp':
        continue
    assert bool(obj.get('accepted')) is True
    assert obj.get('reasonId') == 'ALLOW_DEFAULT'
    assert obj.get('wouldRuleId') == expected
    assert obj.get('wouldDrop') == 1
    assert 'ruleId' not in obj
    found = True
    break
assert found, 'no matching pktstream event'
PY
)" 2>/dev/null; then
        log_pass "PKTSTREAM carries wouldRuleId/wouldDrop overlay when accepted"
    else
        log_fail "PKTSTREAM missing/incorrect wouldRuleId overlay (accept-only)"
        echo "    sample: ${pktSample:0:200}..."
    fi

    log_section "Would-block overlay is suppressed on final DROP (IP_RULE_BLOCK)"
    expect_ok "RESETALL" "RESETALL (would-block suppressed drop test)"
    expect_ok "BLOCK 1" "BLOCK enable"
    expect_ok "IPRULES 1" "IPRULES enable"
    expect_ok "BLOCKIPLEAKS 0" "BLOCKIPLEAKS off (drop case)"

    local dropTargetIp wouldRid blockRid
    dropTargetIp="1.1.1.1"
    wouldRid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=block priority=10 enforce=0 log=1 proto=icmp dst=${dropTargetIp}/32" "ADD would-block rule (drop case)")"
    blockRid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=block priority=100 proto=icmp dst=${dropTargetIp}/32" "ADD enforce block rule (drop case)")"

    expect_ok "METRICS.REASONS.RESET" "METRICS.REASONS.RESET (drop case)"
    pingPid="$(ping4_async "$dropTargetIp" 1)"
    pktSample="$(stream_sample "PKTSTREAM.START 0 0" "PKTSTREAM.STOP" 3)"
    wait "$pingPid" >/dev/null 2>&1 || true

    local wouldHits
    wouldHits="$(get_rule_stat "$wouldRid" "wouldHitPackets")"
    if [[ "${wouldHits:-0}" -eq 0 ]]; then
        log_pass "wouldHitPackets stays 0 when final verdict is DROP (wouldHitPackets=$wouldHits)"
    else
        log_fail "wouldHitPackets grew unexpectedly on DROP (wouldHitPackets=$wouldHits)"
    fi

    if echo "$pktSample" | python3 -c "$(cat <<PY
import sys, json
uid = int('${TEST_UID}')
target = '${dropTargetIp}'
expected_block = int('${blockRid}')
found = False
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
    except Exception:
        continue
    if obj.get('uid') != uid or obj.get('direction') != 'out' or obj.get('dstIp') != target or obj.get('protocol') != 'icmp':
        continue
    assert bool(obj.get('accepted')) is False
    assert obj.get('reasonId') == 'IP_RULE_BLOCK'
    assert obj.get('ruleId') == expected_block
    assert 'wouldRuleId' not in obj
    assert 'wouldDrop' not in obj
    found = True
    break
assert found, 'no matching pktstream event'
PY
)" 2>/dev/null; then
        log_pass "PKTSTREAM suppresses wouldRuleId overlay when final verdict is DROP"
    else
        log_fail "PKTSTREAM incorrectly emitted wouldRuleId overlay on DROP"
        echo "    sample: ${pktSample:0:200}..."
    fi

    log_section "Legacy frozen knobs (fixed/no-op)"
    assert_frozen_knob "BLOCKIPLEAKS" "1" "0" "BLOCKIPLEAKS frozen/no-op"
    assert_frozen_knob "GETBLACKIPS" "1" "0" "GETBLACKIPS frozen/no-op"
    assert_frozen_knob "MAXAGEIP" "1" "14400" "MAXAGEIP frozen/no-op"

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

    log_section "Persistence across restart (ruleId high-water)"
    expect_ok "RESETALL" "RESETALL (persistence test)"
    expect_ok "BLOCK 1" "BLOCK enable"
    expect_ok "IPRULES 1" "IPRULES enable"

    local pr0 pr1 pr2
    pr0="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=1 proto=icmp" "ADD persist rule0")"
    pr1="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=2 proto=tcp dport=443" "ADD persist rule1")"
    pr2="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=3 proto=udp dport=53" "ADD persist rule2")"
    if [[ "$pr0" != "0" || "$pr1" != "1" || "$pr2" != "2" ]]; then
        log_fail "unexpected initial ruleIds for persistence test (got $pr0,$pr1,$pr2)"
    else
        log_pass "initial ruleIds allocated sequentially (0,1,2)"
    fi

    expect_ok "IPRULES.REMOVE ${pr2}" "REMOVE highest ruleId before restart"
    expect_ok "DEV.SHUTDOWN" "DEV.SHUTDOWN (save + exit)"

    if [[ $DO_DEPLOY -eq 1 ]]; then
        log_info "重启守护进程（deploy 模式）..."
        if ! bash dev/dev-deploy.sh --no-clear-log >/dev/null; then
            log_fail "re-deploy failed"
            print_summary
            exit 1
        fi
    else
        log_info "重启守护进程（skip-deploy 模式，复用 /data/local/tmp/sucre-snort-dev）..."
        adb_su "rm -f /dev/socket/sucre-snort-control /dev/socket/sucre-snort-netd 2>/dev/null || true"
        adb_su "/data/local/tmp/sucre-snort-dev >> /data/local/tmp/sucre-snort-dev.log 2>&1 &"
        sleep 2
    fi

    if ! init_test_env; then
        log_fail "init_test_env after restart"
        print_summary
        exit 1
    fi

    local persisted
    persisted="$(send_cmd "IPRULES.PRINT")"
    if [[ "$(json_get "$persisted" "rules.0.ruleId")" == "0" && "$(json_get "$persisted" "rules.1.ruleId")" == "1" ]]; then
        log_pass "rules persisted across restart (ruleId 0/1 present)"
    else
        log_fail "rules did not persist as expected across restart"
        echo "    IPRULES.PRINT: $persisted"
    fi

    local pr3
    pr3="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=4 proto=icmp" "ADD after restart")"
    if [[ "$pr3" == "3" ]]; then
        log_pass "nextRuleId high-water persisted (new ruleId=3)"
    else
        log_fail "nextRuleId high-water not persisted (expected 3, got $pr3)"
    fi

    if [[ $CLEANUP_FORWARD -eq 1 ]]; then
        log_info "移除 adb forward..."
        remove_control_forward "$SNORT_PORT"
    fi

    print_summary
}

main "$@"
