#!/bin/bash

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib_legacy.sh"

DO_DEPLOY=1
CLEANUP_FORWARD=0

TEST_UID="${TEST_UID:-2000}"         # shell user (stable on Android)
TARGET_IPV4="${TARGET_IPV4:-1.1.1.1}"
ALT_IPV4="${ALT_IPV4:-8.8.8.8}"      # for no-match CIDR tests
TCP_PORT="${TCP_PORT:-443}"
UDP_PORT="${UDP_PORT:-12345}"
FIXED_SPORT="${FIXED_SPORT:-55555}"
STRESS_SECONDS="${STRESS_SECONDS:-0}"
DEVICE_BUSYBOX="${DEVICE_BUSYBOX:-}" # resolved in require_device_tools()

show_help() {
    cat <<EOF
用法: $0 [选项]

选项:
  --serial <serial>       指定目标真机 serial
  --skip-deploy           跳过部署，直接复用当前真机上的守护进程
  --cleanup-forward       结束后移除 adb forward
  -h, --help              显示帮助

环境变量:
  TEST_UID, TARGET_IPV4, ALT_IPV4, TCP_PORT, UDP_PORT, FIXED_SPORT, STRESS_SECONDS
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
        --stress-seconds)
            STRESS_SECONDS="$2"
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
    echo "    cmd: $cmd"
    echo "    got: $result"
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
    echo "    cmd: $cmd"
    echo "    got: $result"
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
    echo "    cmd: $cmd" >&2
    echo "    got: $result" >&2
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

get_rule_field() {
    local rid="$1"
    local field="$2"
    local json
    json="$(send_cmd "IPRULES.PRINT RULE ${rid}")"
    json_get "$json" "rules.0.${field}"
}

require_device_tools() {
    if ! adb_shell "command -v ping >/dev/null 2>&1"; then
        log_fail "device missing ping; cannot run matrix"
        return 1
    fi
    if ! adb_shell "command -v nc >/dev/null 2>&1 || command -v netcat >/dev/null 2>&1"; then
        log_fail "device missing nc/netcat; cannot run TCP/UDP matrix"
        return 1
    fi

    # Optional: prefer busybox nc when available (needed for reliable -p local port on some devices).
    if [[ -z "${DEVICE_BUSYBOX:-}" ]] && adb_shell "[ -x /data/local/tmp/busybox ] && /data/local/tmp/busybox nc --help >/dev/null 2>&1"; then
        DEVICE_BUSYBOX="/data/local/tmp/busybox"
        log_info "device busybox detected: $DEVICE_BUSYBOX (will use for nc when needed)"
    fi
    return 0
}

ping4_once() {
    local target="$1"
    adb_shell "ping -4 -c 1 -W 1 \"$target\" >/dev/null 2>&1 || ping -c 1 -W 1 \"$target\" >/dev/null 2>&1 || true" >/dev/null 2>&1
}

tcp_probe_once() {
    local ip="$1"
    local port="$2"
    local sport="${3:-}"
    local sportFlag=""
    if [[ -n "$sport" ]]; then
        sportFlag="-p $sport"
    fi
    if [[ -n "${DEVICE_BUSYBOX:-}" ]]; then
        adb_shell "$DEVICE_BUSYBOX nc -n -z -w 2 $sportFlag \"$ip\" \"$port\" >/dev/null 2>&1 || true" >/dev/null 2>&1
    else
        adb_shell "nc -4 -n -z -w 2 $sportFlag \"$ip\" \"$port\" >/dev/null 2>&1 || true" >/dev/null 2>&1
    fi
}

udp_send_once() {
    local ip="$1"
    local port="$2"
    local sport="${3:-}"
    local sportFlag=""
    if [[ -n "$sport" ]]; then
        sportFlag="-p $sport"
    fi
    if [[ -n "${DEVICE_BUSYBOX:-}" ]]; then
        adb_shell "printf x | $DEVICE_BUSYBOX nc -n -u -w 1 $sportFlag \"$ip\" \"$port\" >/dev/null 2>&1 || true" >/dev/null 2>&1
    else
        # toybox nc requires -q >= 1
        adb_shell "printf x | nc -4 -n -u -w 1 -q 1 $sportFlag \"$ip\" \"$port\" >/dev/null 2>&1 || true" >/dev/null 2>&1
    fi
}

reset_baseline() {
    expect_ok "RESETALL" "RESETALL"
    expect_ok "BLOCK 1" "BLOCK=1"
    expect_ok "BLOCKIPLEAKS 0" "BLOCKIPLEAKS=0"
    expect_ok "IPRULES 1" "IPRULES=1"
    expect_ok "BLOCKIFACE ${TEST_UID} 0" "BLOCKIFACE cleared for uid=$TEST_UID"
}

pick_wrong_iface_kind() {
    local actual="$1"
    local k
    for k in wifi data vpn unmanaged; do
        if [[ "$k" != "$actual" ]]; then
            echo "$k"
            return 0
        fi
    done
    echo "wifi"
    return 0
}

assert_enforce_hit() {
    local rid="$1"
    local reason="$2"
    local desc="$3"
    local rp hp
    rp="$(get_reason_packets "$reason")"
    hp="$(get_rule_stat "$rid" "hitPackets")"
    if [[ "${rp:-0}" -ge 1 && "${hp:-0}" -ge 1 ]]; then
        log_pass "$desc"
        return 0
    fi
    log_fail "$desc"
    echo "    reasonPackets($reason)=$rp hitPackets=$hp"
    return 1
}

assert_no_enforce_match() {
    local rid="$1"
    local desc="$2"
    local allowP blockP hp
    allowP="$(get_reason_packets "IP_RULE_ALLOW")"
    blockP="$(get_reason_packets "IP_RULE_BLOCK")"
    hp="$(get_rule_stat "$rid" "hitPackets")"
    if [[ "${allowP:-0}" -eq 0 && "${blockP:-0}" -eq 0 && "${hp:-0}" -eq 0 ]]; then
        log_pass "$desc"
        return 0
    fi
    log_fail "$desc"
    echo "    IP_RULE_ALLOW.packets=$allowP IP_RULE_BLOCK.packets=$blockP hitPackets=$hp"
    return 1
}

sample_out_meta() {
    # Return: "<name> <ifindex> <kind> <srcIp>"
    local pktSample ifaceName ifacesJson
    local pingPid
    pingPid="$(adb_shell "sleep 1; ping -4 -c 1 -W 1 \"$TARGET_IPV4\" >/dev/null 2>&1 || ping -c 1 -W 1 \"$TARGET_IPV4\" >/dev/null 2>&1 || true" >/dev/null 2>&1 & echo $!)"
    pktSample="$(stream_sample "PKTSTREAM.START 0 0" "PKTSTREAM.STOP" 3)"
    wait "$pingPid" >/dev/null 2>&1 || true

    ifaceName="$(echo "$pktSample" | python3 -c "$(cat <<PY
import sys, json
uid = int('${TEST_UID}')
target = '${TARGET_IPV4}'
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
    except Exception:
        continue
    if obj.get('uid') != uid or obj.get('direction') != 'out' or obj.get('dstIp') != target:
        continue
    name = obj.get('interface')
    src = obj.get('srcIp')
    if isinstance(name, str) and name and isinstance(src, str) and src:
        print(f"{name} {src}")
        raise SystemExit(0)
raise SystemExit(2)
PY
)")"

    if [[ -z "$ifaceName" ]]; then
        return 1
    fi

    local iface srcIp
    iface="$(echo "$ifaceName" | awk '{print $1}')"
    srcIp="$(echo "$ifaceName" | awk '{print $2}')"

    ifacesJson="$(send_cmd "IFACES.PRINT")"
    echo "$ifacesJson" | python3 -c "$(cat <<PY
import sys, json
name = '${iface}'
src = '${srcIp}'
j = json.load(sys.stdin)
for i in j.get('ifaces', []):
    if i.get('name') == name:
        print(f"{name} {int(i.get('ifindex',0))} {i.get('kind','unmanaged')} {src}")
        raise SystemExit(0)
raise SystemExit(3)
PY
)"
}

stress_control_plane() {
    local seconds="$1"
    local until=$((SECONDS + seconds))

    reset_baseline
    local rid
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=block priority=10 proto=icmp dir=out dst=${TARGET_IPV4}/32" "ADD stress baseline rule")"

    # Start a small stream of real packets concurrently with control-plane churn.
    # Keep it host-driven to avoid shell quoting pitfalls on the device side.
    (
        local i
        for ((i = 0; i < 50; i++)); do
            ping4_once "$TARGET_IPV4"
        done
    ) >/dev/null 2>&1 &

    while [[ $SECONDS -lt $until ]]; do
        send_cmd "IPRULES.UPDATE ${rid} priority=10" >/dev/null 2>&1 || true
        send_cmd "IPRULES.ENABLE ${rid} 0" >/dev/null 2>&1 || true
        send_cmd "IPRULES.ENABLE ${rid} 1" >/dev/null 2>&1 || true
        send_cmd "IPRULES.PREFLIGHT" >/dev/null 2>&1 || true
    done

    if [[ "$(send_cmd "HELLO" 2)" == "OK" ]]; then
        log_pass "stress: daemon still responds to HELLO"
    else
        log_fail "stress: daemon not responding after concurrent updates"
        return 1
    fi
    return 0
}

main() {
    log_section "IPRULES device matrix (ICMP/TCP/UDP)"

    if [[ $DO_DEPLOY -eq 1 ]]; then
        log_info "deploy..."
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
    if ! require_device_tools; then
        print_summary
        exit 1
    fi

    # ----------------------------------------------------------------------
    # PRINT normalization / ANY tokens
    # ----------------------------------------------------------------------
    log_section "PRINT normalization (omitted fields -> any)"

    reset_baseline
    local rid
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10" "ADD allow (defaults)")"
    if [[ "$(get_rule_field "$rid" "dir")" == "any" \
        && "$(get_rule_field "$rid" "iface")" == "any" \
        && "$(get_rule_field "$rid" "ifindex")" == "0" \
        && "$(get_rule_field "$rid" "proto")" == "any" \
        && "$(get_rule_field "$rid" "src")" == "any" \
        && "$(get_rule_field "$rid" "dst")" == "any" \
        && "$(get_rule_field "$rid" "sport")" == "any" \
        && "$(get_rule_field "$rid" "dport")" == "any" ]]; then
        log_pass "omitted match fields print as any"
    else
        log_fail "omitted match fields are not normalized to any"
        echo "    PRINT: $(send_cmd "IPRULES.PRINT RULE ${rid}")"
    fi

    # ----------------------------------------------------------------------
    # proto=any / dir=any / iface=any behavior
    # ----------------------------------------------------------------------
    log_section "ANY behavior (proto/dir/iface)"

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=any dir=out dst=${TARGET_IPV4}/32" "ADD proto=any allow(out)")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    ping4_once "$TARGET_IPV4"
    local hitAfterPing
    hitAfterPing="$(get_rule_stat "$rid" "hitPackets")"
    if [[ "${hitAfterPing:-0}" -ge 1 ]]; then
        log_pass "proto=any matches ICMP (hitPackets=$hitAfterPing)"
    else
        log_fail "proto=any did not match ICMP (hitPackets=$hitAfterPing)"
    fi
    tcp_probe_once "$TARGET_IPV4" "$TCP_PORT"
    local hitAfterTcp
    hitAfterTcp="$(get_rule_stat "$rid" "hitPackets")"
    if [[ "${hitAfterTcp:-0}" -gt "${hitAfterPing:-0}" ]]; then
        log_pass "proto=any matches TCP too (hitPackets=$hitAfterPing -> $hitAfterTcp)"
    else
        log_fail "proto=any did not observe TCP hit growth (hitPackets=$hitAfterPing -> $hitAfterTcp)"
    fi

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=block priority=10 proto=icmp dir=any dst=${TARGET_IPV4}/32" "ADD dir=any block (match outbound echo request)")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    ping4_once "$TARGET_IPV4"
    assert_enforce_hit "$rid" "IP_RULE_BLOCK" "dir=any matches outbound icmp request (dst=target)"

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=icmp dir=out dst=${TARGET_IPV4}/32 iface=any ifindex=0" "ADD iface=any allow(out)")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    ping4_once "$TARGET_IPV4"
    assert_enforce_hit "$rid" "IP_RULE_ALLOW" "iface=any matches"

    # ----------------------------------------------------------------------
    # ICMP enforce: out allow/block + in block
    # ----------------------------------------------------------------------
    log_section "ICMP enforce (dir in/out)"

    reset_baseline
    rid=
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=icmp dir=out dst=${TARGET_IPV4}/32" "ADD icmp allow(out)")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    ping4_once "$TARGET_IPV4"
    assert_enforce_hit "$rid" "IP_RULE_ALLOW" "ICMP out allow matches"

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=block priority=10 proto=icmp dir=out dst=${TARGET_IPV4}/32" "ADD icmp block(out)")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    ping4_once "$TARGET_IPV4"
    assert_enforce_hit "$rid" "IP_RULE_BLOCK" "ICMP out block matches"

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=block priority=10 proto=icmp dir=in src=${TARGET_IPV4}/32" "ADD icmp block(in)")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    ping4_once "$TARGET_IPV4"
    local rp hp
    rp="$(get_reason_packets "IP_RULE_BLOCK")"
    hp="$(get_rule_stat "$rid" "hitPackets")"
    if [[ "${rp:-0}" -ge 1 && "${hp:-0}" -ge 1 ]]; then
        log_pass "ICMP in block matches (echo reply)"
    else
        log_skip "ICMP in echo-reply not attributable to uid=$TEST_UID on this device; skip"
    fi

    # ----------------------------------------------------------------------
    # TCP enforce: dport exact/range + sport exact + mismatch
    # ----------------------------------------------------------------------
    log_section "TCP enforce (ports/cidr/dir)"

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=tcp dir=out dst=${TARGET_IPV4}/32 dport=${TCP_PORT}" "ADD tcp allow dport exact")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    tcp_probe_once "$TARGET_IPV4" "$TCP_PORT"
    assert_enforce_hit "$rid" "IP_RULE_ALLOW" "TCP out allow (dport exact) matches"

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=block priority=10 proto=tcp dir=out dst=${TARGET_IPV4}/32 dport=${TCP_PORT}" "ADD tcp block dport exact")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    tcp_probe_once "$TARGET_IPV4" "$TCP_PORT"
    assert_enforce_hit "$rid" "IP_RULE_BLOCK" "TCP out block (dport exact) matches"

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=tcp dir=out dst=${TARGET_IPV4}/32 dport=440-450" "ADD tcp allow dport range")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    tcp_probe_once "$TARGET_IPV4" "$TCP_PORT"
    assert_enforce_hit "$rid" "IP_RULE_ALLOW" "TCP out allow (dport range includes 443) matches"

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=tcp dir=out dst=${TARGET_IPV4}/32 dport=444-445" "ADD tcp allow dport mismatch")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    tcp_probe_once "$TARGET_IPV4" "$TCP_PORT"
    assert_no_enforce_match "$rid" "TCP out no-match when dport range excludes 443"

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=tcp dir=out dst=${TARGET_IPV4}/32 sport=${FIXED_SPORT} dport=${TCP_PORT}" "ADD tcp allow sport exact")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    tcp_probe_once "$TARGET_IPV4" "$TCP_PORT" "$FIXED_SPORT"
    assert_enforce_hit "$rid" "IP_RULE_ALLOW" "TCP out allow (sport exact) matches"

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=tcp dir=out dst=${TARGET_IPV4}/32" "ADD tcp allow (dport any)")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    tcp_probe_once "$TARGET_IPV4" "$TCP_PORT"
    assert_enforce_hit "$rid" "IP_RULE_ALLOW" "TCP out allow (dport any) matches"

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=tcp dir=out dst=${TARGET_IPV4}/32 sport=$((FIXED_SPORT - 10))-$((FIXED_SPORT + 10)) dport=${TCP_PORT}" "ADD tcp allow sport range")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    tcp_probe_once "$TARGET_IPV4" "$TCP_PORT" "$FIXED_SPORT"
    assert_enforce_hit "$rid" "IP_RULE_ALLOW" "TCP out allow (sport range includes) matches"

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=tcp dir=out dst=${TARGET_IPV4}/32 sport=$((FIXED_SPORT + 1))-$((FIXED_SPORT + 2)) dport=${TCP_PORT}" "ADD tcp allow sport range mismatch")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    tcp_probe_once "$TARGET_IPV4" "$TCP_PORT" "$FIXED_SPORT"
    assert_no_enforce_match "$rid" "TCP out no-match when sport range excludes fixed sport"

    # TCP dir=in: block server->client reply (best-effort; requires remote response).
    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=block priority=10 proto=tcp dir=in src=${TARGET_IPV4}/32 sport=${TCP_PORT}" "ADD tcp block(in) sport=443")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    tcp_probe_once "$TARGET_IPV4" "$TCP_PORT"
    # Even if remote doesn't respond, this case may be silent. Treat as best-effort.
    if [[ "$(get_rule_stat "$rid" "hitPackets")" -ge 1 ]]; then
        log_pass "TCP in block observed (server reply hit)"
    else
        log_skip "TCP in block not observed; remote may not have replied in window"
    fi

    # ----------------------------------------------------------------------
    # UDP enforce: dport exact + sport exact
    # ----------------------------------------------------------------------
    log_section "UDP enforce (ports)"

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=udp dir=out dst=${TARGET_IPV4}/32 dport=${UDP_PORT}" "ADD udp allow dport exact")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    udp_send_once "$TARGET_IPV4" "$UDP_PORT"
    assert_enforce_hit "$rid" "IP_RULE_ALLOW" "UDP out allow matches"

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=block priority=10 proto=udp dir=out dst=${TARGET_IPV4}/32 dport=${UDP_PORT}" "ADD udp block dport exact")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    udp_send_once "$TARGET_IPV4" "$UDP_PORT"
    assert_enforce_hit "$rid" "IP_RULE_BLOCK" "UDP out block matches"

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=udp dir=out dst=${TARGET_IPV4}/32 sport=${FIXED_SPORT} dport=${UDP_PORT}" "ADD udp allow sport exact")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    udp_send_once "$TARGET_IPV4" "$UDP_PORT" "$FIXED_SPORT"
    assert_enforce_hit "$rid" "IP_RULE_ALLOW" "UDP out allow (sport exact) matches"

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=udp dir=out dst=${TARGET_IPV4}/32 dport=$((UDP_PORT - 5))-$((UDP_PORT + 5))" "ADD udp allow dport range")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    udp_send_once "$TARGET_IPV4" "$UDP_PORT"
    assert_enforce_hit "$rid" "IP_RULE_ALLOW" "UDP out allow (dport range includes) matches"

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=udp dir=out dst=${TARGET_IPV4}/32 dport=$((UDP_PORT + 1))-$((UDP_PORT + 2))" "ADD udp allow dport range mismatch")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    udp_send_once "$TARGET_IPV4" "$UDP_PORT"
    assert_no_enforce_match "$rid" "UDP out no-match when dport range excludes"

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=udp dir=out dst=${TARGET_IPV4}/32 dport=${UDP_PORT}-${UDP_PORT}" "ADD udp allow dport boundary")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    udp_send_once "$TARGET_IPV4" "$UDP_PORT"
    assert_enforce_hit "$rid" "IP_RULE_ALLOW" "UDP out allow (dport boundary) matches"

    # ----------------------------------------------------------------------
    # CIDR variants: /24 match + no-match
    # ----------------------------------------------------------------------
    log_section "CIDR variants (/24 match/no-match)"

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=icmp dir=out dst=1.1.1.0/24" "ADD icmp allow dst /24 match")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    ping4_once "$TARGET_IPV4"
    assert_enforce_hit "$rid" "IP_RULE_ALLOW" "dst /24 matches"

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=icmp dir=out dst=1.1.2.0/24" "ADD icmp allow dst /24 no-match")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    ping4_once "$TARGET_IPV4"
    assert_no_enforce_match "$rid" "dst /24 no-match does not hit"

    # ----------------------------------------------------------------------
    # iface/ifindex: match + mismatch (derived from pktstream sample)
    # ----------------------------------------------------------------------
    log_section "iface/ifindex match"
    reset_baseline
    local ifaceLine ifaceName ifaceIfindex ifaceKind srcIp wrongKind
    ifaceLine="$(sample_out_meta || true)"
    if [[ -z "$ifaceLine" ]]; then
        log_skip "could not sample iface/srcIp via PKTSTREAM; skip iface/ifindex/src cases"
    else
        ifaceName="$(echo "$ifaceLine" | awk '{print $1}')"
        ifaceIfindex="$(echo "$ifaceLine" | awk '{print $2}')"
        ifaceKind="$(echo "$ifaceLine" | awk '{print $3}')"
        srcIp="$(echo "$ifaceLine" | awk '{print $4}')"
        log_info "out meta: iface=$ifaceName ifindex=$ifaceIfindex kind=$ifaceKind srcIp=$srcIp"
        wrongKind="$(pick_wrong_iface_kind "$ifaceKind")"

        rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=icmp dir=out dst=${TARGET_IPV4}/32 iface=${ifaceKind} ifindex=${ifaceIfindex}" "ADD icmp allow (iface+ifindex)")"
        expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
        ping4_once "$TARGET_IPV4"
        assert_enforce_hit "$rid" "IP_RULE_ALLOW" "iface+ifindex exact matches"

        reset_baseline
        rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=icmp dir=out dst=${TARGET_IPV4}/32 iface=any ifindex=${ifaceIfindex}" "ADD icmp allow (iface=any + ifindex exact)")"
        expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
        ping4_once "$TARGET_IPV4"
        assert_enforce_hit "$rid" "IP_RULE_ALLOW" "iface=any + ifindex exact matches"

        reset_baseline
        rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=icmp dir=out dst=${TARGET_IPV4}/32 iface=${ifaceKind} ifindex=0" "ADD icmp allow (iface any-ifindex)")"
        expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
        ping4_once "$TARGET_IPV4"
        assert_enforce_hit "$rid" "IP_RULE_ALLOW" "ifindex=0(any) matches"

        reset_baseline
        rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=icmp dir=out dst=${TARGET_IPV4}/32 iface=${ifaceKind} ifindex=$((ifaceIfindex + 1))" "ADD icmp allow (wrong ifindex)")"
        expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
        ping4_once "$TARGET_IPV4"
        assert_no_enforce_match "$rid" "wrong ifindex does not match"

        reset_baseline
        rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=icmp dir=out dst=${TARGET_IPV4}/32 iface=${wrongKind} ifindex=${ifaceIfindex}" "ADD icmp allow (wrong iface kind)")"
        expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
        ping4_once "$TARGET_IPV4"
        assert_no_enforce_match "$rid" "wrong iface kind does not match"

        reset_baseline
        rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=icmp dir=out src=${srcIp}/32 dst=${TARGET_IPV4}/32" "ADD icmp allow (src /32 exact)")"
        expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
        ping4_once "$TARGET_IPV4"
        assert_enforce_hit "$rid" "IP_RULE_ALLOW" "src /32 exact matches"

        reset_baseline
        rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=icmp dir=out src=203.0.113.1/32 dst=${TARGET_IPV4}/32" "ADD icmp allow (src /32 mismatch)")"
        expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
        ping4_once "$TARGET_IPV4"
        assert_no_enforce_match "$rid" "src /32 mismatch does not match"
    fi

    # ----------------------------------------------------------------------
    # priority and tie-break
    # ----------------------------------------------------------------------
    log_section "priority and tie-break"

    reset_baseline
    local allowRid blockRid
    allowRid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=icmp dir=out dst=${TARGET_IPV4}/32" "ADD allow p10")"
    blockRid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=block priority=20 proto=icmp dir=out dst=${TARGET_IPV4}/32" "ADD block p20")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    ping4_once "$TARGET_IPV4"
    assert_enforce_hit "$blockRid" "IP_RULE_BLOCK" "higher priority wins (block p20 over allow p10)"

    reset_baseline
    allowRid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=icmp dir=out dst=${TARGET_IPV4}/32" "ADD allow p10 (tie)")"
    blockRid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=block priority=10 proto=icmp dir=out dst=${TARGET_IPV4}/32" "ADD block p10 (tie)")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    ping4_once "$TARGET_IPV4"
    assert_enforce_hit "$allowRid" "IP_RULE_ALLOW" "tie-break stable: first-added wins (ruleId=$allowRid)"

    # ----------------------------------------------------------------------
    # would-block (TCP) and enforce-first suppression
    # ----------------------------------------------------------------------
    log_section "would-block (TCP) and enforce-first"

    reset_baseline
    local wouldRid enforceRid
    wouldRid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=block priority=10 enforce=0 log=1 proto=tcp dir=out dst=${TARGET_IPV4}/32 dport=${TCP_PORT}" "ADD would-block tcp")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    tcp_probe_once "$TARGET_IPV4" "$TCP_PORT"
    local wouldHits
    wouldHits="$(get_rule_stat "$wouldRid" "wouldHitPackets")"
    if [[ "${wouldHits:-0}" -ge 1 ]]; then
        log_pass "wouldHitPackets grows when accepted (tcp) (wouldHitPackets=$wouldHits)"
    else
        log_fail "wouldHitPackets did not grow (tcp) (wouldHitPackets=$wouldHits)"
    fi

    reset_baseline
    enforceRid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=allow priority=10 proto=tcp dir=out dst=${TARGET_IPV4}/32 dport=${TCP_PORT}" "ADD enforce allow tcp")"
    wouldRid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=block priority=100 enforce=0 log=1 proto=tcp dir=out dst=${TARGET_IPV4}/32 dport=${TCP_PORT}" "ADD would-block tcp (suppressed)")"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    tcp_probe_once "$TARGET_IPV4" "$TCP_PORT"
    if [[ "$(get_rule_stat "$enforceRid" "hitPackets")" -ge 1 && "$(get_rule_stat "$wouldRid" "wouldHitPackets")" -eq 0 ]]; then
        log_pass "enforce-first suppresses would-hit"
    else
        log_fail "enforce-first did not suppress would-hit"
        echo "    enforce.hitPackets=$(get_rule_stat \"$enforceRid\" \"hitPackets\") would.wouldHitPackets=$(get_rule_stat \"$wouldRid\" \"wouldHitPackets\")"
    fi

    # ----------------------------------------------------------------------
    # IPRULES=0 bypass
    # ----------------------------------------------------------------------
    log_section "IPRULES=0 bypass"

    reset_baseline
    rid="$(expect_uint "IPRULES.ADD ${TEST_UID} action=block priority=10 proto=icmp dir=out dst=${TARGET_IPV4}/32" "ADD icmp block (for bypass)")"
    expect_ok "IPRULES 0" "IPRULES=0"
    expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
    ping4_once "$TARGET_IPV4"
    assert_no_enforce_match "$rid" "IPRULES=0 bypasses rule evaluation"

    # ----------------------------------------------------------------------
    # best-effort stress (control plane + traffic concurrency)
    # ----------------------------------------------------------------------
    if [[ "${STRESS_SECONDS:-0}" -gt 0 ]]; then
        log_section "stress (best-effort): control plane + traffic concurrency (${STRESS_SECONDS}s)"
        stress_control_plane "$STRESS_SECONDS" || true
    fi

    print_summary
    if [[ $FAILED -ne 0 ]]; then
        exit 1
    fi
}

main
