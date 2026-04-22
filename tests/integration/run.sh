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

    local help
    help="$(send_cmd "HELP")"
    if [[ -z "$help" ]]; then
        log_fail "$case_id HELP (empty response)"
        return 1
    fi

    local -a missing=()
    local token
    for token in "BLOCKIPLEAKS" "GETBLACKIPS" "MAXAGEIP" "frozen/no-op" "sucre-snort-ctl"; do
        if ! echo "$help" | grep -q "$token"; then
            missing+=("$token")
        fi
    done
    if ! echo "$help" | grep -q "60607" && ! echo "$help" | grep -q "sucre-snort-control-vnext"; then
        missing+=("60607|sucre-snort-control-vnext")
    fi

    if [[ ${#missing[@]} -eq 0 ]]; then
        log_pass "$case_id HELP (frozen/no-op + vNext guidance)"
        return 0
    fi

    log_fail "$case_id HELP missing tokens: ${missing[*]}"
    echo "    HELP: ${help:0:200}..."
    return 1
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
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "BLOCKIPLEAKS frozen/no-op"; return 0; }

    assert_frozen_knob "BLOCKIPLEAKS" "1" "0" "$case_id BLOCKIPLEAKS frozen/no-op"
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

case_it_10_metrics_reasons() {
    local group="core"
    local case_id="IT-10"
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "METRICS.REASONS"; return 0; }

    local help
    help=$(send_cmd "HELP")
    if ! echo "$help" | grep -q "METRICS.REASONS"; then
        log_fail "$case_id HELP exposes METRICS.REASONS"
        return 1
    fi

    local orig_block orig_bil
    orig_block=$(send_cmd "BLOCK")
    orig_bil=$(send_cmd "BLOCKIPLEAKS")

    # Reset under BLOCK=0 to avoid background traffic affecting the counters.
    send_cmd "BLOCK 0" >/dev/null || true
    local reset_result
    reset_result=$(send_cmd "METRICS.REASONS.RESET")
    if [[ "$reset_result" != "OK" ]]; then
        log_fail "$case_id METRICS.REASONS.RESET returns OK"
        echo "    响应: $reset_result"
        return 1
    fi

    local j0
    j0=$(send_cmd "METRICS.REASONS")
    if ! echo "$j0" | python3 -c "import sys, json; d=json.load(sys.stdin); r=d['reasons']; req=['IFACE_BLOCK','ALLOW_DEFAULT','IP_RULE_ALLOW','IP_RULE_BLOCK']; assert all(k in r for k in req); assert all(int(r[k]['packets'])==0 and int(r[k]['bytes'])==0 for k in req)" 2>/dev/null; then
        log_fail "$case_id METRICS.REASONS returns stable keys and zeros after reset"
        echo "    响应: ${j0:0:200}..."
        # restore best-effort
        send_cmd "BLOCK $orig_block" >/dev/null 2>&1 || true
        send_cmd "BLOCKIPLEAKS $orig_bil" >/dev/null 2>&1 || true
        return 1
    fi

    # Enable BLOCK and trigger minimal traffic; counters should grow.
    send_cmd "BLOCKIPLEAKS 0" >/dev/null || true
    send_cmd "BLOCK 1" >/dev/null || true
    adb_su "command -v ping >/dev/null 2>&1 && (ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1 || ping -c 1 -W 1 8.8.8.8 >/dev/null 2>&1 || true)" >/dev/null 2>&1 || true

    local j1
    j1=$(send_cmd "METRICS.REASONS")
    local total
    total=$(echo "$j1" | python3 -c "import sys, json; d=json.load(sys.stdin); r=d.get('reasons',{}); print(sum(int(v.get('packets',0)) for v in r.values()))" 2>/dev/null || echo 0)
    if [[ "$total" -ge 1 ]]; then
        log_pass "$case_id METRICS.REASONS grows under traffic (totalPackets=$total)"
    else
        log_fail "$case_id METRICS.REASONS grows under traffic"
        echo "    提示: 确认真机有网络且 BLOCK=1，可进入 NFQUEUE"
        echo "    响应: ${j1:0:200}..."
        # restore best-effort
        send_cmd "BLOCK $orig_block" >/dev/null 2>&1 || true
        send_cmd "BLOCKIPLEAKS $orig_bil" >/dev/null 2>&1 || true
        return 1
    fi

    # Tracked-independence: reason counters MUST still grow when tracked=0 (use uid=0 as a controllable source).
    local app0 tracked_orig
    app0=$(send_cmd "APP.UID 0")
    tracked_orig=$(echo "$app0" | python3 -c "import sys, json; d=json.load(sys.stdin); assert len(d)==1; print(int(d[0]['tracked']))" 2>/dev/null || echo "")
    if [[ -z "$tracked_orig" ]]; then
        log_fail "$case_id tracked-independence precheck (APP.UID 0)"
        echo "    响应: ${app0:0:200}..."
        send_cmd "BLOCK $orig_block" >/dev/null 2>&1 || true
        send_cmd "BLOCKIPLEAKS $orig_bil" >/dev/null 2>&1 || true
        return 1
    fi

    send_cmd "UNTRACK 0" >/dev/null || true
    app0=$(send_cmd "APP.UID 0")
    if ! echo "$app0" | python3 -c "import sys, json; d=json.load(sys.stdin); assert len(d)==1; assert int(d[0]['tracked'])==0" 2>/dev/null; then
        log_fail "$case_id UNTRACK 0 takes effect"
        echo "    响应: ${app0:0:200}..."
        send_cmd "BLOCK $orig_block" >/dev/null 2>&1 || true
        send_cmd "BLOCKIPLEAKS $orig_bil" >/dev/null 2>&1 || true
        return 1
    fi

    send_cmd "BLOCK 0" >/dev/null || true
    send_cmd "METRICS.REASONS.RESET" >/dev/null || true
    send_cmd "BLOCK 1" >/dev/null || true
    adb_su "command -v ping >/dev/null 2>&1 && (ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1 || ping -c 1 -W 1 8.8.8.8 >/dev/null 2>&1 || true)" >/dev/null 2>&1 || true
    j1=$(send_cmd "METRICS.REASONS")
    total=$(echo "$j1" | python3 -c "import sys, json; d=json.load(sys.stdin); r=d.get('reasons',{}); print(sum(int(v.get('packets',0)) for v in r.values()))" 2>/dev/null || echo 0)
    if [[ "$total" -ge 1 ]]; then
        log_pass "$case_id METRICS.REASONS does not depend on tracked (tracked=0)"
    else
        log_fail "$case_id METRICS.REASONS does not depend on tracked (tracked=0)"
        echo "    响应: ${j1:0:200}..."
        send_cmd "BLOCK $orig_block" >/dev/null 2>&1 || true
        send_cmd "BLOCKIPLEAKS $orig_bil" >/dev/null 2>&1 || true
        return 1
    fi

    if [[ "$tracked_orig" -eq 1 ]]; then
        send_cmd "TRACK 0" >/dev/null 2>&1 || true
    fi

    # Restore best-effort.
    send_cmd "BLOCK $orig_block" >/dev/null 2>&1 || true
    send_cmd "BLOCKIPLEAKS $orig_bil" >/dev/null 2>&1 || true
}

case_it_11_pktstream_schema() {
    local group="streams"
    local case_id="IT-11"
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "PKTSTREAM schema"; return 0; }

    local orig_block orig_bil
    orig_block=$(send_cmd "BLOCK")
    orig_bil=$(send_cmd "BLOCKIPLEAKS")

    send_cmd "BLOCKIPLEAKS 0" >/dev/null || true
    send_cmd "BLOCK 1" >/dev/null || true
    adb_su "command -v ping >/dev/null 2>&1 && (ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1 || ping -c 1 -W 1 8.8.8.8 >/dev/null 2>&1 || true)" >/dev/null 2>&1 || true

    local result
    result=$(stream_sample "PKTSTREAM.START 10 1" "PKTSTREAM.STOP" 1)
    if [[ $? -ne 0 || "$result" == ERROR:* ]]; then
        log_fail "$case_id PKTSTREAM sample"
        echo "    响应: $result"
        send_cmd "BLOCK $orig_block" >/dev/null 2>&1 || true
        send_cmd "BLOCKIPLEAKS $orig_bil" >/dev/null 2>&1 || true
        return 1
    fi

    if ! echo "$result" | python3 -c "import sys, json\nobj=None\nfor line in sys.stdin:\n  line=line.strip()\n  if not line: continue\n  try:\n    obj=json.loads(line)\n    break\n  except Exception:\n    continue\nif obj is None:\n  raise SystemExit(2)\nfor k in ['ipVersion','srcIp','dstIp','reasonId']:\n  assert k in obj\nassert 'ipv4' not in obj and 'ipv6' not in obj\nassert obj['ipVersion'] in (4,6)\nassert isinstance(obj['srcIp'], str) and isinstance(obj['dstIp'], str)\nassert isinstance(obj['reasonId'], str)\n" 2>/dev/null; then
        log_pass "$case_id PKTSTREAM packet schema vNext"
    else
        log_fail "$case_id PKTSTREAM packet schema vNext"
        echo "    采样: ${result:0:200}..."
        send_cmd "BLOCK $orig_block" >/dev/null 2>&1 || true
        send_cmd "BLOCKIPLEAKS $orig_bil" >/dev/null 2>&1 || true
        return 1
    fi

    # Restore best-effort.
    send_cmd "BLOCK $orig_block" >/dev/null 2>&1 || true
    send_cmd "BLOCKIPLEAKS $orig_bil" >/dev/null 2>&1 || true
}

case_it_12_metrics_domain_sources() {
    local group="core"
    local case_id="IT-12"
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "METRICS.DOMAIN.SOURCES"; return 0; }

    local help
    help=$(send_cmd "HELP")
    if ! echo "$help" | grep -q "METRICS.DOMAIN.SOURCES"; then
        log_fail "$case_id HELP exposes METRICS.DOMAIN.SOURCES"
        return 1
    fi

    local orig_block orig_bil
    orig_block=$(send_cmd "BLOCK")
    orig_bil=$(send_cmd "BLOCKIPLEAKS")

    # Reset under BLOCK=0 so that counters are deterministic (no background DNS).
    send_cmd "BLOCK 0" >/dev/null || true
    local reset_result
    reset_result=$(send_cmd "METRICS.DOMAIN.SOURCES.RESET")
    if [[ "$reset_result" != "OK" ]]; then
        log_fail "$case_id METRICS.DOMAIN.SOURCES.RESET returns OK"
        echo "    响应: $reset_result"
        send_cmd "BLOCK $orig_block" >/dev/null 2>&1 || true
        send_cmd "BLOCKIPLEAKS $orig_bil" >/dev/null 2>&1 || true
        return 1
    fi

    local j0
    j0=$(send_cmd "METRICS.DOMAIN.SOURCES")
    if ! echo "$j0" | python3 -c "import sys, json; d=json.load(sys.stdin); s=d['sources']; req=['CUSTOM_WHITELIST','CUSTOM_BLACKLIST','CUSTOM_RULE_WHITE','CUSTOM_RULE_BLACK','GLOBAL_AUTHORIZED','GLOBAL_BLOCKED','MASK_FALLBACK']; assert all(k in s for k in req); assert all(int(s[k]['allow'])==0 and int(s[k]['block'])==0 for k in req)" 2>/dev/null; then
        log_fail "$case_id METRICS.DOMAIN.SOURCES returns stable keys and zeros after reset"
        echo "    响应: ${j0:0:200}..."
        send_cmd "BLOCK $orig_block" >/dev/null 2>&1 || true
        send_cmd "BLOCKIPLEAKS $orig_bil" >/dev/null 2>&1 || true
        return 1
    fi

    # Gating: BLOCK=0 must NOT update counters even if DNS queries happen.
    local dom0
    dom0="t${RANDOM}${RANDOM}.example.com"
    # Host-driven tests do not depend on the system resolver being hooked to the netd socket.
    # Use a DEV.* trigger to generate a deterministic DomainPolicy verdict path.
    local devq0
    devq0=$(send_cmd "DEV.DNSQUERY 0 $dom0" 5)
    if ! echo "$devq0" | python3 -c "import sys, json; d=json.load(sys.stdin); assert 'policySource' in d" 2>/dev/null; then
        log_fail "$case_id DEV.DNSQUERY returns JSON (BLOCK=0)"
        echo "    响应: ${devq0:0:200}..."
        send_cmd "BLOCK $orig_block" >/dev/null 2>&1 || true
        send_cmd "BLOCKIPLEAKS $orig_bil" >/dev/null 2>&1 || true
        return 1
    fi

    local j1 total
    j1=$(send_cmd "METRICS.DOMAIN.SOURCES")
    total=$(echo "$j1" | python3 -c "import sys, json; d=json.load(sys.stdin); s=d.get('sources',{}); print(sum(int(v.get('allow',0))+int(v.get('block',0)) for v in s.values()))" 2>/dev/null || echo 0)
    if [[ "$total" -eq 0 ]]; then
        log_pass "$case_id METRICS.DOMAIN.SOURCES gated by BLOCK=0 (total=$total)"
    else
        log_fail "$case_id METRICS.DOMAIN.SOURCES gated by BLOCK=0 (total=$total)"
        echo "    响应: ${j1:0:200}..."
        send_cmd "BLOCK $orig_block" >/dev/null 2>&1 || true
        send_cmd "BLOCKIPLEAKS $orig_bil" >/dev/null 2>&1 || true
        return 1
    fi

    # Enable BLOCK and trigger a DNS query; counters should grow.
    send_cmd "BLOCKIPLEAKS 0" >/dev/null || true
    send_cmd "BLOCK 1" >/dev/null || true
    send_cmd "METRICS.DOMAIN.SOURCES.RESET" >/dev/null || true

    local dom1
    dom1="t${RANDOM}${RANDOM}.example.com"
    local devq1
    devq1=$(send_cmd "DEV.DNSQUERY 0 $dom1" 5)
    if ! echo "$devq1" | python3 -c "import sys, json; d=json.load(sys.stdin); assert 'policySource' in d" 2>/dev/null; then
        log_fail "$case_id DEV.DNSQUERY returns JSON (BLOCK=1)"
        echo "    响应: ${devq1:0:200}..."
        send_cmd "BLOCK $orig_block" >/dev/null 2>&1 || true
        send_cmd "BLOCKIPLEAKS $orig_bil" >/dev/null 2>&1 || true
        return 1
    fi

    local j2
    j2=$(send_cmd "METRICS.DOMAIN.SOURCES")
    total=$(echo "$j2" | python3 -c "import sys, json; d=json.load(sys.stdin); s=d.get('sources',{}); print(sum(int(v.get('allow',0))+int(v.get('block',0)) for v in s.values()))" 2>/dev/null || echo 0)
    if [[ "$total" -ge 1 ]]; then
        log_pass "$case_id METRICS.DOMAIN.SOURCES grows under DNS traffic (total=$total)"
    else
        log_fail "$case_id METRICS.DOMAIN.SOURCES grows under DNS traffic (total=$total)"
        echo "    提示: 确认真机有网络且 BLOCK=1；ping 域名应触发 DNS 请求"
        echo "    响应: ${j2:0:200}..."
        send_cmd "BLOCK $orig_block" >/dev/null 2>&1 || true
        send_cmd "BLOCKIPLEAKS $orig_bil" >/dev/null 2>&1 || true
        return 1
    fi

    # Tracked-independence: per-app DomainPolicy source counters MUST still grow when tracked=0 (uid=0).
    local app0 tracked_orig
    app0=$(send_cmd "APP.UID 0")
    tracked_orig=$(echo "$app0" | python3 -c "import sys, json; d=json.load(sys.stdin); assert len(d)==1; print(int(d[0]['tracked']))" 2>/dev/null || echo "")
    if [[ -z "$tracked_orig" ]]; then
        log_fail "$case_id tracked-independence precheck (APP.UID 0)"
        echo "    响应: ${app0:0:200}..."
        send_cmd "BLOCK $orig_block" >/dev/null 2>&1 || true
        send_cmd "BLOCKIPLEAKS $orig_bil" >/dev/null 2>&1 || true
        return 1
    fi

    send_cmd "UNTRACK 0" >/dev/null || true
    app0=$(send_cmd "APP.UID 0")
    if ! echo "$app0" | python3 -c "import sys, json; d=json.load(sys.stdin); assert len(d)==1; assert int(d[0]['tracked'])==0" 2>/dev/null; then
        log_fail "$case_id UNTRACK 0 takes effect"
        echo "    响应: ${app0:0:200}..."
        send_cmd "BLOCK $orig_block" >/dev/null 2>&1 || true
        send_cmd "BLOCKIPLEAKS $orig_bil" >/dev/null 2>&1 || true
        return 1
    fi

    send_cmd "BLOCK 0" >/dev/null || true
    send_cmd "METRICS.DOMAIN.SOURCES.RESET.APP 0" >/dev/null || true
    send_cmd "BLOCK 1" >/dev/null || true
    dom1="t${RANDOM}${RANDOM}.example.com"
    send_cmd "DEV.DNSQUERY 0 $dom1" >/dev/null 2>&1 || true

    local japp tapp
    japp=$(send_cmd "METRICS.DOMAIN.SOURCES.APP 0")
    tapp=$(echo "$japp" | python3 -c "import sys, json; d=json.load(sys.stdin); s=d.get('sources',{}); print(sum(int(v.get('allow',0))+int(v.get('block',0)) for v in s.values()))" 2>/dev/null || echo 0)
    if [[ "$tapp" -ge 1 ]]; then
        log_pass "$case_id METRICS.DOMAIN.SOURCES.APP grows with tracked=0 (total=$tapp)"
    else
        log_fail "$case_id METRICS.DOMAIN.SOURCES.APP grows with tracked=0 (total=$tapp)"
        echo "    响应: ${japp:0:200}..."
        send_cmd "BLOCK $orig_block" >/dev/null 2>&1 || true
        send_cmd "BLOCKIPLEAKS $orig_bil" >/dev/null 2>&1 || true
        return 1
    fi

    if [[ "$tracked_orig" -eq 1 ]]; then
        send_cmd "TRACK 0" >/dev/null 2>&1 || true
    fi

    # Restore best-effort.
    send_cmd "BLOCK $orig_block" >/dev/null 2>&1 || true
    send_cmd "BLOCKIPLEAKS $orig_bil" >/dev/null 2>&1 || true
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
    case_it_10_metrics_reasons
    case_it_12_metrics_domain_sources
    case_it_11_pktstream_schema
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
