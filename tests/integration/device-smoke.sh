#!/bin/bash

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/lib.sh"

GROUP_FILTER=""
CASE_FILTER=""
DO_DEPLOY=1
CLEANUP_FORWARD=0

show_help() {
    cat <<USAGE
用法: $0 [选项]

选项:
  --serial <serial>       指定目标真机 serial
  --group <csv>           只运行指定 group（env,sockets,netd,firewall,selinux,lifecycle）
  --case <csv>            只运行指定 case（如 P2-01,P2-06）
  --skip-deploy           跳过部署，直接复用当前真机上的守护进程
  --cleanup-forward       结束后移除 adb forward
  -h, --help              显示帮助

说明:
  - 这里是 P2 rooted 真机平台 smoke / compatibility 入口。
  - lifecycle case 会在测试末尾执行 shutdown / redeploy，并把 daemon 恢复为可用状态。
USAGE
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

rule_count() {
    local tool="$1"
    local rule="$2"
    local output
    output=$(adb_su "$tool -S 2>/dev/null" | tr -d '\r') || return 1
    printf '%s\n' "$output" | grep -Fxc -- "$rule"
}

rule_exists_regex() {
    local tool="$1"
    local regex="$2"
    adb_su "$tool -S 2>/dev/null" | tr -d '\r' | grep -Eq -- "$regex"
}

nfqueue_packets() {
    local tool="$1"
    local chain="$2"
    adb_su "$tool -L $chain -v -n 2>/dev/null | awk '/NFQUEUE/{print \$1; exit}'" | tr -d '\r\n'
}

case_p2_01_root_preflight() {
    local group="env"
    local case_id="P2-01"
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "root preflight"; return 0; }

    local identity
    identity=$(adb_su "id" | tr -d '\r\n')
    if [[ "$identity" == *"uid=0(root)"* ]]; then
        log_pass "$case_id root preflight"
    else
        log_fail "$case_id root preflight"
        echo "    identity: $identity"
    fi
}

case_p2_02_daemon_health() {
    local group="env"
    local case_id="P2-02"
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "daemon health"; return 0; }

    local pid hello
    pid=$(adb_su "pidof sucre-snort-dev || true" | tr -d '\r\n')
    hello=$(send_cmd "HELLO" 3)
    if [[ -n "$pid" && "$hello" == "OK" ]]; then
        log_pass "$case_id daemon health (pid=$pid)"
    else
        log_fail "$case_id daemon health"
        echo "    pid: ${pid:-<empty>}"
        echo "    HELLO: $hello"
    fi
}

case_p2_03_socket_namespace() {
    local group="sockets"
    local case_id="P2-03"
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "socket namespace"; return 0; }

    local sockets
    sockets=$(adb_su "ls -lZ /dev/socket/sucre-snort-control /dev/socket/sucre-snort-netd 2>/dev/null" | tr -d '\r')
    if printf '%s\n' "$sockets" | grep -q "/dev/socket/sucre-snort-control" && \
       printf '%s\n' "$sockets" | grep -q "/dev/socket/sucre-snort-netd"; then
        log_pass "$case_id socket namespace"
    else
        log_fail "$case_id socket namespace"
        printf '%s\n' "$sockets" | sed 's/^/    /'
    fi
}

case_p2_04_netd_prerequisite() {
    local group="netd"
    local case_id="P2-04"
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "netd prerequisite"; return 0; }

    local mount_line
    mount_line=$(adb_su "mount | grep libnetd_resolv.so || true" | tr -d '\r')
    if [[ -n "$mount_line" ]]; then
        log_pass "$case_id netd prerequisite"
    else
        log_skip "$case_id netd prerequisite missing (libnetd_resolv.so 未挂载；先跑 bash dev/dev-netd-resolv.sh prepare，必要时再用模块方案)"
    fi
}

case_p2_05_ipv4_firewall_hooks() {
    local group="firewall"
    local case_id="P2-05"
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "ipv4 firewall hooks"; return 0; }

    local input_hook output_hook input_chain output_chain
    input_hook=$(rule_count iptables "-A INPUT -j sucre-snort_INPUT")
    output_hook=$(rule_count iptables "-A OUTPUT -j sucre-snort_OUTPUT")
    input_chain=$(rule_count iptables "-N sucre-snort_INPUT")
    output_chain=$(rule_count iptables "-N sucre-snort_OUTPUT")

    if [[ "$input_hook" == "1" && "$output_hook" == "1" && "$input_chain" == "1" && "$output_chain" == "1" ]]; then
        log_pass "$case_id ipv4 firewall hooks"
    else
        log_fail "$case_id ipv4 firewall hooks"
        echo "    input_hook=$input_hook output_hook=$output_hook input_chain=$input_chain output_chain=$output_chain"
        adb_su "iptables -S 2>/dev/null | grep sucre-snort || true" | sed 's/^/    /'
    fi
}

case_p2_06_ipv4_nfqueue_smoke() {
    local group="firewall"
    local case_id="P2-06"
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "ipv4 NFQUEUE smoke"; return 0; }

    if ! rule_exists_regex iptables '^-A sucre-snort_INPUT( .*)? -j NFQUEUE' || \
       ! rule_exists_regex iptables '^-A sucre-snort_OUTPUT( .*)? -j NFQUEUE'; then
        log_fail "$case_id ipv4 NFQUEUE smoke"
        adb_su "iptables -S 2>/dev/null | grep sucre-snort || true" | sed 's/^/    /'
        return 0
    fi

    local before after
    before=$(nfqueue_packets iptables sucre-snort_OUTPUT)
    if ! adb_su "toybox nc -z -w 2 1.1.1.1 443 >/dev/null 2>&1"; then
        log_fail "$case_id ipv4 NFQUEUE smoke"
        echo "    无法在真机上完成最小 TCP 出站流量 smoke"
        return 0
    fi
    after=$(nfqueue_packets iptables sucre-snort_OUTPUT)

    if [[ "$before" =~ ^[0-9]+$ && "$after" =~ ^[0-9]+$ && "$after" -gt "$before" ]]; then
        log_pass "$case_id ipv4 NFQUEUE smoke ($before -> $after)"
    else
        log_fail "$case_id ipv4 NFQUEUE smoke"
        echo "    before=$before after=$after"
    fi
}

case_p2_07_ipv6_firewall_hooks() {
    local group="firewall"
    local case_id="P2-07"
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "ipv6 firewall hooks"; return 0; }

    local input_hook output_hook input_chain output_chain
    input_hook=$(rule_count ip6tables "-A INPUT -j sucre-snort_INPUT")
    output_hook=$(rule_count ip6tables "-A OUTPUT -j sucre-snort_OUTPUT")
    input_chain=$(rule_count ip6tables "-N sucre-snort_INPUT")
    output_chain=$(rule_count ip6tables "-N sucre-snort_OUTPUT")

    if [[ "$input_hook" == "1" && "$output_hook" == "1" && "$input_chain" == "1" && "$output_chain" == "1" ]] && \
       rule_exists_regex ip6tables '^-A sucre-snort_INPUT( .*)? -j NFQUEUE' && \
       rule_exists_regex ip6tables '^-A sucre-snort_OUTPUT( .*)? -j NFQUEUE'; then
        log_pass "$case_id ipv6 firewall hooks"
    else
        log_fail "$case_id ipv6 firewall hooks"
        echo "    input_hook=$input_hook output_hook=$output_hook input_chain=$input_chain output_chain=$output_chain"
        adb_su "ip6tables -S 2>/dev/null | grep sucre-snort || true" | sed 's/^/    /'
    fi
}

case_p2_08_selinux_runtime() {
    local group="selinux"
    local case_id="P2-08"
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "SELinux runtime"; return 0; }

    local mode context denials
    mode=$(adb_su "getenforce" | tr -d '\r\n')
    context=$(adb_su "ps -AZ | grep sucre-snort-dev | head -1 || true" | tr -d '\r')
    denials=$(adb_su "logcat -d -s AVC 2>/dev/null | grep -i sucre | tail -20 || true" | tr -d '\r')

    if [[ -z "$mode" || -z "$context" ]]; then
        log_fail "$case_id SELinux runtime"
        echo "    mode=$mode"
        echo "    context=${context:-<empty>}"
        return 0
    fi

    if [[ -n "$denials" ]]; then
        log_fail "$case_id SELinux runtime"
        printf '%s\n' "$denials" | sed 's/^/    /'
        return 0
    fi

    log_pass "$case_id SELinux runtime ($mode)"
}

case_p2_09_lifecycle_restart() {
    local group="lifecycle"
    local case_id="P2-09"
    should_run_case "$group" "$case_id" || { skip_case "$case_id" "lifecycle restart"; return 0; }

    local shutdown_result pid_after deploy_log input_hook output_hook ipv6_input_hook ipv6_output_hook
    shutdown_result=$(send_cmd "DEV.SHUTDOWN" 5)
    if [[ "$shutdown_result" != "OK" ]]; then
        log_fail "$case_id lifecycle restart"
        echo "    DEV.SHUTDOWN: $shutdown_result"
        return 0
    fi

    for _ in 1 2 3 4 5 6 7 8 9 10; do
        pid_after=$(adb_su "pidof sucre-snort-dev || true" | tr -d '\r\n')
        [[ -z "$pid_after" ]] && break
        sleep 1
    done

    deploy_log=$(mktemp)
    if ! bash "$SNORT_ROOT/dev/dev-deploy.sh" --serial "$(adb_target_desc)" >"$deploy_log" 2>&1; then
        log_fail "$case_id lifecycle restart"
        tail -20 "$deploy_log" | sed 's/^/    /'
        rm -f "$deploy_log"
        return 0
    fi
    rm -f "$deploy_log"

    if [[ "$(send_cmd "HELLO" 3)" != "OK" ]]; then
        log_fail "$case_id lifecycle restart"
        echo "    daemon 在 redeploy 后未恢复响应"
        return 0
    fi

    input_hook=$(rule_count iptables "-A INPUT -j sucre-snort_INPUT")
    output_hook=$(rule_count iptables "-A OUTPUT -j sucre-snort_OUTPUT")
    ipv6_input_hook=$(rule_count ip6tables "-A INPUT -j sucre-snort_INPUT")
    ipv6_output_hook=$(rule_count ip6tables "-A OUTPUT -j sucre-snort_OUTPUT")

    if [[ "$input_hook" == "1" && "$output_hook" == "1" && "$ipv6_input_hook" == "1" && "$ipv6_output_hook" == "1" ]]; then
        log_pass "$case_id lifecycle restart"
    else
        log_fail "$case_id lifecycle restart"
        echo "    ipv4 hooks: in=$input_hook out=$output_hook"
        echo "    ipv6 hooks: in=$ipv6_input_hook out=$ipv6_output_hook"
    fi
}

main() {
    log_section "P2 rooted real-device platform smoke"

    if [[ $DO_DEPLOY -eq 1 ]]; then
        log_info "先执行 deploy，确保真机处于干净可测状态..."
        local -a deploy_cmd=(bash "$SNORT_ROOT/dev/dev-deploy.sh")
        if [[ -n "${ADB_SERIAL:-}" ]]; then
            deploy_cmd+=(--serial "$ADB_SERIAL")
        fi
        "${deploy_cmd[@]}" || exit 1
    fi

    init_test_env || exit 1

    case_p2_01_root_preflight
    case_p2_02_daemon_health
    case_p2_03_socket_namespace
    case_p2_04_netd_prerequisite
    case_p2_05_ipv4_firewall_hooks
    case_p2_06_ipv4_nfqueue_smoke
    case_p2_07_ipv6_firewall_hooks
    case_p2_08_selinux_runtime
    case_p2_09_lifecycle_restart

    if [[ $CLEANUP_FORWARD -eq 1 ]]; then
        log_info "移除 adb forward..."
        remove_control_forward "$SNORT_PORT"
    fi

    print_summary
}

main "$@"
