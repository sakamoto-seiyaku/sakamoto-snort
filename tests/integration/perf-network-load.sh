#!/bin/bash

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/lib.sh"

DO_DEPLOY=1
CLEANUP_FORWARD=0

BYTES="${BYTES:-20000000}"          # Only used for Cloudflare URL
TIMEOUT_SEC="${TIMEOUT_SEC:-25}"    # Per-URL timeout on device
CONCURRENCY="${CONCURRENCY:-1}"     # Parallel downloads on device
URL_OVERRIDE="${URL_OVERRIDE:-}"    # If set, only try this URL
IDLE_SEC="${IDLE_SEC:-3}"          # Idle window duration for baseline comparison

show_help() {
    cat <<USAGE
用法: $0 [选项]

选项:
  --serial <serial>       指定目标真机 serial
  --skip-deploy           跳过部署，复用当前真机守护进程
  --cleanup-forward       结束后移除 adb forward
  --url <url>             覆盖默认 URL 列表
  --bytes <n>             Cloudflare 下载 bytes（默认: $BYTES）
  --timeout <sec>         设备侧每个 URL 的 timeout（默认: $TIMEOUT_SEC）
  --concurrency <n>       并发下载数（默认: $CONCURRENCY）
  --idle-sec <sec>        空闲窗口时长，用于 baseline 对比（默认: $IDLE_SEC）
  -h, --help              显示帮助

环境变量（同名优先）:
  BYTES, TIMEOUT_SEC, CONCURRENCY, URL_OVERRIDE, IDLE_SEC

说明:
  - 该测试在设备侧用 curl/wget/toybox wget 下载到 /dev/null，产生真实网络 I/O 负载，
    然后读取 METRICS.PERF（JSON）。
  - 若所有 URL 不可达（离线/受限网络），测试会明确 SKIP。
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
        --url)
            URL_OVERRIDE="$2"
            shift 2
            ;;
        --bytes)
            BYTES="$2"
            shift 2
            ;;
        --timeout)
            TIMEOUT_SEC="$2"
            shift 2
            ;;
        --concurrency)
            CONCURRENCY="$2"
            shift 2
            ;;
        --idle-sec)
            IDLE_SEC="$2"
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

netd_hook_present() {
    # Heuristic: the patched resolver contains the snort netd socket path string.
    adb_su "strings /apex/com.android.resolv/lib64/libnetd_resolv.so 2>/dev/null | grep -q '/dev/socket/sucre-snort-netd'"
}

trigger_dns_requests() {
    # Use ping for a simple DNS lookup trigger (ICMP may fail; DNS resolution still happens).
    if ! adb_su "command -v ping >/dev/null 2>&1"; then
        return 1
    fi
    adb_su "for i in 1 2 3; do ping -c 1 -W 1 example.com >/dev/null 2>&1 || true; done"
}

detect_downloader() {
    if adb_shell "command -v curl >/dev/null 2>&1"; then
        printf '%s\n' "curl"
        return 0
    fi
    if adb_shell "command -v wget >/dev/null 2>&1"; then
        printf '%s\n' "wget"
        return 0
    fi
    if adb_shell "command -v busybox >/dev/null 2>&1 && busybox wget --help >/dev/null 2>&1"; then
        printf '%s\n' "busybox_wget"
        return 0
    fi
    # Fallback: toybox nc/netcat doing plain HTTP GET (no TLS).
    if adb_shell "command -v nc >/dev/null 2>&1"; then
        printf '%s\n' "nc_http"
        return 0
    fi
    if adb_shell "command -v netcat >/dev/null 2>&1"; then
        printf '%s\n' "nc_http"
        return 0
    fi
    return 1
}

device_download() {
    local tool="$1"
    local url="$2"

    local cmd=""
    case "$tool" in
        curl)
            cmd="curl -L -o /dev/null -sS \"$url\""
            ;;
        wget)
            cmd="wget -O /dev/null -q \"$url\""
            ;;
        busybox_wget)
            cmd="busybox wget -q -O /dev/null \"$url\""
            ;;
        nc_http)
            if [[ "$url" != http://* ]]; then
                return 1
            fi
            local stripped="${url#http://}"
            local host="${stripped%%/*}"
            local path="/"
            if [[ "$stripped" != "$host" ]]; then
                path="/${stripped#*/}"
            fi
            cmd="printf \"GET ${path} HTTP/1.1\\r\\nHost: ${host}\\r\\nConnection: close\\r\\n\\r\\n\" | nc -w 10 ${host} 80 > /dev/null"
            ;;
        *)
            return 2
            ;;
    esac

    # Run N downloads in parallel, with a simple watchdog timeout.
    local script="
pids=\"\"
i=0
while [ \"\$i\" -lt \"$CONCURRENCY\" ]; do
  $cmd &
  pids=\"\$pids \$!\"
  i=\$((i+1))
done

( sleep \"$TIMEOUT_SEC\"; for pid in \$pids; do kill -9 \"\$pid\" 2>/dev/null || true; done ) &
wd=\$!

status=0
for pid in \$pids; do
  wait \"\$pid\" || status=1
done
kill \"\$wd\" 2>/dev/null || true
exit \"\$status\"
"
    adb_shell "$script" >/dev/null 2>&1
}

assert_metrics_samples_eq() {
    local path="$1"
    local expected="$2"
    python3 -c 'import json, sys
path = sys.argv[1].split(".")
expected = int(sys.argv[2])
d = json.load(sys.stdin)
cur = d
for k in path:
    cur = cur[k]
sys.exit(0 if int(cur) == expected else 1)
' "$path" "$expected"
}

get_metrics_samples() {
    local path="$1"
    python3 -c 'import json, sys
path = sys.argv[1].split(".")
d = json.load(sys.stdin)
cur = d
for k in path:
    cur = cur[k]
print(int(cur))
' "$path"
}

main() {
    log_section "Perf network load (METRICS.PERF)"

    if [[ $DO_DEPLOY -eq 1 ]]; then
        log_info "先执行 deploy，确保真机处于干净可测状态..."
        local -a deploy_cmd=(bash "$SNORT_ROOT/dev/dev-deploy.sh")
        if [[ -n "${ADB_SERIAL:-}" ]]; then
            deploy_cmd+=(--serial "$ADB_SERIAL")
        fi
        "${deploy_cmd[@]}" || exit 1
    fi

    init_test_env || exit 1

    local tool=""
    if ! tool="$(detect_downloader)"; then
        echo "SKIP: perf-network-load missing curl/wget/toybox wget"
        return 0
    fi
    log_info "设备侧 downloader: $tool"

    local -a urls=()
    if [[ -n "$URL_OVERRIDE" ]]; then
        urls+=("$URL_OVERRIDE")
    else
        urls+=("https://speed.cloudflare.com/__down?bytes=${BYTES}")
        urls+=("https://fsn1-speed.hetzner.com/100MB.bin")
        urls+=("http://speedtest.tele2.net/10MB.zip")
    fi

    # 1) Disabled: must return zeros even under traffic.
    assert_ok "PERFMETRICS 0" "PERFMETRICS disable"

    local ok_url=""
    local u
    for u in "${urls[@]}"; do
        log_info "设备侧 download (disabled) => $u"
        if device_download "$tool" "$u"; then
            ok_url="$u"
            break
        fi
    done
    if [[ -z "$ok_url" ]]; then
        echo "SKIP: perf-network-load all URLs unreachable"
        return 0
    fi

    local j0
    j0="$(send_cmd "METRICS.PERF")" || true
    if ! echo "$j0" | python3 -c "import sys, json; json.load(sys.stdin)" >/dev/null 2>&1; then
        log_fail "METRICS.PERF JSON (disabled)"
        echo "    响应: ${j0:0:200}..."
        return 1
    fi
    if echo "$j0" | assert_metrics_samples_eq "perf.nfq_total_us.samples" 0 &&
       echo "$j0" | assert_metrics_samples_eq "perf.dns_decision_us.samples" 0; then
        log_pass "PERFMETRICS=0 returns all zeros under traffic"
    else
        log_fail "PERFMETRICS=0 returns all zeros under traffic"
        echo "    响应: ${j0:0:200}..."
        return 1
    fi

    # 2) Enabled: samples should grow.
    assert_ok "PERFMETRICS 1" "PERFMETRICS enable"

    # 2.0) Idle baseline window (best-effort; background traffic may exist).
    assert_ok "METRICS.PERF.RESET" "METRICS.PERF.RESET (baseline)"
    if [[ "$IDLE_SEC" =~ ^[0-9]+$ && "$IDLE_SEC" -gt 0 ]]; then
        log_info "空闲 baseline 窗口: ${IDLE_SEC}s"
        adb_shell "sleep $IDLE_SEC" >/dev/null 2>&1 || true
    fi
    local j_idle
    j_idle="$(send_cmd "METRICS.PERF")"
    if ! echo "$j_idle" | python3 -c "import sys, json; json.load(sys.stdin)" >/dev/null 2>&1; then
        log_fail "METRICS.PERF JSON (baseline)"
        echo "    响应: ${j_idle:0:200}..."
        return 1
    fi
    local idle_nfq_samples idle_nfq_avg idle_nfq_p95 idle_nfq_max
    local idle_dns_samples idle_dns_avg idle_dns_p95 idle_dns_max
    idle_nfq_samples="$(echo "$j_idle" | get_metrics_samples "perf.nfq_total_us.samples")" || idle_nfq_samples=0
    idle_nfq_avg="$(echo "$j_idle" | get_metrics_samples "perf.nfq_total_us.avg")" || idle_nfq_avg=0
    idle_nfq_p95="$(echo "$j_idle" | get_metrics_samples "perf.nfq_total_us.p95")" || idle_nfq_p95=0
    idle_nfq_max="$(echo "$j_idle" | get_metrics_samples "perf.nfq_total_us.max")" || idle_nfq_max=0
    idle_dns_samples="$(echo "$j_idle" | get_metrics_samples "perf.dns_decision_us.samples")" || idle_dns_samples=0
    idle_dns_avg="$(echo "$j_idle" | get_metrics_samples "perf.dns_decision_us.avg")" || idle_dns_avg=0
    idle_dns_p95="$(echo "$j_idle" | get_metrics_samples "perf.dns_decision_us.p95")" || idle_dns_p95=0
    idle_dns_max="$(echo "$j_idle" | get_metrics_samples "perf.dns_decision_us.max")" || idle_dns_max=0
    log_info "baseline(idle): nfq(samples=$idle_nfq_samples avg=$idle_nfq_avg p95=$idle_nfq_p95 max=$idle_nfq_max) dns(samples=$idle_dns_samples avg=$idle_dns_avg p95=$idle_dns_p95 max=$idle_dns_max)"

    # 2.1) Load window: reset to isolate download workload.
    assert_ok "METRICS.PERF.RESET" "METRICS.PERF.RESET (load)"

    local expect_dns=0
    if netd_hook_present; then
        expect_dns=1
        log_info "检测到 netd resolv hook，触发 DNS 判决请求（example.com）..."
        trigger_dns_requests || true
    else
        log_info "未检测到 netd resolv hook，跳过 dns_decision_us 增长断言"
    fi

    log_info "设备侧 download (enabled) => $ok_url"
    local t0 t1 load_sec
    t0="$(date +%s)"
    if ! device_download "$tool" "$ok_url"; then
        echo "SKIP: perf-network-load URL failed after enable"
        return 0
    fi
    t1="$(date +%s)"
    load_sec=$((t1 - t0))
    if [[ "$load_sec" -le 0 ]]; then
        load_sec=1
    fi

    local j1
    j1="$(send_cmd "METRICS.PERF")"
    if ! echo "$j1" | python3 -c "import sys, json; json.load(sys.stdin)" >/dev/null 2>&1; then
        log_fail "METRICS.PERF JSON (enabled)"
        echo "    响应: ${j1:0:200}..."
        return 1
    fi

    local samples
    samples="$(echo "$j1" | get_metrics_samples "perf.nfq_total_us.samples")" || samples=0
    if [[ "$samples" -ge 1 ]]; then
        log_pass "perf.nfq_total_us.samples grows under traffic (samples=$samples)"
        echo "$j1" | head -c 800
        echo ""
    else
        log_fail "perf.nfq_total_us.samples grows under traffic"
        echo "    响应: ${j1:0:200}..."
        return 1
    fi

    local dns_samples
    dns_samples="$(echo "$j1" | get_metrics_samples "perf.dns_decision_us.samples")" || dns_samples=0

    local load_nfq_avg load_nfq_p95 load_nfq_max
    local load_dns_avg load_dns_p95 load_dns_max
    load_nfq_avg="$(echo "$j1" | get_metrics_samples "perf.nfq_total_us.avg")" || load_nfq_avg=0
    load_nfq_p95="$(echo "$j1" | get_metrics_samples "perf.nfq_total_us.p95")" || load_nfq_p95=0
    load_nfq_max="$(echo "$j1" | get_metrics_samples "perf.nfq_total_us.max")" || load_nfq_max=0
    load_dns_avg="$(echo "$j1" | get_metrics_samples "perf.dns_decision_us.avg")" || load_dns_avg=0
    load_dns_p95="$(echo "$j1" | get_metrics_samples "perf.dns_decision_us.p95")" || load_dns_p95=0
    load_dns_max="$(echo "$j1" | get_metrics_samples "perf.dns_decision_us.max")" || load_dns_max=0
    log_info "load(download ~${load_sec}s): nfq(samples=$samples avg=$load_nfq_avg p95=$load_nfq_p95 max=$load_nfq_max) dns(samples=$dns_samples avg=$load_dns_avg p95=$load_dns_p95 max=$load_dns_max)"
    if [[ "$idle_nfq_samples" -gt 0 ]]; then
        log_info "compare(nfq p95): idle=$idle_nfq_p95 -> load=$load_nfq_p95 (us)"
    else
        log_info "compare(nfq p95): idle samples=0，跳过 latency 对比"
    fi

    if [[ $expect_dns -eq 1 ]]; then
        if [[ "$dns_samples" -ge 1 ]]; then
            log_pass "perf.dns_decision_us.samples grows under DNS requests (samples=$dns_samples)"
        else
            log_fail "perf.dns_decision_us.samples grows under DNS requests"
            echo "    响应: ${j1:0:200}..."
            return 1
        fi
    fi

    # 2.1) Idempotency: PERFMETRICS 1->1 MUST NOT clear aggregates.
    assert_ok "PERFMETRICS 1" "PERFMETRICS idempotent (1->1)"
    local j2
    j2="$(send_cmd "METRICS.PERF")"
    local samples2 dns_samples2
    samples2="$(echo "$j2" | get_metrics_samples "perf.nfq_total_us.samples")" || samples2=0
    dns_samples2="$(echo "$j2" | get_metrics_samples "perf.dns_decision_us.samples")" || dns_samples2=0
    if [[ "$samples2" -ge "$samples" ]]; then
        log_pass "PERFMETRICS 1->1 does not clear nfq_total_us (samples=$samples2)"
    else
        log_fail "PERFMETRICS 1->1 does not clear nfq_total_us"
        echo "    before=$samples after=$samples2"
        return 1
    fi
    if [[ $expect_dns -eq 1 ]]; then
        if [[ "$dns_samples2" -ge "$dns_samples" ]]; then
            log_pass "PERFMETRICS 1->1 does not clear dns_decision_us (samples=$dns_samples2)"
        else
            log_fail "PERFMETRICS 1->1 does not clear dns_decision_us"
            echo "    before=$dns_samples after=$dns_samples2"
            return 1
        fi
    fi

    # 3) Invalid arg must be rejected.
    local inv
    inv="$(send_cmd "PERFMETRICS 2")"
    if [[ "$inv" == "NOK" ]]; then
        log_pass "PERFMETRICS rejects invalid value"
    else
        log_fail "PERFMETRICS rejects invalid value (expected NOK)"
        echo "    响应: $inv"
        return 1
    fi

    if [[ $CLEANUP_FORWARD -eq 1 ]]; then
        log_info "移除 adb forward..."
        remove_control_forward "$SNORT_PORT"
    fi

    print_summary
}

main "$@"
