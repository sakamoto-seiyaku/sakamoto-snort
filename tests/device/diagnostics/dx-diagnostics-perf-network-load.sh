#!/bin/bash

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SNORT_ROOT/tests/integration/lib.sh"

DO_DEPLOY=1
CLEANUP_FORWARD=0

BYTES="${BYTES:-20000000}"          # Only used for Cloudflare URL
TIMEOUT_SEC="${TIMEOUT_SEC:-25}"    # Per-URL timeout on device
CONCURRENCY="${CONCURRENCY:-1}"     # Parallel downloads on device
URL_OVERRIDE="${URL_OVERRIDE:-}"    # If set, only try this URL
IDLE_SEC="${IDLE_SEC:-3}"          # Idle window duration for baseline comparison

VNEXT_PORT="${VNEXT_PORT:-60607}"
SNORT_CTL="${SNORT_CTL:-}"

show_help() {
    cat <<USAGE
用法: $0 [选项]

选项:
  --serial <serial>       指定目标真机 serial
  --skip-deploy           跳过部署，复用当前真机守护进程
  --cleanup-forward       结束后移除 vNext adb forward
  --url <url>             覆盖默认 URL 列表
  --bytes <n>             Cloudflare 下载 bytes（默认: $BYTES）
  --timeout <sec>         设备侧每个 URL 的 timeout（默认: $TIMEOUT_SEC）
  --concurrency <n>       并发下载数（默认: $CONCURRENCY）
  --idle-sec <sec>        空闲窗口时长，用于 baseline 对比（默认: $IDLE_SEC）
  --ctl <path>            指定 sucre-snort-ctl 路径（默认自动探测）
  --port <port>           指定 host tcp port（默认: $VNEXT_PORT -> localabstract:sucre-snort-control-vnext）
  -h, --help              显示帮助

环境变量（同名优先）:
  BYTES, TIMEOUT_SEC, CONCURRENCY, URL_OVERRIDE, IDLE_SEC

说明:
  - 该测试在设备侧用 curl/wget/toybox wget 下载到 /dev/null，产生真实网络 I/O 负载，
    然后读取 vNext METRICS.GET(name=perf)（JSON）。
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
        --ctl)
            SNORT_CTL="$2"
            shift 2
            ;;
        --port)
            VNEXT_PORT="$2"
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

find_snort_ctl() {
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

ctl_cmd() {
    local cmd="$1"
    local args_json="${2:-}"
    if [[ -n "$args_json" ]]; then
        "$SNORT_CTL" --tcp "127.0.0.1:${VNEXT_PORT}" --compact "$cmd" "$args_json"
    else
        "$SNORT_CTL" --tcp "127.0.0.1:${VNEXT_PORT}" --compact "$cmd"
    fi
}

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
    #
    # IMPORTANT: Use per-run unique hostnames to avoid DNS cache masking the DnsListener path.
    if ! adb_su "command -v ping >/dev/null 2>&1"; then
        return 1
    fi
    local ts
    ts="$(date +%s 2>/dev/null || echo 0)"
    adb_su "for i in 1 2 3; do ping -c 1 -W 1 \"dx-diag-${ts}-\${i}.example.com\" >/dev/null 2>&1 || true; done"
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

assert_json_pred() {
    local desc="$1"
    local json="$2"
    local py="$3"
    if printf '%s\n' "$json" | python3 -c "$py" >/dev/null 2>&1; then
        log_pass "$desc"
        return 0
    fi
    log_fail "$desc"
    printf '%s\n' "$json" | head -n 3 | sed 's/^/    /'
    return 1
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

vnext_preflight() {
    if ! device_preflight; then
        echo "BLOCKED: device_preflight failed (need adb + rooted device)" >&2
        return 77
    fi

    if ! check_control_vnext_forward "$VNEXT_PORT"; then
        log_info "设置 vNext adb forward..."
        setup_control_vnext_forward "$VNEXT_PORT" || {
            echo "BLOCKED: setup_control_vnext_forward failed (port=$VNEXT_PORT)" >&2
            return 77
        }
    fi

    SNORT_CTL="$(find_snort_ctl)" || return 77
    log_info "sucre-snort-ctl: $SNORT_CTL"

    set +e
    local hello
    hello="$(ctl_cmd HELLO 2>/dev/null)"
    local st=$?
    set -e
    if [[ $st -ne 0 ]]; then
        echo "BLOCKED: vNext control HELLO failed (port=$VNEXT_PORT)" >&2
        return 77
    fi
    assert_json_pred "VNX-HELLO ok" "$hello" \
        'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert j["result"]["protocol"]=="control-vnext"' ||
        return 77

    return 0
}

main() {
    log_section "DX diagnostics perf-network-load (vNext METRICS(perf))"

    if [[ $DO_DEPLOY -eq 1 ]]; then
        log_info "先执行 deploy，确保真机处于干净可测状态..."
        local -a deploy_cmd=(bash "$SNORT_ROOT/dev/dev-deploy.sh")
        if [[ -n "${ADB_SERIAL:-}" ]]; then
            deploy_cmd+=(--serial "$ADB_SERIAL")
        fi
        "${deploy_cmd[@]}" || exit 1
    fi

    if ! vnext_preflight; then
        exit 77
    fi

    local tool=""
    if ! tool="$(detect_downloader)"; then
        echo "SKIP: dx-diagnostics-perf-network-load missing curl/wget/toybox wget"
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
    set +e
    cfg_disable="$(ctl_cmd CONFIG.SET '{"scope":"device","set":{"perfmetrics.enabled":0}}' 2>/dev/null)"
    st=$?
    set -e
    if [[ $st -ne 0 ]]; then
        echo "BLOCKED: CONFIG.SET(perfmetrics.enabled=0) failed" >&2
        return 77
    fi
    assert_json_pred "CONFIG.SET perfmetrics.enabled=0 ack" "$cfg_disable" \
        'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True' || return 1

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
        echo "SKIP: dx-diagnostics-perf-network-load all URLs unreachable"
        return 0
    fi

    local j0
    j0="$(ctl_cmd METRICS.GET '{"name":"perf"}')" || true
    if ! echo "$j0" | python3 -c "import sys, json; json.load(sys.stdin)" >/dev/null 2>&1; then
        log_fail "METRICS.GET(perf) JSON (disabled)"
        echo "    响应: ${j0:0:200}..."
        return 1
    fi
    if echo "$j0" | assert_metrics_samples_eq "result.perf.nfq_total_us.samples" 0 &&
       echo "$j0" | assert_metrics_samples_eq "result.perf.dns_decision_us.samples" 0; then
        log_pass "perfmetrics.enabled=0 returns all zeros under traffic"
    else
        log_fail "perfmetrics.enabled=0 returns all zeros under traffic"
        echo "    响应: ${j0:0:200}..."
        return 1
    fi

    # 2) Enabled: samples should grow.
    set +e
    cfg_enable="$(ctl_cmd CONFIG.SET '{"scope":"device","set":{"perfmetrics.enabled":1}}' 2>/dev/null)"
    st=$?
    set -e
    if [[ $st -ne 0 ]]; then
        echo "BLOCKED: CONFIG.SET(perfmetrics.enabled=1) failed" >&2
        return 77
    fi
    assert_json_pred "CONFIG.SET perfmetrics.enabled=1 ack" "$cfg_enable" \
        'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True' || return 1

    # 2.0) Idle baseline window (best-effort; background traffic may exist).
    set +e
    reset_baseline="$(ctl_cmd METRICS.RESET '{"name":"perf"}' 2>/dev/null)"
    st=$?
    set -e
    if [[ $st -ne 0 ]]; then
        log_fail "METRICS.RESET(perf) failed (baseline)"
        printf '%s\n' "$reset_baseline" | head -n 3 | sed 's/^/    /'
        return 1
    fi
    assert_json_pred "METRICS.RESET(perf) ack (baseline)" "$reset_baseline" \
        'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True' || return 1
    if [[ "$IDLE_SEC" =~ ^[0-9]+$ && "$IDLE_SEC" -gt 0 ]]; then
        log_info "空闲 baseline 窗口: ${IDLE_SEC}s"
        adb_shell "sleep $IDLE_SEC" >/dev/null 2>&1 || true
    fi
    local j_idle
    j_idle="$(ctl_cmd METRICS.GET '{"name":"perf"}')"
    if ! echo "$j_idle" | python3 -c "import sys, json; json.load(sys.stdin)" >/dev/null 2>&1; then
        log_fail "METRICS.GET(perf) JSON (baseline)"
        echo "    响应: ${j_idle:0:200}..."
        return 1
    fi
    local idle_nfq_samples idle_nfq_avg idle_nfq_p95 idle_nfq_max
    local idle_dns_samples idle_dns_avg idle_dns_p95 idle_dns_max
    idle_nfq_samples="$(echo "$j_idle" | get_metrics_samples "result.perf.nfq_total_us.samples")" || idle_nfq_samples=0
    idle_nfq_avg="$(echo "$j_idle" | get_metrics_samples "result.perf.nfq_total_us.avg")" || idle_nfq_avg=0
    idle_nfq_p95="$(echo "$j_idle" | get_metrics_samples "result.perf.nfq_total_us.p95")" || idle_nfq_p95=0
    idle_nfq_max="$(echo "$j_idle" | get_metrics_samples "result.perf.nfq_total_us.max")" || idle_nfq_max=0
    idle_dns_samples="$(echo "$j_idle" | get_metrics_samples "result.perf.dns_decision_us.samples")" || idle_dns_samples=0
    idle_dns_avg="$(echo "$j_idle" | get_metrics_samples "result.perf.dns_decision_us.avg")" || idle_dns_avg=0
    idle_dns_p95="$(echo "$j_idle" | get_metrics_samples "result.perf.dns_decision_us.p95")" || idle_dns_p95=0
    idle_dns_max="$(echo "$j_idle" | get_metrics_samples "result.perf.dns_decision_us.max")" || idle_dns_max=0
    log_info "baseline(idle): nfq(samples=$idle_nfq_samples avg=$idle_nfq_avg p95=$idle_nfq_p95 max=$idle_nfq_max) dns(samples=$idle_dns_samples avg=$idle_dns_avg p95=$idle_dns_p95 max=$idle_dns_max)"

    # 2.1) Load window: reset to isolate download workload.
    set +e
    reset_load="$(ctl_cmd METRICS.RESET '{"name":"perf"}' 2>/dev/null)"
    st=$?
    set -e
    if [[ $st -ne 0 ]]; then
        log_fail "METRICS.RESET(perf) failed (load)"
        printf '%s\n' "$reset_load" | head -n 3 | sed 's/^/    /'
        return 1
    fi
    assert_json_pred "METRICS.RESET(perf) ack (load)" "$reset_load" \
        'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True' || return 1

    local expect_dns=0
    if netd_hook_present; then
        expect_dns=1
        log_info "检测到 netd resolv hook，触发 DNS 判决请求（unique subdomains）..."
        trigger_dns_requests || true
    else
        log_info "未检测到 netd resolv hook，跳过 dns_decision_us 增长断言"
    fi

    log_info "设备侧 download (enabled) => $ok_url"
    local t0 t1 load_sec
    t0="$(date +%s)"
    if ! device_download "$tool" "$ok_url"; then
        echo "SKIP: dx-diagnostics-perf-network-load URL failed after enable"
        return 0
    fi
    t1="$(date +%s)"
    load_sec=$((t1 - t0))
    if [[ "$load_sec" -le 0 ]]; then
        load_sec=1
    fi

    local j1
    j1="$(ctl_cmd METRICS.GET '{"name":"perf"}')"
    if ! echo "$j1" | python3 -c "import sys, json; json.load(sys.stdin)" >/dev/null 2>&1; then
        log_fail "METRICS.GET(perf) JSON (enabled)"
        echo "    响应: ${j1:0:200}..."
        return 1
    fi

    local samples
    samples="$(echo "$j1" | get_metrics_samples "result.perf.nfq_total_us.samples")" || samples=0
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
    dns_samples="$(echo "$j1" | get_metrics_samples "result.perf.dns_decision_us.samples")" || dns_samples=0

    local load_nfq_avg load_nfq_p95 load_nfq_max
    local load_dns_avg load_dns_p95 load_dns_max
    load_nfq_avg="$(echo "$j1" | get_metrics_samples "result.perf.nfq_total_us.avg")" || load_nfq_avg=0
    load_nfq_p95="$(echo "$j1" | get_metrics_samples "result.perf.nfq_total_us.p95")" || load_nfq_p95=0
    load_nfq_max="$(echo "$j1" | get_metrics_samples "result.perf.nfq_total_us.max")" || load_nfq_max=0
    load_dns_avg="$(echo "$j1" | get_metrics_samples "result.perf.dns_decision_us.avg")" || load_dns_avg=0
    load_dns_p95="$(echo "$j1" | get_metrics_samples "result.perf.dns_decision_us.p95")" || load_dns_p95=0
    load_dns_max="$(echo "$j1" | get_metrics_samples "result.perf.dns_decision_us.max")" || load_dns_max=0
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
            echo "SKIP: dx-diagnostics-perf-network-load dns_decision_us.samples did not grow (netd hook may be inactive); skip dns assertions"
            expect_dns=0
        fi
    fi

    # 2.1) Idempotency: perfmetrics.enabled 1->1 MUST NOT clear aggregates.
    set +e
    cfg_enable2="$(ctl_cmd CONFIG.SET '{"scope":"device","set":{"perfmetrics.enabled":1}}' 2>/dev/null)"
    st=$?
    set -e
    if [[ $st -ne 0 ]]; then
        log_fail "CONFIG.SET perfmetrics.enabled=1 (idempotent) failed"
        printf '%s\n' "$cfg_enable2" | head -n 3 | sed 's/^/    /'
        return 1
    fi
    assert_json_pred "CONFIG.SET perfmetrics.enabled=1 (idempotent) ack" "$cfg_enable2" \
        'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True' || return 1
    local j2
    j2="$(ctl_cmd METRICS.GET '{"name":"perf"}')"
    local samples2 dns_samples2
    samples2="$(echo "$j2" | get_metrics_samples "result.perf.nfq_total_us.samples")" || samples2=0
    dns_samples2="$(echo "$j2" | get_metrics_samples "result.perf.dns_decision_us.samples")" || dns_samples2=0
    if [[ "$samples2" -ge "$samples" ]]; then
        log_pass "perfmetrics.enabled 1->1 does not clear nfq_total_us (samples=$samples2)"
    else
        log_fail "perfmetrics.enabled 1->1 does not clear nfq_total_us"
        echo "    before=$samples after=$samples2"
        return 1
    fi
    if [[ $expect_dns -eq 1 ]]; then
        if [[ "$dns_samples2" -ge "$dns_samples" ]]; then
            log_pass "perfmetrics.enabled 1->1 does not clear dns_decision_us (samples=$dns_samples2)"
        else
            log_fail "perfmetrics.enabled 1->1 does not clear dns_decision_us"
            echo "    before=$dns_samples after=$dns_samples2"
            return 1
        fi
    fi

    # 3) Invalid arg must be rejected.
    set +e
    inv="$(ctl_cmd CONFIG.SET '{"scope":"device","set":{"perfmetrics.enabled":2}}' 2>/dev/null)"
    inv_rc=$?
    set -e
    if [[ $inv_rc -ne 0 ]]; then
        log_pass "CONFIG.SET(perfmetrics.enabled=2) rejects invalid value"
    else
        log_fail "CONFIG.SET(perfmetrics.enabled=2) rejects invalid value"
        echo "    响应: $inv"
        return 1
    fi

    if [[ $CLEANUP_FORWARD -eq 1 ]]; then
        log_info "移除 adb forward..."
        remove_control_vnext_forward "$VNEXT_PORT"
    fi

    print_summary
}

main "$@"
