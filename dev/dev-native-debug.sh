#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/dev-android-device-lib.sh"

LINEAGE_ROOT="${LINEAGE_ROOT:-$HOME/android/lineage}"
LLDBCLIENT="$LINEAGE_ROOT/development/scripts/lldbclient.py"
LLDBCLIENT_WRAPPER="$SCRIPT_DIR/dev-lldbclient-wrapper.py"
AOSP_PYTHON_DEFAULT="$LINEAGE_ROOT/prebuilts/build-tools/path/linux-x86/python3"
DEFAULT_BINARY="/data/local/tmp/sucre-snort-dev"
DEFAULT_HOST_BINARY="$SCRIPT_DIR/../build-output/sucre-snort"
DEFAULT_PROCESS="sucre-snort-dev"
DEFAULT_PORT="5039"
DEFAULT_LUNCH_TARGET="${DEV_LUNCH_TARGET:-lineage_bluejay-bp2a-userdebug}"
DEFAULT_LAUNCH_FILE="$PWD/.vscode/launch.json"
DEVICE_LLDB_SERVER="/data/local/tmp/arm64-lldb-server"
WORKSPACE_ROOT="${SNORT_VSCODE_WORKSPACE_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"

show_help() {
    cat <<EOF
用法: $0 <attach|run|vscode-attach|vscode-run|wait-debugger> [选项]

子命令:
  attach           附加到已运行的真机进程
  run              在真机上以 LLDB 方式直接启动二进制
  vscode-attach    为 VS Code + CodeLLDB 生成 attach 准备
  vscode-run       为 VS Code + CodeLLDB 生成 run 准备
  wait-debugger    设置/查询 debug.debuggerd.wait_for_debugger

通用选项:
  --serial <serial>        指定目标真机 serial
  --port <port>            指定 lldb 端口（默认: $DEFAULT_PORT）
  --lunch-target <target>  指定 lunch target（默认: $DEFAULT_LUNCH_TARGET）
  --print-only             只打印最终命令，不执行

attach/vscode-attach 选项:
  --pid <pid>              指定 PID
  --process <name>         按进程名查 PID（默认: $DEFAULT_PROCESS）

run/vscode-run 选项:
  --binary <path>          真机上的二进制路径（默认: $DEFAULT_BINARY）
  --host-binary <path>     host 上用于符号解析的二进制；若默认产物被 strip，会自动回退到匹配 Build ID 的 unstripped 版本

vscode 选项:
  --launch-file <path>     launch.json 目标路径（默认: $DEFAULT_LAUNCH_FILE）

wait-debugger 用法:
  $0 wait-debugger on
  $0 wait-debugger off
  $0 wait-debugger status
EOF
}

require_lldbclient() {
    if [[ ! -f "$LLDBCLIENT" ]]; then
        echo "❌ 未找到 lldbclient.py: $LLDBCLIENT" >&2
        exit 1
    fi
    if [[ ! -f "$LLDBCLIENT_WRAPPER" ]]; then
        echo "❌ 未找到 lldbclient wrapper: $LLDBCLIENT_WRAPPER" >&2
        exit 1
    fi
}

resolve_python_bin() {
    if [[ -x "$AOSP_PYTHON_DEFAULT" ]]; then
        printf "%s\n" "$AOSP_PYTHON_DEFAULT"
        return 0
    fi
    if command -v python3 >/dev/null 2>&1; then
        printf "%s\n" "$(command -v python3)"
        return 0
    fi

    echo "❌ 未找到可用 Python 解释器" >&2
    exit 1
}

prepare_host_env() {
    export PATH="$(dirname "$ADB_BIN"):$PATH"
}

ensure_lineage_env() {
    if [[ ! -d "$LINEAGE_ROOT" ]]; then
        echo "❌ 未找到 LINEAGE_ROOT: $LINEAGE_ROOT" >&2
        exit 1
    fi
    if [[ ! -f "$LINEAGE_ROOT/build/envsetup.sh" ]]; then
        echo "❌ 未找到 envsetup.sh: $LINEAGE_ROOT/build/envsetup.sh" >&2
        exit 1
    fi
}

ensure_vscode_launch_file() {
    local launch_file="$1"
    local begin='// #lldbclient-generated-begin'
    local end='// #lldbclient-generated-end'

    mkdir -p "$(dirname "$launch_file")"
    if [[ ! -f "$launch_file" ]]; then
        cat > "$launch_file" <<EOF
{
  "version": "0.2.0",
  "configurations": [
    $begin
    $end
  ]
}
EOF
        return 0
    fi

    if ! grep -Fq "$begin" "$launch_file" || ! grep -Fq "$end" "$launch_file"; then
        echo "❌ launch.json 缺少 lldbclient marker，请补上后重试: $launch_file" >&2
        exit 1
    fi
}

binary_build_id() {
    local binary_path="$1"

    [[ -f "$binary_path" ]] || return 1
    readelf -n "$binary_path" 2>/dev/null | awk '/Build ID:/ { print $3; exit }'
}

binary_has_debug_info() {
    local binary_path="$1"

    [[ -f "$binary_path" ]] || return 1
    readelf -S "$binary_path" 2>/dev/null | grep -q '\.debug_info'
}

find_matching_unstripped_host_binary() {
    local binary_name="$1"
    local expected_build_id="$2"
    local debug_output="$SCRIPT_DIR/../build-output/${binary_name}.debug"
    local candidate=""

    if [[ -f "$debug_output" ]] \
        && [[ "$(binary_build_id "$debug_output" 2>/dev/null || true)" == "$expected_build_id" ]] \
        && binary_has_debug_info "$debug_output"; then
        printf '%s\n' "$debug_output"
        return 0
    fi

    while IFS= read -r candidate; do
        if [[ "$(binary_build_id "$candidate" 2>/dev/null || true)" == "$expected_build_id" ]] \
            && binary_has_debug_info "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done < <(find "$LINEAGE_ROOT/out/soong/.intermediates/system/sucre-snort" -path "*/unstripped/$binary_name" -type f 2>/dev/null | sort)

    return 1
}

resolve_host_debug_binary() {
    local host_binary="$1"
    local resolved_build_id=""
    local resolved_binary=""
    local binary_name=""

    if [[ ! -f "$host_binary" ]]; then
        echo "❌ 未找到 host 调试二进制: $host_binary" >&2
        exit 1
    fi

    if binary_has_debug_info "$host_binary"; then
        printf '%s\n' "$host_binary"
        return 0
    fi

    resolved_build_id="$(binary_build_id "$host_binary" 2>/dev/null || true)"
    if [[ -z "$resolved_build_id" ]]; then
        printf '%s\n' "$host_binary"
        return 0
    fi

    binary_name="$(basename "$host_binary")"
    resolved_binary="$(find_matching_unstripped_host_binary "$binary_name" "$resolved_build_id" || true)"
    if [[ -n "$resolved_binary" ]]; then
        echo "使用匹配 Build ID 的 unstripped 符号文件: $resolved_binary" >&2
        printf '%s\n' "$resolved_binary"
        return 0
    fi

    printf '%s\n' "$host_binary"
}

build_lldbclient_cmd() {
    local python_bin="$1"
    local lunch_target="$2"
    local device_product="$3"
    local remote_binary="$4"
    local host_binary="$5"
    shift 5
    local pycmd
    local shim_cmd=""
    local mirror_cmd=""

    printf -v pycmd '%q ' "$python_bin" "$LLDBCLIENT_WRAPPER" "$LLDBCLIENT" --adb "$ADB_BIN" -s "$ADB_SERIAL_RESOLVED" "$@"
    if [[ -n "$device_product" ]]; then
        printf -v shim_cmd 'if [[ "${TARGET_PRODUCT:-}" == lineage_* && "${TARGET_PRODUCT#lineage_}" == %q ]]; then export TARGET_PRODUCT=%q; fi && ' "$device_product" "$device_product"
    fi
    mirror_cmd="$(build_symbol_mirror_cmd "$remote_binary" "$host_binary")"

    printf 'cd %q && source build/envsetup.sh >/dev/null && lunch %q >/dev/null && %s%s%s' "$LINEAGE_ROOT" "$lunch_target" "$shim_cmd" "$mirror_cmd" "$pycmd"
}

resolve_device_product() {
    local product

    product="$(adb_cmd shell getprop ro.build.product 2>/dev/null | tr -d '\r\n')"
    if [[ -n "$product" ]]; then
        printf '%s\n' "$product"
        return 0
    fi

    product="$(adb_cmd shell getprop ro.product.name 2>/dev/null | tr -d '\r\n')"
    if [[ -n "$product" ]]; then
        printf '%s\n' "$product"
        return 0
    fi

    echo "❌ 无法解析设备 product 名称" >&2
    return 1
}

resolve_pid_binary() {
    local pid="$1"
    local binary_path

    binary_path="$(adb_su "readlink -e -n /proc/$pid/exe" 2>/dev/null | tr -d '\r\n')"
    if [[ -z "$binary_path" ]]; then
        echo "❌ 无法解析 PID 对应的二进制路径: $pid" >&2
        return 1
    fi
    printf '%s\n' "$binary_path"
}

build_symbol_mirror_cmd() {
    local remote_binary="$1"
    local host_binary="$2"
    local mirror_cmd=""

    if [[ "$remote_binary" == /data/local/tmp/* ]]; then
        if [[ ! -f "$host_binary" ]]; then
            echo "❌ 未找到 host 调试二进制: $host_binary" >&2
            exit 1
        fi
        printf -v mirror_cmd 'mirror_target="$ANDROID_PRODUCT_OUT/symbols%q" && mkdir -p "$(dirname "$mirror_target")" && ln -snf %q "$mirror_target" && ' "$remote_binary" "$host_binary"
    fi

    printf '%s' "$mirror_cmd"
}

resolve_pid() {
    local pid="$1"
    local process_name="$2"
    if [[ -n "$pid" ]]; then
        printf '%s\n' "$pid"
        return 0
    fi

    local resolved
    resolved="$(adb_su "pidof $process_name" 2>/dev/null | tr -d '\r\n' | awk '{print $1}')"
    if [[ -z "$resolved" ]]; then
        echo "❌ 未找到进程: $process_name" >&2
        return 1
    fi
    printf '%s\n' "$resolved"
}

control_socket_roundtrip() {
    local request="$1"
    local expected="$2"
    local control_forward_port="$3"

    if ! adb_su "ls /dev/socket/sucre-snort-control" >/dev/null 2>&1; then
        return 1
    fi

    adb_cmd forward "tcp:${control_forward_port}" localabstract:sucre-snort-control >/dev/null 2>&1 || return 1
    python3 - <<PY >/dev/null 2>&1
import socket, sys
port = int(${control_forward_port})
request = ${request@Q}.encode("utf-8") + b"\0"
expected = ${expected@Q}
try:
    sock = socket.create_connection(("127.0.0.1", port), timeout=2)
    sock.sendall(request)
    sock.settimeout(3)
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if data.endswith(b"\0"):
            break
    sock.close()
    if data.endswith(b"\0"):
        data = data[:-1]
    sys.exit(0 if data.decode("utf-8", errors="replace").strip() == expected else 1)
except Exception:
    sys.exit(1)
PY
    local status=$?
    adb_cmd forward --remove "tcp:${control_forward_port}" >/dev/null 2>&1 || true
    return $status
}

request_dev_shutdown() {
    local control_forward_port="$1"
    control_socket_roundtrip "DEV.SHUTDOWN" "OK" "$control_forward_port"
}

resolve_tracer_pid() {
    local pid="$1"
    adb_su "awk '/^TracerPid:/ {print \$2}' /proc/$pid/status 2>/dev/null || true" | tr -d '\r\n'
}

clear_process_debugger_residue() {
    local pid="$1"
    local tracer_pid

    tracer_pid="$(resolve_tracer_pid "$pid")"
    if [[ -n "$tracer_pid" && "$tracer_pid" != "0" ]]; then
        echo "检测到残留 debugger (TracerPid: $tracer_pid)，先清理..."
        adb_su "kill -9 $tracer_pid 2>/dev/null || true"
        adb_su "kill -CONT $pid 2>/dev/null || true"
        sleep 1
    fi
}

clear_lldb_server_residue() {
    local port="$1"
    adb_cmd forward --remove "tcp:${port}" >/dev/null 2>&1 || true
    adb_su "killall -9 arm64-lldb-server lldb-server gdbserver 2>/dev/null || true"
}

debug_prepare_attach() {
    local pid="$1"
    local port="$2"

    clear_lldb_server_residue "$port"
    clear_process_debugger_residue "$pid"
}

debug_prepare_run() {
    local process_name="$1"
    local port="$2"
    local control_forward_port="60616"
    local pid=""

    clear_lldb_server_residue "$port"
    pid="$(adb_su "pidof $process_name 2>/dev/null | awk '{print \$1}'" | tr -d '\r\n' || true)"
    if [[ -n "$pid" ]]; then
        clear_process_debugger_residue "$pid"
        if request_dev_shutdown "$control_forward_port"; then
            echo "已通过 DEV.SHUTDOWN 请求旧进程退出"
        else
            adb_su "killall $process_name 2>/dev/null || true"
        fi
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            if ! adb_su "pidof $process_name >/dev/null 2>&1" >/dev/null 2>&1; then
                break
            fi
            sleep 1
        done
        if adb_su "pidof $process_name >/dev/null 2>&1" >/dev/null 2>&1; then
            pid="$(adb_su "pidof $process_name 2>/dev/null | awk '{print \$1}'" | tr -d '\r\n' || true)"
            if [[ -n "$pid" ]]; then
                clear_process_debugger_residue "$pid"
            fi
            adb_su "killall -9 $process_name 2>/dev/null || true"
            sleep 1
        fi
    fi

    adb_su "rm -f /dev/socket/sucre-snort-control /dev/socket/sucre-snort-netd 2>/dev/null || true"
}

resolve_symbols_root() {
    local device_product="$1"
    printf '%s\n' "$LINEAGE_ROOT/out/target/product/$device_product/symbols"
}

build_exec_search_paths() {
    local symbols_root="$1"
    local candidates=(
        "$symbols_root/system/lib64/"
        "$symbols_root/system/lib64/hw"
        "$symbols_root/system/lib64/ssl/engines"
        "$symbols_root/system/lib64/drm"
        "$symbols_root/system/lib64/egl"
        "$symbols_root/system/lib64/soundfx"
        "$symbols_root/vendor/lib64/"
        "$symbols_root/vendor/lib64/hw"
        "$symbols_root/vendor/lib64/egl"
    )
    local existing=()
    local candidate=""

    for candidate in "${candidates[@]}"; do
        [[ -d "$candidate" ]] && existing+=("$candidate")
    done

    printf '%s\n' "${existing[*]}"
}

ensure_device_lldb_server() {
    local local_server=""

    if adb_su "test -x $DEVICE_LLDB_SERVER" >/dev/null 2>&1; then
        return 0
    fi

    local_server="$(find "$LINEAGE_ROOT/prebuilts/clang/host/linux-x86" -path '*/runtimes_ndk_cxx/aarch64/lldb-server' -type f 2>/dev/null | sort | tail -n 1)"
    if [[ -z "$local_server" ]]; then
        echo "❌ 未找到 host lldb-server" >&2
        exit 1
    fi

    echo "推送设备侧 lldb-server: $local_server"
    adb_push_file "$local_server" "$DEVICE_LLDB_SERVER" >/dev/null
    adb_su "chmod 755 $DEVICE_LLDB_SERVER"
}

write_vscode_generated_launch() {
    local launch_file="$1"
    local host_binary="$2"
    local symbols_root="$3"
    local lineage_root="$4"
    local workspace_root="$5"
    local port="$6"
    local exec_search_paths="$7"

    "$AOSP_PYTHON_DEFAULT" - <<PY
import json
from pathlib import Path

launch_file = Path(${launch_file@Q})
host_binary = ${host_binary@Q}
symbols_root = ${symbols_root@Q}
lineage_root = ${lineage_root@Q}
workspace_root = ${workspace_root@Q}
port = ${port@Q}
exec_search_paths = ${exec_search_paths@Q}.strip()

config = {
    "name": f"(sucre-snort) VS Code helper ({port})",
    "type": "lldb",
    "request": "launch",
    "relativePathBase": workspace_root,
    "sourceMap": {
        "/b/f/w/system/sucre-snort": workspace_root,
        "system/sucre-snort": workspace_root,
        "/b/f/w": lineage_root,
        ".": lineage_root,
    },
    "initCommands": [],
    "targetCreateCommands": [
        f"target create {host_binary}",
        f"target modules search-paths add / {symbols_root}/",
    ],
    "processCreateCommands": [
        f"gdb-remote {port}",
    ],
}
if exec_search_paths:
    config["initCommands"].append(
        f"settings append target.exec-search-paths {exec_search_paths}"
    )

data = {"version": "0.2.0", "configurations": [config]}
launch_file.parent.mkdir(parents=True, exist_ok=True)
launch_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
PY
}

start_vscode_debug_server() {
    local mode="$1"
    local pid="$2"
    local binary="$3"
    local port="$4"
    local cmd=""

    ensure_device_lldb_server
    adb_su "rm -f /data/local/tmp/lldb-server.log 2>/dev/null || true"
    if [[ "$mode" == "attach" ]]; then
        cmd="nohup $DEVICE_LLDB_SERVER gdbserver localhost:$port --attach $pid >/data/local/tmp/lldb-server.log 2>&1 &"
    else
        cmd="nohup $DEVICE_LLDB_SERVER gdbserver localhost:$port -- $binary >/data/local/tmp/lldb-server.log 2>&1 &"
    fi
    adb_su "$cmd"
    sleep 1
    adb_cmd forward "tcp:${port}" "tcp:${port}" >/dev/null
}

cleanup_vscode_debug_session() {
    local mode="$1"
    local pid="$2"
    local process_name="$3"
    local port="$4"

    adb_cmd forward --remove "tcp:${port}" >/dev/null 2>&1 || true
    adb_su "killall -9 arm64-lldb-server lldb-server gdbserver 2>/dev/null || true"
    if [[ "$mode" == "run" ]]; then
        adb_su "killall -9 $process_name 2>/dev/null || true"
        adb_su "rm -f /dev/socket/sucre-snort-control /dev/socket/sucre-snort-netd 2>/dev/null || true"
    elif [[ -n "$pid" ]]; then
        clear_process_debugger_residue "$pid"
        adb_su "kill -CONT $pid 2>/dev/null || true"
    fi
}

run_vscode_helper_action() {
    local action="$1"

    case "$action" in
        restart)
            cleanup_vscode_debug_session "$mode" "$cleanup_pid" "$process_name" "$port"
            if [[ "$mode" == "attach" ]]; then
                pid="$(resolve_pid "" "$process_name")"
                remote_binary="$(resolve_pid_binary "$pid")"
                debug_prepare_attach "$pid" "$port"
                start_vscode_debug_server "$mode" "$pid" "$remote_binary" "$port"
                cleanup_pid="$pid"
            else
                debug_prepare_run "$process_name" "$port"
                start_vscode_debug_server "$mode" "$pid" "$remote_binary" "$port"
                cleanup_pid="$(adb_su "pidof $process_name 2>/dev/null | awk '{print \$1}'" | tr -d '\r\n' || true)"
            fi
            write_vscode_generated_launch "$launch_file" "$host_binary" "$symbols_root" "$LINEAGE_ROOT" "$WORKSPACE_ROOT" "$port" "$exec_search_paths"
            ;;
        terminate)
            cleanup_vscode_debug_session "$mode" "$cleanup_pid" "$process_name" "$port"
            cleanup_pid=""
            ;;
        *)
            echo "unknown helper action: $action" >&2
            return 1
            ;;
    esac
}

run_vscode_helper_backend() {
    local mode="$1"
    local launch_file="$2"
    local host_binary="$3"
    local remote_binary="$4"
    local port="$5"
    local pid="$6"
    local process_name="$7"
    local device_product="$8"
    local symbols_root=""
    local exec_search_paths=""
    local cleanup_pid="$pid"
    local state_dir=""
    local command=""
    local action=""
    local token=""
    local action_status=0

    state_dir="$(dirname "$launch_file")"
    symbols_root="$(resolve_symbols_root "$device_product")"
    exec_search_paths="$(build_exec_search_paths "$symbols_root")"
    start_vscode_debug_server "$mode" "$pid" "$remote_binary" "$port"
    if [[ "$mode" == "run" ]]; then
        cleanup_pid="$(adb_su "pidof $process_name 2>/dev/null | awk '{print \$1}'" | tr -d '\r\n' || true)"
    fi
    write_vscode_generated_launch "$launch_file" "$host_binary" "$symbols_root" "$LINEAGE_ROOT" "$WORKSPACE_ROOT" "$port" "$exec_search_paths"
    echo "Generated config written to '$launch_file'"
    echo
    echo "Waiting for VS Code debug lifecycle commands..."
    trap 'cleanup_vscode_debug_session "$mode" "$cleanup_pid" "$process_name" "$port"; exit 0' INT TERM

    while IFS= read -r command; do
        if [[ -z "$command" ]]; then
            break
        fi

        action="$command"
        token=""
        if [[ "$command" == *" "* ]]; then
            action="${command%% *}"
            token="${command#* }"
        fi

        set +e
        run_vscode_helper_action "$action"
        action_status=$?
        set -e

        if [[ -n "$token" ]]; then
            if [[ $action_status -eq 0 ]]; then
                printf 'ok\n' > "$state_dir/hook-$token.status"
            else
                printf 'error: helper action %s failed\n' "$action" > "$state_dir/hook-$token.status"
            fi
        fi
    done

    cleanup_vscode_debug_session "$mode" "$cleanup_pid" "$process_name" "$port"
}

print_command() {
    printf '命令: '
    printf '%q ' "$@"
    printf '\n'
}

main() {
    if [[ $# -lt 1 ]]; then
        show_help
        exit 1
    fi

    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
    esac

    local mode="$1"
    shift

    local port="$DEFAULT_PORT"
    local lunch_target="$DEFAULT_LUNCH_TARGET"
    local pid=""
    local process_name="$DEFAULT_PROCESS"
    local binary="$DEFAULT_BINARY"
    local host_binary="$DEFAULT_HOST_BINARY"
    local remote_binary=""
    local launch_file="$DEFAULT_LAUNCH_FILE"
    local wait_debugger_action=""
    local print_only=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --serial)
                ADB_SERIAL="$2"
                export ADB_SERIAL
                shift 2
                ;;
            --port)
                port="$2"
                shift 2
                ;;
            --lunch-target)
                lunch_target="$2"
                shift 2
                ;;
            --pid)
                pid="$2"
                shift 2
                ;;
            --process)
                process_name="$2"
                shift 2
                ;;
            --binary)
                binary="$2"
                shift 2
                ;;
            --host-binary)
                host_binary="$2"
                shift 2
                ;;
            --launch-file)
                launch_file="$2"
                shift 2
                ;;
            --print-only)
                print_only=1
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                if [[ "$mode" == "wait-debugger" && -z "$wait_debugger_action" ]]; then
                    wait_debugger_action="$1"
                    shift
                else
                    echo "未知选项: $1" >&2
                    show_help
                    exit 1
                fi
                ;;
        esac
    done

    device_preflight

    if [[ "$mode" == "wait-debugger" ]]; then
        local state="$wait_debugger_action"
        case "$state" in
            on)
                adb_cmd shell setprop debug.debuggerd.wait_for_debugger true
                echo "已开启 debug.debuggerd.wait_for_debugger"
                ;;
            off)
                adb_cmd shell setprop debug.debuggerd.wait_for_debugger false
                echo "已关闭 debug.debuggerd.wait_for_debugger"
                ;;
            status|"")
                adb_cmd shell getprop debug.debuggerd.wait_for_debugger
                ;;
            *)
                echo "wait-debugger 仅支持 on/off/status" >&2
                exit 1
                ;;
        esac
        exit 0
    fi

    require_lldbclient
    ensure_lineage_env
    prepare_host_env

    local python_bin
    local device_product
    local lldb_args=()
    local cmd
    python_bin="$(resolve_python_bin)"
    device_product="$(resolve_device_product)"
    case "$mode" in
        attach)
            pid="$(resolve_pid "$pid" "$process_name")"
            remote_binary="$(resolve_pid_binary "$pid")"
            lldb_args=(--port "$port" -p "$pid")
            ;;
        run)
            remote_binary="$binary"
            lldb_args=(--port "$port" -r "$binary")
            ;;
        vscode-attach)
            pid="$(resolve_pid "$pid" "$process_name")"
            remote_binary="$(resolve_pid_binary "$pid")"
            ensure_vscode_launch_file "$launch_file"
            lldb_args=(--setup-forwarding vscode-lldb --vscode-launch-file "$launch_file" --port "$port" -p "$pid")
            ;;
        vscode-run)
            remote_binary="$binary"
            ensure_vscode_launch_file "$launch_file"
            lldb_args=(--setup-forwarding vscode-lldb --vscode-launch-file "$launch_file" --port "$port" -r "$binary")
            ;;
        vscode-helper-attach)
            pid="$(resolve_pid "$pid" "$process_name")"
            remote_binary="$(resolve_pid_binary "$pid")"
            ;;
        vscode-helper-run)
            remote_binary="$binary"
            ;;
        wait-debugger)
            if [[ -z "${process_name:-}" ]]; then
                :
            fi
            ;;
        *)
            echo "未知子命令: $mode" >&2
            show_help
            exit 1
            ;;
    esac

    if [[ "$remote_binary" == /data/local/tmp/* ]]; then
        host_binary="$(resolve_host_debug_binary "$host_binary")"
    fi

    echo "目标真机: $(adb_target_desc)"
    echo "device product: $device_product"
    echo "LINEAGE_ROOT: $LINEAGE_ROOT"
    echo "lunch target: $lunch_target"
    if [[ -n "$remote_binary" ]]; then
        echo "remote binary: $remote_binary"
    fi
    if [[ "$remote_binary" == /data/local/tmp/* ]]; then
        echo "host binary: $host_binary"
    fi
    echo "python: $python_bin"

    case "$mode" in
        vscode-helper-attach|vscode-helper-run)
            echo "launch file: $launch_file"
            if [[ $print_only -eq 1 ]]; then
                exit 0
            fi
            case "$mode" in
                vscode-helper-attach)
                    debug_prepare_attach "$pid" "$port"
                    run_vscode_helper_backend "attach" "$launch_file" "$host_binary" "$remote_binary" "$port" "$pid" "$process_name" "$device_product"
                    ;;
                vscode-helper-run)
                    debug_prepare_run "$(basename "$binary")" "$port"
                    run_vscode_helper_backend "run" "$launch_file" "$host_binary" "$remote_binary" "$port" "" "$(basename "$binary")" "$device_product"
                    ;;
            esac
            exit 0
            ;;
    esac

    cmd="$(build_lldbclient_cmd "$python_bin" "$lunch_target" "$device_product" "$remote_binary" "$host_binary" "${lldb_args[@]}")"
    echo "命令: bash -lc $cmd"
    if [[ $print_only -eq 1 ]]; then
        exit 0
    fi

    case "$mode" in
        attach|vscode-attach)
            debug_prepare_attach "$pid" "$port"
            ;;
        run|vscode-run)
            debug_prepare_run "$(basename "$binary")" "$port"
            ;;
    esac

    exec bash -lc "$cmd"
}

main "$@"
