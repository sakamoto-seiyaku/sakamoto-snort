#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

source "$SCRIPT_DIR/dev-android-device-lib.sh"
source "$SCRIPT_DIR/dev-ndk-env.sh"

DEFAULT_BINARY="/data/local/tmp/sucre-snort-dev"
DEFAULT_HOST_BINARY="$SNORT_ROOT/build-output/sucre-snort-ndk"
DEFAULT_PROCESS="sucre-snort-dev"
DEFAULT_PORT="5039"
DEFAULT_LAUNCH_FILE="$PWD/.vscode/launch.json"
DEVICE_LLDB_SERVER="/data/local/tmp/arm64-lldb-server"
WORKSPACE_ROOT="${SNORT_VSCODE_WORKSPACE_ROOT:-$SNORT_ROOT}"

show_help() {
    cat <<EOF
用法: $0 <attach|run|vscode-helper-attach|vscode-helper-run|wait-debugger> [选项]

子命令:
  attach                 用 NDK lldb 附加到已运行的真机进程
  run                    用 NDK lldb 在真机上启动二进制
  vscode-helper-attach   为 VS Code + CodeLLDB 准备 attach 会话
  vscode-helper-run      为 VS Code + CodeLLDB 准备 run 会话
  wait-debugger          设置/查询 debug.debuggerd.wait_for_debugger

通用选项:
  --serial <serial>      指定目标真机 serial
  --port <port>          指定 lldb 端口（默认: $DEFAULT_PORT）
  --print-only           只打印解析后的配置，不执行

attach 选项:
  --pid <pid>            指定 PID
  --process <name>       按进程名查 PID（默认: $DEFAULT_PROCESS）

run 选项:
  --binary <path>        真机上的二进制路径（默认: $DEFAULT_BINARY）
  --host-binary <path>   host 上用于符号解析的 NDK 二进制（默认: $DEFAULT_HOST_BINARY）

VS Code 选项:
  --launch-file <path>   生成的 launch.json 路径（默认: $DEFAULT_LAUNCH_FILE）

wait-debugger 用法:
  $0 wait-debugger on
  $0 wait-debugger off
  $0 wait-debugger status
EOF
}

resolve_ndk_lldb() {
    local ndk_root="$1"
    local lldb_bin="$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin/lldb"

    if [[ ! -x "$lldb_bin" ]]; then
        echo "❌ 未找到 NDK host lldb: $lldb_bin" >&2
        exit 1
    fi
    printf '%s\n' "$lldb_bin"
}

resolve_ndk_lldb_server() {
    local ndk_root="$1"
    local server=""

    server="$(find "$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/lib/clang" \
        -path '*/lib/linux/aarch64/lldb-server' -type f 2>/dev/null | sort -V | tail -n 1)"
    if [[ -z "$server" || ! -f "$server" ]]; then
        echo "❌ 未找到 NDK arm64 lldb-server under: $ndk_root" >&2
        exit 1
    fi
    printf '%s\n' "$server"
}

resolve_pid() {
    local pid="$1"
    local process_name="$2"
    local resolved=""

    if [[ -n "$pid" ]]; then
        printf '%s\n' "$pid"
        return 0
    fi

    resolved="$(adb_su "pidof $process_name 2>/dev/null | awk '{print \$1}'" | tr -d '\r\n' || true)"
    if [[ -z "$resolved" ]]; then
        echo "❌ 未找到进程: $process_name" >&2
        return 1
    fi
    printf '%s\n' "$resolved"
}

resolve_pid_binary() {
    local pid="$1"
    local binary_path=""

    binary_path="$(adb_su "readlink -e -n /proc/$pid/exe" 2>/dev/null | tr -d '\r\n' || true)"
    if [[ -z "$binary_path" ]]; then
        echo "❌ 无法解析 PID 对应的二进制路径: $pid" >&2
        return 1
    fi
    printf '%s\n' "$binary_path"
}

resolve_tracer_pid() {
    local pid="$1"
    adb_su "awk '/^TracerPid:/ {print \$2}' /proc/$pid/status 2>/dev/null || true" | tr -d '\r\n'
}

clear_process_debugger_residue() {
    local pid="$1"
    local tracer_pid=""

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
    local pid=""

    clear_lldb_server_residue "$port"
    pid="$(adb_su "pidof $process_name 2>/dev/null | awk '{print \$1}'" | tr -d '\r\n' || true)"
    if [[ -n "$pid" ]]; then
        clear_process_debugger_residue "$pid"
        adb_su "killall $process_name 2>/dev/null || true"
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            if ! adb_su "pidof $process_name >/dev/null 2>&1" >/dev/null 2>&1; then
                break
            fi
            sleep 1
        done
        if adb_su "pidof $process_name >/dev/null 2>&1" >/dev/null 2>&1; then
            adb_su "killall -9 $process_name 2>/dev/null || true"
            sleep 1
        fi
    fi

    adb_su "rm -f /dev/socket/sucre-snort-control /dev/socket/sucre-snort-netd 2>/dev/null || true"
}

ensure_device_lldb_server() {
    local local_server="$1"

    if adb_su "test -x $DEVICE_LLDB_SERVER" >/dev/null 2>&1; then
        return 0
    fi

    echo "推送设备侧 lldb-server: $local_server"
    adb_push_file "$local_server" "$DEVICE_LLDB_SERVER" >/dev/null
    adb_su "chmod 755 $DEVICE_LLDB_SERVER"
}

start_debug_server() {
    local mode="$1"
    local pid="$2"
    local binary="$3"
    local port="$4"
    local local_server="$5"
    local cmd=""

    ensure_device_lldb_server "$local_server"
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

cleanup_debug_session() {
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

write_vscode_generated_launch() {
    local launch_file="$1"
    local host_binary="$2"
    local workspace_root="$3"
    local port="$4"

    python3 - "$launch_file" "$host_binary" "$workspace_root" "$port" <<'PY'
import json
import sys
from pathlib import Path

launch_file = Path(sys.argv[1])
host_binary = sys.argv[2]
workspace_root = sys.argv[3]
port = sys.argv[4]

config = {
    "name": f"(sucre-snort) NDK helper ({port})",
    "type": "lldb",
    "request": "launch",
    "relativePathBase": workspace_root,
    "sourceMap": {
        workspace_root: workspace_root,
    },
    "initCommands": [],
    "targetCreateCommands": [
        f"target create {host_binary}",
    ],
    "processCreateCommands": [
        f"gdb-remote {port}",
    ],
}

launch_file.parent.mkdir(parents=True, exist_ok=True)
launch_file.write_text(
    json.dumps({"version": "0.2.0", "configurations": [config]}, indent=2) + "\n",
    encoding="utf-8",
)
PY
}

run_helper_action() {
    local action="$1"

    case "$action" in
        restart)
            cleanup_debug_session "$mode" "$cleanup_pid" "$process_name" "$port"
            if [[ "$mode" == "attach" ]]; then
                pid="$(resolve_pid "" "$process_name")"
                remote_binary="$(resolve_pid_binary "$pid")"
                debug_prepare_attach "$pid" "$port"
                start_debug_server "$mode" "$pid" "$remote_binary" "$port" "$local_server"
                cleanup_pid="$pid"
            else
                debug_prepare_run "$process_name" "$port"
                start_debug_server "$mode" "" "$remote_binary" "$port" "$local_server"
                cleanup_pid="$(adb_su "pidof $process_name 2>/dev/null | awk '{print \$1}'" | tr -d '\r\n' || true)"
            fi
            write_vscode_generated_launch "$launch_file" "$host_binary" "$WORKSPACE_ROOT" "$port"
            ;;
        terminate)
            cleanup_debug_session "$mode" "$cleanup_pid" "$process_name" "$port"
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
    local local_server="$8"
    local cleanup_pid="$pid"
    local state_dir=""
    local command=""
    local action=""
    local token=""
    local action_status=0

    state_dir="$(dirname "$launch_file")"
    start_debug_server "$mode" "$pid" "$remote_binary" "$port" "$local_server"
    if [[ "$mode" == "run" ]]; then
        cleanup_pid="$(adb_su "pidof $process_name 2>/dev/null | awk '{print \$1}'" | tr -d '\r\n' || true)"
    fi
    write_vscode_generated_launch "$launch_file" "$host_binary" "$WORKSPACE_ROOT" "$port"
    echo "Generated config written to '$launch_file'"
    echo
    echo "Waiting for VS Code debug lifecycle commands..."
    trap 'cleanup_debug_session "$mode" "$cleanup_pid" "$process_name" "$port"; exit 0' INT TERM

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
        run_helper_action "$action"
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

    cleanup_debug_session "$mode" "$cleanup_pid" "$process_name" "$port"
}

run_host_lldb() {
    local lldb_bin="$1"
    local mode="$2"
    local host_binary="$3"
    local port="$4"
    local pid="$5"
    local process_name="$6"
    local command_file=""
    local status=0

    command_file="$(mktemp "${TMPDIR:-/tmp}/sucre-snort-lldb.XXXXXX")"
    {
        printf 'target create %s\n' "$host_binary"
        printf 'process handle SIGCHLD -n false -p true -s false\n'
        printf 'gdb-remote %s\n' "$port"
    } > "$command_file"

    trap 'cleanup_debug_session "$mode" "$pid" "$process_name" "$port"; rm -f "$command_file"' EXIT
    "$lldb_bin" -s "$command_file" || status=$?
    return "$status"
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
        case "$wait_debugger_action" in
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

    local ndk_root=""
    local lldb_bin=""
    local local_server=""
    ndk_root="$(snort_ndk_require)"
    lldb_bin="$(resolve_ndk_lldb "$ndk_root")"
    local_server="$(resolve_ndk_lldb_server "$ndk_root")"

    case "$mode" in
        attach|vscode-helper-attach)
            pid="$(resolve_pid "$pid" "$process_name")"
            remote_binary="$(resolve_pid_binary "$pid")"
            ;;
        run|vscode-helper-run)
            remote_binary="$binary"
            process_name="$(basename "$binary")"
            ;;
        *)
            echo "未知子命令: $mode" >&2
            show_help
            exit 1
            ;;
    esac

    if [[ "$remote_binary" == /data/local/tmp/* && ! -f "$host_binary" ]]; then
        echo "❌ 未找到 host 调试二进制: $host_binary" >&2
        echo "运行: bash dev/dev-build-ndk.sh" >&2
        exit 1
    fi

    echo "目标真机: $(adb_target_desc)"
    echo "NDK root: $ndk_root"
    echo "lldb: $lldb_bin"
    echo "lldb-server: $local_server"
    echo "remote binary: $remote_binary"
    echo "host binary: $host_binary"
    echo "port: $port"

    if [[ $print_only -eq 1 ]]; then
        exit 0
    fi

    case "$mode" in
        attach)
            debug_prepare_attach "$pid" "$port"
            start_debug_server "attach" "$pid" "$remote_binary" "$port" "$local_server"
            run_host_lldb "$lldb_bin" "attach" "$host_binary" "$port" "$pid" "$process_name"
            ;;
        run)
            debug_prepare_run "$process_name" "$port"
            start_debug_server "run" "" "$remote_binary" "$port" "$local_server"
            run_host_lldb "$lldb_bin" "run" "$host_binary" "$port" "" "$process_name"
            ;;
        vscode-helper-attach)
            echo "launch file: $launch_file"
            debug_prepare_attach "$pid" "$port"
            run_vscode_helper_backend "attach" "$launch_file" "$host_binary" "$remote_binary" "$port" "$pid" "$process_name" "$local_server"
            ;;
        vscode-helper-run)
            echo "launch file: $launch_file"
            debug_prepare_run "$process_name" "$port"
            run_vscode_helper_backend "run" "$launch_file" "$host_binary" "$remote_binary" "$port" "" "$process_name" "$local_server"
            ;;
    esac
}

main "$@"
