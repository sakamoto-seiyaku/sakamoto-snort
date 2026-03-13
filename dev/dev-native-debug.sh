#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/dev-android-device-lib.sh"

LINEAGE_ROOT="${LINEAGE_ROOT:-$HOME/android/lineage}"
LLDBCLIENT="$LINEAGE_ROOT/development/scripts/lldbclient.py"
DEFAULT_BINARY="/data/local/tmp/sucre-snort-dev"
DEFAULT_PROCESS="sucre-snort-dev"
DEFAULT_PORT="5039"
DEFAULT_LAUNCH_FILE="$PWD/.vscode/launch.json"

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
  --print-only             只打印最终命令，不执行

attach/vscode-attach 选项:
  --pid <pid>              指定 PID
  --process <name>         按进程名查 PID（默认: $DEFAULT_PROCESS）

run/vscode-run 选项:
  --binary <path>          真机上的二进制路径（默认: $DEFAULT_BINARY）

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
}

prepare_host_env() {
    export PATH="$(dirname "$ADB_BIN"):$PATH"
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
    local pid=""
    local process_name="$DEFAULT_PROCESS"
    local binary="$DEFAULT_BINARY"
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
    require_lldbclient
    prepare_host_env

    local cmd=()
    case "$mode" in
        attach)
            pid="$(resolve_pid "$pid" "$process_name")"
            cmd=(python3 "$LLDBCLIENT" --port "$port" -p "$pid")
            ;;
        run)
            cmd=(python3 "$LLDBCLIENT" --port "$port" -r "$binary")
            ;;
        vscode-attach)
            pid="$(resolve_pid "$pid" "$process_name")"
            cmd=(python3 "$LLDBCLIENT" --setup-forwarding vscode-lldb --vscode-launch-file "$launch_file" --port "$port" -p "$pid")
            ;;
        vscode-run)
            cmd=(python3 "$LLDBCLIENT" --setup-forwarding vscode-lldb --vscode-launch-file "$launch_file" --port "$port" -r "$binary")
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

    echo "目标真机: $(adb_target_desc)"
    print_command "${cmd[@]}"
    if [[ $print_only -eq 1 ]]; then
        exit 0
    fi

    exec "${cmd[@]}"
}

main "$@"
