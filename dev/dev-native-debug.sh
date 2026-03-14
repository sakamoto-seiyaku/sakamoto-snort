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
  --host-binary <path>     host 上对应的未剥离二进制（默认: $DEFAULT_HOST_BINARY）

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

    printf -v pycmd '%q ' "$python_bin" "$LLDBCLIENT_WRAPPER" "$LLDBCLIENT" "$@"
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

    cmd="$(build_lldbclient_cmd "$python_bin" "$lunch_target" "$device_product" "$remote_binary" "$host_binary" "${lldb_args[@]}")"

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
    echo "命令: bash -lc $cmd"
    if [[ $print_only -eq 1 ]]; then
        exit 0
    fi

    exec bash -lc "$cmd"
}

main "$@"
