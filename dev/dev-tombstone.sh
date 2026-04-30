#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/dev-android-device-lib.sh"
source "$SCRIPT_DIR/dev-ndk-env.sh"

OUTPUT_DIR="${TOMBSTONE_OUTPUT_DIR:-$SNORT_ROOT/build-output/tombstones}"
SYMBOL_DIR="${TOMBSTONE_SYMBOL_DIR:-$SNORT_ROOT/build-output}"

show_help() {
    cat <<EOF
用法: $0 <latest|pull|symbolize> [选项]

子命令:
  latest                 打印设备上最新 tombstone 路径
  pull                   拉取最新 tombstone 到本地
  symbolize              对本地 tombstone 做 NDK r29 ndk-stack 符号化

选项:
  --serial <serial>      指定目标真机 serial
  --path <path>          指定 tombstone 路径（pull/symbolize）
  --sym-dir <path>       指定 ndk-stack 符号目录（默认 build-output）
EOF
}

latest_tombstone() {
    adb_su "ls -t /data/tombstones/tombstone_* 2>/dev/null | head -1" | tr -d '\r\n'
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
    local tombstone_path=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --serial)
                ADB_SERIAL="$2"
                export ADB_SERIAL
                shift 2
                ;;
            --path)
                tombstone_path="$2"
                shift 2
                ;;
            --sym-dir)
                SYMBOL_DIR="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo "未知选项: $1" >&2
                exit 1
                ;;
        esac
    done

    device_preflight

    case "$mode" in
        latest)
            latest_tombstone
            ;;
        pull)
            if [[ -z "$tombstone_path" ]]; then
                tombstone_path="$(latest_tombstone)"
            fi
            if [[ -z "$tombstone_path" ]]; then
                echo "❌ 设备上未找到 tombstone" >&2
                exit 1
            fi
            mkdir -p "$OUTPUT_DIR"
            local base
            base="$(basename "$tombstone_path")"
            adb_cmd pull "$tombstone_path" "$OUTPUT_DIR/$base" >/dev/null
            echo "$OUTPUT_DIR/$base"
            ;;
        symbolize)
            ndk_root="$(snort_ndk_require)"
            ndk_stack="$ndk_root/ndk-stack"
            if [[ ! -x "$ndk_stack" ]]; then
                echo "❌ 未找到 ndk-stack: $ndk_stack" >&2
                exit 1
            fi
            if [[ ! -d "$SYMBOL_DIR" ]]; then
                echo "❌ 未找到符号目录: $SYMBOL_DIR" >&2
                exit 1
            fi
            if [[ -z "$tombstone_path" ]]; then
                tombstone_path="$(latest_tombstone)"
                if [[ -n "$tombstone_path" ]]; then
                    mkdir -p "$OUTPUT_DIR"
                    local base
                    base="$(basename "$tombstone_path")"
                    adb_cmd pull "$tombstone_path" "$OUTPUT_DIR/$base" >/dev/null
                    tombstone_path="$OUTPUT_DIR/$base"
                fi
            fi
            if [[ -z "$tombstone_path" || ! -f "$tombstone_path" ]]; then
                echo "❌ 未找到本地 tombstone 文件" >&2
                exit 1
            fi
            "$ndk_stack" -sym "$SYMBOL_DIR" -dump "$tombstone_path"
            ;;
        *)
            echo "未知子命令: $mode" >&2
            show_help
            exit 1
            ;;
    esac
}

main "$@"
