#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOLKIT_ROOT_DEFAULT="$(cd "$SNORT_ROOT/.." && pwd)/sucre-android16-toolkit"
TOOLKIT_ROOT="${SUCRE_TOOLKIT:-$TOOLKIT_ROOT_DEFAULT}"
HOST_LIB_DEFAULT="$TOOLKIT_ROOT/output/sucre-debug-base/overlay.d/sbin/libnetd_resolv.so"
HOST_LIB="$HOST_LIB_DEFAULT"
REMOTE_LIB="/data/local/tmp/libnetd_resolv.so"
MODE="status"

source "$SCRIPT_DIR/dev-android-device-lib.sh"

show_help() {
    cat <<EOF
用法: $0 <status|mount|unmount|prepare|permissive> [选项]

子命令:
  status                  查看当前 libnetd_resolv.so 挂载状态与 SELinux 模式
  mount                   推送并临时挂载 libnetd_resolv.so 到 resolver APEX
  unmount                 解除当前临时挂载
  prepare                 等价于: mount + permissive on
  permissive <on|off|status>
                          切换/查看 SELinux 模式（通过 nsenter 进入 init mount namespace）

选项:
  --serial <serial>       指定目标真机 serial
  --lib <path>            指定本地 libnetd_resolv.so 路径
  --remote <path>         指定设备临时文件路径（默认: /data/local/tmp/libnetd_resolv.so）
  -h, --help              显示帮助

说明:
  - 这是开发态快速验证工具，目标是避免每次都重新刷完整模块。
  - 当前实现已在 APatch 真机上验证可用。
EOF
}

resolve_device_busybox() {
    local candidate
    for candidate in /data/adb/ap/bin/busybox /data/adb/ksu/bin/busybox /system/xbin/busybox busybox; do
        if adb_su "${candidate} --help >/dev/null 2>&1" >/dev/null 2>&1; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    echo "❌ 设备上未找到可用 busybox" >&2
    exit 1
}

read_apex_dirs() {
    mapfile -t APEX_DIRS < <(adb_su 'ls -d /apex/com.android.resolv* 2>/dev/null || true' | tr -d '\r')
    if [[ ${#APEX_DIRS[@]} -eq 0 ]]; then
        echo "❌ 未找到 /apex/com.android.resolv*" >&2
        exit 1
    fi
}

print_status() {
    echo "目标真机: $(adb_target_desc)"
    echo "SELinux: $(adb_su "nsenter -t 1 -m -- getenforce" | tr -d '\r\n')"
    echo "临时库: $REMOTE_LIB"
    echo "resolver APEX:"
    read_apex_dirs
    printf '  - %s\n' "${APEX_DIRS[@]}"
    echo ""
    echo "挂载状态:"
    local mount_output
    mount_output=$(adb_su "nsenter -t 1 -m -- mount | grep libnetd_resolv.so || true" | tr -d '\r')
    if [[ -n "$mount_output" ]]; then
        printf '%s\n' "$mount_output" | sed 's/^/  /'
    else
        echo "  (未挂载)"
    fi

    if adb_su "test -f $REMOTE_LIB" >/dev/null 2>&1; then
        echo ""
        echo "MD5 校验:"
        adb_su "md5sum $REMOTE_LIB /apex/com.android.resolv/lib64/libnetd_resolv.so /apex/com.android.resolv@360735080/lib64/libnetd_resolv.so 2>/dev/null || true" | tr -d '\r' | sed 's/^/  /'
    fi
}

set_permissive() {
    local state="$1"
    case "$state" in
        on)
            adb_su "nsenter -t 1 -m -- setenforce 0" >/dev/null
            adb_su "nsenter -t 1 -m -- getenforce" | tr -d '\r\n'
            ;;
        off)
            adb_su "nsenter -t 1 -m -- setenforce 1" >/dev/null
            adb_su "nsenter -t 1 -m -- getenforce" | tr -d '\r\n'
            ;;
        status)
            adb_su "nsenter -t 1 -m -- getenforce" | tr -d '\r\n'
            ;;
        *)
            echo "❌ permissive 仅支持 on/off/status" >&2
            exit 1
            ;;
    esac
}

mount_lib() {
    if [[ ! -f "$HOST_LIB" ]]; then
        echo "❌ 未找到本地库: $HOST_LIB" >&2
        echo "   可通过 --lib 指定，或先在 sucre-android16-toolkit 中生成 debug-base 产物。" >&2
        exit 1
    fi

    read_apex_dirs
    local busybox
    busybox="$(resolve_device_busybox)"

    echo "推送本地库: $HOST_LIB"
    adb_push_file "$HOST_LIB" "$REMOTE_LIB" >/dev/null
    adb_su "chmod 644 $REMOTE_LIB"

    local dir target
    for dir in "${APEX_DIRS[@]}"; do
        target="$dir/lib64/libnetd_resolv.so"
        adb_su "nsenter -t 1 -m -- $busybox umount $target >/dev/null 2>&1 || true"
        adb_su "nsenter -t 1 -m -- $busybox mount -o bind $REMOTE_LIB $target"
        echo "✓ 已挂载: $target"
    done
}

unmount_lib() {
    read_apex_dirs
    local busybox
    busybox="$(resolve_device_busybox)"

    local dir target
    for dir in "${APEX_DIRS[@]}"; do
        target="$dir/lib64/libnetd_resolv.so"
        adb_su "nsenter -t 1 -m -- $busybox umount $target >/dev/null 2>&1 || true"
        echo "✓ 已卸载: $target"
    done
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        status|mount|unmount|prepare|permissive)
            MODE="$1"
            shift
            ;;
        --serial)
            ADB_SERIAL="$2"
            export ADB_SERIAL
            shift 2
            ;;
        --lib)
            HOST_LIB="$2"
            shift 2
            ;;
        --remote)
            REMOTE_LIB="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            if [[ "$MODE" == "permissive" && -z "${PERMISSIVE_ACTION:-}" ]]; then
                PERMISSIVE_ACTION="$1"
                shift
            else
                echo "未知参数: $1" >&2
                show_help
                exit 1
            fi
            ;;
    esac
done

device_preflight

case "$MODE" in
    status)
        print_status
        ;;
    mount)
        mount_lib
        print_status
        ;;
    unmount)
        unmount_lib
        print_status
        ;;
    prepare)
        mount_lib
        echo "SELinux -> $(set_permissive on)"
        print_status
        ;;
    permissive)
        echo "SELinux -> $(set_permissive "${PERMISSIVE_ACTION:-status}")"
        ;;
    *)
        show_help
        exit 1
        ;;
esac
