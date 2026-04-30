#!/bin/bash

SNORT_DEFAULT_ANDROID_SDK_ROOT="${SNORT_DEFAULT_ANDROID_SDK_ROOT:-/home/js/.local/share/android-sdk}"

pick_adb_bin() {
    local -a candidates=()
    local -A seen=()

    append_candidate() {
        local c="$1"
        if [[ -z "$c" || ! -x "$c" ]]; then
            return 0
        fi
        if [[ -n "${seen["$c"]:-}" ]]; then
            return 0
        fi
        seen["$c"]=1
        candidates+=("$c")
        return 0
    }

    append_sdk_adb_candidates() {
        local sdk_root="$1"
        if [[ -z "$sdk_root" ]]; then
            return 0
        fi
        append_candidate "$sdk_root/platform-tools/adb"
        append_candidate "$sdk_root/platform-tools/adb.exe"
        return 0
    }

    if [[ -n "${ADB:-}" ]]; then
        append_candidate "$ADB"
    fi

    append_sdk_adb_candidates "${ANDROID_SDK_ROOT:-}"
    append_sdk_adb_candidates "${ANDROID_HOME:-}"
    append_sdk_adb_candidates "$SNORT_DEFAULT_ANDROID_SDK_ROOT"
    append_sdk_adb_candidates "$HOME/Android/Sdk"

    local IFS=':'
    local dir
    for dir in $PATH; do
        if [[ -n "$dir" ]]; then
            append_candidate "$dir/adb"
            append_candidate "$dir/adb.exe"
        fi
    done

    local c
    for c in "${candidates[@]}"; do
        if "$c" devices 2>&1 | tr -d '\r' | grep -q '^List of devices attached$'; then
            printf '%s\n' "$c"
            return 0
        fi
    done
    return 1
}

ADB_BIN="$(pick_adb_bin)" || {
    echo "❌ 未找到可用的 adb/adb.exe" >&2
    return 1 2>/dev/null || exit 1
}

ADB="${ADB_BIN}"
ADB_SERIAL="${ADB_SERIAL:-${ANDROID_SERIAL:-}}"
ADB_SERIAL_RESOLVED="${ADB_SERIAL_RESOLVED:-}"

resolve_adb_serial() {
    local explicit_serial="${ADB_SERIAL:-${ANDROID_SERIAL:-}}"
    if [[ -n "$explicit_serial" ]]; then
        printf '%s\n' "$explicit_serial"
        return 0
    fi

    mapfile -t devices < <("$ADB_BIN" devices | tr -d '\r' | awk 'NR > 1 && $2 == "device" { print $1 }' | grep -Ev '^adb-.*\._adb-tls-connect\._tcp$')
    if [[ ${#devices[@]} -eq 0 ]]; then
        echo "❌ 未检测到已连接的 Android 真机" >&2
        return 1
    fi
    if [[ ${#devices[@]} -gt 1 ]]; then
        echo "❌ 检测到多台 Android 真机，请设置 ADB_SERIAL 或 ANDROID_SERIAL" >&2
        printf '   - %s\n' "${devices[@]}" >&2
        return 1
    fi

    printf '%s\n' "${devices[0]}"
}

ensure_adb_target() {
    if [[ -n "$ADB_SERIAL_RESOLVED" ]]; then
        return 0
    fi

    ADB_SERIAL_RESOLVED="$(resolve_adb_serial)" || return 1
    export ADB_SERIAL_RESOLVED
    return 0
}

adb_cmd() {
    ensure_adb_target || return 1
    "$ADB_BIN" -s "$ADB_SERIAL_RESOLVED" "$@"
}

shell_single_quote() {
    local value="$1"
    value=${value//\'/\'"\'"\'}
    printf "'%s'" "$value"
}

adb_su() {
    local command="$1"
    local quoted_command
    quoted_command="$(shell_single_quote "$command")"
    adb_cmd shell "su 0 sh -c $quoted_command"
}

adb_target_desc() {
    ensure_adb_target || return 1
    printf '%s\n' "$ADB_SERIAL_RESOLVED"
}

require_adb_device() {
    ensure_adb_target || return 1

    local state
    state="$(adb_cmd get-state 2>/dev/null | tr -d '\r\n')"
    if [[ "$state" != "device" ]]; then
        echo "❌ ADB 目标不可用: ${ADB_SERIAL_RESOLVED:-unknown}" >&2
        return 1
    fi
    return 0
}

require_device_root() {
    local identity
    identity="$(adb_su 'id' 2>/dev/null | tr -d '\r')" || {
        echo "❌ 无法通过 su 获取 root 权限" >&2
        return 1
    }

    if [[ "$identity" != *"uid=0(root)"* ]]; then
        echo "❌ 目标设备未返回 root 身份: $identity" >&2
        return 1
    fi
    return 0
}

device_preflight() {
    require_adb_device || return 1
    require_device_root || return 1
    return 0
}

selinux_get_mode() {
    # Best-effort: prefer init mount namespace (matches dev-netd-resolv workflow),
    # but fall back to plain getenforce if nsenter is unavailable.
    local had_errexit=0
    case $- in *e*) had_errexit=1 ;; esac
    set +e

    local mode=""
    mode="$(adb_su "nsenter -t 1 -m -- getenforce 2>/dev/null || getenforce 2>/dev/null || true" 2>/dev/null | tr -d '\r\n')"
    local rc=$?

    if [[ $had_errexit -eq 1 ]]; then
        set -e
    fi

    if [[ $rc -ne 0 || -z "$mode" ]]; then
        return 1
    fi
    if [[ "$mode" != "Enforcing" && "$mode" != "Permissive" ]]; then
        return 1
    fi
    printf '%s\n' "$mode"
    return 0
}

selinux_ensure_permissive() {
    # Many device tests rely on netd/resolver hooks and privileged sockets which
    # are routinely blocked under SELinux Enforcing on dev devices.
    local mode
    mode="$(selinux_get_mode 2>/dev/null || true)"
    if [[ "$mode" == "Permissive" ]]; then
        return 0
    fi

    local had_errexit=0
    case $- in *e*) had_errexit=1 ;; esac
    set +e
    adb_su "nsenter -t 1 -m -- setenforce 0 2>/dev/null || setenforce 0 2>/dev/null" >/dev/null 2>&1
    if [[ $had_errexit -eq 1 ]]; then
        set -e
    fi

    mode="$(selinux_get_mode 2>/dev/null || true)"
    [[ "$mode" == "Permissive" ]]
}

check_control_forward() {
    local port="${1:-60606}"
    ensure_adb_target || return 1
    adb_cmd forward --list 2>/dev/null | tr -d '\r' | grep -q "${ADB_SERIAL_RESOLVED} .*tcp:${port} .*localabstract:sucre-snort-control"
}

setup_control_forward() {
    local port="${1:-60606}"
    adb_cmd forward "tcp:${port}" localabstract:sucre-snort-control >/dev/null
}

remove_control_forward() {
    local port="${1:-60606}"
    adb_cmd forward --remove "tcp:${port}" >/dev/null 2>&1 || true
}

check_control_vnext_forward() {
    local port="${1:-60607}"
    ensure_adb_target || return 1
    adb_cmd forward --list 2>/dev/null | tr -d '\r' | grep -q "${ADB_SERIAL_RESOLVED} .*tcp:${port} .*localabstract:sucre-snort-control-vnext"
}

setup_control_vnext_forward() {
    local port="${1:-60607}"
    adb_cmd forward "tcp:${port}" localabstract:sucre-snort-control-vnext >/dev/null
}

remove_control_vnext_forward() {
    local port="${1:-60607}"
    adb_cmd forward --remove "tcp:${port}" >/dev/null 2>&1 || true
}

adb_uses_windows_host() {
    if [[ "$ADB_BIN" == *.exe ]]; then
        return 0
    fi

    if [[ -f "$ADB_BIN" ]] && head -n 5 "$ADB_BIN" 2>/dev/null | grep -q 'adb.exe'; then
        return 0
    fi

    return 1
}

adb_local_path() {
    local path="$1"
    if adb_uses_windows_host && command -v wslpath >/dev/null 2>&1; then
        wslpath -w "$path"
    else
        printf '%s\n' "$path"
    fi
}

adb_push_file() {
    local local_path="$1"
    local remote_path="$2"
    adb_cmd push "$(adb_local_path "$local_path")" "$remote_path"
}
