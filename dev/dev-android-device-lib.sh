#!/bin/bash

if [[ -n "${ADB:-}" ]]; then
    ADB_BIN="$ADB"
elif command -v adb >/dev/null 2>&1; then
    ADB_BIN="$(command -v adb)"
elif command -v adb.exe >/dev/null 2>&1; then
    ADB_BIN="$(command -v adb.exe)"
else
    echo "❌ 未找到 adb/adb.exe" >&2
    return 1 2>/dev/null || exit 1
fi

ADB="${ADB_BIN}"
ADB_SERIAL="${ADB_SERIAL:-${ANDROID_SERIAL:-}}"
ADB_SERIAL_RESOLVED="${ADB_SERIAL_RESOLVED:-}"

resolve_adb_serial() {
    local explicit_serial="${ADB_SERIAL:-${ANDROID_SERIAL:-}}"
    if [[ -n "$explicit_serial" ]]; then
        printf '%s\n' "$explicit_serial"
        return 0
    fi

    mapfile -t devices < <("$ADB_BIN" devices | tr -d '\r' | awk 'NR > 1 && $2 == "device" { print $1 }')
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

adb_su() {
    local command="$1"
    adb_cmd shell su -c "$command"
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
