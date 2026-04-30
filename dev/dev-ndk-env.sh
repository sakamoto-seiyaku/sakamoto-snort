#!/usr/bin/env bash

# Sourceable Android NDK r29 discovery helpers for local and CI builds.

SNORT_NDK_VERSION="${SNORT_NDK_VERSION:-29.0.14206865}"
SNORT_ANDROID_API="${SNORT_ANDROID_API:-31}"
SNORT_NDK_DEFAULT_SDK_ROOT="${SNORT_NDK_DEFAULT_SDK_ROOT:-$HOME/.local/share/android-sdk}"
SNORT_NDK_DEFAULT_ROOT="${SNORT_NDK_DEFAULT_ROOT:-$SNORT_NDK_DEFAULT_SDK_ROOT/ndk/$SNORT_NDK_VERSION}"

snort_ndk_source_version() {
    local ndk_root="$1"
    local source_properties="$ndk_root/source.properties"

    [[ -f "$source_properties" ]] || return 1
    awk -F '= *' '$1 == "Pkg.Revision " || $1 == "Pkg.Revision" { print $2; exit }' "$source_properties"
}

snort_ndk_validate() {
    local ndk_root="$1"
    local actual_version=""

    [[ -n "$ndk_root" ]] || return 1
    [[ -d "$ndk_root" ]] || return 1

    actual_version="$(snort_ndk_source_version "$ndk_root" 2>/dev/null || true)"
    [[ "$actual_version" == "$SNORT_NDK_VERSION" ]] || return 1

    [[ -f "$ndk_root/build/cmake/android.toolchain.cmake" ]] || return 1
    [[ -d "$ndk_root/toolchains/llvm/prebuilt/linux-x86_64" ]] || return 1
    [[ -x "$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android${SNORT_ANDROID_API}-clang++" ]] || return 1

    return 0
}

snort_ndk_print_error() {
    cat >&2 <<EOF
Android NDK r29 was not found or failed validation.

Required:
  NDK version: $SNORT_NDK_VERSION
  Android API: $SNORT_ANDROID_API

Discovery order:
  1. ANDROID_NDK_HOME
  2. ANDROID_NDK_ROOT
  3. \$ANDROID_SDK_ROOT/ndk/$SNORT_NDK_VERSION
  4. \$ANDROID_HOME/ndk/$SNORT_NDK_VERSION
  5. $SNORT_NDK_DEFAULT_ROOT

Install locally with:
  bash dev/dev-setup-ndk.sh --install

Or set:
  export ANDROID_SDK_ROOT=$SNORT_NDK_DEFAULT_SDK_ROOT
EOF
}

snort_ndk_resolve() {
    local candidate=""
    local -a candidates=()
    local -A seen=()

    add_candidate() {
        local path="$1"
        [[ -n "$path" ]] || return 0
        [[ -z "${seen["$path"]:-}" ]] || return 0
        seen["$path"]=1
        candidates+=("$path")
    }

    if [[ -n "${ANDROID_NDK_HOME:-}" ]]; then
        if snort_ndk_validate "$ANDROID_NDK_HOME"; then
            printf '%s\n' "$ANDROID_NDK_HOME"
            return 0
        fi
        echo "ANDROID_NDK_HOME is set but is not NDK $SNORT_NDK_VERSION: $ANDROID_NDK_HOME" >&2
        snort_ndk_print_error
        return 1
    fi

    if [[ -n "${ANDROID_NDK_ROOT:-}" ]]; then
        if snort_ndk_validate "$ANDROID_NDK_ROOT"; then
            printf '%s\n' "$ANDROID_NDK_ROOT"
            return 0
        fi
        echo "ANDROID_NDK_ROOT is set but is not NDK $SNORT_NDK_VERSION: $ANDROID_NDK_ROOT" >&2
        snort_ndk_print_error
        return 1
    fi

    [[ -n "${ANDROID_SDK_ROOT:-}" ]] && add_candidate "$ANDROID_SDK_ROOT/ndk/$SNORT_NDK_VERSION"
    [[ -n "${ANDROID_HOME:-}" ]] && add_candidate "$ANDROID_HOME/ndk/$SNORT_NDK_VERSION"
    add_candidate "$SNORT_NDK_DEFAULT_ROOT"

    for candidate in "${candidates[@]}"; do
        if snort_ndk_validate "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    snort_ndk_print_error
    return 1
}

snort_ndk_sdk_root_for() {
    local ndk_root="$1"
    local suffix="/ndk/$SNORT_NDK_VERSION"

    if [[ "$ndk_root" == *"$suffix" ]]; then
        printf '%s\n' "${ndk_root%$suffix}"
    fi
}

snort_ndk_export_env() {
    local ndk_root="$1"
    local sdk_root=""

    sdk_root="$(snort_ndk_sdk_root_for "$ndk_root" || true)"
    export ANDROID_NDK_HOME="$ndk_root"
    export ANDROID_NDK_ROOT="$ndk_root"
    if [[ -n "$sdk_root" ]]; then
        export ANDROID_SDK_ROOT="$sdk_root"
        export ANDROID_HOME="$sdk_root"
    fi
}

snort_ndk_print_exports() {
    local ndk_root="$1"
    local sdk_root=""

    sdk_root="$(snort_ndk_sdk_root_for "$ndk_root" || true)"
    if [[ -n "$sdk_root" ]]; then
        printf 'export ANDROID_SDK_ROOT=%q\n' "$sdk_root"
        printf 'export ANDROID_HOME=%q\n' "$sdk_root"
    fi
    printf 'export ANDROID_NDK_HOME=%q\n' "$ndk_root"
    printf 'export ANDROID_NDK_ROOT=%q\n' "$ndk_root"
}

snort_ndk_require() {
    local ndk_root=""

    ndk_root="$(snort_ndk_resolve)" || return 1
    snort_ndk_export_env "$ndk_root"
    printf '%s\n' "$ndk_root"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    case "${1:---check}" in
        --check)
            snort_ndk_require >/dev/null
            ;;
        --print-root)
            snort_ndk_require
            ;;
        --print-env)
            ndk_root="$(snort_ndk_resolve)" || exit 1
            snort_ndk_print_exports "$ndk_root"
            ;;
        -h|--help)
            cat <<EOF
Usage: $0 [--check|--print-root|--print-env]

Validates Android NDK $SNORT_NDK_VERSION for sucre-snort NDK builds.
EOF
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
fi
