#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$SCRIPT_DIR/.."

source "$SCRIPT_DIR/dev-ndk-env.sh"

MODE="check"
SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$SNORT_NDK_DEFAULT_SDK_ROOT}}"

show_help() {
    cat <<EOF
Usage: $0 [--check|--install|--print-env] [--sdk-root <path>]

Options:
  --check             Validate Android NDK $SNORT_NDK_VERSION discovery (default).
  --install           Install Android NDK $SNORT_NDK_VERSION with sdkmanager.
  --print-env         Print shell exports for the discovered NDK.
  --sdk-root <path>   Android SDK root to use for install/discovery.
  -h, --help          Show this help.

Default local SDK root:
  $SNORT_NDK_DEFAULT_SDK_ROOT

Default local NDK path:
  $SNORT_NDK_DEFAULT_ROOT
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check)
            MODE="check"
            shift
            ;;
        --install)
            MODE="install"
            shift
            ;;
        --print-env)
            MODE="print-env"
            shift
            ;;
        --sdk-root)
            SDK_ROOT="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            show_help >&2
            exit 1
            ;;
    esac
done

find_sdkmanager() {
    local -a candidates=()
    local candidate=""

    candidates+=("$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager")
    candidates+=("$SDK_ROOT/cmdline-tools/bin/sdkmanager")

    if command -v sdkmanager >/dev/null 2>&1; then
        candidates+=("$(command -v sdkmanager)")
    fi

    for candidate in "${candidates[@]}"; do
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    return 1
}

install_ndk() {
    local sdkmanager_bin=""

    mkdir -p "$SDK_ROOT"

    sdkmanager_bin="$(find_sdkmanager)" || {
        cat >&2 <<EOF
Android sdkmanager was not found.

Install Android command-line tools first, or use GitHub Actions setup-android.
Expected one of:
  $SDK_ROOT/cmdline-tools/latest/bin/sdkmanager
  $SDK_ROOT/cmdline-tools/bin/sdkmanager
  sdkmanager on PATH

Then run:
  bash dev/dev-setup-ndk.sh --install --sdk-root "$SDK_ROOT"
EOF
        exit 1
    }

    echo "=== Sucre-Snort NDK setup ==="
    echo "SDK root: $SDK_ROOT"
    echo "sdkmanager: $sdkmanager_bin"
    echo "NDK version: $SNORT_NDK_VERSION"
    echo ""

    yes | "$sdkmanager_bin" --sdk_root="$SDK_ROOT" --licenses >/dev/null
    "$sdkmanager_bin" --sdk_root="$SDK_ROOT" "ndk;$SNORT_NDK_VERSION"
}

case "$MODE" in
    check)
        ndk_root="$(ANDROID_SDK_ROOT="$SDK_ROOT" ANDROID_HOME="$SDK_ROOT" snort_ndk_require)"
        echo "NDK OK: $ndk_root"
        ;;
    install)
        install_ndk
        ndk_root="$(ANDROID_SDK_ROOT="$SDK_ROOT" ANDROID_HOME="$SDK_ROOT" snort_ndk_require)"
        echo "NDK OK: $ndk_root"
        ;;
    print-env)
        ndk_root="$(ANDROID_SDK_ROOT="$SDK_ROOT" ANDROID_HOME="$SDK_ROOT" snort_ndk_resolve)"
        snort_ndk_print_exports "$ndk_root"
        ;;
    *)
        echo "Internal error: unknown mode $MODE" >&2
        exit 1
        ;;
esac
