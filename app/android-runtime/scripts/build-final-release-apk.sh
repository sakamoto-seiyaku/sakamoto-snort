#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

die() { echo "error: $*" >&2; exit 1; }

: "${ANDROID_RUNTIME_RELEASE_SIGNING_KEYSTORE:?missing final release signing input: ANDROID_RUNTIME_RELEASE_SIGNING_KEYSTORE}"
: "${ANDROID_RUNTIME_RELEASE_SIGNING_ALIAS:?missing final release signing input: ANDROID_RUNTIME_RELEASE_SIGNING_ALIAS}"
: "${ANDROID_RUNTIME_RELEASE_STORE_PASS_FILE:?missing final release signing input: ANDROID_RUNTIME_RELEASE_STORE_PASS_FILE}"

[[ -f "$ANDROID_RUNTIME_RELEASE_SIGNING_KEYSTORE" ]] \
  || die "missing final release signing keystore: $ANDROID_RUNTIME_RELEASE_SIGNING_KEYSTORE"
[[ -f "$ANDROID_RUNTIME_RELEASE_STORE_PASS_FILE" ]] \
  || die "missing final release signing store password file: $ANDROID_RUNTIME_RELEASE_STORE_PASS_FILE"
if [[ -n "${ANDROID_RUNTIME_RELEASE_KEY_PASS_FILE:-}" ]]; then
  [[ -f "$ANDROID_RUNTIME_RELEASE_KEY_PASS_FILE" ]] \
    || die "missing final release signing key password file: $ANDROID_RUNTIME_RELEASE_KEY_PASS_FILE"
fi

ANDROID_RUNTIME_BUILD_VARIANT=final-release \
  exec "$script_dir/build-debug-apk.sh" "$@"
