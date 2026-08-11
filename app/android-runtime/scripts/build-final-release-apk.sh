#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

ANDROID_RUNTIME_BUILD_VARIANT=final-release \
  exec "$script_dir/build-debug-apk.sh" "$@"
