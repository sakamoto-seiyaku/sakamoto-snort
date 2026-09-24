#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
classes="$(mktemp -d)"
trap 'rm -rf "$classes"' EXIT
javac -d "$classes" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuleConfiguration.java" \
  "$repo_root/tests/android/RuleConfigurationTest.java"
java -cp "$classes" RuleConfigurationTest
