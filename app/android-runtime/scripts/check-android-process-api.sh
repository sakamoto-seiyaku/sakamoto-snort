#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-172 artifact API boundary.
#
# This gate deliberately delegates all DEX parsing and validation to the
# Android Open Source Project dexdump binary.  It does not read DEX headers,
# ID tables, offsets, checksums, or instructions itself.  The 2026-08-29
# inventory found the installed Lineage/AOSP tool at:
#   /home/js/android/lineage/prebuilts/sdk/tools/linux/bin/dexdump
# Its banner identifies it as Android Open Source Project dexdump; its ELF
# .comment reports Android build 11368308 (based on r510928), clang 18.0.0,
# and LLD 18.0.0.  The binary has no --version option.  Discovery accepts an
# explicit override, Android SDK/Lineage prebuilts, and PATH, but never falls
# back to a homemade parser or a third-party disassembler.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"

die() {
  echo "Android Process API gate: ERROR: $*" >&2
  exit 2
}

official_dexdump_banner() {
  local output="$1"
  [[ "$output" == *"Copyright (C) 2007 The Android Open Source Project"* &&
     "$output" == *"dexdump:"* ]]
}

resolve_dexdump() {
  local explicit="${SAKAMOTO_ANDROID_DEXDUMP:-}"
  local candidate
  local resolved
  local banner
  local sdk_root
  local path_candidate
  local -a candidates=()

  if [[ -n "$explicit" ]]; then
    [[ -f "$explicit" && -x "$explicit" ]] || \
      die "SAKAMOTO_ANDROID_DEXDUMP is not an executable file: $explicit"
    resolved="$(realpath -e -- "$explicit" 2>/dev/null)" || \
      die "SAKAMOTO_ANDROID_DEXDUMP cannot be resolved: $explicit"
    banner="$("$resolved" 2>&1 || true)"
    official_dexdump_banner "$banner" || \
      die "SAKAMOTO_ANDROID_DEXDUMP is not the Android Open Source Project dexdump: $resolved"
    printf '%s\n' "$resolved"
    return 0
  fi

  # Repository-local and known Lineage/AOSP host-tool locations are checked
  # before PATH so an unrelated dexdump cannot silently change the gate.
  candidates+=(
    "$repo_root/prebuilts/sdk/tools/linux/bin/dexdump"
    "$repo_root/android-sdk/build-tools/dexdump"
    "/home/js/android/lineage/prebuilts/sdk/tools/linux/bin/dexdump"
    "/home/js/android/lineage/out/host/linux-x86/bin/dexdump"
  )
  for sdk_root in "${ANDROID_SDK_ROOT:-}" "${ANDROID_HOME:-}" \
      "/home/js/.local/share/android-sdk"; do
    [[ -n "$sdk_root" ]] || continue
    candidates+=(
      "$sdk_root/build-tools"/*/dexdump
      "$sdk_root/cmdline-tools"/*/bin/dexdump
      "$sdk_root/tools/bin/dexdump"
    )
  done
  path_candidate="$(command -v dexdump 2>/dev/null || true)"
  [[ -n "$path_candidate" ]] && candidates+=("$path_candidate")

  for candidate in "${candidates[@]}"; do
    [[ -f "$candidate" && -x "$candidate" ]] || continue
    resolved="$(realpath -e -- "$candidate" 2>/dev/null)" || continue
    banner="$("$resolved" 2>&1 || true)"
    if official_dexdump_banner "$banner"; then
      printf '%s\n' "$resolved"
      return 0
    fi
  done

  die "official Android Open Source Project dexdump is unavailable; checked repository/SDK/Lineage locations and PATH. Set SAKAMOTO_ANDROID_DEXDUMP to a verified AOSP dexdump. No homemade DEX parser fallback is permitted"
}

run_dexdump() {
  local label="$1"
  local dex_path="$2"
  local dump_path="$3"
  local scan_path="$4"
  local -a findings=()

  # -d asks dexdump to parse and disassemble the complete DEX.  A non-zero
  # result is an official parser/checksum/structural failure and therefore a
  # fail-closed artifact error.  Do not pass -i or -j.
  if ! "$dexdump" -d -- "$dex_path" >"$dump_path" 2>&1; then
    sed -n '1,80p' "$dump_path" >&2 || true
    die "$label cannot be parsed by official Android Open Source Project dexdump ($dexdump)"
  fi

  # dexdump includes the input path in its Processing line.  Exclude only that
  # provenance line before matching, so a valid path containing "ProcessHandle"
  # or "Process.pid" cannot create an artifact false positive.
  sed '/^Processing /d' "$dump_path" >"$scan_path"
  if grep -Fq 'Ljava/lang/Process;.pid:()J' "$scan_path"; then
    findings+=("java/lang/Process.pid:()J")
  fi
  if grep -Fq 'Ljava/lang/Process;.toHandle:' "$scan_path"; then
    findings+=("java/lang/Process.toHandle")
  fi
  # Match only a DEX type descriptor (including arrays and nested classes),
  # not an unrelated string constant that happens to contain the class name.
  if grep -Eq '(\[*)Ljava/lang/ProcessHandle([;$])' "$scan_path"; then
    findings+=("java/lang/ProcessHandle")
  fi
  if ((${#findings[@]} > 0)); then
    echo "Android Process API gate: FAIL: $label contains unsupported references:" >&2
    printf '  %s\n' "${findings[@]}" >&2
    return 1
  fi
}

check_zip() {
  local input="$1"
  local entries_file="$2"
  local dex_file="$3"
  local dump_file="$4"
  local scan_file="$5"
  local name
  local index=0
  local current_dex_file
  local current_dump_file
  local current_scan_file
  local -a entries=()
  local -a dex_entries=()
  declare -A seen_entries=()

  # Info-ZIP is used only for ZIP entry enumeration/extraction.  It does not
  # inspect DEX contents; dexdump remains the sole artifact parser.
  if ! "$unzip_bin" -Z1 -- "$input" >"$entries_file" 2>"$entries_file.error"; then
    sed -n '1,40p' "$entries_file.error" >&2 || true
    die "APK/ZIP cannot be enumerated by unzip: $input"
  fi
  mapfile -t entries <"$entries_file"
  ((${#entries[@]} > 0)) || die "APK/ZIP has no entries: $input"

  for name in "${entries[@]}"; do
    if [[ -n "${seen_entries["$name"]+present}" ]]; then
      die "APK/ZIP contains duplicate entry: $name"
    fi
    seen_entries["$name"]=1
    case "$name" in
      classes*.dex) dex_entries+=("$name") ;;
    esac
  done

  ((${#dex_entries[@]} > 0)) || \
    die "APK/ZIP has no classes*.dex entry: $input"

  # Enumerate and send each unique classes*.dex entry through the official
  # parser before applying the product's single-dex policy.  This keeps the
  # artifact seam honest for every DEX while avoiding a second DEX parser in
  # this repository.  Duplicate names are rejected above because ZIP lookup
  # by name cannot safely distinguish duplicate records.
  for name in "${dex_entries[@]}"; do
    current_dex_file="$dex_file"
    current_dump_file="$dump_file"
    current_scan_file="$scan_file"
    if ((index > 0)); then
      current_dex_file="${dex_file}.${index}"
      current_dump_file="${dump_file}.${index}"
      current_scan_file="${scan_file}.${index}"
    fi
    if ! "$unzip_bin" -p -- "$input" "$name" >"$current_dex_file"; then
      die "cannot extract $name from APK/ZIP: $input"
    fi
    if ! run_dexdump "${input}:$name" "$current_dex_file" \
        "$current_dump_file" "$current_scan_file"; then
      return 1
    fi
    index=$((index + 1))
  done

  if ((${#dex_entries[@]} != 1)) || [[ "${dex_entries[0]}" != "classes.dex" ]]; then
    printf 'Android Process API gate: ERROR: APK/ZIP must contain exactly one classes.dex; found:\n' >&2
    printf '  %s\n' "${dex_entries[@]}" >&2
    die "multidex or non-standard classes*.dex layout is unsupported"
  fi
}

[[ $# -eq 1 ]] || die "usage: check-android-process-api.sh <classes.dex|apk>"
input="$1"
[[ -f "$input" ]] || die "artifact is not a regular file: $input"

dexdump="$(resolve_dexdump)"
unzip_bin="$(command -v unzip 2>/dev/null || true)"
[[ -n "$unzip_bin" && -x "$unzip_bin" ]] || \
  die "unzip is required to inspect final APK classes*.dex entries"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/sakamoto-android-process-api.XXXXXX")" || \
  die "cannot create temporary directory for official artifact inspection"
trap 'rm -rf -- "$work_dir"' EXIT

if [[ "$input" == *.apk || "$input" == *.zip ]]; then
  check_zip "$input" "$work_dir/zip.entries" "$work_dir/classes.dex" \
    "$work_dir/dexdump.txt" "$work_dir/dexdump.scan"
else
  run_dexdump "$input" "$input" "$work_dir/dexdump.txt" "$work_dir/dexdump.scan"
fi

echo "Android Process API gate: PASS: $input (official AOSP dexdump: $dexdump)"
