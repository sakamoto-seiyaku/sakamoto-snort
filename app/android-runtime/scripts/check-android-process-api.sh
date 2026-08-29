#!/usr/bin/env bash
set -euo pipefail

# S172 uses the pinned AOSP/Lineage host parser and only interprets its
# structured output.  No DEX bytes are parsed here.
default_dexdump="/home/js/android/lineage/prebuilts/sdk/tools/linux/bin/dexdump"
default_dexdump_sha256="cccd6b7473b8715672879672838a8e4cf1dfa8a0f008f432c7deb5c79cdce19d"

die() { echo "Android Process API gate: ERROR: $*" >&2; exit 2; }

resolve_dexdump() {
  local candidate="${SAKAMOTO_ANDROID_DEXDUMP:-}"
  local expected actual banner comment sha_bin readelf_bin
  sha_bin="$(command -v sha256sum 2>/dev/null || true)"
  readelf_bin="$(command -v readelf 2>/dev/null || true)"
  [[ -n "$sha_bin" && -x "$sha_bin" ]] || die "sha256sum is required"
  [[ -n "$readelf_bin" && -x "$readelf_bin" ]] || die "readelf is required"
  if [[ -n "$candidate" ]]; then
    expected="${SAKAMOTO_ANDROID_DEXDUMP_SHA256:-}"
    [[ -n "$expected" ]] || die \
      "SAKAMOTO_ANDROID_DEXDUMP_SHA256 is required with SAKAMOTO_ANDROID_DEXDUMP"
  else
    [[ -z "${SAKAMOTO_ANDROID_DEXDUMP_SHA256:-}" ]] || die \
      "SAKAMOTO_ANDROID_DEXDUMP_SHA256 requires an explicit SAKAMOTO_ANDROID_DEXDUMP"
    candidate="$default_dexdump"
    expected="$default_dexdump_sha256"
  fi
  expected="${expected,,}"
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || die "expected dexdump SHA-256 is invalid"
  [[ -f "$candidate" && -x "$candidate" ]] || die "dexdump is not executable: $candidate"
  candidate="$(realpath -e -- "$candidate" 2>/dev/null)" || die "dexdump path cannot be resolved"
  actual="$("$sha_bin" -- "$candidate" 2>/dev/null)" || die "cannot hash dexdump: $candidate"
  actual="${actual%% *}"
  [[ "$actual" == "$expected" ]] || die \
    "dexdump SHA-256 mismatch: expected $expected, got $actual ($candidate)"
  # Banner is a sanity check only; hash and ELF provenance establish identity.
  banner="$("$candidate" 2>&1 || true)"
  [[ "$banner" == *"Copyright (C) 2007 The Android Open Source Project"* &&
     "$banner" == *"dexdump:"* ]] || die "dexdump AOSP banner check failed: $candidate"
  comment="$("$readelf_bin" -p .comment -- "$candidate" 2>/dev/null)" || \
    die "cannot read dexdump ELF .comment: $candidate"
  [[ "$comment" == *"Android ("*"based on r"*"clang version "* ]] || \
    die "dexdump ELF .comment has no Android/AOSP provenance: $candidate"
  [[ "$comment" == *"Linker: LLD "* ]] || \
    die "dexdump ELF .comment has no Android LLD provenance: $candidate"
  dexdump_path="$candidate"
  dexdump_sha256="$actual"
}

parse_dexdump() {
  awk '
    function add(v) { if (!(v in found)) { found[v] = 1; why[++n] = v } }
    function types(s) {
      if (s ~ /Ljava\/lang\/ProcessHandle(\$[^;]*)?;/)
        add("java/lang/ProcessHandle type reference")
    }
    {
      l = $0
      if (l ~ /^Processing /) { processing = 1; next }
      if (l ~ /^Opened .*DEX version/) { opened = 1; next }
      if (l ~ /^Class #[0-9]+ annotations:/) {
        structured = 1; annotation = 1; method_handle = call_site = 0; next
      }
      if (l ~ /^Class #[0-9]+[[:space:]]+-/) {
        structured = 1; annotation = method_handle = call_site = 0; next
      }
      if (l ~ /^Method handle #[0-9]+:/) {
        structured = 1; annotation = call_site = 0; method_handle = 1
        target_pid = target_to_handle = 0; next
      }
      if (l ~ /^Call site #[0-9]+:/) {
        structured = 1; annotation = method_handle = 0; call_site = 1; next
      }
      if (l ~ /\|.*const-string([[:space:]]|$)/) next
      clean = l
      while (clean ~ /"[^"]*"/) sub(/"[^"]*"/, "", clean)
      if (annotation) { types(clean); next }
      if (method_handle) {
        if (l ~ /^[[:space:]]*target[[:space:]]*:/) {
          types(clean)
          target_pid = clean ~ /^[[:space:]]*target[[:space:]]*:[[:space:]]*Ljava\/lang\/Process;[[:space:]]+pid[[:space:]]*$/
          target_to_handle = clean ~ /^[[:space:]]*target[[:space:]]*:[[:space:]]*Ljava\/lang\/Process;[[:space:]]+toHandle[[:space:]]*$/
        }
        if (l ~ /^[[:space:]]*target_type[[:space:]]*:/) {
          types(clean)
          if (target_pid && clean ~ /^[[:space:]]*target_type[[:space:]]*:[[:space:]]*\(\)J[[:space:]]*$/)
            add("java/lang/Process.pid:()J method-handle reference")
          if (target_to_handle && clean ~ /^[[:space:]]*target_type[[:space:]]*:[[:space:]]*\(\)Ljava\/lang\/ProcessHandle;[[:space:]]*$/)
            add("java/lang/Process.toHandle:()Ljava/lang/ProcessHandle; method-handle reference")
        }
        next
      }
      if (call_site) {
        if (l ~ /\(MethodType\)[[:space:]]*$/ || l ~ /\(Class\)[[:space:]]*$/)
          types(clean)
        next
      }
      if (l ~ /^[[:space:]]*Class descriptor[[:space:]]*:/ ||
          l ~ /^[[:space:]]*Superclass[[:space:]]*:/ ||
          l ~ /^[[:space:]]*type[[:space:]]*:/ ||
          l ~ /^[[:space:]]*#[0-9]+[[:space:]]*:/ ||
          l ~ /^[[:space:]]*0x[0-9a-f]+[[:space:]]+-.*reg=/)
        types(clean)
      if (l ~ /\|[[:space:]]*[0-9a-f]+:[[:space:]]+/) {
        types(clean)
        if (clean ~ /\|[[:space:]]*[0-9a-f]+:[[:space:]]+invoke-[^[:space:]]+[[:space:]].*Ljava\/lang\/Process;\.pid:\(\)J([[:space:]]|$)/)
          add("java/lang/Process.pid:()J method reference")
        if (clean ~ /\|[[:space:]]*[0-9a-f]+:[[:space:]]+invoke-[^[:space:]]+[[:space:]].*Ljava\/lang\/Process;\.toHandle:\(\)Ljava\/lang\/ProcessHandle;([[:space:]]|$)/)
          add("java/lang/Process.toHandle:()Ljava/lang/ProcessHandle; method reference")
      }
    }
    END {
      if (!processing || !opened || !structured) {
        print "ERROR: official dexdump output format is not recognized"; exit 2
      }
      if (n) {
        print "FAIL: structured unsupported references detected:"
        for (i = 1; i <= n; i++) print "  " why[i]
        exit 1
      }
      print "PASS: official dexdump output recognized; no unsupported references"
    }
  ' "$1"
}

run_dexdump() {
  local label="$1" dex="$2" dump="$3" scan="$4" status=0
  if ! "$dexdump_path" -a -d -- "$dex" >"$dump" 2>&1; then
    sed -n '1,80p' "$dump" >&2 || true
    die "$label cannot be parsed by official Android AOSP dexdump ($dexdump_path)"
  fi
  [[ -s "$dump" ]] || die "$label produced empty official dexdump output"
  parse_dexdump "$dump" >"$scan" || status=$?
  cat "$scan" >&2
  case "$status" in 0) ;; 1) return 1 ;; *) die "$label produced unrecognized official dexdump output" ;; esac
}

check_zip() {
  local input="$1" entries_file="$2" dex_file="$3" dump_file="$4" scan_file="$5"
  local name suffix index=0
  local -a entries=() dex_entries=()
  declare -A seen_entries=()
  "$unzip_bin" -Z1 -- "$input" >"$entries_file" 2>"$entries_file.error" || {
    sed -n '1,40p' "$entries_file.error" >&2 || true
    die "APK/ZIP cannot be enumerated by unzip: $input"
  }
  mapfile -t entries <"$entries_file"
  ((${#entries[@]} > 0)) || die "APK/ZIP has no entries: $input"
  for name in "${entries[@]}"; do
    [[ -z "${seen_entries["$name"]+present}" ]] || die "APK/ZIP contains duplicate entry: $name"
    seen_entries["$name"]=1
    case "$name" in classes*.dex) dex_entries+=("$name");; esac
  done
  ((${#dex_entries[@]} > 0)) || die "APK/ZIP has no classes*.dex entry: $input"
  for name in "${dex_entries[@]}"; do
    suffix=""; ((index > 0)) && suffix=".$index"
    "$unzip_bin" -p -- "$input" "$name" >"${dex_file}${suffix}" || \
      die "cannot extract $name from APK/ZIP: $input"
    run_dexdump "${input}:$name" "${dex_file}${suffix}" \
      "${dump_file}${suffix}" "${scan_file}${suffix}" || return 1
    index=$((index + 1))
  done
  if ((${#dex_entries[@]} != 1)) || [[ "${dex_entries[0]}" != classes.dex ]]; then
    printf 'Android Process API gate: ERROR: APK/ZIP must contain exactly one classes.dex; found:\n' >&2
    printf '  %s\n' "${dex_entries[@]}" >&2
    die "multidex or non-standard classes*.dex layout is unsupported"
  fi
}

[[ $# -eq 1 ]] || die "usage: check-android-process-api.sh <classes.dex|apk>"
input="$1"
[[ -f "$input" ]] || die "artifact is not a regular file: $input"
resolve_dexdump
unzip_bin="$(command -v unzip 2>/dev/null || true)"
[[ -n "$unzip_bin" && -x "$unzip_bin" ]] || die "unzip is required for APK/ZIP inspection"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/sakamoto-android-process-api.XXXXXX")" || \
  die "cannot create temporary directory for official artifact inspection"
trap 'rm -rf -- "$work_dir"' EXIT
if [[ "$input" == *.apk || "$input" == *.zip ]]; then
  check_zip "$input" "$work_dir/zip.entries" "$work_dir/classes.dex" \
    "$work_dir/dexdump.txt" "$work_dir/dexdump.scan"
else
  run_dexdump "$input" "$input" "$work_dir/dexdump.txt" "$work_dir/dexdump.scan"
fi
echo "Android Process API gate: PASS: $input (official AOSP dexdump: $dexdump_path; sha256=$dexdump_sha256)"
