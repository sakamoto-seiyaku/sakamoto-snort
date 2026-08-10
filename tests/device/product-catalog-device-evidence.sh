#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
adb_bin="$repo_root/dev/adb"

package_name="${PACKAGE:-com.sakamoto.snort.androidruntime}"
apk_path="${APK:-$repo_root/app/android-runtime/build/outputs/sakamoto-runtime-debug.apk}"
serial_arg="${ADB_SERIAL:-${ANDROID_SERIAL:-}}"

usage() {
  cat <<EOF
Usage: $0 [--serial <serial>]

Records bounded SAKAMOTO-50 Android device evidence:
  - git/device/user-profile metadata
  - per-user package UID samples from cmd package list packages --user <id> -U
  - current S50 package/projection availability, without STOP or data clearing

Environment overrides:
  PACKAGE, APK, ADB_SERIAL, ANDROID_SERIAL
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial)
      serial_arg="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

kv() {
  local key="$1"
  local value="${2:-}"
  value="${value//$'\r'/}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\t'/ }"
  printf '%s=%s\n' "$key" "$value"
}

join_by_comma() {
  local IFS=,
  printf '%s' "$*"
}

adb_raw() {
  "$adb_bin" "$@"
}

adb_cmd() {
  if [[ -n "$serial_arg" ]]; then
    "$adb_bin" -s "$serial_arg" "$@"
  else
    "$adb_bin" "$@"
  fi
}

resolve_serial() {
  if [[ -n "$serial_arg" ]]; then
    printf '%s\n' "$serial_arg"
    return 0
  fi

  local devices
  devices="$(adb_raw devices 2>/dev/null | tr -d '\r' \
    | awk 'NR > 1 && $2 == "device" { print $1 }' \
    | grep -Ev '^adb-.*\._adb-tls-connect\._tcp$' || true)"
  local count
  count="$(printf '%s\n' "$devices" | sed '/^$/d' | wc -l | tr -d ' ')"
  if [[ "$count" == "1" ]]; then
    printf '%s\n' "$devices" | sed -n '1p'
    return 0
  fi
  if [[ "$count" == "0" ]]; then
    return 1
  fi
  return 2
}

parse_users() {
  awk '
    match($0, /UserInfo\{[0-9]+:/) {
      value = substr($0, RSTART + 9, RLENGTH - 10)
      print value
    }
  '
}

package_uid_lines() {
  local user_id="$1"
  adb_cmd shell cmd package list packages --user "$user_id" -U 2>/dev/null \
    | tr -d '\r' \
    | sed -n 's/^package:\([^ ]*\).*uid:\([0-9][0-9]*\).*$/\1=\2/p'
}

projection_probe_script() {
  local user_id="$1"
  local path="/data/user/${user_id}/${package_name}/files/product-catalog-projection/projection.properties"
  printf '%s\n' \
    "path='$path'" \
    'if [ -f "$path" ]; then' \
    '  echo present=1' \
    '  awk -F= '"'"'/^(schemaVersion|selectedProfile|boundApplicationCount|catalogEntryCount|catalogStatus|productStateStatus|rows\.count|selectableRows\.count)=/ { print $1"="$2 }'"'"' "$path" 2>/dev/null | head -n 16' \
    'else' \
    '  echo present=0' \
    'fi'
}

probe_projection_for_user() {
  local user_id="$1"
  local script
  script="$(projection_probe_script "$user_id")"

  if adb_cmd shell su 0 sh -c "$script" 2>/dev/null | tr -d '\r'; then
    return 0
  fi

  if [[ "$user_id" == "0" ]]; then
    adb_cmd shell run-as "$package_name" sh -c "$script" 2>/dev/null | tr -d '\r' \
      && return 0
  fi

  return 1
}

cleanup() {
  if [[ "${resolved_serial:-}" == "UNAVAILABLE" ]]; then
    return 0
  fi
  kv cleanup.force_stop "SKIPPED_NOT_LAUNCHED"
  local forwards
  forwards="$(adb_cmd forward --list 2>/dev/null | tr -d '\r' || true)"
  if [[ -z "$forwards" ]]; then
    kv cleanup.adb_forward_list "EMPTY"
  else
    local relevant
    relevant="$(printf '%s\n' "$forwards" \
      | grep -E 'sakamoto|sucre-snort|tcp:6060|tcp:6061|tcp:6067' || true)"
    if [[ -z "$relevant" ]]; then
      kv cleanup.adb_forward_residue "NONE_RELEVANT"
    else
      kv cleanup.adb_forward_residue "$relevant"
    fi
  fi
}

kv harness "s50_product_catalog_device_evidence"
kv git_head "$(git -C "$repo_root" rev-parse --verify HEAD 2>/dev/null || printf UNKNOWN)"
kv package "$package_name"

if [[ -f "$apk_path" ]]; then
  kv apk_artifact "FOUND"
  kv apk_artifact.path "$apk_path"
else
  kv apk_artifact "UNAVAILABLE"
  kv apk_artifact.reason "debug_apk_artifact_absent_build_with_app_android_runtime_scripts_build_debug_apk_sh_if_needed"
fi

serial_status=0
resolved_serial="$(resolve_serial)" || serial_status=$?
if [[ "$serial_status" -ne 0 ]]; then
  resolved_serial="UNAVAILABLE"
  kv device "UNAVAILABLE"
  if [[ "$serial_status" -eq 1 ]]; then
    kv device.reason "no_single_connected_android_device"
  else
    kv device.reason "multiple_connected_android_devices_set_ADB_SERIAL_or_use_serial"
  fi
  kv multi_user_identity "UNAVAILABLE"
  kv multi_user_identity.reason "device_unavailable_cannot_prove_same_package_multi_user_uid_differentiation"
  cleanup
  exit 0
fi

serial_arg="$resolved_serial"
kv device "AVAILABLE"
kv device.serial "$resolved_serial"

trap cleanup EXIT

kv device.model "$(adb_cmd shell getprop ro.product.model 2>/dev/null | tr -d '\r' || printf UNKNOWN)"
kv device.sdk "$(adb_cmd shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r' || printf UNKNOWN)"
kv device.release "$(adb_cmd shell getprop ro.build.version.release 2>/dev/null | tr -d '\r' || printf UNKNOWN)"

users_raw="$(adb_cmd shell pm list users 2>/dev/null | tr -d '\r' || true)"
kv users.raw "$(printf '%s\n' "$users_raw" | sed 's/[[:space:]][[:space:]]*/ /g' | sed '/^$/d' | paste -sd '|' -)"
mapfile -t user_ids < <(printf '%s\n' "$users_raw" | parse_users)
kv users.count "${#user_ids[@]}"
if [[ "${#user_ids[@]}" -gt 0 ]]; then
  kv users.ids "$(join_by_comma "${user_ids[@]}")"
else
  kv users.ids "UNAVAILABLE"
fi

all_uid_samples="$(mktemp)"
trap 'rm -f "$all_uid_samples"; cleanup' EXIT
for user_id in "${user_ids[@]}"; do
  uid_lines="$(package_uid_lines "$user_id" || true)"
  sample_count="$(printf '%s\n' "$uid_lines" | sed '/^$/d' | wc -l | tr -d ' ')"
  kv "package_uid.user_${user_id}.count" "$sample_count"
  target_uid="$(printf '%s\n' "$uid_lines" \
    | awk -F= -v package="$package_name" '$1 == package { print $2; exit }')"
  if [[ -n "$target_uid" ]]; then
    kv "package_uid.user_${user_id}.target" "$target_uid"
  else
    kv "package_uid.user_${user_id}.target" "UNAVAILABLE"
  fi
  printf '%s\n' "$uid_lines" \
    | awk -F= -v user="$user_id" 'NF == 2 { print $1, user, $2 }' >>"$all_uid_samples"
done

installed_any=0
for user_id in "${user_ids[@]}"; do
  if adb_cmd shell cmd package path --user "$user_id" "$package_name" \
      >/dev/null 2>&1; then
    installed_any=1
    kv "product_package.user_${user_id}" "INSTALLED"
  else
    kv "product_package.user_${user_id}" "UNAVAILABLE"
  fi
done
if [[ "$installed_any" -eq 0 ]]; then
  kv product_catalog "UNAVAILABLE"
  kv product_catalog.reason "package_not_installed_on_visible_users"
  kv product_projection "UNAVAILABLE"
  kv product_projection.reason "package_not_installed_on_visible_users"
else
  projection_any=0
  projection_probe_any=0
  for user_id in "${user_ids[@]}"; do
    projection_output="$(probe_projection_for_user "$user_id" || true)"
    if [[ -z "$projection_output" ]]; then
      kv "product_projection.user_${user_id}" "UNAVAILABLE"
      kv "product_projection.user_${user_id}.reason" "projection_read_requires_root_or_debuggable_run_as"
      continue
    fi
    projection_probe_any=1
    present="$(printf '%s\n' "$projection_output" \
      | awk -F= '$1 == "present" { print $2; exit }')"
    if [[ "$present" == "1" ]]; then
      projection_any=1
      kv "product_projection.user_${user_id}" "PRESENT"
      while IFS='=' read -r key value; do
        [[ -n "$key" && "$key" != "present" ]] || continue
        kv "product_projection.user_${user_id}.${key}" "$value"
      done <<<"$projection_output"
    else
      kv "product_projection.user_${user_id}" "ABSENT"
    fi
  done
  if [[ "$projection_any" -eq 1 ]]; then
    kv product_projection "PRESENT"
    kv product_catalog "AVAILABLE_VIA_PROJECTION"
  elif [[ "$projection_probe_any" -eq 1 ]]; then
    kv product_projection "ABSENT"
    kv product_catalog "UNAVAILABLE"
    kv product_catalog.reason "projection_file_absent_query_service_not_launched"
  else
    kv product_projection "UNAVAILABLE"
    kv product_catalog "UNAVAILABLE"
    kv product_catalog.reason "projection_read_requires_root_or_debuggable_run_as"
  fi
fi

if [[ "${#user_ids[@]}" -lt 2 ]]; then
  kv multi_user_identity "UNAVAILABLE"
  kv multi_user_identity.reason "only_${#user_ids[@]}_android_user_or_profile_visible_cannot_prove_same_package_multi_user_uid_differentiation"
  exit 0
fi

comparison="$(awk '
  {
    package = $1
    user = $2
    uid = $3
    seen[package] = seen[package] " " user ":" uid
    uid_seen[package, uid] = 1
  }
  END {
    for (package in seen) {
      split("", unique)
      count = 0
      for (key in uid_seen) {
        split(key, parts, SUBSEP)
        if (parts[1] == package) {
          count++
        }
      }
      if (count >= 2) {
        print package seen[package]
        exit
      }
    }
  }
' "$all_uid_samples")"

if [[ -n "$comparison" ]]; then
  kv multi_user_identity "PASS"
  kv multi_user_identity.evidence "$comparison"
else
  kv multi_user_identity "PARTIAL"
  kv multi_user_identity.reason "no_same_package_with_different_uids_seen_across_visible_users"
fi
