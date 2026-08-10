#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
adb_bin="$repo_root/dev/adb"

package_name="${PACKAGE:-com.sakamoto.snort.androidruntime}"
apk_path="${APK:-$repo_root/app/android-runtime/build/outputs/sakamoto-runtime-debug.apk}"
serial_arg="${ADB_SERIAL:-${ANDROID_SERIAL:-}}"
install_apk=0
refresh_projection=0
exercise_binding=0
create_test_profile=0
binding_exercise_failed=0
projection_activity_launched=0
binding_exercise_bound_subject=""
created_user_id=""

usage() {
  cat <<EOF
Usage: $0 [--serial <serial>] [--install-apk] [--refresh-projection] [--exercise-binding] [--create-test-profile]

Records bounded SAKAMOTO-50 Android device evidence:
  - git/device/user-profile metadata
  - per-user package UID samples from cmd package list packages --user <id> -U
  - current S50 package/projection availability, without STOP or data clearing

Default behavior is read-only. Opt-in flags:
  --install-apk          adb install -r the debug APK artifact; never clears data
  --refresh-projection   launch DebugControlActivity and poll the projection file
  --exercise-binding     bind then unbind one projected current-user app via RuntimeService
  --create-test-profile  create a temporary managed profile for multi-user evidence;
                         removed during cleanup; implies --refresh-projection

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
    --install-apk)
      install_apk=1
      shift
      ;;
    --refresh-projection)
      refresh_projection=1
      shift
      ;;
    --exercise-binding)
      exercise_binding=1
      refresh_projection=1
      shift
      ;;
    --create-test-profile)
      create_test_profile=1
      refresh_projection=1
      shift
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

start_debug_control_activity_for_user() {
  local user_id="$1"
  shift
  adb_cmd shell am start --user "$user_id" \
    -n "${package_name}/.DebugControlActivity" "$@"
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

emit_projection_properties() {
  local properties="$1"
  if [[ -z "$properties" ]]; then
    printf 'present=0\n'
    return 0
  fi
  printf 'present=1\n'
  printf '%s\n' "$properties" \
    | awk -F= '/^(schemaVersion|selectedProfile|boundApplicationCount|catalogEntryCount|catalogStatus|productStateStatus|rows\.count|selectableRows\.count)=/ { print $1"="$2 }' \
    | head -n 16
}

projection_properties_for_user() {
  local user_id="$1"
  local absolute_path="/data/user/${user_id}/${package_name}/files/product-catalog-projection/projection.properties"
  local relative_path="files/product-catalog-projection/projection.properties"
  local root_output

  root_output="$(adb_cmd shell su -c "cat '$absolute_path'" 2>/dev/null | tr -d '\r' || true)"
  if [[ -n "$root_output" ]]; then
    printf '%s\n' "$root_output"
    return 0
  fi

  if [[ "$user_id" == "0" ]]; then
    local run_as_output
    run_as_output="$(adb_cmd shell run-as "$package_name" cat "$relative_path" 2>/dev/null \
      | tr -d '\r' || true)"
    printf '%s\n' "$run_as_output"
    return 0
  fi

  return 0
}

probe_projection_for_user() {
  local user_id="$1"
  local properties
  properties="$(projection_properties_for_user "$user_id" || true)"
  if [[ -n "$properties" ]]; then
    emit_projection_properties "$properties"
    return 0
  fi
  printf 'present=0\n'
  return 0
}

projection_present_for_user() {
  local user_id="$1"
  local projection_output
  projection_output="$(probe_projection_for_user "$user_id" || true)"
  printf '%s\n' "$projection_output" \
    | awk -F= '$1 == "present" && $2 == "1" { found = 1 } END { exit(found ? 0 : 1) }'
}

projection_includes_profile_user_for_user() {
  local user_id="$1"
  local profile_user_id="$2"
  projection_properties_for_user "$user_id" \
    | awk -F= -v profile_user_id="$profile_user_id" '
      $1 ~ /^selectableRows\.[0-9]+\.userId$/ && $2 == profile_user_id {
        found = 1
      }
      END { exit(found ? 0 : 1) }'
}

refresh_projection_for_user() {
  local user_id="$1"
  local timeout_seconds="${PROJECTION_REFRESH_TIMEOUT_SECONDS:-45}"
  local deadline
  deadline=$((SECONDS + timeout_seconds))

  if ! start_debug_control_activity_for_user "$user_id" >/dev/null 2>&1; then
    kv projection_refresh.result "FAIL"
    kv projection_refresh.reason "debug_control_activity_launch_failed"
    return 1
  fi

  projection_activity_launched=1
  kv projection_refresh.launch "DebugControlActivity"
  kv projection_refresh.user "$user_id"

  while (( SECONDS <= deadline )); do
    if projection_present_for_user "$user_id"; then
      if [[ -n "$created_user_id" ]] \
          && ! projection_includes_profile_user_for_user "$user_id" "$created_user_id"; then
        sleep 1
        continue
      fi
      kv projection_refresh.result "PASS"
      return 0
    fi
    sleep 1
  done

  kv projection_refresh.result "FAIL"
  if [[ -n "$created_user_id" ]]; then
    kv projection_refresh.reason "projection_missing_created_profile_after_debug_control_activity_query_service"
  else
    kv projection_refresh.reason "projection_file_absent_after_debug_control_activity_query_service"
  fi
  return 1
}

create_test_profile_for_user() {
  local parent_user_id="$1"
  local profile_name="sakamoto-s50-test-$$"
  local output
  output="$(adb_cmd shell pm create-user --profileOf "$parent_user_id" --managed \
      --ephemeral --for-testing "$profile_name" 2>&1 | tr -d '\r' || true)"
  local profile_user_id
  profile_user_id="$(printf '%s\n' "$output" \
    | sed -n 's/.*created user id \([0-9][0-9]*\).*/\1/p' \
    | sed -n '1p')"
  if [[ -z "$profile_user_id" ]]; then
    kv test_profile.create "FAIL"
    kv test_profile.create.output "$output"
    return 1
  fi
  created_user_id="$profile_user_id"
  kv test_profile.create "PASS"
  kv test_profile.user "$created_user_id"

  if adb_cmd shell am start-user -w "$created_user_id" >/dev/null 2>&1; then
    kv test_profile.start_user "PASS"
  else
    kv test_profile.start_user "UNAVAILABLE"
  fi
  if adb_cmd shell am unlock-user "$created_user_id" >/dev/null 2>&1; then
    kv test_profile.unlock_user "PASS"
  else
    kv test_profile.unlock_user "UNAVAILABLE"
  fi
  if adb_cmd shell pm install-existing --user "$created_user_id" "$package_name" \
      >/dev/null 2>&1; then
    kv test_profile.install_existing "PASS"
  else
    kv test_profile.install_existing "FAIL"
    return 1
  fi
}

first_bindable_subject_for_user() {
  local user_id="$1"
  projection_properties_for_user "$user_id" \
    | awk -F= '
      {
        if (match($1, /^selectableRows\.([0-9]+)\./)) {
          idx = substr($1, RSTART + 15, RLENGTH - 16)
          field = substr($1, RSTART + RLENGTH)
          seen[idx] = 1
          if (field == "subjectId") {
            value = $2
            gsub(/\\:/, ":", value)
            subject[idx] = value
          } else if (field == "availability") {
            availability[idx] = $2
          } else if (field == "bound") {
            bound[idx] = $2
          } else if (field == "productStateValid") {
            valid[idx] = $2
          }
        }
      }
      END {
        for (i = 0; i < 1024; i++) {
          if (!seen[i]) {
            continue
          }
          uid_value = subject[i]
          if (uid_value !~ /^android[.]uid:[0-9]+$/) {
            continue
          }
          sub(/^android[.]uid:/, "", uid_value)
          app_id = uid_value % 100000
          if (app_id >= 10000 && availability[i] == "available" && bound[i] == "false" && valid[i] == "true") {
            print subject[i]
            exit
          }
        }
      }'
}

projection_multi_user_identity_for_user() {
  local user_id="$1"
  projection_properties_for_user "$user_id" \
    | awk -F= '
      {
        if (match($1, /^selectableRows\.([0-9]+)\./)) {
          idx = substr($1, RSTART + 15, RLENGTH - 16)
          field = substr($1, RSTART + RLENGTH)
          seen[idx] = 1
          if (field == "subjectId") {
            value = $2
            gsub(/\\:/, ":", value)
            subject[idx] = value
          } else if (field == "packageName") {
            packageName[idx] = $2
          } else if (field == "userId") {
            profileUser[idx] = $2
          }
        }
      }
      END {
        for (i = 0; i < 1024; i++) {
          if (!seen[i] || packageName[i] == "" || subject[i] == "") {
            continue
          }
          for (j = i + 1; j < 1024; j++) {
            if (!seen[j] || packageName[j] == "" || subject[j] == "") {
              continue
            }
            uid_i = subject[i]
            uid_j = subject[j]
            if (uid_i !~ /^android[.]uid:[0-9]+$/ || uid_j !~ /^android[.]uid:[0-9]+$/) {
              continue
            }
            sub(/^android[.]uid:/, "", uid_i)
            sub(/^android[.]uid:/, "", uid_j)
            app_id_i = uid_i % 100000
            app_id_j = uid_j % 100000
            if (app_id_i >= 10000 && app_id_j >= 10000 && packageName[i] == packageName[j] && subject[i] != subject[j] && profileUser[i] != profileUser[j]) {
              print packageName[i] " user_" profileUser[i] ":" subject[i] \
                    " user_" profileUser[j] ":" subject[j]
              exit
            }
          }
        }
      }'
}

subject_bound_for_user() {
  local user_id="$1"
  local subject_id="$2"
  projection_properties_for_user "$user_id" \
    | awk -F= -v subject_id="$subject_id" '
      {
        if (match($1, /^selectableRows\.([0-9]+)\./)) {
          idx = substr($1, RSTART + 15, RLENGTH - 16)
          field = substr($1, RSTART + RLENGTH)
          seen[idx] = 1
          if (field == "subjectId") {
            value = $2
            gsub(/\\:/, ":", value)
            subject[idx] = value
          } else if (field == "bound") {
            bound[idx] = $2
          }
        }
      }
      END {
        matched = 0
        any_bound = 0
        for (i = 0; i < 1024; i++) {
          if (seen[i] && subject[i] == subject_id) {
            matched = 1
            if (bound[i] == "true") {
              any_bound = 1
            }
          }
        }
        if (any_bound) {
          print "true"
        } else if (matched) {
          print "false"
        } else {
          print "UNKNOWN"
        }
      }'
}

wait_subject_bound_state() {
  local user_id="$1"
  local subject_id="$2"
  local expected="$3"
  local timeout_seconds="${BINDING_EXERCISE_TIMEOUT_SECONDS:-45}"
  local deadline
  deadline=$((SECONDS + timeout_seconds))

  while (( SECONDS <= deadline )); do
    if [[ "$(subject_bound_for_user "$user_id" "$subject_id")" == "$expected" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

exercise_binding_for_user() {
  local user_id="$1"
  local subject_id
  subject_id="$(first_bindable_subject_for_user "$user_id" || true)"
  if [[ -z "$subject_id" ]]; then
    kv binding_exercise.result "UNAVAILABLE"
    kv binding_exercise.reason "no_bindable_projected_application_subject"
    return 0
  fi

  kv binding_exercise.subject "$subject_id"
  if ! start_debug_control_activity_for_user "$user_id" \
      --es debugBindApplicationSubject "$subject_id" >/dev/null 2>&1; then
    kv binding_exercise.bind "FAIL"
    kv binding_exercise.reason "debug_bind_activity_launch_failed"
    return 1
  fi
  projection_activity_launched=1
  if wait_subject_bound_state "$user_id" "$subject_id" "true"; then
    kv binding_exercise.bind "PASS"
    binding_exercise_bound_subject="$subject_id"
  else
    if start_debug_control_activity_for_user "$user_id" \
        --es debugBindApplicationSubject "$subject_id" >/dev/null 2>&1 \
        && wait_subject_bound_state "$user_id" "$subject_id" "true"; then
      kv binding_exercise.bind "PASS_AFTER_RETRY"
      binding_exercise_bound_subject="$subject_id"
    else
      kv binding_exercise.bind "FAIL"
      kv binding_exercise.reason "subject_not_bound_after_debug_bind"
      binding_exercise_failed=1
    fi
  fi

  if ! start_debug_control_activity_for_user "$user_id" \
      --es debugUnbindApplicationSubject "$subject_id" >/dev/null 2>&1; then
    kv binding_exercise.unbind "FAIL"
    kv binding_exercise.reason "debug_unbind_activity_launch_failed"
    binding_exercise_failed=1
    return 1
  fi
  if wait_subject_bound_state "$user_id" "$subject_id" "false"; then
    kv binding_exercise.unbind "PASS"
    binding_exercise_bound_subject=""
  else
    if start_debug_control_activity_for_user "$user_id" \
        --es debugUnbindApplicationSubject "$subject_id" >/dev/null 2>&1 \
        && wait_subject_bound_state "$user_id" "$subject_id" "false"; then
      kv binding_exercise.unbind "PASS_AFTER_RETRY"
      binding_exercise_bound_subject=""
    else
      kv binding_exercise.unbind "FAIL"
      kv binding_exercise.reason "subject_not_unbound_after_debug_unbind"
      binding_exercise_failed=1
    fi
  fi
}

cleanup() {
  if [[ "${resolved_serial:-}" == "UNAVAILABLE" ]]; then
    return 0
  fi
  if [[ -n "$binding_exercise_bound_subject" ]]; then
    if start_debug_control_activity_for_user "${current_user_id:-0}" \
        --es debugUnbindApplicationSubject "$binding_exercise_bound_subject" \
        >/dev/null 2>&1 \
        && wait_subject_bound_state "${current_user_id:-0}" \
          "$binding_exercise_bound_subject" "false"; then
      kv binding_exercise.cleanup_unbind "PASS"
      binding_exercise_bound_subject=""
    else
      kv binding_exercise.cleanup_unbind "FAILED"
      kv binding_exercise.cleanup_unbind.subject "$binding_exercise_bound_subject"
    fi
  fi
  if [[ "$projection_activity_launched" -eq 1 ]]; then
    if adb_cmd shell am force-stop "$package_name" >/dev/null 2>&1; then
      kv cleanup.force_stop "ISSUED"
    else
      kv cleanup.force_stop "FAILED"
    fi
  else
    kv cleanup.force_stop "SKIPPED_NOT_LAUNCHED"
  fi
  if [[ -n "$created_user_id" ]]; then
    if adb_cmd shell pm remove-user --wait "$created_user_id" >/dev/null 2>&1; then
      kv test_profile.cleanup "REMOVED"
      created_user_id=""
    else
      kv test_profile.cleanup "FAILED"
      kv test_profile.cleanup.user "$created_user_id"
    fi
  fi
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

if [[ "$install_apk" -eq 1 ]]; then
  kv apk_install "REQUESTED"
else
  kv apk_install "SKIPPED"
fi
if [[ "$refresh_projection" -eq 1 ]]; then
  kv projection_refresh "REQUESTED"
else
  kv projection_refresh "SKIPPED"
fi
if [[ "$exercise_binding" -eq 1 ]]; then
  kv binding_exercise "REQUESTED"
else
  kv binding_exercise "SKIPPED"
fi
if [[ "$create_test_profile" -eq 1 ]]; then
  kv test_profile "REQUESTED"
else
  kv test_profile "SKIPPED"
fi

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

if [[ "$install_apk" -eq 1 ]]; then
  if [[ ! -f "$apk_path" ]]; then
    kv apk_install "FAIL"
    kv apk_install.reason "debug_apk_artifact_absent"
    exit 1
  elif adb_cmd install -r "$apk_path" >/dev/null 2>&1; then
    kv apk_install "PASS"
  else
    kv apk_install "FAIL"
    kv apk_install.reason "adb_install_r_failed"
    exit 1
  fi
fi

kv device.model "$(adb_cmd shell getprop ro.product.model 2>/dev/null | tr -d '\r' || printf UNKNOWN)"
kv device.sdk "$(adb_cmd shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r' || printf UNKNOWN)"
kv device.release "$(adb_cmd shell getprop ro.build.version.release 2>/dev/null | tr -d '\r' || printf UNKNOWN)"

current_user_id="$(adb_cmd shell am get-current-user 2>/dev/null | tr -d '\r' | awk '/^[0-9]+$/ { print; exit }' || true)"
if [[ -n "$current_user_id" ]]; then
  kv current_user.id "$current_user_id"
else
  current_user_id="0"
  kv current_user.id "UNAVAILABLE"
  kv current_user.reason "am_get_current_user_unavailable_defaulting_to_user_0_for_projection_refresh"
fi

if [[ "$create_test_profile" -eq 1 && "$exercise_binding" -eq 1 ]]; then
  refresh_projection_for_user "$current_user_id" || true
  exercise_binding_for_user "$current_user_id" || true
fi

if [[ "$create_test_profile" -eq 1 ]]; then
  create_test_profile_for_user "$current_user_id" || true
fi

users_raw="$(adb_cmd shell pm list users 2>/dev/null | tr -d '\r' || true)"
kv users.raw "$(printf '%s\n' "$users_raw" | sed 's/[[:space:]][[:space:]]*/ /g' | sed '/^$/d' | paste -sd '|' -)"
mapfile -t user_ids < <(printf '%s\n' "$users_raw" | parse_users)
kv users.count "${#user_ids[@]}"
if [[ "${#user_ids[@]}" -gt 0 ]]; then
  kv users.ids "$(join_by_comma "${user_ids[@]}")"
else
  kv users.ids "UNAVAILABLE"
fi

if [[ "$refresh_projection" -eq 1 ]]; then
  refresh_projection_for_user "$current_user_id" || true
fi
if [[ "$exercise_binding" -eq 1 && "$create_test_profile" -eq 0 ]]; then
  exercise_binding_for_user "$current_user_id" || true
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
      projection_multi_user_evidence="$(projection_multi_user_identity_for_user "$user_id" || true)"
      if [[ -n "$projection_multi_user_evidence" ]]; then
        kv "product_projection.user_${user_id}.multi_user_identity" "PASS"
        kv "product_projection.user_${user_id}.multi_user_identity.evidence" \
          "$projection_multi_user_evidence"
      else
        kv "product_projection.user_${user_id}.multi_user_identity" "PARTIAL"
        kv "product_projection.user_${user_id}.multi_user_identity.reason" \
          "no_same_package_distinct_profile_subjects_in_projection"
      fi
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
    if [[ "$projection_activity_launched" -eq 1 ]]; then
      kv product_catalog.reason "projection_file_absent_after_debug_control_activity_query_service"
    else
      kv product_catalog.reason "projection_file_absent_query_service_not_launched"
    fi
  else
    kv product_projection "UNAVAILABLE"
    kv product_catalog "UNAVAILABLE"
    kv product_catalog.reason "projection_read_requires_root_or_debuggable_run_as"
  fi
fi

if [[ "${#user_ids[@]}" -lt 2 ]]; then
  kv multi_user_identity "UNAVAILABLE"
  kv multi_user_identity.reason "only_${#user_ids[@]}_android_user_or_profile_visible_cannot_prove_same_package_multi_user_uid_differentiation"
  if [[ "$binding_exercise_failed" -eq 1 ]]; then
    exit 1
  fi
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

if [[ "$binding_exercise_failed" -eq 1 ]]; then
  exit 1
fi
