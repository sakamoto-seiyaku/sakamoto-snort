#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: lpi_provider_source_intake_gate.sh --evidence-root <dir>

Validates a candidate S61 LPI provider source-package evidence directory.
This is a pre-decision intake gate only: it does not approve vendoring,
distribution, runtime enablement, corpus import, or ProtocolRule work.
USAGE
}

evidence_root=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --evidence-root)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      evidence_root="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

[[ -n "$evidence_root" ]] || { usage; exit 2; }
[[ -d "$evidence_root" ]] || {
  echo "provider source evidence root is missing: $evidence_root" >&2
  exit 1
}

properties="$evidence_root/source-package.properties"
[[ -f "$properties" ]] || {
  echo "source-package.properties is missing under evidence root" >&2
  exit 1
}

property_value() {
  local key="$1"
  local value=""
  value="$(awk -F= -v key="$key" '
    $0 !~ /^[[:space:]]*(#|$)/ && $1 == key {
      sub(/^[^=]*=/, "")
      print
      exit
    }
  ' "$properties")"
  [[ -n "$value" ]] || {
    echo "required source-package property is missing or empty: $key" >&2
    exit 1
  }
  printf '%s\n' "$value"
}

require_allowed_value() {
  local key="$1"
  local value="$2"
  shift 2
  local allowed=""
  for allowed in "$@"; do
    [[ "$value" == "$allowed" ]] && return 0
  done
  echo "invalid $key: $value" >&2
  exit 1
}

require_relative_path() {
  local key="$1"
  local path="$2"
  local -a path_components=()
  local component=""
  [[ "$path" != /* ]] || {
    echo "$key must be relative to evidence root: $path" >&2
    exit 1
  }
  [[ -n "$path" ]] || {
    echo "$key must not be empty" >&2
    exit 1
  }
  [[ ! "$path" =~ ^[[:space:]]|[[:space:]]$ ]] || {
    echo "$key must not have leading or trailing whitespace: $path" >&2
    exit 1
  }
  [[ "$path" != *,* ]] || {
    echo "$key must not contain comma delimiters: $path" >&2
    exit 1
  }

  IFS='/' read -r -a path_components <<<"$path"
  for component in "${path_components[@]}"; do
    [[ -n "$component" ]] || {
      echo "$key must not contain empty path segments: $path" >&2
      exit 1
    }
    [[ "$component" != "." && "$component" != ".." ]] || {
      echo "$key must not contain parent traversal path segments: $path" >&2
      exit 1
    }
  done
}

require_path_inside_evidence_root() {
  local key="$1"
  local path="$2"
  local root_real=""
  local file_real=""

  root_real="$(realpath -e -- "$evidence_root")"
  file_real="$(realpath -e -- "$evidence_root/$path")"
  case "$file_real" in
    "$root_real"/*)
      ;;
    *)
      echo "$key resolves outside evidence root: $path" >&2
      exit 1
      ;;
  esac
}

require_existing_relative_file() {
  local key="$1"
  local path="$2"
  require_relative_path "$key" "$path"
  [[ -f "$evidence_root/$path" ]] || {
    echo "$key file is missing: $path" >&2
    exit 1
  }
  require_path_inside_evidence_root "$key" "$path"
}

require_existing_relative_source_file() {
  local key="$1"
  local path="$2"
  require_existing_relative_file "$key" "$path"
  [[ ! -L "$evidence_root/$path" ]] || {
    echo "$key must not be a symlink: $path" >&2
    exit 1
  }
}

require_existing_relative_evidence_file() {
  local key="$1"
  local path="$2"
  require_existing_relative_file "$key" "$path"
  [[ ! -L "$evidence_root/$path" ]] || {
    echo "$key evidence file must not be a symlink: $path" >&2
    exit 1
  }
}

source_strategy="$(property_value "source.strategy")"
source_origin="$(property_value "source.origin")"
source_pin="$(property_value "source.pin")"
source_archive_sha256="$(property_value "source.archiveSha256")"
source_manifest="$(property_value "source.manifest")"
license_files="$(property_value "license.files")"
notice_files="$(property_value "notice.files")"
provenance_files="$(property_value "provenance.files")"
linking_choice="$(property_value "linking.choice")"
android_abis="$(property_value "android.abis")"
android_min_api="$(property_value "android.minApi")"
android_ndk="$(property_value "android.ndk")"
warning_policy="$(property_value "warning.policy")"
runtime_enablement="$(property_value "runtime.enablement")"
corpus_import="$(property_value "corpus.import")"
protocol_rule="$(property_value "protocolRule")"
decision_record="$(property_value "decision.record")"
license_decision_record="$(property_value "license.decision.record")"
corpus_decision_record="$(property_value "corpus.decision.record")"

require_allowed_value "source.strategy" "$source_strategy" \
  "backup_vpp_wrapper" "reference_only_external" "external_curated"
require_allowed_value "linking.choice" "$linking_choice" \
  "static" "dynamic" "separate"
require_allowed_value "runtime.enablement" "$runtime_enablement" \
  "disabled_by_default"
require_allowed_value "corpus.import" "$corpus_import" \
  "not_included"
require_allowed_value "protocolRule" "$protocol_rule" \
  "out_of_scope"

[[ "$source_archive_sha256" =~ ^sha256:[0-9a-fA-F]{64}$ ]] || {
  echo "source.archiveSha256 must have sha256:<64 hex chars> form" >&2
  exit 1
}
[[ "$android_min_api" =~ ^[0-9]+$ ]] || {
  echo "android.minApi must be numeric" >&2
  exit 1
}
[[ -n "$source_origin" && -n "$source_pin" && -n "$android_abis" \
  && -n "$android_ndk" && -n "$warning_policy" \
  && -n "$decision_record" && -n "$license_decision_record" \
  && -n "$corpus_decision_record" ]] || {
  echo "source package decision metadata must be non-empty" >&2
  exit 1
}

require_existing_relative_file "source.manifest" "$source_manifest"

IFS=',' read -r -a license_file_array <<<"$license_files"
IFS=',' read -r -a notice_file_array <<<"$notice_files"
IFS=',' read -r -a provenance_file_array <<<"$provenance_files"
for file in "${license_file_array[@]}"; do
  require_existing_relative_evidence_file "license.files" "$file"
done
for file in "${notice_file_array[@]}"; do
  require_existing_relative_evidence_file "notice.files" "$file"
done
for file in "${provenance_file_array[@]}"; do
  require_existing_relative_evidence_file "provenance.files" "$file"
done

manifest_entries=0
while IFS= read -r entry || [[ -n "$entry" ]]; do
  [[ "$entry" =~ ^[[:space:]]*(#|$) ]] && continue
  require_existing_relative_source_file "source manifest entry" "$entry"
  case "$entry" in
    *.pcap|*.pcapng|*.json)
      echo "source manifest must not include corpus or expected-result files: $entry" >&2
      exit 1
      ;;
  esac
  ((manifest_entries += 1))
done <"$evidence_root/$source_manifest"

[[ "$manifest_entries" -gt 0 ]] || {
  echo "source manifest must contain at least one source file" >&2
  exit 1
}

while IFS= read -r corpus_path; do
  [[ -z "$corpus_path" ]] && continue
  echo "pre-decision source evidence must not include corpus or expected-result files: $corpus_path" >&2
  exit 1
done < <(
  find "$evidence_root" \( -type f -o -type l \) \( \
    -name '*.pcap' -o -name '*.pcapng' -o -name '*expected*.json' \
  \) -print
)

printf 'providerSourceIntake=PASS\n'
printf 'providerSourceEvidence=predecision_intake_only\n'
printf 'source.strategy=%s\n' "$source_strategy"
printf 'source.manifest.entries=%s\n' "$manifest_entries"
printf 'runtime.enablement=%s\n' "$runtime_enablement"
printf 'corpus.import=%s\n' "$corpus_import"
printf 'protocolRule=%s\n' "$protocol_rule"
printf 'realProviderEnabled=not_claimed\n'
