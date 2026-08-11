#!/usr/bin/env bash
set -euo pipefail

# Emits a stable, machine-readable inventory of the modified backup VPP
# stellar_lpi PCAP corpus. This script does not copy captures into this repo and
# does not make a provider-source or licensing decision.

reference_root="${VPP_REFERENCE_ROOT:-/home/js/backup/backup/Git/vpp}"
corpus_root="${VPP_LPI_CORPUS_ROOT:-${reference_root}/test/decoders/stellar_lpi/test_pcap}"

die() {
  echo "error: $*" >&2
  exit 1
}

count_files() {
  local root="$1"
  local pattern="$2"
  find "$root" -type f -name "$pattern" | wc -l | tr -d ' '
}

count_group_files() {
  local root="$1"
  local pattern="$2"
  find "$root" -maxdepth 1 -type f -name "$pattern" | wc -l | tr -d ' '
}

join_group_files() {
  local root="$1"
  local pattern="$2"
  find "$root" -maxdepth 1 -type f -name "$pattern" -printf '%f\n' \
    | sort \
    | paste -sd, -
}

json_summary() {
  local expected_json="$1"
  python3 - "$expected_json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    rows = json.load(handle)

app_names = []
unknown_rows = 0
multi_result_rows = 0
directions = []
for row in rows:
    if row.get("APP_ID") == "UNKNOWN":
        unknown_rows += 1
    names = row.get("APP_NAME")
    if isinstance(names, list):
        if len(names) > 1:
            multi_result_rows += 1
        app_names.extend(str(name) for name in names)
    direction = row.get("FLOW_DIRECTION")
    if direction:
        directions.append(str(direction))

print(len(rows))
print(",".join(sorted(set(app_names))) or "-")
print(unknown_rows)
print(multi_result_rows)
print(",".join(sorted(set(directions))) or "-")
PY
}

[[ -d "$reference_root" ]] || die "missing VPP reference root: $reference_root"
[[ -d "$corpus_root" ]] || die "missing stellar_lpi corpus root: $corpus_root"

printf 'source=%s\n' "$reference_root"
printf 'corpusRoot=%s\n' "$corpus_root"
printf 'policy.copiesPcapIntoRepo=false\n'
printf 'policy.requiresLicenseAndPrivacyReviewBeforeImport=true\n'
printf 'total.pcap=%s\n' "$(count_files "$corpus_root" '*.pcap')"
printf 'total.json=%s\n' "$(count_files "$corpus_root" '*.json')"

mapfile -t group_dirs < <(find "$corpus_root" -mindepth 1 -maxdepth 1 -type d | sort)
printf 'groups.count=%s\n' "${#group_dirs[@]}"

for group_dir in "${group_dirs[@]}"; do
  group="$(basename "$group_dir")"
  expected_json="$(find "$group_dir" -maxdepth 1 -type f -name '*.json' | sort | head -n 1)"
  printf 'group.%s.pcap=%s\n' "$group" "$(count_group_files "$group_dir" '*.pcap')"
  printf 'group.%s.json=%s\n' "$group" "$(count_group_files "$group_dir" '*.json')"
  printf 'group.%s.expectedJson=%s\n' "$group" "$(join_group_files "$group_dir" '*.json')"
  if [[ -n "$expected_json" ]]; then
    mapfile -t summary < <(json_summary "$expected_json")
    printf 'group.%s.expectedSessions=%s\n' "$group" "${summary[0]}"
    printf 'group.%s.expectedApps=%s\n' "$group" "${summary[1]}"
    printf 'group.%s.expectedUnknownRows=%s\n' "$group" "${summary[2]}"
    printf 'group.%s.expectedMultiResultRows=%s\n' "$group" "${summary[3]}"
    printf 'group.%s.expectedDirections=%s\n' "$group" "${summary[4]}"
  fi
done
