#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.." && pwd)"
pin_file="$repo_root/src/product/vpp/pinned-vpp-revision.txt"
patch_dir="$repo_root/src/product/vpp/android/patches"
profile=""
source_dir=""
work_dir=""

usage() {
  cat >&2 <<'EOF'
usage: apply-profile.sh --profile android-api31-arm64 --source-dir DIR --work-dir DIR

The source directory must be a clean checkout at the product's pinned VPP
revision. The work directory is a newly materialized temporary checkout; the
input checkout is never patched in place.
EOF
}

die() {
  echo "Android VPP profile: $*" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      [[ $# -ge 2 ]] || die "--profile requires a value"
      profile="$2"
      shift 2
      ;;
    --source-dir)
      [[ $# -ge 2 ]] || die "--source-dir requires a value"
      source_dir="$2"
      shift 2
      ;;
    --work-dir)
      [[ $# -ge 2 ]] || die "--work-dir requires a value"
      work_dir="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage
      die "unknown option: $1"
      ;;
  esac
done

[[ "$profile" == "android-api31-arm64" ]] || \
  die "unsupported profile: ${profile:-missing}"
[[ -n "$source_dir" ]] || die "--source-dir is required"
[[ -n "$work_dir" ]] || die "--work-dir is required"
[[ -f "$pin_file" ]] || die "pinned VPP revision file is missing"
canonical_source_dir="$(realpath -e "$source_dir" 2>/dev/null)" || \
  die "source directory cannot be canonicalized"
source_dir="$canonical_source_dir"
[[ -d "$source_dir/.git" || -f "$source_dir/.git" ]] || \
  die "source directory is not a Git checkout"
case "${source_dir,,}" in
  *experiments*|*poc*) die "POC/experiment source is not permitted" ;;
esac
[[ ! -e "$work_dir" ]] || die "work directory already exists"

pinned_revision="$(tr -d '[:space:]' < "$pin_file")"
[[ "$pinned_revision" =~ ^[[:xdigit:]]{40}$ ]] || \
  die "pinned VPP revision is not a 40-character commit"
source_head="$(git -C "$source_dir" rev-parse HEAD)"
[[ "$source_head" == "$pinned_revision" ]] || \
  die "source checkout is not at the product's pinned revision"
[[ -z "$(git -C "$source_dir" status --porcelain)" ]] || \
  die "source checkout must be clean"

mkdir -p "$(dirname -- "$work_dir")"
git clone --no-local --no-checkout "$source_dir" "$work_dir" >/dev/null
git -C "$work_dir" checkout --detach "$pinned_revision" >/dev/null

series="$patch_dir/series"
[[ -f "$series" ]] || die "profile patch series is missing"
while IFS= read -r patch_name || [[ -n "$patch_name" ]]; do
  [[ -n "$patch_name" ]] || continue
  [[ "$patch_name" != \#* ]] || continue
  patch_file="$patch_dir/$patch_name"
  [[ -f "$patch_file" ]] || die "profile patch is missing: $patch_name"
  git -C "$work_dir" apply --check --whitespace=error "$patch_file" || \
    die "profile patch does not apply: $patch_name"
  git -C "$work_dir" apply --whitespace=error "$patch_file"
done < "$series"

[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$source_head" ]] || \
  die "source checkout changed while applying profile"
[[ -z "$(git -C "$source_dir" status --porcelain)" ]] || \
  die "source checkout changed while applying profile"
[[ "$(git -C "$work_dir" rev-parse HEAD)" == "$pinned_revision" ]] || \
  die "profile changed the pinned revision"
expected_changed_files=$'src/CMakeLists.txt\nsrc/svm/CMakeLists.txt\nsrc/svm/message_queue.c\nsrc/svm/message_queue.h\nsrc/svm/queue.c\nsrc/svm/ssvm.c\nsrc/svm/svm.c\nsrc/svm/svm_android_file.c\nsrc/svm/svm_android_file.h\nsrc/vlib/CMakeLists.txt\nsrc/vlib/threads.c\nsrc/vlibmemory/memclnt_api.c\nsrc/vlibmemory/vlib_api_cli.c\nsrc/vnet/session/session.c\nsrc/vnet/sfdp/timer/timer.h\nsrc/vpp-api/vapi/CMakeLists.txt\nsrc/vpp/vnet/main.c\nsrc/vppinfra/CMakeLists.txt\nsrc/vppinfra/dlmalloc.h\nsrc/vppinfra/maplog.c\nsrc/vppinfra/mem_intercept.c'
changed_files="$(
  git -C "$work_dir" diff --name-only
  git -C "$work_dir" ls-files --others --exclude-standard
  )"
changed_files="$(printf '%s\n' "$changed_files" | LC_ALL=C sort)"
[[ "$changed_files" == "$expected_changed_files" ]] || \
  die "profile changed files outside the ordered Android patch series"

echo "profile=android-api31-arm64"
echo "sourceHead=$source_head"
echo "workDir=$work_dir"
echo "patchedPaths=$expected_changed_files"
