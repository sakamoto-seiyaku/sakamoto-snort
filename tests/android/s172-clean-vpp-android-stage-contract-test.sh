#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
stage_script="$repo_root/src/product/vpp/android/build-stage.sh"
pin_file="$repo_root/src/product/vpp/pinned-vpp-revision.txt"
pinned_revision="$(tr -d '[:space:]' < "$pin_file")"
expected_patch_series_count=18
expected_patch_series_sha256=2f2b87b011cc131cada294ae31e6ebfb618ccdf3f303b303ff4b7f00b562af74
source_dir="${SAKAMOTO_S172_VPP_SOURCE_DIR:-/tmp/sakamoto-172-vpp-official.6CoCcd/source-git}"
ndk_root="${SAKAMOTO_S172_ANDROID_NDK_ROOT:-/home/js/.local/share/android-sdk/ndk/29.0.14206865}"
python_path="${SAKAMOTO_S172_VPP_PYTHONPATH:-/home/js/android/lineage/external/ply/ply}"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/sakamoto-172-clean-stage.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

fail() {
  echo "s172 clean VPP Android stage contract: $*" >&2
  exit 1
}

[[ -x "$stage_script" ]] || fail "repo-owned build-stage.sh is missing"
[[ "$(grep -Fc 'assert_owned_stage' "$stage_script")" -ge 2 ]] || \
  fail "stage publication does not revalidate the owned marker"
grep -Fq 'flock_bin' "$stage_script" || \
  fail "stage publication is not serialized"
grep -Fq 'RENAME_EXCHANGE = 2' "$stage_script" || \
  fail "owned-stage publication is not an atomic exchange"
grep -Fq 'RENAME_NOREPLACE = 1' "$stage_script" || \
  fail "fresh-stage publication is not an atomic no-replace"
grep -Fq 'publish_stage_atomic fresh' "$stage_script" || \
  fail "fresh-stage publication does not use the atomic helper"
if grep -Fq 'mv -- "$candidate_dir" "$stage_dir"' "$stage_script"; then
  fail "fresh-stage publication still uses a TOCTOU-prone move"
fi
grep -Fq 'validate_staged_symlinks' "$stage_script" || \
  fail "stage symlink containment validation is missing"
[[ "$pinned_revision" =~ ^[[:xdigit:]]{40}$ ]] || fail "pinned revision is invalid"
[[ -d "$ndk_root/build/cmake" ]] || fail "NDK root is missing"
[[ -d "$python_path" ]] || fail "official VPP host-tool Python dependencies are missing"

canonical_source_dir="$(realpath -e "$source_dir" 2>/dev/null)" || \
  fail "source directory cannot be canonicalized"
source_dir="$canonical_source_dir"
case "${source_dir,,}" in
  *experiments*|*poc*) fail "POC/experiment source is not permitted" ;;
esac
[[ -d "$source_dir/.git" || -f "$source_dir/.git" ]] || \
  fail "source directory is not a Git checkout"
[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$pinned_revision" ]] || \
  fail "source directory is not at the exact product pin"
[[ -z "$(git -C "$source_dir" status --porcelain)" ]] || \
  fail "source checkout must remain clean"

atomic_noreplace() {
  python3 - "$1" "$2" <<'PY'
import ctypes
import os
import sys

renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
renameat2.argtypes = [
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_uint,
]
renameat2.restype = ctypes.c_int
if renameat2(
    -100,
    os.fsencode(sys.argv[2]),
    -100,
    os.fsencode(sys.argv[1]),
    1,
) != 0:
    error_number = ctypes.get_errno()
    raise OSError(error_number, os.strerror(error_number))
PY
}

atomic_root="$work_dir/atomic-publish"
fresh_candidate="$atomic_root/fresh-candidate"
fresh_stage="$atomic_root/fresh-stage"
mkdir -p "$fresh_candidate"
printf '%s\n' fresh >"$fresh_candidate/payload"
atomic_noreplace "$fresh_stage" "$fresh_candidate" || \
  fail "fresh atomic publication helper failed"
[[ -f "$fresh_stage/payload" ]] || fail "fresh atomic publication omitted payload"
[[ ! -e "$fresh_candidate" ]] || fail "fresh atomic publication left candidate"

occupied_candidate="$atomic_root/occupied-candidate"
occupied_stage="$atomic_root/occupied-stage"
mkdir -p "$occupied_candidate" "$occupied_stage"
printf '%s\n' new >"$occupied_candidate/payload"
printf '%s\n' old >"$occupied_stage/payload"
if atomic_noreplace "$occupied_stage" "$occupied_candidate"; then
  fail "atomic no-replace accepted a preexisting output"
fi
grep -Fxq old "$occupied_stage/payload" || \
  fail "preexisting output changed after atomic no-replace failure"
grep -Fxq new "$occupied_candidate/payload" || \
  fail "candidate changed after atomic no-replace failure"

unowned_stage="$work_dir/unowned-stage"
mkdir -p "$unowned_stage"
printf '%s\n' user-data >"$unowned_stage/keep-me"
if SAKAMOTO_S172_ANDROID_API=31 "$stage_script" \
    --source-dir "$source_dir" --stage-dir "$unowned_stage" \
    >"$work_dir/unowned.log" 2>&1; then
  fail "stage builder overwrote an output without its owned marker"
fi
grep -Fq 'owned marker' "$work_dir/unowned.log" || \
  fail "unowned stage rejection did not identify the owned-marker contract"
[[ -f "$unowned_stage/keep-me" ]] || fail "unowned stage was modified"

invalid_stage="$work_dir/invalid-api-stage"
if SAKAMOTO_S172_ANDROID_API=30 "$stage_script" \
    --source-dir "$source_dir" --stage-dir "$invalid_stage" \
    >"$work_dir/invalid-api.log" 2>&1; then
  fail "stage builder accepted an unsupported Android API"
fi
grep -Fq 'only Android API 31 is supported' "$work_dir/invalid-api.log" || \
  fail "unsupported API rejection is not fail-closed"
[[ ! -e "$invalid_stage" ]] || fail "unsupported API created a stage"

if "$stage_script" --source-dir "$source_dir" --stage-dir / \
    >"$work_dir/root-stage.log" 2>&1; then
  fail "stage builder accepted the filesystem root as output"
fi
grep -Fq 'filesystem root' "$work_dir/root-stage.log" || \
  fail "filesystem-root rejection is not explicit"

mkdir -p "$work_dir/poc-parent"
stage_dir="$work_dir/poc-parent/stage"
SAKAMOTO_S172_ANDROID_API=31 \
SAKAMOTO_S172_ANDROID_NDK_ROOT="$ndk_root" \
SAKAMOTO_S172_VPP_PYTHONPATH="$python_path" \
  "$stage_script" --source-dir "$source_dir" --stage-dir "$stage_dir" \
  >"$work_dir/build.log"

marker="$stage_dir/.sakamoto-android-vpp-stage"
manifest="$stage_dir/android-vpp-stage.properties"
[[ -f "$marker" && ! -L "$marker" ]] || fail "stage owned marker is missing"
grep -Fxq 'sakamoto-android-vpp-stage/v1' "$marker" || \
  fail "stage owned marker has the wrong value"
[[ -f "$manifest" ]] || fail "stage manifest is missing"
grep -Fxq 'schema=sakamoto-android-vpp-stage/v1' "$manifest"
grep -Fxq "revision=$pinned_revision" "$manifest"
grep -Fxq 'profile=android-api31-arm64' "$manifest"
grep -Fxq "patchSeriesCount=$expected_patch_series_count" "$manifest"
grep -Fxq "patchSeriesSha256=$expected_patch_series_sha256" "$manifest"
grep -Fxq 'api=31' "$manifest"
grep -Fxq 'abi=arm64-v8a' "$manifest"
grep -Fxq 'binary=bin/vpp' "$manifest"
grep -Fxq 'libraries=lib' "$manifest"
grep -Fxq 'headers=include' "$manifest"
grep -Fxq 'hostTools=host-tools' "$manifest"
runtime_closure_sha256="$(sed -n 's/^runtimeClosureSha256=//p' "$manifest")"
runtime_payload_bytes="$(sed -n 's/^runtimePayloadBytes=//p' "$manifest")"
build_support_payload_bytes="$(sed -n 's/^buildSupportPayloadBytes=//p' "$manifest")"
stage_payload_bytes="$(sed -n 's/^stagePayloadBytes=//p' "$manifest")"
[[ "$runtime_payload_bytes" =~ ^[1-9][0-9]*$ ]] || \
  fail "stage manifest runtime payload size is invalid"
[[ "$runtime_closure_sha256" =~ ^[[:xdigit:]]{64}$ ]] || \
  fail "stage manifest runtime closure hash is invalid"
[[ "$build_support_payload_bytes" =~ ^[1-9][0-9]*$ ]] || \
  fail "stage manifest build-support payload size is invalid"
[[ "$stage_payload_bytes" =~ ^[1-9][0-9]*$ ]] || \
  fail "stage manifest payload size is invalid"
measured_runtime_payload_bytes="$(
  du -sb -- "$stage_dir/bin" "$stage_dir/lib" |
    awk '{ total += $1 } END { print total }'
)"
measured_build_support_payload_bytes="$(
  du -sb -- "$stage_dir/include" "$stage_dir/host-tools" |
    awk '{ total += $1 } END { print total }'
)"
[[ "$runtime_payload_bytes" == "$measured_runtime_payload_bytes" ]] || \
  fail "runtime payload size was not measured from the published stage"
measured_runtime_closure_sha256="$(
  for runtime_artifact in \
    "$stage_dir/bin/vpp" \
    "$stage_dir/lib/libsvm.so" \
    "$stage_dir/lib/libvapiclient.so" \
    "$stage_dir/lib/libvlib.so" \
    "$stage_dir/lib/libvlibapi.so" \
    "$stage_dir/lib/libvlibmemory.so" \
    "$stage_dir/lib/libvlibmemoryclient.so" \
    "$stage_dir/lib/libvnet.so" \
    "$stage_dir/lib/libvppinfra.so"; do
    sha256sum "$runtime_artifact" | awk '{ print $1 }'
  done | sha256sum | awk '{ print $1 }'
)"
[[ "$runtime_closure_sha256" == "$measured_runtime_closure_sha256" ]] || \
  fail "runtime closure hash does not match the published stage"
[[ "$build_support_payload_bytes" == "$measured_build_support_payload_bytes" ]] || \
  fail "build-support payload size was not measured from the published stage"
[[ "$stage_payload_bytes" -eq $((runtime_payload_bytes + build_support_payload_bytes)) ]] || \
  fail "stage manifest payload size was not measured from the published stage"

[[ -x "$stage_dir/bin/vpp" ]] || fail "stage is missing bin/vpp"
[[ -x "$stage_dir/host-tools/vppapigen" ]] || \
  fail "stage is missing the production vppapigen host tool"
for generator in \
  vppapigen_c.py vppapigen_json.py generate_json.py \
  vapi_c_gen.py vapi_cpp_gen.py vapi_json_parser.py; do
  [[ -f "$stage_dir/host-tools/$generator" ]] || \
    fail "stage is missing host generator $generator"
done

for header in \
  vppinfra/clib.h \
  vlib/vlib.h \
  vlibapi/api.h \
  vlibmemory/api.h \
  vnet/plugin/plugin.h \
  vnet/vnet.h \
  vpp/app/version.h \
  vapi/vapi.h; do
  [[ -f "$stage_dir/include/$header" ]] || \
    fail "stage is missing external-plugin header include/$header"
done

for library in \
  libsvm.so \
  libvapiclient.so \
  libvlib.so \
  libvlibapi.so \
  libvlibmemory.so \
  libvlibmemoryclient.so \
  libvnet.so \
  libvppinfra.so; do
  artifact="$stage_dir/lib/$library"
  [[ -f "$artifact" ]] || fail "stage is missing $library"
  file -Lb "$artifact" | grep -Fq 'ARM aarch64' || \
    fail "stage artifact is not a real AArch64 ELF: $library"
done
file -Lb "$stage_dir/bin/vpp" | grep -Fq 'ARM aarch64' || \
  fail "stage bin/vpp is not a real AArch64 ELF"
file -Lb "$stage_dir/bin/vpp" | grep -Fq 'stripped' || \
  fail "stage bin/vpp retains non-release debug/symbol payload"
while IFS= read -r artifact; do
  file -Lb "$artifact" | grep -Fq 'stripped' || \
    fail "stage shared library retains non-release debug/symbol payload: $artifact"
done < <(find "$stage_dir/lib" -maxdepth 1 -type f -name '*.so*' -print)

while IFS= read -r -d '' link; do
  target="$(readlink -- "$link")"
  [[ "$target" != /* ]] || fail "stage contains an absolute symlink target"
  resolved="$(realpath -e "$link" 2>/dev/null)" || \
    fail "stage contains a dangling symlink"
  case "$resolved" in
    "$stage_dir"/*) ;;
    *) fail "stage symlink escapes the stage" ;;
  esac
done < <(find "$stage_dir" -type l -print0)

while IFS= read -r artifact; do
  basename_artifact="$(basename -- "$artifact")"
  case "$basename_artifact" in
    libsvm.so*|libvapiclient.so*|libvlib.so*|libvlibapi.so*|\
    libvlibmemory.so*|libvlibmemoryclient.so*|libvnet.so*|libvppinfra.so*) ;;
    *) fail "stage contains a non-product shared library: $basename_artifact" ;;
  esac
done < <(find "$stage_dir/lib" -maxdepth 1 \( -type f -o -type l \) -name '*.so*' -print)

poc_paths="$(cd "$stage_dir" && find . \( -type f -o -type l \) \
  \( -ipath '*poc*' -o -ipath '*experiment*' -o -ipath '*fixture*' \
  -o -ipath '*nfqueue*' -o -ipath '*hev*' -o -ipath '*sucre*' \) -print)"
if [[ -n "$poc_paths" ]]; then
  fail "retired or POC artifact entered clean VPP stage"
fi

[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$pinned_revision" ]] || \
  fail "stage build changed the input checkout revision"
[[ -z "$(git -C "$source_dir" status --porcelain)" ]] || \
  fail "stage build modified the input checkout"

echo "stage tree: bin/vpp lib/{core,client} include host-tools manifest"
echo "s172 clean VPP Android stage contract: PASS"
