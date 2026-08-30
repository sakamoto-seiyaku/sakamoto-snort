#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.." && pwd)"
pin_file="$repo_root/src/product/vpp/pinned-vpp-revision.txt"
profile_module="$repo_root/src/product/vpp/android/apply-profile.sh"
source_dir=""
stage_dir=""
android_api="${SAKAMOTO_S172_ANDROID_API:-31}"
android_abi="${SAKAMOTO_S172_ANDROID_ABI:-arm64-v8a}"
profile_name=android-api31-arm64
ndk_root="${SAKAMOTO_S172_ANDROID_NDK_ROOT:-/home/js/.local/share/android-sdk/ndk/29.0.14206865}"
python_path="${SAKAMOTO_S172_VPP_PYTHONPATH:-/home/js/android/lineage/external/ply/ply}"
cmake_bin="${SAKAMOTO_S172_CMAKE:-cmake}"
build_jobs="${SAKAMOTO_S172_BUILD_JOBS:-2}"
stage_marker_value="sakamoto-android-vpp-stage/v1"
expected_patch_series_count=17
expected_patch_series_sha256=0fedcc6f52070d45f934afa76e23a2aae54beb75cc9d8037d879c80275d6878e
python_bin="$(command -v python3 2>/dev/null || true)"
flock_bin="$(command -v flock 2>/dev/null || true)"

usage() {
  cat >&2 <<'EOF'
usage: build-stage.sh --source-dir DIR --stage-dir DIR

Build the exact pinned official VPP Android profile with the direct NDK
toolchain and atomically publish a caller-owned arm64-v8a stage.
EOF
}

die() {
  echo "Android VPP stage: $*" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source-dir)
      [[ $# -ge 2 ]] || die "--source-dir requires a value"
      source_dir="$2"
      shift 2
      ;;
    --stage-dir)
      [[ $# -ge 2 ]] || die "--stage-dir requires a value"
      stage_dir="$2"
      shift 2
      ;;
    --android-api)
      [[ $# -ge 2 ]] || die "--android-api requires a value"
      android_api="$2"
      shift 2
      ;;
    --android-abi)
      [[ $# -ge 2 ]] || die "--android-abi requires a value"
      android_abi="$2"
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

[[ -n "$source_dir" ]] || die "--source-dir is required"
[[ -n "$stage_dir" ]] || die "--stage-dir is required"
[[ "$stage_dir" != "/" ]] || die "stage directory cannot be the filesystem root"
[[ "$android_api" == "31" ]] || \
  die "only Android API 31 is supported by this stage"
[[ "$android_abi" == "arm64-v8a" ]] || \
  die "only arm64-v8a is supported by this stage"
[[ -f "$pin_file" ]] || die "pinned VPP revision file is missing"
[[ -x "$profile_module" ]] || die "Android VPP profile module is missing"
[[ -x "$(command -v "$cmake_bin")" ]] || die "CMake is missing"
[[ -n "$python_bin" && -x "$python_bin" ]] || die "host Python3 is missing"
[[ -n "$flock_bin" && -x "$flock_bin" ]] || die "host flock is missing"
toolchain_file="$ndk_root/build/cmake/android.toolchain.cmake"
llvm_readelf="$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf"
llvm_strip="$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"
[[ -f "$toolchain_file" ]] || die "NDK Android CMake toolchain is missing"
[[ -x "$llvm_readelf" ]] || die "NDK llvm-readelf is missing"
[[ -x "$llvm_strip" ]] || die "NDK llvm-strip is missing"
[[ -d "$python_path" ]] || die "official VPP host-tool Python dependencies are missing"

pinned_revision="$(tr -d '[:space:]' < "$pin_file")"
[[ "$pinned_revision" =~ ^[[:xdigit:]]{40}$ ]] || \
  die "pinned VPP revision is not a 40-character commit"

canonical_source_dir="$(realpath -e "$source_dir" 2>/dev/null)" || \
  die "source directory cannot be canonicalized"
source_dir="$canonical_source_dir"
case "${source_dir,,}" in
  *experiments*|*poc*) die "POC/experiment source is not permitted" ;;
esac
[[ -d "$source_dir/.git" || -f "$source_dir/.git" ]] || \
  die "source directory is not a Git checkout"
source_head="$(git -C "$source_dir" rev-parse HEAD)"
[[ "$source_head" == "$pinned_revision" ]] || \
  die "source checkout is not at the product's pinned revision"
[[ -z "$(git -C "$source_dir" status --porcelain)" ]] || \
  die "source checkout must be clean"

stage_parent_input="$(dirname -- "$stage_dir")"
stage_name="$(basename -- "$stage_dir")"
[[ -n "$stage_name" && "$stage_name" != "." && "$stage_name" != ".." ]] || \
  die "stage directory name is invalid"
mkdir -p -- "$stage_parent_input"
stage_parent="$(realpath -e "$stage_parent_input" 2>/dev/null)" || \
  die "stage parent cannot be canonicalized"
stage_dir="$stage_parent/$stage_name"

stage_lock_file="$stage_parent/.${stage_name}.lock"
[[ ! -L "$stage_lock_file" ]] || die "stage lock path is a symlink"
exec {stage_lock_fd}>"$stage_lock_file" || die "cannot open stage lock"
"$flock_bin" -x "$stage_lock_fd" || die "cannot acquire stage lock"

assert_owned_stage() {
  local existing_marker="$stage_dir/.sakamoto-android-vpp-stage"
  [[ -d "$stage_dir" && ! -L "$stage_dir" ]] || \
    die "output stage exists without an owned marker"
  [[ -f "$existing_marker" && ! -L "$existing_marker" ]] || \
    die "output stage exists without an owned marker"
  [[ "$(<"$existing_marker")" == "$stage_marker_value" ]] || \
    die "output stage exists without an owned marker"
}

if [[ -e "$stage_dir" || -L "$stage_dir" ]]; then
  assert_owned_stage
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/sakamoto-172-vpp-stage.XXXXXX")"
ccache_dir="${SAKAMOTO_S172_CCACHE_DIR:-$work_dir/ccache}"
mkdir -p -- "$ccache_dir"
export CCACHE_DIR="$ccache_dir"
candidate_dir=""
cleanup() {
  if [[ -n "$candidate_dir" && -e "$candidate_dir" ]]; then
    rm -rf -- "$candidate_dir"
  fi
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

patched_source="$work_dir/patched-source"
SAKAMOTO_S172_ANDROID_API="$android_api" \
SAKAMOTO_S172_ANDROID_ABI="$android_abi" \
  bash "$profile_module" \
    --profile "$profile_name" \
    --source-dir "$source_dir" \
    --work-dir "$patched_source" >"$work_dir/profile.log"
patch_series_count="$(sed -n 's/^patchSeriesCount=//p' "$work_dir/profile.log")"
patch_series_sha256="$(sed -n 's/^patchSeriesSha256=//p' "$work_dir/profile.log")"
[[ "$patch_series_count" =~ ^[1-9][0-9]*$ ]] || \
  die "profile did not report a valid patch series count"
[[ "$patch_series_sha256" =~ ^[[:xdigit:]]{64}$ ]] || \
  die "profile did not report a valid patch series hash"
[[ "$patch_series_count" == "$expected_patch_series_count" ]] || \
  die "profile patch series count does not match the product allowlist"
[[ "$patch_series_sha256" == "$expected_patch_series_sha256" ]] || \
  die "profile patch series hash does not match the product allowlist"

export PYTHONPATH="$python_path${PYTHONPATH:+:$PYTHONPATH}"
build_dir="$work_dir/build"
install_dir="$work_dir/install"
configure_args=(
  -S "$patched_source/src"
  -B "$build_dir"
  -G Ninja
  "-DCMAKE_TOOLCHAIN_FILE=$toolchain_file"
  "-DANDROID_ABI=$android_abi"
  "-DANDROID_PLATFORM=android-$android_api"
  "-DCMAKE_BUILD_TYPE=Release"
  "-DCMAKE_INSTALL_PREFIX=$install_dir"
  -DCMAKE_INSTALL_BINDIR=bin
  -DCMAKE_INSTALL_LIBDIR=lib
  -DCMAKE_INSTALL_INCLUDEDIR=include
  -DVPP_RUNTIME_DIR=bin
  -DVPP_LIBRARY_DIR=lib
  -DVPP_SET_RPATH=OFF
  -DVPP_BUILD_TESTS=OFF
  -DVPP_BUILD_VPPINFRA_TESTS=OFF
  -DVPP_BUILD_PYTHON_API=OFF
  -DVPP_MARCH_VARIANT_OCTEONTX2=OFF
  -DVPP_MARCH_VARIANT_THUNDERX2T99=OFF
  -DVPP_MARCH_VARIANT_CORTEXA72=OFF
  -DVPP_MARCH_VARIANT_NEOVERSEN1=OFF
  -DVPP_MARCH_VARIANT_NEOVERSEV2=OFF
  -DSAKAMOTO_VPP_NO_IPSEC=ON
  -DSAKAMOTO_VPP_ANDROID_IDLE_PROFILE=ON
)
if ! "$cmake_bin" "${configure_args[@]}" >"$work_dir/configure.log" 2>&1; then
  sed -n '1,220p' "$work_dir/configure.log" >&2
  die "direct NDK Android configure failed"
fi

if ! "$cmake_bin" --build "$build_dir" --target vpp vapiclient \
    --parallel "$build_jobs" >"$work_dir/build.log" 2>&1; then
  sed -n '/error:/p; /fatal error:/p; /undefined reference/p' \
    "$work_dir/build.log" | sed -n '1,80p' >&2
  sed -n '1,120p' "$work_dir/build.log" >&2
  die "vpp and vapiclient targets did not build"
fi

for component in libvppinfra libvppinfra-dev vpp-dev; do
  if ! "$cmake_bin" --install "$build_dir" --component "$component" \
      >"$work_dir/install-$component.log" 2>&1; then
    sed -n '1,160p' "$work_dir/install-$component.log" >&2
    die "CMake component install failed: $component"
  fi
done

candidate_dir="$(mktemp -d "$stage_parent/.${stage_name}.build.XXXXXX")"
mkdir -p "$candidate_dir/bin" "$candidate_dir/lib" \
  "$candidate_dir/include" "$candidate_dir/host-tools"

copy_required() {
  local input="$1"
  local output="$2"
  [[ -e "$input" || -L "$input" ]] || die "required staged input is missing: $input"
  cp -a -- "$input" "$output"
}

copy_required "$build_dir/bin/vpp" "$candidate_dir/bin/vpp"
[[ -x "$candidate_dir/bin/vpp" ]] || die "installed vpp executable is not runnable"

for library in \
  libsvm.so \
  libvapiclient.so \
  libvlib.so \
  libvlibapi.so \
  libvlibmemory.so \
  libvlibmemoryclient.so \
  libvnet.so \
  libvppinfra.so; do
  matches=("$build_dir/lib/${library}"*)
  [[ -e "${matches[0]}" || -L "${matches[0]}" ]] || \
    die "installed library family is missing: $library"
  for artifact in "${matches[@]}"; do
    [[ -e "$artifact" || -L "$artifact" ]] || continue
    cp -a -- "$artifact" "$candidate_dir/lib/"
  done
  [[ -e "$candidate_dir/lib/$library" || -L "$candidate_dir/lib/$library" ]] || \
    die "installed library SONAME link is missing: $library"
done

[[ -d "$install_dir/include" ]] || die "CMake vpp-dev include install is missing"
cp -a -- "$install_dir/include/." "$candidate_dir/include/"

copy_host_tool() {
  local input="$1"
  local output_name="$2"
  copy_required "$input" "$candidate_dir/host-tools/$output_name"
}

copy_host_tool "$install_dir/bin/vppapigen" vppapigen
for generator in vppapigen_c.py vppapigen_json.py generate_json.py; do
  copy_host_tool "$install_dir/share/vpp/$generator" "$generator"
done
for generator in vapi_c_gen.py vapi_cpp_gen.py vapi_json_parser.py; do
  copy_host_tool "$install_dir/bin/$generator" "$generator"
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
  [[ -f "$candidate_dir/include/$header" ]] || \
    die "CMake vpp-dev install omitted external-plugin header: $header"
done

elf_is_aarch64() {
  "$llvm_readelf" -h "$1" 2>/dev/null |
    grep -Eq '^[[:space:]]*Machine:[[:space:]]+AArch64([[:space:]]|$)'
}

elf_needed_is_allowed() {
  local artifact="$1"
  local dynamic_log="$work_dir/$(basename -- "$artifact").dynamic"
  local needed_name
  "$llvm_readelf" -d "$artifact" >"$dynamic_log" 2>/dev/null || return 1
  while IFS= read -r needed_name; do
    case "$needed_name" in
      libc.so|libdl.so|libm.so|libsvm.so|libvapiclient.so|\
      libvlib.so|libvlibapi.so|libvlibmemory.so|libvlibmemoryclient.so|\
      libvnet.so|libvppinfra.so) ;;
      *) echo "unexpected DT_NEEDED for $(basename -- "$artifact"): $needed_name" >&2; return 1 ;;
    esac
  done < <(sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' "$dynamic_log")
}

for artifact in "$candidate_dir/bin/vpp" "$candidate_dir"/lib/*.so*; do
  [[ -f "$artifact" && ! -L "$artifact" ]] || continue
  "$llvm_strip" --strip-unneeded "$artifact" || \
    die "failed to strip Android release ELF: $artifact"
done

for artifact in "$candidate_dir/bin/vpp" "$candidate_dir"/lib/*.so*; do
  [[ -e "$artifact" || -L "$artifact" ]] || continue
  elf_is_aarch64 "$artifact" || die "staged artifact is not a real AArch64 ELF: $artifact"
  elf_needed_is_allowed "$artifact" || die "staged artifact has an invalid Android dependency closure: $artifact"
done

validate_staged_symlinks() {
  local root="$1"
  local link target resolved
  while IFS= read -r -d '' link; do
    target="$(readlink -- "$link")" || die "cannot read staged symlink: $link"
    [[ "$target" != /* ]] || die "staged symlink uses an absolute target: $link"
    resolved="$(realpath -e "$link" 2>/dev/null)" || \
      die "staged symlink is dangling: $link"
    case "$resolved" in
      "$root"/*) ;;
      *) die "staged symlink escapes the stage: $link" ;;
    esac
  done < <(find "$root" -type l -print0)
}

validate_staged_symlinks "$candidate_dir"

runtime_closure_sha256="$(
  for runtime_artifact in \
    "$candidate_dir/bin/vpp" \
    "$candidate_dir/lib/libsvm.so" \
    "$candidate_dir/lib/libvapiclient.so" \
    "$candidate_dir/lib/libvlib.so" \
    "$candidate_dir/lib/libvlibapi.so" \
    "$candidate_dir/lib/libvlibmemory.so" \
    "$candidate_dir/lib/libvlibmemoryclient.so" \
    "$candidate_dir/lib/libvnet.so" \
    "$candidate_dir/lib/libvppinfra.so"; do
    sha256sum "$runtime_artifact" | awk '{ print $1 }'
  done | sha256sum | awk '{ print $1 }'
)"
[[ "$runtime_closure_sha256" =~ ^[[:xdigit:]]{64}$ ]] || \
  die "runtime closure hash is invalid"

poc_paths="$(cd "$candidate_dir" && find . \( -type f -o -type l \) \
  \( -ipath '*poc*' -o -ipath '*experiment*' -o -ipath '*fixture*' \
  -o -ipath '*nfqueue*' -o -ipath '*hev*' -o -ipath '*sucre*' \) -print)"
if [[ -n "$poc_paths" ]]; then
  die "retired or POC artifact entered clean VPP stage"
fi

runtime_payload_bytes="$(
  du -sb -- "$candidate_dir/bin" "$candidate_dir/lib" |
    awk '{ total += $1 } END { print total }'
)"
build_support_payload_bytes="$(
  du -sb -- "$candidate_dir/include" "$candidate_dir/host-tools" |
    awk '{ total += $1 } END { print total }'
)"
stage_payload_bytes=$((runtime_payload_bytes + build_support_payload_bytes))
[[ "$runtime_payload_bytes" =~ ^[1-9][0-9]*$ ]] || \
  die "runtime payload size measurement is invalid"
[[ "$build_support_payload_bytes" =~ ^[1-9][0-9]*$ ]] || \
  die "build-support payload size measurement is invalid"
[[ "$stage_payload_bytes" =~ ^[1-9][0-9]*$ ]] || \
  die "stage payload size measurement is invalid"

printf '%s\n' "$stage_marker_value" >"$candidate_dir/.sakamoto-android-vpp-stage"
cat >"$candidate_dir/android-vpp-stage.properties" <<EOF
schema=$stage_marker_value
revision=$source_head
profile=$profile_name
runtimeClosureSha256=$runtime_closure_sha256
runtimePayloadBytes=$runtime_payload_bytes
buildSupportPayloadBytes=$build_support_payload_bytes
stagePayloadBytes=$stage_payload_bytes
patchSeriesCount=$patch_series_count
patchSeriesSha256=$patch_series_sha256
api=$android_api
abi=$android_abi
binary=bin/vpp
libraries=lib
headers=include
hostTools=host-tools
EOF

[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$source_head" ]] || \
  die "stage build changed the input checkout revision"
[[ -z "$(git -C "$source_dir" status --porcelain)" ]] || \
  die "stage build modified the input checkout"

publish_stage_atomic() {
  local operation="$1"
  local target="$2"
  local candidate="$3"
  "$python_bin" - "$operation" "$target" "$candidate" <<'PY'
import ctypes
import os
import sys

AT_FDCWD = -100
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2
operation = sys.argv[1]
target_path = os.fsencode(sys.argv[2])
candidate_path = os.fsencode(sys.argv[3])
flags_by_operation = {
    "fresh": RENAME_NOREPLACE,
    "exchange": RENAME_EXCHANGE,
}
try:
    flags = flags_by_operation[operation]
except KeyError:
    print(f"unknown atomic stage operation: {operation}", file=sys.stderr)
    raise SystemExit(2)

try:
    renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
except AttributeError:
    print("host libc does not provide renameat2", file=sys.stderr)
    raise SystemExit(1)

renameat2.argtypes = [
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_uint,
]
renameat2.restype = ctypes.c_int
if renameat2(
    AT_FDCWD,
    candidate_path,
    AT_FDCWD,
    target_path,
    flags,
) != 0:
    error_number = ctypes.get_errno()
    raise OSError(error_number, os.strerror(error_number))
PY
}

if [[ -e "$stage_dir" || -L "$stage_dir" ]]; then
  assert_owned_stage
  if ! publish_stage_atomic exchange "$stage_dir" "$candidate_dir"; then
    die "atomic stage exchange is unavailable"
  fi
  old_stage_dir="$candidate_dir"
  candidate_dir=""
  rm -rf -- "$old_stage_dir"
else
  if ! publish_stage_atomic fresh "$stage_dir" "$candidate_dir"; then
    die "atomic stage publication failed; output appeared during build or atomic no-replace is unavailable"
  fi
  candidate_dir=""
fi

echo "stage=$stage_dir"
echo "revision=$source_head"
echo "patchSeriesCount=$patch_series_count"
echo "patchSeriesSha256=$patch_series_sha256"
echo "api=$android_api"
echo "abi=$android_abi"
echo "GREEN: direct NDK API 31/arm64-v8a built and staged vpp/vapiclient closure"
