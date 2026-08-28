#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
pin_file="$repo_root/src/product/vpp/pinned-vpp-revision.txt"
profile_module="$repo_root/src/product/vpp/android/apply-profile.sh"
pinned_revision="$(tr -d '[:space:]' < "$pin_file")"
source_dir="${SAKAMOTO_S172_VPP_SOURCE_DIR:-/tmp/sakamoto-172-vpp-official.6CoCcd/source-git}"
ndk_root="${SAKAMOTO_S172_ANDROID_NDK_ROOT:-/home/js/.local/share/android-sdk/ndk/29.0.14206865}"
android_api="${SAKAMOTO_S172_ANDROID_API:-31}"
android_abi="${SAKAMOTO_S172_ANDROID_ABI:-arm64-v8a}"
python_path="${SAKAMOTO_S172_VPP_PYTHONPATH:-/home/js/android/lineage/external/ply/ply}"
cmake_bin="${SAKAMOTO_S172_CMAKE:-cmake}"
llvm_readelf="$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf"
toolchain_file="$ndk_root/build/cmake/android.toolchain.cmake"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/sakamoto-172-vlibapi.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

fail() {
  echo "s172 vlibapi Android build contract: $*" >&2
  exit 1
}

[[ -f "$pin_file" ]] || fail "pinned revision file is missing"
[[ "$pinned_revision" =~ ^[[:xdigit:]]{40}$ ]] || \
  fail "pinned VPP revision is not a 40-character commit"
[[ "$android_api" == "31" ]] || \
  fail "only Android API 31 is supported by this contract"
[[ "$android_abi" == "arm64-v8a" ]] || \
  fail "only arm64-v8a is supported by this contract"
[[ -f "$toolchain_file" ]] || fail "NDK Android CMake toolchain is missing"
[[ -x "$llvm_readelf" ]] || fail "NDK llvm-readelf is missing"
[[ -d "$python_path" ]] || fail "official VPP host-tool Python dependencies are missing"
[[ -x "$profile_module" ]] || fail "Android VPP profile module is missing"

canonical_source_dir="$(realpath -e "$source_dir" 2>/dev/null)" || \
  fail "source directory cannot be canonicalized"
source_dir="$canonical_source_dir"
case "${source_dir,,}" in
  *experiments*|*poc*) fail "POC/experiment source is not permitted" ;;
esac
[[ -d "$source_dir/.git" || -f "$source_dir/.git" ]] || \
  fail "set SAKAMOTO_S172_VPP_SOURCE_DIR to a clean official VPP checkout"
[[ -f "$source_dir/src/CMakeLists.txt" ]] || \
  fail "official VPP CMake source is missing"
[[ -x "$(command -v "$cmake_bin")" ]] || fail "CMake is missing"

source_head="$(git -C "$source_dir" rev-parse HEAD)"
[[ "$source_head" == "$pinned_revision" ]] || \
  fail "official VPP source is not at the exact pinned revision"
[[ -z "$(git -C "$source_dir" status --porcelain)" ]] || \
  fail "official VPP source must remain clean"
export PYTHONPATH="$python_path${PYTHONPATH:+:$PYTHONPATH}"
export CCACHE_DIR="$work_dir/ccache"

patched_tree="$work_dir/patched-source"
bash "$profile_module" \
  --profile android-api31-arm64 \
  --source-dir "$source_dir" \
  --work-dir "$patched_tree" >"$work_dir/profile.log"
grep -Fxq "profile=android-api31-arm64" "$work_dir/profile.log" || \
  fail "profile did not select android-api31-arm64"

changed_files="$(
  git -C "$patched_tree" diff --name-only
  git -C "$patched_tree" ls-files --others --exclude-standard
  )"
changed_files="$(printf '%s\n' "$changed_files" | LC_ALL=C sort)"
expected_changed_files=$'src/CMakeLists.txt\nsrc/svm/CMakeLists.txt\nsrc/svm/message_queue.c\nsrc/svm/message_queue.h\nsrc/svm/queue.c\nsrc/svm/ssvm.c\nsrc/svm/svm.c\nsrc/svm/svm_android_file.c\nsrc/svm/svm_android_file.h\nsrc/vlib/CMakeLists.txt\nsrc/vlib/threads.c\nsrc/vlibmemory/memclnt_api.c\nsrc/vlibmemory/vlib_api_cli.c\nsrc/vnet/session/session.c\nsrc/vnet/sfdp/timer/timer.h\nsrc/vpp-api/vapi/CMakeLists.txt\nsrc/vpp/vnet/main.c\nsrc/vppinfra/CMakeLists.txt\nsrc/vppinfra/dlmalloc.h\nsrc/vppinfra/maplog.c\nsrc/vppinfra/mem_intercept.c'
[[ "$changed_files" == "$expected_changed_files" ]] || \
  fail "profile changed files outside the ordered vlibapi build slice: $changed_files"
grep -Fq 'add_vpp_library (vlibapi' \
  "$patched_tree/src/vlibapi/CMakeLists.txt" || \
  fail "official vlibapi target definition is missing"
grep -Fq 'vppinfra svm' "$patched_tree/src/vlibapi/CMakeLists.txt" || \
  fail "vlibapi production dependency closure is missing vppinfra/svm"
if grep -R -Fq 'sakamoto_product_host_fixture_abi.c' "$patched_tree/src"; then
  fail "host fixture source must never enter the Android profile"
fi
build_dir="$work_dir/build"
configure_log="$work_dir/configure.log"
configure_args=(
  -S "$patched_tree/src"
  -B "$build_dir"
  -G Ninja
  "-DCMAKE_TOOLCHAIN_FILE=$toolchain_file"
  "-DANDROID_ABI=$android_abi"
  "-DANDROID_PLATFORM=android-$android_api"
  -DCMAKE_BUILD_TYPE=Release
  -DVPP_BUILD_TESTS=OFF
  -DVPP_BUILD_VPPINFRA_TESTS=OFF
  -DVPP_BUILD_PYTHON_API=OFF
)
if ! "$cmake_bin" "${configure_args[@]}" >"$configure_log" 2>&1; then
  sed -n '1,220p' "$configure_log" >&2
  fail "patched Android profile did not configure"
fi

grep -Fxq "CMAKE_TOOLCHAIN_FILE:FILEPATH=$toolchain_file" \
  "$build_dir/CMakeCache.txt" || \
  fail "configure did not use the direct NDK Android toolchain"
grep -Fxq "ANDROID_ABI:UNINITIALIZED=$android_abi" \
  "$build_dir/CMakeCache.txt" || fail "configure ABI is not arm64-v8a"
grep -Fxq "ANDROID_PLATFORM:UNINITIALIZED=android-$android_api" \
  "$build_dir/CMakeCache.txt" || fail "configure API is not android-31"

build_log="$work_dir/vlibapi-build.log"
if ! "$cmake_bin" --build "$build_dir" --target vlibapi \
  --parallel "${SAKAMOTO_S172_BUILD_JOBS:-2}" >"$build_log" 2>&1; then
  echo "RED: vlibapi target build failed; first compiler/linker evidence:" >&2
  sed -n '/error:/p; /fatal error:/p; /undefined reference/p' "$build_log" | \
    sed -n '1,80p' >&2
  sed -n '1,120p' "$build_log" >&2
  fail "Android vlibapi target did not build"
fi

artifact="$build_dir/lib/aarch64-linux-android/libvlibapi.so"
[[ -f "$artifact" ]] || fail "vlibapi shared library was not produced"
file -Lb "$artifact" | grep -Fq 'ARM aarch64' || \
  fail "vlibapi shared library is not a real AArch64 ELF"

dynamic_log="$work_dir/vlibapi-dynamic.log"
if ! "$llvm_readelf" -d "$artifact" >"$dynamic_log" 2>&1; then
  sed -n '1,120p' "$dynamic_log" >&2
  fail "NDK llvm-readelf could not parse the vlibapi artifact"
fi
needed="$work_dir/vlibapi-needed.txt"
sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' \
  "$dynamic_log" >"$needed"
needed_count="$(awk '/\(NEEDED\)/ { count++ } END { print count + 0 }' "$dynamic_log")"
parsed_count="$(wc -l <"$needed")"
[[ "$needed_count" -gt 0 ]] || fail "vlibapi artifact has no parsed DT_NEEDED entries"
[[ "$needed_count" == "$parsed_count" ]] || \
  fail "NDK llvm-readelf DT_NEEDED entries were not all parsed"
while IFS= read -r needed_name; do
  case "$needed_name" in
    libc.so|libdl.so|libm.so|libsvm.so|libvppinfra.so) ;;
    *) fail "unexpected non-Android DT_NEEDED library: $needed_name" ;;
  esac
done <"$needed"
echo "DT_NEEDED: $(tr '\n' ' ' <"$needed")"

[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$source_head" ]] || \
  fail "build modified the input checkout revision"
[[ -z "$(git -C "$source_dir" status --porcelain)" ]] || \
  fail "build modified the input checkout"

echo "GREEN: direct NDK API ${android_api}/${android_abi} built real libvlibapi.so"
echo "s172 vlibapi Android build contract: PASS"
