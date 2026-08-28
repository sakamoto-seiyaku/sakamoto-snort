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
ninja_bin="${SAKAMOTO_S172_NINJA:-ninja}"
toolchain_file="$ndk_root/build/cmake/android.toolchain.cmake"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/sakamoto-172-vpp-cmake.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

fail() {
  echo "s172 VPP Android CMake profile contract: $*" >&2
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
[[ -x "$(command -v "$ninja_bin")" ]] || fail "Ninja is missing"

source_head="$(git -C "$source_dir" rev-parse HEAD)"
[[ "$source_head" == "$pinned_revision" ]] || \
  fail "official VPP source is not at the exact pinned revision"
[[ -z "$(git -C "$source_dir" status --porcelain)" ]] || \
  fail "official VPP source must remain clean"
export PYTHONPATH="$python_path${PYTHONPATH:+:$PYTHONPATH}"

configure_args=(
  -S "$source_dir/src"
  -B "$work_dir/red-build"
  -G Ninja
  "-DCMAKE_TOOLCHAIN_FILE=$toolchain_file"
  "-DANDROID_ABI=$android_abi"
  "-DANDROID_PLATFORM=android-$android_api"
  -DCMAKE_BUILD_TYPE=Release
  -DVPP_BUILD_TESTS=OFF
  -DVPP_BUILD_VPPINFRA_TESTS=OFF
  -DVPP_BUILD_PYTHON_API=OFF
)

red_log="$work_dir/red-configure.log"
if "$cmake_bin" "${configure_args[@]}" >"$red_log" 2>&1; then
  fail "unpatched clean pin unexpectedly configured for Android"
fi
grep -Fq "Unsupported system: Android" "$red_log" || {
  sed -n '1,160p' "$red_log" >&2
  fail "RED did not fail at the official Android system acceptance guard"
}
echo "RED: clean pin + NDK API ${android_api}/${android_abi} fails at Unsupported system: Android"

patched_tree="$work_dir/patched-source"
profile_log="$work_dir/profile.log"
bash "$profile_module" \
  --profile android-api31-arm64 \
  --source-dir "$source_dir" \
  --work-dir "$patched_tree" >"$profile_log"
grep -Fxq "profile=android-api31-arm64" "$profile_log" || \
  fail "profile did not select android-api31-arm64"

[[ "$(git -C "$patched_tree" rev-parse HEAD)" == "$pinned_revision" ]] || \
  fail "profile changed the pinned revision"
changed_files="$(git -C "$patched_tree" diff --name-only)"
expected_changed_files=$'src/CMakeLists.txt\nsrc/vppinfra/CMakeLists.txt\nsrc/vppinfra/dlmalloc.h\nsrc/vppinfra/maplog.c\nsrc/vppinfra/mem_intercept.c'
[[ "$changed_files" == "$expected_changed_files" ]] || \
  fail "profile changed files outside the ordered Android patch series: $changed_files"
[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$source_head" ]] || \
  fail "profile modified the input checkout revision"
[[ -z "$(git -C "$source_dir" status --porcelain)" ]] || \
  fail "profile modified the input checkout"

green_build="$work_dir/green-build"
green_log="$work_dir/green-configure.log"
green_args=(
  -S "$patched_tree/src"
  -B "$green_build"
  -G Ninja
  "-DCMAKE_TOOLCHAIN_FILE=$toolchain_file"
  "-DANDROID_ABI=$android_abi"
  "-DANDROID_PLATFORM=android-$android_api"
  -DCMAKE_BUILD_TYPE=Release
  -DVPP_BUILD_TESTS=OFF
  -DVPP_BUILD_VPPINFRA_TESTS=OFF
  -DVPP_BUILD_PYTHON_API=OFF
)
if ! "$cmake_bin" "${green_args[@]}" >"$green_log" 2>&1; then
  sed -n '1,220p' "$green_log" >&2
  fail "patched Android profile did not configure with the official NDK toolchain"
fi

grep -Fxq "CMAKE_TOOLCHAIN_FILE:FILEPATH=$toolchain_file" \
  "$green_build/CMakeCache.txt" || \
  fail "configure did not use the official NDK android.toolchain.cmake"
grep -R -F -q 'set(CMAKE_SYSTEM_NAME "Android")' "$green_build/CMakeFiles" || \
  fail "configure did not retain Android as the target system"
! grep -R -F -q 'set(CMAKE_SYSTEM_NAME "Linux")' "$green_build/CMakeFiles" || \
  fail "configure was disguised as a Linux target"
grep -Fxq "ANDROID_ABI:UNINITIALIZED=$android_abi" "$green_build/CMakeCache.txt" || \
  fail "configure ABI is not arm64-v8a"
grep -Fxq "ANDROID_PLATFORM:UNINITIALIZED=android-$android_api" \
  "$green_build/CMakeCache.txt" || fail "configure API is not android-31"

rules_file="$green_build/CMakeFiles/rules.ninja"
[[ -f "$rules_file" ]] || fail "Ninja compiler rules are missing"
grep -Eq -- '(--target=aarch64-none-linux-android31|-triple aarch64-none-linux-android31)' \
  "$green_build/CMakeFiles/CMakeOutput.log" || \
  fail "NDK compiler target lost the API 31 suffix"
if grep -Fq -- '--target=aarch64-linux-android' "$rules_file"; then
  fail "VPP profile overwrote the NDK API 31 compiler target with bare aarch64-linux-android"
fi
grep -Eq -- '--target=aarch64-none-linux-android31' "$rules_file" || \
  fail "Ninja rules do not retain the NDK aarch64 Android API 31 target"

targets="$work_dir/ninja-targets.txt"
"$ninja_bin" -C "$green_build" -t targets all >"$targets"
grep -Eq '^vpp(:|[[:space:]])' "$targets" || \
  fail "configured build.ninja has no public vpp target"
grep -Eq '^vapiclient(:|[[:space:]])' "$targets" || \
  fail "configured build.ninja has no public vapiclient target"
for excluded_dir in vat vat2 vcl plugins drivers crypto_engines pkg; do
  if grep -Eq "^CMakeFiles/${excluded_dir}(/|:)" "$targets"; then
    fail "Android profile unexpectedly configured ${excluded_dir}"
  fi
done
for excluded_tool in g2 perftool appimage; do
  if grep -Eq "^CMakeFiles/tools/${excluded_tool}(/|:)" "$targets"; then
    fail "Android profile unexpectedly configured tools/${excluded_tool}"
  fi
done

echo "GREEN: pinned Android profile configures vpp and vapiclient with the direct NDK toolchain"
echo "s172 VPP Android CMake profile contract: PASS"
