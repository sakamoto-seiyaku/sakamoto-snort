#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
pin_file="$repo_root/src/product/vpp/pinned-vpp-revision.txt"
profile_module="$repo_root/src/product/vpp/android/apply-profile.sh"
pinned_revision="$(tr -d '[:space:]' < "$pin_file")"
source_dir="${SAKAMOTO_S172_VPP_SOURCE_DIR:-/tmp/sakamoto-172-vpp-official.6CoCcd/source-git}"
ndk_root="${SAKAMOTO_S172_ANDROID_NDK_ROOT:-/home/js/.local/share/android-sdk/ndk/29.0.14206865}"
android_api="${SAKAMOTO_S172_ANDROID_API:-31}"
ndk_bin="$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin"
android_clang="$ndk_bin/aarch64-linux-android${android_api}-clang"
llvm_nm="$ndk_bin/llvm-nm"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/sakamoto-172-dlmallinfo.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

fail() {
  echo "s172 dlmallinfo Android profile contract: $*" >&2
  exit 1
}

[[ -f "$pin_file" ]] || fail "pinned revision file is missing"
[[ "$pinned_revision" =~ ^[[:xdigit:]]{40}$ ]] || \
  fail "pinned revision is not a 40-character commit"
[[ "$android_api" == "31" ]] || fail "only Android API 31 is supported by this contract"
canonical_source_dir="$(realpath -e "$source_dir" 2>/dev/null)" || \
  fail "source directory cannot be canonicalized"
source_dir="$canonical_source_dir"
case "${source_dir,,}" in
  *experiments*|*poc*) fail "POC/experiment source is not permitted" ;;
esac
[[ -d "$source_dir/.git" || -f "$source_dir/.git" ]] || \
  fail "set SAKAMOTO_S172_VPP_SOURCE_DIR to a clean official VPP checkout"
[[ -x "$android_clang" ]] || fail "Android API ${android_api} clang is missing"
[[ -x "$llvm_nm" ]] || fail "Android llvm-nm is missing"

source_head="$(git -C "$source_dir" rev-parse HEAD)"
[[ "$source_head" == "$pinned_revision" ]] || \
  fail "official VPP source is not at the exact pinned revision"
[[ -z "$(git -C "$source_dir" status --porcelain)" ]] || \
  fail "official VPP source must remain clean"

make_config_include() {
  local tree="$1"
  local include_dir="$tree/.s172-generated"
  mkdir -p "$include_dir/vppinfra"
  printf '%s\n' \
    '#ifndef included_clib_config_h' \
    '#define included_clib_config_h' \
    '#define CLIB_LOG2_CACHE_LINE_BYTES 6' \
    '#define CLIB_N_PREFETCHES 6' \
    '#define CLIB_LIB_DIR ""' \
    '#define CLIB_VECTOR_GROW_BY_ONE 0' \
    '#endif' > "$include_dir/vppinfra/config.h"
  printf '%s\n' "$include_dir"
}

compile_mem_dlmalloc() {
  local tree="$1"
  local output="$2"
  local log="$3"
  local generated_include
  generated_include="$(make_config_include "$tree")"
  "$android_clang" \
    -std=gnu11 \
    -D_FORTIFY_SOURCE=2 \
    -I"$generated_include" \
    -I"$tree/src" \
    -Wno-error=user-defined-warnings \
    -fPIC -g -Werror -Wall -Wno-address-of-packed-member \
    -O3 -fstack-protector -fno-common -march=armv8-a+crc \
    -c "$tree/src/vppinfra/mem_dlmalloc.c" \
    -o "$output" >"$log" 2>&1
}

clone_at_pin() {
  local destination="$1"
  git clone --no-local --no-checkout "$source_dir" "$destination" >/dev/null
  git -C "$destination" checkout --detach "$pinned_revision" >/dev/null
}

# RED: the exact clean source must fail for the known Android guard collision.
red_tree="$work_dir/red-source"
clone_at_pin "$red_tree"
red_object="$work_dir/red-mem_dlmalloc.o"
red_log="$work_dir/red.log"

# RED provenance: use the actual Android NDK preprocessor before compiling so
# the guard collision is independently visible in the test evidence.
"$android_clang" \
  -E -dM -x c \
  -I"$red_tree/src" \
  -include stdlib.h \
  -include "$red_tree/src/vppinfra/dlmalloc.h" \
  /dev/null > "$work_dir/red-macros.txt" 2> "$work_dir/red-preprocess.log"
grep -Fxq '#define STRUCT_MALLINFO_DECLARED 1' "$work_dir/red-macros.txt" || \
  fail "RED preprocessor evidence did not expose STRUCT_MALLINFO_DECLARED=1"
grep -Fxq '#define NO_MALLINFO 0' "$work_dir/red-macros.txt" || \
  fail "RED preprocessor evidence did not expose NO_MALLINFO=0"

if compile_mem_dlmalloc "$red_tree" "$red_object" "$red_log"; then
  fail "unpatched official mem_dlmalloc.c unexpectedly compiled"
fi
red_errors="$work_dir/red-errors.txt"
grep 'error:' "$red_log" > "$red_errors" || {
  sed -n '1,120p' "$red_log" >&2
  fail "RED compile emitted no clang error diagnostics"
}
while IFS= read -r error_line; do
  case "$error_line" in
    *"variable has incomplete type 'struct dlmallinfo'"*|\
    *"calling 'mspace_mallinfo' with incomplete return type 'struct dlmallinfo'"*)
      ;;
    *)
      sed -n '1,120p' "$red_log" >&2
      fail "RED compile has a non-dlmallinfo error: $error_line"
      ;;
  esac
done < "$red_errors"
grep -Eq "incomplete type 'struct dlmallinfo'|incomplete return type 'struct dlmallinfo'" \
  "$red_errors" || fail "RED compile did not reproduce the dlmallinfo guard collision"
echo "RED: clean pin + Android API ${android_api} fails only at dlmallinfo guard"

[[ -x "$profile_module" ]] || fail "Android VPP profile module is missing"
patched_tree="$work_dir/patched-source"
bash "$profile_module" \
  --profile android-dlmallinfo \
  --source-dir "$source_dir" \
  --work-dir "$patched_tree"

[[ "$(git -C "$patched_tree" rev-parse HEAD)" == "$pinned_revision" ]] || \
  fail "profile changed the pinned revision"
changed_files="$(git -C "$patched_tree" diff --name-only)"
[[ "$changed_files" == "src/vppinfra/dlmalloc.h" ]] || \
  fail "profile changed files outside src/vppinfra/dlmalloc.h: $changed_files"
[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$source_head" ]] || \
  fail "profile modified the input checkout revision"
[[ -z "$(git -C "$source_dir" status --porcelain)" ]] || \
  fail "profile modified the input checkout"

green_object="$work_dir/green-mem_dlmalloc.o"
green_log="$work_dir/green.log"
compile_mem_dlmalloc "$patched_tree" "$green_object" "$green_log"
file -Lb "$green_object" | grep -Fq 'ARM aarch64' || \
  fail "compiled object is not a real AArch64 relocatable object"
"$llvm_nm" -u "$green_object" | grep -Eq '[[:space:]]mspace_mallinfo$' || \
  fail "compiled object lost the mspace_mallinfo dependency"

probe="$work_dir/dlmallinfo-semantics.c"
printf '%s\n' \
  '#include <stddef.h>' \
  '#include <stdlib.h>' \
  '#include <vppinfra/dlmalloc.h>' \
  '_Static_assert(sizeof(struct dlmallinfo) == 10 * sizeof(size_t), "dlmallinfo field count changed");' \
  '_Static_assert(offsetof(struct dlmallinfo, arena) == 0 * sizeof(size_t), "arena layout changed");' \
  '_Static_assert(offsetof(struct dlmallinfo, ordblks) == 1 * sizeof(size_t), "ordblks layout changed");' \
  '_Static_assert(offsetof(struct dlmallinfo, smblks) == 2 * sizeof(size_t), "smblks layout changed");' \
  '_Static_assert(offsetof(struct dlmallinfo, hblks) == 3 * sizeof(size_t), "hblks layout changed");' \
  '_Static_assert(offsetof(struct dlmallinfo, hblkhd) == 4 * sizeof(size_t), "hblkhd layout changed");' \
  '_Static_assert(offsetof(struct dlmallinfo, usmblks) == 5 * sizeof(size_t), "usmblks layout changed");' \
  '_Static_assert(offsetof(struct dlmallinfo, fsmblks) == 6 * sizeof(size_t), "fsmblks layout changed");' \
  '_Static_assert(offsetof(struct dlmallinfo, uordblks) == 7 * sizeof(size_t), "uordblks layout changed");' \
  '_Static_assert(offsetof(struct dlmallinfo, fordblks) == 8 * sizeof(size_t), "fordblks layout changed");' \
  '_Static_assert(offsetof(struct dlmallinfo, keepcost) == 9 * sizeof(size_t), "keepcost layout changed");' \
  'static struct dlmallinfo (*const mallinfo_signature)(mspace) = mspace_mallinfo;' \
  'int main(void) { return mallinfo_signature != NULL; }' > "$probe"
green_include="$patched_tree/.s172-generated"
"$android_clang" \
  -std=gnu11 -I"$green_include" -I"$patched_tree/src" \
  -fPIC -Werror -c "$probe" -o "$work_dir/dlmallinfo-semantics.o"

echo "GREEN: pinned Android profile preserves dlmallinfo layout and mspace_mallinfo"
echo "s172 dlmallinfo Android profile contract: PASS"
