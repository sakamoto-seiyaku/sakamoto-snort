#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
profile_module="$repo_root/src/product/vpp/android/apply-profile.sh"
stage_script="$repo_root/src/product/vpp/android/build-stage.sh"
pin_file="$repo_root/src/product/vpp/pinned-vpp-revision.txt"
profile_name=android-api31-arm64
source_dir="${SAKAMOTO_S196_VPP_SOURCE_DIR:-/tmp/sakamoto-172-vpp-official.6CoCcd/source-git}"
ndk_root="${SAKAMOTO_S196_ANDROID_NDK_ROOT:-/home/js/.local/share/android-sdk/ndk/29.0.14206865}"
python_path="${SAKAMOTO_S196_VPP_PYTHONPATH:-/home/js/android/lineage/external/ply/ply}"
cmake_bin="${SAKAMOTO_S196_CMAKE:-cmake}"
ninja_bin="${SAKAMOTO_S196_NINJA:-ninja}"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/sakamoto-196-release-profile.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT

fail() {
  echo "s196 Android VPP release profile contract: $*" >&2
  exit 1
}

require_literal() {
  local path="$1"
  local literal="$2"
  local description="$3"
  grep -Fq -- "$literal" "$path" || fail "$description"
}

require_regex() {
  local path="$1"
  local expression="$2"
  local description="$3"
  grep -Eq -- "$expression" "$path" || fail "$description"
}

[[ -x "$profile_module" ]] || fail "Android VPP profile module is missing"
[[ -x "$stage_script" ]] || fail "Android VPP stage builder is missing"
[[ -f "$pin_file" ]] || fail "pinned VPP revision file is missing"
[[ -f "$ndk_root/build/cmake/android.toolchain.cmake" ]] || \
  fail "Android NDK toolchain is missing"
[[ -d "$python_path" ]] || fail "VPP host-tool Python dependencies are missing"
[[ -x "$(command -v "$cmake_bin")" ]] || fail "CMake is missing"
[[ -x "$(command -v "$ninja_bin")" ]] || fail "Ninja is missing"
pinned_revision="$(tr -d '[:space:]' < "$pin_file")"
[[ "$pinned_revision" =~ ^[[:xdigit:]]{40}$ ]] || \
  fail "pinned VPP revision is invalid"

canonical_source_dir="$(realpath -e "$source_dir" 2>/dev/null)" || \
  fail "clean pinned VPP source cannot be canonicalized"
source_dir="$canonical_source_dir"
case "${source_dir,,}" in
  *experiments*|*poc*) fail "POC/experiment source is not permitted" ;;
esac
[[ -d "$source_dir/.git" || -f "$source_dir/.git" ]] || \
  fail "source is not a Git checkout"
[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$pinned_revision" ]] || \
  fail "source is not at the exact product pin"
[[ -z "$(git -C "$source_dir" status --porcelain)" ]] || \
  fail "source checkout is not clean"

# The stage builder is the public build profile: these settings must not rely
# on caller overrides. Keep the existing S172 Android closure while restoring
# only the previously accepted release trimming and idle behavior.
for required_setting in \
  '-DCMAKE_BUILD_TYPE=Release' \
  '-DVPP_BUILD_TESTS=OFF' \
  '-DVPP_BUILD_VPPINFRA_TESTS=OFF' \
  '-DVPP_BUILD_PYTHON_API=OFF' \
  '-DVPP_MARCH_VARIANT_OCTEONTX2=OFF' \
  '-DVPP_MARCH_VARIANT_THUNDERX2T99=OFF' \
  '-DVPP_MARCH_VARIANT_CORTEXA72=OFF' \
  '-DVPP_MARCH_VARIANT_NEOVERSEN1=OFF' \
  '-DVPP_MARCH_VARIANT_NEOVERSEV2=OFF' \
  '-DSAKAMOTO_VPP_NO_IPSEC=ON' \
  '-DSAKAMOTO_VPP_ANDROID_IDLE_PROFILE=ON'; do
  require_literal "$stage_script" "$required_setting" \
    "stage builder does not enable $required_setting"
done

require_literal "$stage_script" '[[ "$android_api" == "31" ]]' \
  "stage builder lost the Android API 31 boundary"
require_literal "$stage_script" '[[ "$android_abi" == "arm64-v8a" ]]' \
  "stage builder lost the arm64-v8a boundary"
require_literal "$stage_script" 'elf_is_aarch64' \
  "stage builder lost the real AArch64 ELF gate"
require_literal "$stage_script" '*experiments*|*poc*)' \
  "stage builder no longer rejects POC/experiment source"
require_literal "$stage_script" 'git -C "$source_dir" status --porcelain' \
  "stage builder no longer requires a clean pinned source"

# The published manifest names the exact profile and reports measured payload
# bytes (bin/lib/include/host-tools), rather than restating a historical size.
require_regex "$stage_script" '^profile=(\$profile_name|android-api31-arm64)$' \
  "stage manifest does not record the Android profile identity"
require_regex "$stage_script" '^stage(Payload|Size)Bytes=\$[a-z_]*stage[a-z_]*bytes$' \
  "stage manifest does not record the measured stage payload size"
require_literal "$stage_script" 'du -sb' \
  "stage payload size is not measured from the candidate stage"
require_literal "$stage_script" 'runtimeClosureSha256=' \
  "stage manifest does not bind the VPP runtime closure"
require_literal "$stage_script" 'llvm-strip' \
  "Android release ELF closure is not stripped"
require_literal "$stage_script" '--strip-unneeded' \
  "Android release ELF closure does not use strip-unneeded"

patched_source="$work_dir/patched-source"
profile_log="$work_dir/profile.log"
"$profile_module" \
  --profile "$profile_name" \
  --source-dir "$source_dir" \
  --work-dir "$patched_source" >"$profile_log"
require_literal "$profile_log" "profile=$profile_name" \
  "profile module did not identify the selected Android profile"

# The source-level profile is opt-in and preserves the generic AArch64
# armv8-a+crc baseline while removing only the five server-oriented variants.
require_literal "$patched_source/src/cmake/cpu.cmake" \
  'set(VPP_DEFAULT_MARCH_FLAGS -march=armv8-a+crc)' \
  "generic AArch64 baseline was not preserved"

# No-IPsec is a source closure, not merely a packaging filter. Its option must
# guard VNET IPsec sources/APIs/headers/tests, and the stage must enable it.
require_literal "$patched_source/src/CMakeLists.txt" \
  'option(SAKAMOTO_VPP_NO_IPSEC' \
  "patched source has no explicit no-IPsec option"
require_literal "$patched_source/src/vnet/CMakeLists.txt" \
  'SAKAMOTO_VPP_NO_IPSEC' \
  "VNET sources are not governed by the no-IPsec profile"

# Configure (but do not build) the real patched source. This observes the
# public CMake build graph and catches a no-IPsec option that leaves the IPsec
# object closure enabled.
export PYTHONPATH="$python_path${PYTHONPATH:+:$PYTHONPATH}"
configure_dir="$work_dir/configure"
configure_log="$work_dir/configure.log"
"$cmake_bin" \
  -S "$patched_source/src" \
  -B "$configure_dir" \
  -G Ninja \
  "-DCMAKE_TOOLCHAIN_FILE=$ndk_root/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-31 \
  -DCMAKE_BUILD_TYPE=Release \
  -DVPP_BUILD_TESTS=OFF \
  -DVPP_BUILD_VPPINFRA_TESTS=OFF \
  -DVPP_BUILD_PYTHON_API=OFF \
  -DVPP_MARCH_VARIANT_OCTEONTX2=OFF \
  -DVPP_MARCH_VARIANT_THUNDERX2T99=OFF \
  -DVPP_MARCH_VARIANT_CORTEXA72=OFF \
  -DVPP_MARCH_VARIANT_NEOVERSEN1=OFF \
  -DVPP_MARCH_VARIANT_NEOVERSEV2=OFF \
  -DSAKAMOTO_VPP_NO_IPSEC=ON \
  -DSAKAMOTO_VPP_ANDROID_IDLE_PROFILE=ON \
  >"$configure_log" 2>&1 || {
    sed -n '1,160p' "$configure_log" >&2
    fail "restored Android release profile does not configure"
  }

for disabled_variant in OCTEONTX2 THUNDERX2T99 CORTEXA72 NEOVERSEN1 NEOVERSEV2; do
  require_regex "$configure_dir/CMakeCache.txt" \
    "^VPP_MARCH_VARIANT_${disabled_variant}:[A-Z]+=(OFF|FALSE)$" \
    "server multiarch variant is not disabled: $disabled_variant"
done
require_regex "$configure_dir/CMakeCache.txt" \
  '^SAKAMOTO_VPP_NO_IPSEC:[A-Z]+=(ON|TRUE)$' \
  "configured build did not enable no-IPsec"
require_regex "$configure_dir/CMakeCache.txt" \
  '^SAKAMOTO_VPP_ANDROID_IDLE_PROFILE:[A-Z]+=(ON|TRUE)$' \
  "configured build did not enable the accepted Android idle behavior"
"$ninja_bin" -C "$configure_dir" -t targets all >"$work_dir/targets.txt"
if grep -Eq '/ipsec/[^: ]+\.(c|cc)\.o([: ]|$)' "$work_dir/targets.txt"; then
  fail "configured no-IPsec build graph still contains IPsec objects"
fi

# Common-core reassembly expiry is clock-driven only while a context exists.
# With no retained context it becomes event-only, so Android keeps the idle
# win without making fragment timeout depend on a later packet/config event.
reassembly_expiry_files=(
  src/vnet/ip/reass/ip4_full_reass.c
  src/vnet/ip/reass/ip6_full_reass.c
  src/vnet/ip/reass/ip4_sv_reass.c
  src/vnet/ip/reass/ip6_sv_reass.c
)
reassembly_expiry_functions=(
  ip4_full_reass_walk_expired
  ip6_full_reass_walk_expired
  ip4_sv_reass_walk_expired
  ip6_sv_reass_walk_expired
)
[[ "${#reassembly_expiry_files[@]}" -eq 4 &&
   "${#reassembly_expiry_functions[@]}" -eq 4 ]] || \
  fail "reassembly expiry allowlist must contain exactly four entries"
for index in "${!reassembly_expiry_files[@]}"; do
  relative_path="${reassembly_expiry_files[$index]}"
  function_name="${reassembly_expiry_functions[$index]}"
  path="$patched_source/$relative_path"
  [[ -f "$path" ]] || fail "reassembly expiry source is missing: $relative_path"
  python3 - "$path" "$function_name" <<'PY' || \
    fail "$function_name is not active-context clock / idle event driven"
import re
import sys

path, function_name = sys.argv[1:]
text = open(path, encoding="utf-8").read()
match = re.search(r"\b" + re.escape(function_name) + r"\s*\(", text)
if match is None:
    raise SystemExit(1)
window = text[match.start():match.start() + 3400]
pattern = re.compile(
    r"if\s*\(\s*__atomic_load_n\s*\([^;{}]*active_reass_n[^;{}]*\)\s*\)"
    r"\s*vlib_process_wait_for_event_or_clock\s*\(.*?\)\s*;"
    r"\s*else\s*vlib_process_wait_for_event\s*\(",
    re.DOTALL,
)
raise SystemExit(0 if pattern.search(window) else 1)
PY
done

# The Android-only idle profile keeps exactly these four other default
# periodic processes event-only. Other VPP timers are not globally delayed or
# disabled by this contract.
idle_process_files=(
  src/vnet/ip6-nd/ip6_mld.c
  src/vnet/ip6-nd/ip6_ra.c
  src/vnet/fib/fib_walk.c
  src/vlib/stats/collector.c
)
idle_process_functions=(
  ip6_mld_event_process
  ip6_ra_event_process
  fib_walk_process
  stat_segment_collector_process
)
[[ "${#idle_process_files[@]}" -eq 4 &&
   "${#idle_process_functions[@]}" -eq 4 ]] || \
  fail "Android-only idle process allowlist must contain exactly four entries"
idle_process_pairs=()
for index in "${!idle_process_files[@]}"; do
  relative_path="${idle_process_files[$index]}"
  function_name="${idle_process_functions[$index]}"
  path="$patched_source/$relative_path"
  [[ -f "$path" ]] || fail "idle process source is missing: $relative_path"
  require_literal "$path" 'SAKAMOTO_VPP_ANDROID_IDLE_PROFILE' \
    "idle profile does not guard $relative_path"
  require_regex "$path" 'vlib_process_wait_for_event[[:space:]]*\(' \
    "idle profile does not use event wait in $relative_path"
  python3 - "$path" "$function_name" <<'PY' || \
    fail "profile event wait is not inside $function_name"
import re
import sys

path, function_name = sys.argv[1:]
text = open(path, encoding="utf-8").read()
match = re.search(r"\b" + re.escape(function_name) + r"\s*\(", text)
if match is None:
    raise SystemExit(1)
window = text[match.start():match.start() + 2600]
pattern = re.compile(
    r"#ifdef\s+SAKAMOTO_VPP_ANDROID_IDLE_PROFILE"
    r"(?:(?!#endif).)*vlib_process_wait_for_event\s*\("
    r"(?:(?!#endif).)*#else"
    r"(?:(?!#endif).)*(?:vlib_process_wait_for_event_or_clock|vlib_process_suspend)\s*\("
    r"(?:(?!#endif).)*#endif",
    re.DOTALL,
)
raise SystemExit(0 if pattern.search(window) else 1)
PY
  idle_process_pairs+=("$relative_path:$function_name")
done
python3 - "$patched_source" "${idle_process_pairs[@]}" <<'PY' || \
  fail "accepted idle event-wait profile is not limited to the exact eight processes"
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1])
expected = set(sys.argv[2:])
observed = set()
profile_block = re.compile(
    r"#ifdef\s+SAKAMOTO_VPP_ANDROID_IDLE_PROFILE"
    r"(?P<body>(?:(?!#endif).)*)#endif",
    re.DOTALL,
)
function_start = re.compile(
    r"\n(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\([^;{}]*\)\s*\n?\{",
    re.DOTALL,
)
for path in source.joinpath("src").rglob("*.c"):
    text = path.read_text(encoding="utf-8")
    for block in profile_block.finditer(text):
        if "vlib_process_wait_for_event" not in block.group("body"):
            continue
        functions = list(function_start.finditer(text, 0, block.start()))
        if not functions:
            raise SystemExit(1)
        relative = path.relative_to(source).as_posix()
        observed.add(f"{relative}:{functions[-1].group('name')}")
raise SystemExit(0 if observed == expected else 1)
PY

# The opt-in profile must leave the pinned upstream graph available when OFF.
configure_off_dir="$work_dir/configure-off"
configure_off_log="$work_dir/configure-off.log"
"$cmake_bin" \
  -S "$patched_source/src" \
  -B "$configure_off_dir" \
  -G Ninja \
  "-DCMAKE_TOOLCHAIN_FILE=$ndk_root/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-31 \
  -DCMAKE_BUILD_TYPE=Release \
  -DVPP_BUILD_TESTS=OFF \
  -DVPP_BUILD_VPPINFRA_TESTS=OFF \
  -DVPP_BUILD_PYTHON_API=OFF \
  >"$configure_off_log" 2>&1 || {
    sed -n '1,160p' "$configure_off_log" >&2
    fail "Android profile OFF branch does not configure"
  }
require_regex "$configure_off_dir/CMakeCache.txt" \
  '^SAKAMOTO_VPP_NO_IPSEC:[A-Z]+=(OFF|FALSE)$' \
  "no-IPsec option does not default OFF"
require_regex "$configure_off_dir/CMakeCache.txt" \
  '^SAKAMOTO_VPP_ANDROID_IDLE_PROFILE:[A-Z]+=(OFF|FALSE)$' \
  "Android idle profile does not default OFF"
if grep -Fq -- '-DSAKAMOTO_VPP_ANDROID_IDLE_PROFILE' \
    "$configure_off_dir/build.ninja"; then
  fail "profile OFF build still defines the Android idle profile"
fi
if grep -Fq -- '-DSAKAMOTO_ANDROID_WORKER_IDLE_IGNORES_RECENT_BARRIER_HOLDOFF' \
    "$configure_off_dir/build.ninja"; then
  fail "profile OFF build still defines the worker idle marker"
fi
"$ninja_bin" -C "$configure_off_dir" -t targets all >"$work_dir/targets-off.txt"
grep -Eq '/ipsec/[^: ]+\.c\.o([: ]|$)' "$work_dir/targets-off.txt" || \
  fail "profile OFF graph does not restore VPP IPsec objects"

require_literal "$patched_source/src/vlib/tw_funcs.h" \
  '#define VLIB_TW_TICKS_PER_SECOND 1e3' \
  "Android idle profile does not use a 1 ms VLIB timer wheel"
require_literal "$patched_source/src/vlib/file.c" \
  'max_timeout_ms = 1000' \
  "Android idle profile does not cap file poll sleep at 1000 ms"
require_literal "$patched_source/src/vlib/file.c" \
  'timeout_ms = clib_min (timeout_ms, max_timeout_ms)' \
  "file poll no longer preserves the computed timer timeout"
require_literal "$patched_source/src/vlib/file.c" \
  'SAKAMOTO_ANDROID_WORKER_IDLE_IGNORES_RECENT_BARRIER_HOLDOFF' \
  "Android workers do not return to sleep after a completed barrier"

# The rejected conditional/per-packet/persistent wake experiment must not be
# smuggled into the release profile. These are its production-distinguishing
# state and mode symbols, not generic stock eventfd wake support.
for rejected_symbol in \
  vlib_frame_queue_wakeup_mode \
  vlib_wakeup_epoch \
  wakeup_epoch_state; do
  if grep -R -Fq -- "$rejected_symbol" "$patched_source/src"; then
    fail "rejected conditional/per-packet/persistent wake state is present: $rejected_symbol"
  fi
done

[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$pinned_revision" ]] || \
  fail "profile application changed the input checkout revision"
[[ -z "$(git -C "$source_dir" status --porcelain)" ]] || \
  fail "profile application modified the clean input checkout"

echo "profile=$profile_name release/no-server-multiarch/no-IPsec/accepted-idle"
echo "s196 Android VPP release profile contract: PASS"
