#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
build_script="$repo_root/app/android-runtime/scripts/build-debug-apk.sh"
product_stage="${SAKAMOTO_S172_PRODUCT_STAGE_DIR:-/tmp/sakamoto-172-product-stage}"
android_jar="${SAKAMOTO_S172_ANDROID_JAR:-/home/js/android/lineage/prebuilts/sdk/36/public/android.jar}"
aapt2="${SAKAMOTO_S172_AAPT2:-/home/js/android/lineage/prebuilts/sdk/tools/linux/bin/aapt2}"
d8="${SAKAMOTO_S172_D8:-/home/js/android/lineage/prebuilts/sdk/tools/linux/bin/d8}"
zipalign="${SAKAMOTO_S172_ZIPALIGN:-/home/js/android/lineage/prebuilts/sdk/tools/linux/bin/zipalign}"
apksigner_jar="${SAKAMOTO_S172_APKSIGNER_JAR:-/home/js/android/lineage/prebuilts/sdk/tools/linux/lib/apksigner.jar}"
debug_key="${SAKAMOTO_S172_DEBUG_KEY:-/home/js/android/lineage/build/make/target/product/security/testkey.pk8}"
debug_cert="${SAKAMOTO_S172_DEBUG_CERT:-/home/js/android/lineage/build/make/target/product/security/testkey.x509.pem}"
llvm_readelf="${SAKAMOTO_S172_LLVM_READELF:-/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf}"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/sakamoto-172-product-spine.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

test -x "$build_script"
test -f "$android_jar"
test -x "$aapt2"
test -x "$d8"
test -x "$zipalign"
test -f "$apksigner_jar"
test -f "$debug_key"
test -f "$debug_cert"
test -x "$llvm_readelf"
grep -Fq -- '--apk-only' "$build_script"
grep -Fq 'SAKAMOTO_ANDROID_APK_OUTPUT_DIR' "$build_script"
grep -Fq 'sakamoto-runtime-debug.apk' "$build_script"
grep -Fq 'mv -fT -- "$signed_apk" "$apk_output_path"' "$build_script"
if grep -Fq 'mv -f -- "$signed_apk" "$apk_output_path"' "$build_script"; then
  echo "APK publication permits target-directory nesting" >&2
  exit 1
fi
grep -Fq 'zipalign' "$build_script"
grep -Fq 'apksigner_jar' "$build_script"
grep -Fq 'libproduct_core_plugin.so' "$build_script"
grep -Fq 'payload_lib' "$build_script"
grep -Fq '"$plugin_name"; do' "$build_script"
if grep -Fq 'payload_assets/$plugin_name' "$build_script"; then
  echo "APK builder still packages the product plugin as an asset" >&2
  exit 1
fi
if grep -Fq 'rm -rf -- "$apk_output_dir"' "$build_script"; then
  echo "apk-only removes the caller's APK output directory" >&2
  exit 1
fi

product_stage="$(realpath -e "$product_stage")"
test -f "$product_stage/.sakamoto-android-product-stage"
grep -Fxq 'sakamoto-android-product-stage/v1' \
  "$product_stage/.sakamoto-android-product-stage"
product_manifest="$product_stage/product-stage.properties"
test -f "$product_manifest"
grep -Fxq 'schema=sakamoto-android-product-stage/v1' "$product_manifest"
grep -Fxq 'abi=arm64-v8a' "$product_manifest"
grep -Fxq 'androidApi=31' "$product_manifest"
pinned_revision="$(tr -d '[:space:]' < "$repo_root/src/product/vpp/pinned-vpp-revision.txt")"
grep -Fxq "vppRevision=$pinned_revision" "$product_manifest"
grep -Fxq 'vppBinary=lib/arm64-v8a/libvpp_runtime.so' "$product_manifest"
grep -Fxq 'productCore=lib/arm64-v8a/libsakamoto_product_core.so' "$product_manifest"
grep -Fxq 'runtimeControl=lib/arm64-v8a/libsakamoto_runtime_control.so' "$product_manifest"
grep -Fxq 'productPlugin=lib/arm64-v8a/libproduct_core_plugin.so' "$product_manifest"
vpp_runtime_closure_sha256="$(
  sed -n 's/^vppRuntimeClosureSha256=//p' "$product_manifest"
)"
[[ "$vpp_runtime_closure_sha256" =~ ^[[:xdigit:]]{64}$ ]]

native_dir="$product_stage/lib/arm64-v8a"
for library in \
  libvpp_runtime.so \
  libsakamoto_product_core.so \
  libsakamoto_runtime_control.so \
  libsvm.so \
  libvapiclient.so \
  libvlib.so \
  libvlibapi.so \
  libvlibmemory.so \
  libvlibmemoryclient.so \
  libvnet.so \
  libvppinfra.so; do
  test -f "$native_dir/$library"
done
test -f "$product_stage/lib/arm64-v8a/libproduct_core_plugin.so"

run_apk() {
  local stage="$1"
  local output_dir="$2"
  local version_state="$3"
  local log="$4"
  SAKAMOTO_ANDROID_PRODUCT_STAGE_DIR="$stage" \
    SAKAMOTO_ANDROID_APK_OUTPUT_DIR="$output_dir" \
    SAKAMOTO_ANDROID_VERSION_STATE_FILE="$version_state" \
    SAKAMOTO_ANDROID_ANDROID_JAR="$android_jar" \
    SAKAMOTO_ANDROID_AAPT2="$aapt2" \
    SAKAMOTO_ANDROID_D8="$d8" \
    SAKAMOTO_ANDROID_ZIPALIGN="$zipalign" \
    SAKAMOTO_ANDROID_APKSIGNER_JAR="$apksigner_jar" \
    SAKAMOTO_ANDROID_DEBUG_KEY="$debug_key" \
    SAKAMOTO_ANDROID_DEBUG_CERT="$debug_cert" \
    bash "$build_script" --apk-only >"$log" 2>&1
}

apk_output_dir="$work_dir/apk-output"
version_state="$work_dir/version-code"
first_log="$work_dir/first.log"
run_apk "$product_stage" "$apk_output_dir" "$version_state" "$first_log"
apk="$apk_output_dir/sakamoto-runtime-debug.apk"
test -f "$apk"
grep -Fxq 'mode=apk-only' "$first_log"
grep -Fxq "apk=$apk" "$first_log"

apk_entries="$(unzip -Z1 "$apk")"
for entry in \
  AndroidManifest.xml \
  classes.dex \
  assets/product-stage.properties; do
  grep -Fxq "$entry" <<<"$apk_entries"
done
if grep -Fxq 'assets/product_core_plugin.so' <<<"$apk_entries"; then
  echo "product plugin must not be copied into APK assets" >&2
  exit 1
fi
grep -Fxq 'lib/arm64-v8a/libproduct_core_plugin.so' <<<"$apk_entries"
unzip -lv "$apk" lib/arm64-v8a/libvnet.so |
  grep -Eq '[[:space:]]Defl' || {
    echo "APK retains an uncompressed VPP runtime payload" >&2
    exit 1
  }
unzip -p "$apk" lib/arm64-v8a/libproduct_core_plugin.so >"$work_dir/plugin.so"
unzip -p "$apk" assets/product-stage.properties >"$work_dir/product-stage.properties"
cmp "$product_stage/lib/arm64-v8a/libproduct_core_plugin.so" "$work_dir/plugin.so"
cmp "$product_stage/product-stage.properties" "$work_dir/product-stage.properties"
plugin_header="$($llvm_readelf -h "$work_dir/plugin.so")"
grep -Fq 'AArch64' <<<"$plugin_header"
for library in \
  libvpp_runtime.so \
  libsakamoto_product_core.so \
  libsakamoto_runtime_control.so \
  libsvm.so \
  libvapiclient.so \
  libvlib.so \
  libvlibapi.so \
  libvlibmemory.so \
  libvlibmemoryclient.so \
  libvnet.so \
  libvppinfra.so; do
  grep -Fxq "lib/arm64-v8a/$library" <<<"$apk_entries"
done
unzip -p "$apk" lib/arm64-v8a/libsakamoto_runtime_control.so \
  >"$work_dir/libsakamoto_runtime_control.so"
"$llvm_readelf" -d "$work_dir/libsakamoto_runtime_control.so" \
  | grep -F 'libsakamoto_product_core.so' >/dev/null
"$llvm_readelf" -d "$native_dir/libsakamoto_runtime_control.so" \
  | grep -F 'libsakamoto_product_core.so' >/dev/null
native_entry_count=0
while IFS= read -r entry; do
  case "$entry" in
    lib/arm64-v8a/*.so) native_entry_count=$((native_entry_count + 1)) ;;
  esac
done <<<"$apk_entries"
test "$native_entry_count" -eq 12

tampered_stage="$work_dir/tampered-product-stage"
cp -a -- "$product_stage" "$tampered_stage"
printf 'tampered\n' >>"$tampered_stage/lib/arm64-v8a/libvnet.so"
if run_apk "$tampered_stage" "$work_dir/tampered-output" \
    "$work_dir/tampered-version-code" "$work_dir/tampered.log"; then
  echo "apk-only accepted a tampered VPP runtime library" >&2
  exit 1
fi
grep -Fq 'product_artifact_hash_mismatch' "$work_dir/tampered.log"

forbidden_entry=""
while IFS= read -r entry; do
  case "${entry,,}" in
    *poc*|*experiment*|*fixture*|*sucre*|*snortd*|*removed-cxx*)
      forbidden_entry="$entry"
      break
      ;;
  esac
done <<<"$apk_entries"
[[ -z "$forbidden_entry" ]] || {
  echo "retired or POC artifact entered APK: $forbidden_entry" >&2
  exit 1
}

unpacked_dir="$work_dir/unpacked"
mkdir -p "$unpacked_dir"
unzip -q "$apk" 'lib/arm64-v8a/*.so' -d "$unpacked_dir"
while IFS= read -r artifact; do
  elf_header="$($llvm_readelf -h "$artifact")"
  grep -Fq 'AArch64' <<<"$elf_header"
done < <(find "$unpacked_dir/lib/arm64-v8a" -type f -name '*.so' -print | sort)

"$aapt2" dump badging "$apk" >"$work_dir/first-badging"
"$aapt2" dump xmltree --file AndroidManifest.xml "$apk" >"$work_dir/first-xmltree"
grep -Fq "package: name='com.sakamoto.snort.androidruntime'" "$work_dir/first-badging"
grep -Fq "minSdkVersion:'31'" "$work_dir/first-badging"
grep -Fq "targetSdkVersion:'36'" "$work_dir/first-badging"
grep -Fq 'application-debuggable' "$work_dir/first-badging"
grep -Fq 'minSdkVersion(0x0101020c)=31' "$work_dir/first-xmltree"
grep -Fq 'targetSdkVersion(0x01010270)=36' "$work_dir/first-xmltree"
grep -Fq 'debuggable(0x0101000f)=true' "$work_dir/first-xmltree"
grep -Fq 'extractNativeLibs(0x010104ea)=true' "$work_dir/first-xmltree"
first_version="$(sed -n "s/.*versionCode='\([^']*\)'.*/\1/p" "$work_dir/first-badging")"
test "$first_version" -gt 0
java -jar "$apksigner_jar" verify --verbose --print-certs "$apk" >"$work_dir/first-verify" 2>&1
grep -Fq 'Verified' "$work_dir/first-verify"
"$zipalign" -c -p 4 "$apk"

second_log="$work_dir/second.log"
run_apk "$product_stage" "$apk_output_dir" "$version_state" "$second_log"
test -f "$apk"
grep -Fxq 'mode=apk-only' "$second_log"
"$aapt2" dump badging "$apk" >"$work_dir/second-badging"
second_version="$(sed -n "s/.*versionCode='\([^']*\)'.*/\1/p" "$work_dir/second-badging")"
test "$second_version" -gt "$first_version"
java -jar "$apksigner_jar" verify --verbose --print-certs "$apk" >"$work_dir/second-verify" 2>&1
grep -Fq 'Verified' "$work_dir/second-verify"
"$zipalign" -c -p 4 "$apk"
if compgen -G "$apk_output_dir/.sakamoto-runtime-debug.build.*" >/dev/null; then
  echo "apk-only candidate remained after atomic publication" >&2
  exit 1
fi

invalid_stage="$work_dir/invalid-stage"
cp -a "$product_stage" "$invalid_stage"
printf '%s\n' wrong-stage >"$invalid_stage/.sakamoto-android-product-stage"
invalid_output="$work_dir/invalid-output"
if run_apk "$invalid_stage" "$invalid_output" "$work_dir/invalid-version-code" \
    "$work_dir/invalid.log"; then
  echo "apk-only accepted an invalid product-stage marker" >&2
  exit 1
fi
grep -Eiq 'owned marker|product stage' "$work_dir/invalid.log"
[[ ! -e "$invalid_output/sakamoto-runtime-debug.apk" ]]
[[ ! -e "$invalid_output" ]]

unowned_stage="$work_dir/unowned-stage"
mkdir -p "$unowned_stage"
unowned_output="$work_dir/unowned-output"
if run_apk "$unowned_stage" "$unowned_output" "$work_dir/unowned-version-code" \
    "$work_dir/unowned.log"; then
  echo "apk-only accepted an unowned product stage" >&2
  exit 1
fi
grep -Eiq 'owned marker|product stage' "$work_dir/unowned.log"
[[ ! -e "$unowned_output/sakamoto-runtime-debug.apk" ]]
[[ ! -e "$unowned_output" ]]

echo "sakamoto-172 product APK spine contract: PASS"
