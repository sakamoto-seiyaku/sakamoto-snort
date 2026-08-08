#!/usr/bin/env bash
set -euo pipefail

# Production-incubator build. The VPP stage is an explicit artifact input;
# this script never falls back to the reconstructed raw daemon.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
app_dir="$(cd -- "${script_dir}/.." && pwd)"
repo_root="$(cd -- "${app_dir}/../.." && pwd)"
default_stage_dir="${repo_root}/build-output/android-vpp-runtime/stage"
stage_dir="${VPP_RUNTIME_STAGE_DIR:-$default_stage_dir}"
stage_dir_explicit=0
if [[ -n "${VPP_RUNTIME_STAGE_DIR+x}" ]]; then
  stage_dir_explicit=1
fi
sdk_prebuilts="${ANDROID_LINEAGE_SDK_PREBUILTS:-/home/js/android/lineage/prebuilts/sdk}"
android_jar="${ANDROID_JAR:-${sdk_prebuilts}/36/public/android.jar}"
aapt2="${AAPT2:-${sdk_prebuilts}/tools/linux/bin/aapt2}"
d8_jar="${D8_JAR:-${sdk_prebuilts}/tools/linux/lib/d8.jar}"
apksigner_jar="${APKSIGNER_JAR:-${sdk_prebuilts}/tools/linux/lib/apksigner.jar}"
zipalign_bin="${ZIPALIGN:-zipalign}"

die() { echo "error: $*" >&2; exit 1; }

profile_source="$app_dir/src/main/java/com/sakamoto/snort/androidruntime/RuntimeProfile.java"
[[ -f "$profile_source" ]] || die "missing runtime profile contract: $profile_source"
root_adapter="$(awk -F'"' '/^[[:space:]]*ROOT\(/ {print $6; exit}' "$profile_source")"
vpn_adapter="$(awk -F'"' '/^[[:space:]]*VPN\(/ {print $6; exit}' "$profile_source")"
[[ -n "$root_adapter" && -n "$vpn_adapter" ]] \
  || die "unable to read profile adapter contract from $profile_source"

required_stage_artifacts=(
  "$stage_dir/bin/vpp"
  "$stage_dir/bin/vppctl"
  "$stage_dir/runtime/startup.conf"
  "$stage_dir/plugins/${root_adapter#lib}"
  "$stage_dir/plugins/${vpn_adapter#lib}"
)
stage_has_required_artifacts() {
  local file
  for file in "${required_stage_artifacts[@]}"; do
    [[ -f "$file" ]] || return 1
  done
  grep -Eq "plugin[[:space:]]+${root_adapter#lib}[[:space:]]+\{[[:space:]]*enable[[:space:]]*\}" \
    "$stage_dir/runtime/startup.conf" || return 1
  grep -Eq "plugin[[:space:]]+${vpn_adapter#lib}[[:space:]]+\{[[:space:]]*enable[[:space:]]*\}" \
    "$stage_dir/runtime/startup.conf" || return 1
}

# The default stage is produced by the repository-local POC staging pipeline.
# Run that boundary on every default build so it can refresh a stage when its
# configured source/build output is newer. An explicitly selected stage is
# never replaced or supplemented implicitly: callers must provide both real
# adapter artifacts and the stage startup contract themselves.
if [[ "$stage_dir_explicit" == 0 ]]; then
  stage_script="$repo_root/experiments/vpp-nfq-poc/android/vpn-lite/scripts/stage-vpp-runtime.sh"
  [[ -f "$stage_script" ]] || die "default runtime stage is incomplete and stage builder is absent: $stage_script"
  VPP_RUNTIME_STAGE_DIR="$stage_dir" bash "$stage_script"
fi
stage_has_required_artifacts \
  || die "runtime stage is missing VPP core, profile adapters, or startup contract: $stage_dir"

for file in "$android_jar" "$aapt2" "$d8_jar" "$apksigner_jar" \
    "$stage_dir/bin/vpp" "$stage_dir/bin/vppctl" \
    "$stage_dir/plugins/${root_adapter#lib}" "$stage_dir/plugins/${vpn_adapter#lib}"; do
  [[ -f "$file" ]] || die "missing required build input: $file"
done
command -v javac >/dev/null || die "missing javac"
command -v java >/dev/null || die "missing java"
command -v keytool >/dev/null || die "missing keytool"
command -v zip >/dev/null || die "missing zip"
command -v "$zipalign_bin" >/dev/null || die "missing zipalign: $zipalign_bin"

build_dir="$app_dir/build"
classes_dir="$build_dir/classes"
dex_dir="$build_dir/dex"
jni_dir="$build_dir/jni/lib/arm64-v8a"
assets_dir="$build_dir/assets"
intermediates="$build_dir/intermediates"
outputs="$build_dir/outputs"
rm -rf "$classes_dir" "$dex_dir" "$build_dir/jni" "$assets_dir" \
    "$intermediates" "$outputs"
mkdir -p "$classes_dir" "$dex_dir" "$jni_dir" "$assets_dir" "$intermediates" "$outputs"

cp "$stage_dir/bin/vpp" "$jni_dir/libvpp_runtime.so"
cp "$stage_dir/bin/vppctl" "$jni_dir/libvppctl.so"
chmod 755 "$jni_dir/libvpp_runtime.so" "$jni_dir/libvppctl.so"
for so in "$stage_dir"/lib/*.so; do
  [[ -f "$so" ]] || continue
  cp "$so" "$jni_dir/$(basename "$so")"
  chmod 755 "$jni_dir/$(basename "$so")"
done
# VPP stages use the conventional no-lib plugin filenames, while Android's
# native-library packaging and RuntimeProfile contract use lib*.so names.
# Rename the real plugin artifacts at this one packaging boundary.
for adapter in "$root_adapter" "$vpn_adapter"; do
  source_plugin="$stage_dir/plugins/${adapter#lib}"
  [[ -f "$source_plugin" ]] || die "profile adapter is missing from runtime stage: $source_plugin"
  cp "$source_plugin" "$jni_dir/$adapter"
  chmod 755 "$jni_dir/$adapter"
done

version="${VPP_RUNTIME_VERSION:-$(strings "$stage_dir/bin/vpp" \
    | awk '/vpp v[0-9]/{if (!found) {print $2; found=1}}') }"
version="$(printf '%s' "$version" | tr -d '[:space:]')"
[[ "$version" =~ ^v[0-9]+\.[0-9]+ ]] || die "unable to determine VPP version"
artifact="sha256:$(sha256sum "$jni_dir/libvpp_runtime.so" | awk '{print $1}')"
printf 'version=%s\nabi=arm64-v8a\nprotocol=vpp-runtime-health/v1\nartifact=%s\n' \
  "$version" "$artifact" >"$assets_dir/vpp-runtime.properties"
printf 'adapter.root=%s\nadapter.vpn=%s\n' "$root_adapter" "$vpn_adapter" \
  >>"$assets_dir/vpp-runtime.properties"
for mapping in "root:$root_adapter" "vpn:$vpn_adapter"; do
  profile="${mapping%%:*}"
  adapter="${mapping#*:}"
  declared="$(awk -F= -v key="adapter.$profile" '$1 == key {print $2}' \
    "$assets_dir/vpp-runtime.properties")"
  [[ "$declared" == "$adapter" ]] \
    || die "manifest adapter.$profile disagrees with RuntimeProfile: $declared != $adapter"
  [[ -f "$jni_dir/$declared" ]] \
    || die "manifest adapter.$profile is not packaged: $declared"
done
printf '%s\n' "${artifact#sha256:}" >"$assets_dir/vpp-runtime.sha256"

mapfile -t sources < <(find "$app_dir/src/main/java" -name '*.java' | sort)
javac -Xlint:-options -source 8 -target 8 -classpath "$android_jar" -d "$classes_dir" "${sources[@]}"
mapfile -t class_files < <(find "$classes_dir" -name '*.class' | sort)
java -cp "$d8_jar" com.android.tools.r8.D8 --min-api 31 --lib "$android_jar" \
  --output "$dex_dir" "${class_files[@]}"

base_apk="$intermediates/base.apk"
unsigned_apk="$intermediates/unsigned.apk"
aligned_apk="$intermediates/aligned.apk"
apk="$outputs/sakamoto-runtime-debug.apk"
"$aapt2" link -o "$base_apk" -I "$android_jar" \
  --manifest "$app_dir/src/main/AndroidManifest.xml" --min-sdk-version 31 \
  --target-sdk-version 36 --version-code "${APK_VERSION_CODE:-1}" \
  --version-name "${APK_VERSION_NAME:-0.1-runtime-debug}" --debug-mode
cp "$base_apk" "$unsigned_apk"
(cd "$dex_dir" && zip -q -r "$unsigned_apk" classes.dex)
(cd "$build_dir/jni" && zip -q -r "$unsigned_apk" lib)
(cd "$build_dir" && zip -q -r "$unsigned_apk" assets)
if [[ ! -f "$build_dir/debug.keystore" ]]; then
  keytool -genkeypair -keystore "$build_dir/debug.keystore" -storepass android \
    -keypass android -alias androiddebugkey -keyalg RSA -keysize 2048 \
    -validity 10000 -dname "CN=Android Debug,O=sakamoto,C=US" >/dev/null
fi
"$zipalign_bin" -f -p 4 "$unsigned_apk" "$aligned_apk"
java -jar "$apksigner_jar" sign --ks "$build_dir/debug.keystore" \
  --ks-pass pass:android --key-pass pass:android --ks-key-alias androiddebugkey \
  --out "$apk" "$aligned_apk"
java -jar "$apksigner_jar" verify --print-certs "$apk" >/dev/null
echo "ok: $apk"
