#!/usr/bin/env bash
set -euo pipefail

# Active SAKAMOTO-46 APK build: package one VPP runtime and its dependencies.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
app_dir="$(cd -- "${script_dir}/.." && pwd)"
poc_dir="$(cd -- "${app_dir}/../.." && pwd)"
repo_root="$(cd -- "${poc_dir}/../.." && pwd)"
sdk_prebuilts="${ANDROID_LINEAGE_SDK_PREBUILTS:-/home/js/android/lineage/prebuilts/sdk}"
android_jar="${ANDROID_JAR:-${sdk_prebuilts}/36/public/android.jar}"
aapt2="${AAPT2:-${sdk_prebuilts}/tools/linux/bin/aapt2}"
d8_jar="${D8_JAR:-${sdk_prebuilts}/tools/linux/lib/d8.jar}"
apksigner_jar="${APKSIGNER_JAR:-${sdk_prebuilts}/tools/linux/lib/apksigner.jar}"
zipalign_bin="${ZIPALIGN:-zipalign}"
stage_dir="${VPP_RUNTIME_STAGE_DIR:-${repo_root}/build-output/android-vpp-runtime/stage}"
if [[ ! -x "$stage_dir/bin/vpp" || ! -x "$stage_dir/bin/vppctl" ]]; then
  VPP_RUNTIME_STAGE_DIR="$stage_dir" \
    bash "$script_dir/stage-vpp-runtime.sh" >/dev/null
fi

die() { echo "error: $*" >&2; exit 1; }
for file in "$android_jar" "$aapt2" "$d8_jar" "$apksigner_jar" "$stage_dir/bin/vpp" "$stage_dir/bin/vppctl"; do
  [[ -f "$file" ]] || die "missing file: $file"
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
rm -rf "$classes_dir" "$dex_dir" "$build_dir/jni" "$assets_dir" "$intermediates" "$outputs"
mkdir -p "$classes_dir" "$dex_dir" "$jni_dir" "$assets_dir" "$intermediates" "$outputs"

cp "$stage_dir/bin/vpp" "$jni_dir/libvpp_runtime.so"
cp "$stage_dir/bin/vppctl" "$jni_dir/libvppctl.so"
chmod 755 "$jni_dir/libvpp_runtime.so" "$jni_dir/libvppctl.so"
for so in "$stage_dir"/lib/*.so "$stage_dir"/plugins/*.so; do
  [[ -f "$so" ]] || continue
  cp "$so" "$jni_dir/$(basename "$so")"
  chmod 755 "$jni_dir/$(basename "$so")"
done
version="${VPP_RUNTIME_VERSION:-$(strings "$stage_dir/bin/vpp" | awk '/vpp v[0-9]/{print $2; exit}')}"
[[ "$version" =~ ^v[0-9]+\.[0-9]+ ]] || die "unable to determine VPP version"
printf 'version=%s\nabi=arm64-v8a\nprotocol=vpp-runtime-health/v1\n' "$version" >"$assets_dir/vpp-runtime.properties"
sha256sum "$jni_dir/libvpp_runtime.so" | awk '{print $1}' >"$assets_dir/vpp-runtime.sha256"

mapfile -t sources < <(find "$app_dir/src/main/java" -name '*.java' | sort)
javac -Xlint:-options -source 8 -target 8 -classpath "$android_jar" -d "$classes_dir" "${sources[@]}"
mapfile -t class_files < <(find "$classes_dir" -name '*.class' | sort)
java -cp "$d8_jar" com.android.tools.r8.D8 --min-api 31 --lib "$android_jar" --output "$dex_dir" "${class_files[@]}"

base_apk="$intermediates/base.apk"
unsigned_apk="$intermediates/unsigned.apk"
aligned_apk="$intermediates/aligned.apk"
apk="$outputs/sakamoto-runtime-debug.apk"
"$aapt2" link -o "$base_apk" -I "$android_jar" --manifest "$app_dir/src/main/AndroidManifest.xml" \
  --min-sdk-version 31 --target-sdk-version 36 --version-code "${APK_VERSION_CODE:-1}" \
  --version-name "${APK_VERSION_NAME:-0.1-runtime-debug}" --debug-mode
cp "$base_apk" "$unsigned_apk"
(cd "$dex_dir" && zip -q -r "$unsigned_apk" classes.dex)
(cd "$build_dir/jni" && zip -q -r "$unsigned_apk" lib)
(cd "$build_dir" && zip -q -r "$unsigned_apk" assets)
if [[ ! -f "$build_dir/debug.keystore" ]]; then
  keytool -genkeypair -keystore "$build_dir/debug.keystore" -storepass android -keypass android \
    -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=Android Debug,O=sakamoto,C=US" >/dev/null
fi
"$zipalign_bin" -f -p 4 "$unsigned_apk" "$aligned_apk"
java -jar "$apksigner_jar" sign --ks "$build_dir/debug.keystore" --ks-pass pass:android \
  --key-pass pass:android --ks-key-alias androiddebugkey --out "$apk" "$aligned_apk"
java -jar "$apksigner_jar" verify --print-certs "$apk" >/dev/null
echo "ok: $apk"
