#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
app_dir="$(cd -- "${script_dir}/.." && pwd)"

sdk_prebuilts="${ANDROID_LINEAGE_SDK_PREBUILTS:-/home/js/android/lineage/prebuilts/sdk}"
android_jar="${ANDROID_JAR:-${sdk_prebuilts}/36/public/android.jar}"
aapt2="${AAPT2:-${sdk_prebuilts}/tools/linux/bin/aapt2}"
d8_jar="${D8_JAR:-${sdk_prebuilts}/tools/linux/lib/d8.jar}"
apksigner_jar="${APKSIGNER_JAR:-${sdk_prebuilts}/tools/linux/lib/apksigner.jar}"
zipalign_bin="${ZIPALIGN:-zipalign}"
ndk_root="${NDK_ROOT:-/home/js/.local/share/android-sdk/ndk/29.0.14206865}"
clang="${ANDROID_CLANG:-${ndk_root}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang}"

die() {
  echo "error: $*" >&2
  exit 1
}

require_file() {
  [[ -f "$1" ]] || die "missing file: $1"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

require_file "$android_jar"
require_file "$aapt2"
require_file "$d8_jar"
require_file "$apksigner_jar"
require_file "$clang"
require_cmd javac
require_cmd java
require_cmd keytool
require_cmd zip
command -v "$zipalign_bin" >/dev/null 2>&1 || [[ -x "$zipalign_bin" ]] || die "missing zipalign: $zipalign_bin"

build_dir="$app_dir/build"
classes_dir="$build_dir/classes"
dex_dir="$build_dir/dex"
gen_dir="$build_dir/generated"
jni_root="$build_dir/jni"
jni_dir="$jni_root/lib/arm64-v8a"
intermediates="$build_dir/intermediates"
outputs="$build_dir/outputs"
manifest="$app_dir/src/main/AndroidManifest.xml"
keystore="$build_dir/debug.keystore"

rm -rf "$classes_dir" "$dex_dir" "$gen_dir" "$jni_root" "$intermediates" "$outputs"
mkdir -p "$classes_dir" "$dex_dir" "$gen_dir" "$jni_dir" "$intermediates" "$outputs"

echo "building JNI probe"
"$clang" \
  -shared \
  -fPIC \
  -O2 \
  -Wall \
  -Wextra \
  -Werror \
  -o "$jni_dir/libvpnfdprobe.so" \
  "$app_dir/native/vpn_fd_probe.c" \
  -llog

echo "compiling Java sources"
mapfile -t java_sources < <(find "$app_dir/src/main/java" -name '*.java' | sort)
[[ "${#java_sources[@]}" -gt 0 ]] || die "no Java sources found"
javac -Xlint:-options -source 8 -target 8 -classpath "$android_jar" -d "$classes_dir" "${java_sources[@]}"

echo "dexing"
mapfile -t class_files < <(find "$classes_dir" -name '*.class' | sort)
[[ "${#class_files[@]}" -gt 0 ]] || die "no class files found"
java -cp "$d8_jar" com.android.tools.r8.D8 \
  --min-api 31 \
  --lib "$android_jar" \
  --output "$dex_dir" \
  "${class_files[@]}"

base_apk="$intermediates/base.apk"
unsigned_apk="$intermediates/unsigned.apk"
aligned_apk="$intermediates/aligned.apk"
debug_apk="$outputs/snort-vpn-lite-debug.apk"

echo "linking APK"
"$aapt2" link \
  -o "$base_apk" \
  -I "$android_jar" \
  --manifest "$manifest" \
  --java "$gen_dir" \
  --min-sdk-version 31 \
  --target-sdk-version 36 \
  --version-code 1 \
  --version-name 0.1-debug \
  --debug-mode

cp "$base_apk" "$unsigned_apk"
(
  cd "$dex_dir"
  zip -q -r "$unsigned_apk" classes.dex
)
(
  cd "$jni_root"
  zip -q -r "$unsigned_apk" lib
)

if [[ ! -f "$keystore" ]]; then
  echo "creating debug keystore"
  keytool -genkeypair \
    -keystore "$keystore" \
    -storepass android \
    -keypass android \
    -alias androiddebugkey \
    -keyalg RSA \
    -keysize 2048 \
    -validity 10000 \
    -dname "CN=Android Debug,O=sakamoto,C=US" >/dev/null
fi

echo "zipalign"
"$zipalign_bin" -f -p 4 "$unsigned_apk" "$aligned_apk"

echo "signing"
java -jar "$apksigner_jar" sign \
  --ks "$keystore" \
  --ks-pass pass:android \
  --key-pass pass:android \
  --ks-key-alias androiddebugkey \
  --out "$debug_apk" \
  "$aligned_apk"

java -jar "$apksigner_jar" verify --print-certs "$debug_apk" >/dev/null

echo "ok: $debug_apk"
