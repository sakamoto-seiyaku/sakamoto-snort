#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
build_script="$repo_root/app/android-runtime/scripts/build-debug-apk.sh"
dex_guard="$repo_root/app/android-runtime/scripts/check-android-process-api.sh"
android_jar="${SAKAMOTO_S172_ANDROID_JAR:-/home/js/android/lineage/prebuilts/sdk/36/public/android.jar}"
d8_jar="${SAKAMOTO_S172_D8_JAR:-/home/js/android/lineage/prebuilts/sdk/tools/linux/lib/d8.jar}"
default_dexdump="/home/js/android/lineage/prebuilts/sdk/tools/linux/bin/dexdump"
default_dexdump_sha256="cccd6b7473b8715672879672838a8e4cf1dfa8a0f008f432c7deb5c79cdce19d"
dexdump="${SAKAMOTO_ANDROID_DEXDUMP:-$default_dexdump}"
dexdump_sha256="${SAKAMOTO_ANDROID_DEXDUMP_SHA256:-$default_dexdump_sha256}"

test -f "$build_script"
test -x "$dex_guard"
test -f "$android_jar"
test -f "$d8_jar"
test -f "$dexdump"
test -x "$dexdump"
command -v java >/dev/null
command -v javac >/dev/null
command -v javap >/dev/null
command -v python3 >/dev/null
command -v sha256sum >/dev/null
command -v readelf >/dev/null
command -v unzip >/dev/null
command -v zip >/dev/null
zip_bin="$(command -v zip)"
actual_dexdump_sha256="$(sha256sum -- "$dexdump")"
actual_dexdump_sha256="${actual_dexdump_sha256%% *}"
test "$actual_dexdump_sha256" = "$dexdump_sha256"
dexdump_comment="$(readelf -p .comment -- "$dexdump")"
case "$dexdump_comment" in
  *"Android ("*"based on r"*"clang version "*) ;;
  *) echo "real dexdump lacks Android/AOSP .comment provenance" >&2; exit 1 ;;
esac
case "$dexdump_comment" in
  *"Linker: LLD "*) ;;
  *) echo "real dexdump lacks Android LLD .comment provenance" >&2; exit 1 ;;
esac

run_guard() {
  SAKAMOTO_ANDROID_DEXDUMP="$dexdump" \
  SAKAMOTO_ANDROID_DEXDUMP_SHA256="$dexdump_sha256" \
    "$dex_guard" "$@"
}

# The build must bind javac's platform classes to Android and prove that
# java.lang.Process was loaded from that stub, rather than from host JDK17.
grep -Fq -- '-bootclasspath "$javac_bootclasspath"' "$build_script"
grep -Fq 'javac_bootclasspath="$android_jar:$javac_support_jar"' "$build_script"
grep -Fq 'javac_support_jar' "$build_script"
grep -Fq 'LambdaMetafactory.class' "$build_script"
grep -Fq 'javac.verbose.log' "$build_script"
grep -Fq 'java/lang/Process.class' "$build_script"
grep -Fq 'modules/java.base/java/lang/Process.class' "$build_script"
grep -Fq 'check-android-process-api.sh' "$build_script"
grep -Fq '"$dex_guard" "$dex_dir/classes.dex"' "$build_script"
grep -Fq '"$dex_guard" "$signed_apk"' "$build_script"
grep -Fq 'if ((${#d8_outputs[@]} != 1))' "$build_script"
grep -Fq '"$dexdump_path" -a -d --' "$dex_guard"
grep -Fq 'default_dexdump_sha256=' "$dex_guard"
grep -Fq 'readelf_bin=' "$dex_guard"
grep -Fq 'SAKAMOTO_ANDROID_DEXDUMP_SHA256' "$dex_guard"
if grep -Fq 'command -v dexdump' "$dex_guard" || \
    grep -Fq 'PATH lookup' "$dex_guard"; then
  echo "the official dexdump seam still permits PATH fallback" >&2
  exit 1
fi
if grep -Fq 'check-android-process-api.py' "$build_script" || \
    test -e "$repo_root/app/android-runtime/scripts/check-android-process-api.py"; then
  echo "the homemade DEX parser is still wired into the Android build" >&2
  exit 1
fi
grep -Fq 'process.getOutputStream().close();' \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"

base_dir="$(mktemp -d "${TMPDIR:-/tmp}/sakamoto-172-process-api.XXXXXX")"
work_dir="$base_dir/path with spaces"
trap 'rm -rf -- "$base_dir"' EXIT
mkdir -p "$work_dir/classes" "$work_dir/dex" \
  "$work_dir/bad-classes" "$work_dir/bad-dex" \
  "$work_dir/handle-classes" "$work_dir/handle-dex" \
  "$work_dir/string-classes" "$work_dir/string-dex"

# Resolve all JDK tools from the selected java.home, matching the APK builder.
java_launcher="$(realpath -e -- "$(command -v java)")"
java_home="$($java_launcher -XshowSettings:properties -version 2>&1 \
  | sed -n 's/^[[:space:]]*java.home = //p' | head -n 1)"
java_home="$(realpath -e -- "$java_home")"
java_bin="$java_home/bin/java"
javac_bin="$java_home/bin/javac"
javap_bin="$java_home/bin/javap"
jimage_bin="$java_home/bin/jimage"
jar_bin="$java_home/bin/jar"
for tool_path in "$java_bin" "$javac_bin" "$javap_bin" "$jimage_bin" "$jar_bin"; do
  test -x "$tool_path"
done
test "$(realpath -e -- "$java_bin")" = "$java_launcher"
test -f "$java_home/lib/modules"

mkdir -p "$work_dir/javac-support"
"$jimage_bin" extract --dir="$work_dir/javac-support" \
  --include "glob:**/java/lang/invoke/LambdaMetafactory.class" \
  "$java_home/lib/modules" >/dev/null
"$jar_bin" cf "$work_dir/javac-support.jar" \
  -C "$work_dir/javac-support/java.base" \
  java/lang/invoke/LambdaMetafactory.class
javac_bootclasspath="$android_jar:$work_dir/javac-support.jar"

# Compile the complete Android Java source set using the production
# bootclasspath contract, then inspect class files with the JDK's official
# javap and the generated DEX with the official AOSP dexdump gate.
mapfile -t sources < <(find "$repo_root/app/android-runtime/src/main/java" \
  -type f -name '*.java' -print | sort)
((${#sources[@]} > 0))
"$javac_bin" -encoding UTF-8 -Xlint:-options -source 8 -target 8 \
  -bootclasspath "$javac_bootclasspath" -classpath "$android_jar" -verbose \
  -d "$work_dir/classes" "${sources[@]}" >"$work_dir/javac.log" 2>&1
grep -Fq "$android_jar(/java/lang/Process.class)" "$work_dir/javac.log"
if grep -Fq '/modules/java.base/java/lang/Process.class' "$work_dir/javac.log"; then
  echo "complete Android source compile used host java.base" >&2
  exit 1
fi

mapfile -t class_files < <(find "$work_dir/classes" -type f -name '*.class' -print | sort)
((${#class_files[@]} > 0))
for class_file in "${class_files[@]}"; do
  class_dump="$($javap_bin -verbose "$class_file")"
  if grep -Fq 'java/lang/Process.pid' <<<"$class_dump" || \
      grep -Fq 'java/lang/Process.toHandle' <<<"$class_dump" || \
      grep -Fq 'java/lang/ProcessHandle' <<<"$class_dump"; then
    echo "complete Android source compile emitted an unsupported Process API" >&2
    exit 1
  fi
done

"$java_bin" -cp "$d8_jar" com.android.tools.r8.D8 --lib "$android_jar" \
  --min-api 31 --output "$work_dir/dex" "${class_files[@]}"
mapfile -t dex_outputs < <(find "$work_dir/dex" -mindepth 1 -maxdepth 1 -print | sort)
test "${#dex_outputs[@]}" -eq 1
test "$(basename -- "${dex_outputs[0]}")" = classes.dex
run_guard "$work_dir/dex/classes.dex" >"$work_dir/legal-dex.log"
grep -Fq 'official AOSP dexdump' "$work_dir/legal-dex.log"
env -u SAKAMOTO_ANDROID_DEXDUMP -u SAKAMOTO_ANDROID_DEXDUMP_SHA256 \
  "$dex_guard" "$work_dir/dex/classes.dex" >"$work_dir/default-dex.log"
grep -Fq 'official AOSP dexdump' "$work_dir/default-dex.log"

# A path containing spaces must not alter ZIP enumeration or official-tool
# invocation.  This is a legal single-dex APK and must pass.
legal_apk="$work_dir/legal artifact.apk"
(
  cd "$work_dir/dex"
  "$zip_bin" -q -0 "$legal_apk" classes.dex
)
run_guard "$legal_apk" >"$work_dir/legal-apk.log"
grep -Fq 'official AOSP dexdump' "$work_dir/legal-apk.log"

# A descriptor-looking const-string is data, not a DEX type reference.  The
# official output must preserve that distinction.
printf '%s\n' \
  'public final class LegalProcessApiStrings {' \
  '  public static String value() {' \
  '    return "Ljava/lang/ProcessHandle; Ljava/lang/Process;.pid:()J Ljava/lang/Process;.toHandle:()Ljava/lang/ProcessHandle;";' \
  '  }' \
  '}' >"$work_dir/LegalProcessApiStrings.java"
"$javac_bin" -source 8 -target 8 -d "$work_dir/string-classes" \
  "$work_dir/LegalProcessApiStrings.java" >"$work_dir/string-javac.log" 2>&1
"$java_bin" -cp "$d8_jar" com.android.tools.r8.D8 --lib "$android_jar" \
  --min-api 31 --output "$work_dir/string-dex" \
  "$work_dir/string-classes/LegalProcessApiStrings.class"
run_guard "$work_dir/string-dex/classes.dex" >"$work_dir/string.log" 2>&1
grep -Fq 'no unsupported references' "$work_dir/string.log"

# An override is explicit and must be the artifact actually inspected.  A
# fake banner cannot satisfy the ELF provenance check, even when its own hash
# is supplied; the marker proves the selected override was invoked.
fake_called="$work_dir/fake-dexdump.called"
fake_dexdump="$work_dir/fake-dexdump"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'touch "$FAKE_DEXDUMP_CALLED"' \
  'echo "Copyright (C) 2007 The Android Open Source Project" >&2' \
  'echo "dexdump: fake" >&2' \
  'exit 0' >"$fake_dexdump"
chmod +x "$fake_dexdump"
fake_hash="$(sha256sum -- "$fake_dexdump")"
fake_hash="${fake_hash%% *}"
if FAKE_DEXDUMP_CALLED="$fake_called" \
    SAKAMOTO_ANDROID_DEXDUMP="$fake_dexdump" \
    SAKAMOTO_ANDROID_DEXDUMP_SHA256="$fake_hash" \
    "$dex_guard" "$work_dir/dex/classes.dex" >"$work_dir/fake.log" 2>&1; then
  echo "fake dexdump banner passed the provenance gate" >&2
  exit 1
fi
test -f "$fake_called"
grep -Fq 'ELF .comment' "$work_dir/fake.log"

if SAKAMOTO_ANDROID_DEXDUMP="$dexdump" \
    env -u SAKAMOTO_ANDROID_DEXDUMP_SHA256 \
    "$dex_guard" "$work_dir/dex/classes.dex" >"$work_dir/missing-hash.log" 2>&1; then
  echo "an override without an expected hash passed the artifact gate" >&2
  exit 1
fi
grep -Fq 'SHA256 is required' "$work_dir/missing-hash.log"

# A supplied expected hash cannot bless a different artifact.
if SAKAMOTO_ANDROID_DEXDUMP="$dexdump" \
    SAKAMOTO_ANDROID_DEXDUMP_SHA256="0000000000000000000000000000000000000000000000000000000000000000" \
    "$dex_guard" "$work_dir/dex/classes.dex" >"$work_dir/tampered-hash.log" 2>&1; then
  echo "tampered dexdump hash passed the provenance gate" >&2
  exit 1
fi
grep -Fq 'SHA-256 mismatch' "$work_dir/tampered-hash.log"

# A malformed/truncated artifact must fail closed on the official parser's
# non-zero status.
invalid_dex="$work_dir/not-a-dex.dex"
printf '%s\n' 'not a DEX file' >"$invalid_dex"
if run_guard "$invalid_dex" >"$work_dir/invalid.log" 2>&1; then
  echo "malformed DEX passed the official artifact gate" >&2
  exit 1
fi
grep -Fq 'cannot be parsed by official Android AOSP dexdump' "$work_dir/invalid.log"

# Compile a real host-JDK Process.pid() call.  The DEX gate must reject its
# emitted method reference; a source spelling check would not prove this.
printf '%s\n' \
  'public final class BadProcessApi {' \
  '  public static long pid(java.lang.Process process) { return process.pid(); }' \
  '}' >"$work_dir/BadProcessApi.java"
"$javac_bin" -source 8 -target 8 -d "$work_dir/bad-classes" \
  "$work_dir/BadProcessApi.java" >"$work_dir/bad-javac.log" 2>&1
"$java_bin" -cp "$d8_jar" com.android.tools.r8.D8 --lib "$android_jar" \
  --min-api 31 --output "$work_dir/bad-dex" \
  "$work_dir/bad-classes/BadProcessApi.class"
bad_apk="$work_dir/host-process-pid.apk"
(
  cd "$work_dir/bad-dex"
  "$zip_bin" -q -0 "$bad_apk" classes.dex
)
if run_guard "$bad_apk" >"$work_dir/bad-process.log" 2>&1; then
  echo "host Process.pid() artifact passed the official Android API gate" >&2
  exit 1
fi
grep -Fq 'java/lang/Process.pid:()J' "$work_dir/bad-process.log"

# Compile real references to ProcessHandle in fields, annotations, class
# literals, arrays, nested types, and a method reference.  dexdump prints
# these from its structured output; this test never constructs or reads DEX.
printf '%s\n' \
  'import java.lang.annotation.Retention;' \
  'import java.lang.annotation.RetentionPolicy;' \
  '@Retention(RetentionPolicy.RUNTIME)' \
  '@interface ProcessHandleMarker { Class<?> value(); }' \
  '@ProcessHandleMarker(java.lang.ProcessHandle.class)' \
  'public final class BadProcessHandleApis {' \
  '  public java.lang.ProcessHandle field;' \
  '  public static Class<?> literal() { return java.lang.ProcessHandle.class; }' \
  '  public static java.lang.ProcessHandle[] one(java.lang.ProcessHandle[] value) { return value; }' \
  '  public static java.lang.ProcessHandle[][] two(java.lang.ProcessHandle[][] value) { return value; }' \
  '  public static java.lang.ProcessHandle.Info nested(java.lang.ProcessHandle.Info value) { return value; }' \
  '  public static java.lang.ProcessHandle handle(java.lang.Process process) { return process.toHandle(); }' \
  '}' >"$work_dir/BadProcessHandleApis.java"
"$javac_bin" -source 8 -target 8 -d "$work_dir/handle-classes" \
  "$work_dir/BadProcessHandleApis.java" >"$work_dir/handle-javac.log" 2>&1
"$java_bin" -cp "$d8_jar" com.android.tools.r8.D8 --lib "$android_jar" \
  --min-api 31 --output "$work_dir/handle-dex" \
  "$work_dir/handle-classes"/*.class
if run_guard "$work_dir/handle-dex/classes.dex" \
    >"$work_dir/handle-process.log" 2>&1; then
  echo "ProcessHandle artifact passed the official Android API gate" >&2
  exit 1
fi
grep -Fq 'java/lang/ProcessHandle' "$work_dir/handle-process.log"
grep -Fq 'java/lang/Process.toHandle' "$work_dir/handle-process.log"

# A duplicate classes.dex record is rejected before name-based ZIP extraction.
# Python is used only for a duplicate ZIP-container fixture; it does not read
# or construct DEX bytes.
duplicate_apk="$work_dir/duplicate-classes.apk"
python3 - "$work_dir/dex/classes.dex" "$duplicate_apk" <<'PY'
import pathlib
import sys
import zipfile

dex = pathlib.Path(sys.argv[1]).read_bytes()
with zipfile.ZipFile(sys.argv[2], "w", compression=zipfile.ZIP_STORED) as archive:
    archive.writestr("classes.dex", dex)
    archive.writestr("classes.dex", dex)
PY
if run_guard "$duplicate_apk" >"$work_dir/duplicate.log" 2>&1; then
  echo "duplicate classes.dex APK passed the artifact gate" >&2
  exit 1
fi
grep -Fq 'duplicate entry: classes.dex' "$work_dir/duplicate.log"

# The product assembler is intentionally single-dex.  A disabled reference
# hidden in classes2.dex must still be parsed and rejected before policy.
multidex_apk="$work_dir/multidex.apk"
(
  cd "$work_dir/dex"
  cp "$work_dir/bad-dex/classes.dex" classes2.dex
  "$zip_bin" -q -0 "$multidex_apk" classes.dex classes2.dex
)
if run_guard "$multidex_apk" >"$work_dir/multidex.log" 2>&1; then
  echo "multidex APK passed the single-dex artifact policy" >&2
  exit 1
fi
grep -Fq 'java/lang/Process.pid:()J' "$work_dir/multidex.log"

echo "sakamoto-172 Android Process API contract: PASS (official AOSP dexdump)"
