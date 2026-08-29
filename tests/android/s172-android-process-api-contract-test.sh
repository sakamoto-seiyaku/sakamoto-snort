#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
build_script="$repo_root/app/android-runtime/scripts/build-debug-apk.sh"
dex_guard="$repo_root/app/android-runtime/scripts/check-android-process-api.py"
android_jar="${SAKAMOTO_S172_ANDROID_JAR:-/home/js/android/lineage/prebuilts/sdk/36/public/android.jar}"
d8_jar="${SAKAMOTO_S172_D8_JAR:-/home/js/android/lineage/prebuilts/sdk/tools/linux/lib/d8.jar}"

test -f "$build_script"
test -f "$dex_guard"
test -f "$android_jar"
test -f "$d8_jar"
command -v java >/dev/null
command -v python3 >/dev/null
command -v zip >/dev/null

# The build must bind javac's platform classes to Android and prove that
# java.lang.Process was loaded from that stub, rather than from host JDK17.
grep -Fq -- '-bootclasspath "$javac_bootclasspath"' "$build_script"
grep -Fq 'javac_bootclasspath="$android_jar:$javac_support_jar"' "$build_script"
grep -Fq 'javac_support_jar' "$build_script"
grep -Fq 'LambdaMetafactory.class' "$build_script"
grep -Fq 'javac.verbose.log' "$build_script"
grep -Fq 'java/lang/Process.class' "$build_script"
grep -Fq 'modules/java.base/java/lang/Process.class' "$build_script"
grep -Fq 'check-android-process-api.py' "$build_script"
grep -Fq 'process.getOutputStream().close();' "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/sakamoto-172-process-api.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT
mkdir -p "$work_dir/classes" "$work_dir/dex" "$work_dir/bad-classes" "$work_dir/bad-dex"
java_launcher="$(command -v java)"
java_launcher="$(realpath -e -- "$java_launcher")"
python_bin="$(command -v python3)"
zip_bin="$(command -v zip)"
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
mkdir -p "$work_dir/javac-support"
"$jimage_bin" extract --dir="$work_dir/javac-support" \
  --include "glob:**/java/lang/invoke/LambdaMetafactory.class" \
  "$java_home/lib/modules" >/dev/null
"$jar_bin" cf "$work_dir/javac-support.jar" \
  -C "$work_dir/javac-support/java.base" java/lang/invoke/LambdaMetafactory.class
javac_bootclasspath="$android_jar:$work_dir/javac-support.jar"

# Compile the complete Android Java source set using the same bootclasspath
# contract as the APK builder, then inspect both class files and DEX output.
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

while IFS= read -r -d '' class_file; do
  class_dump="$("$javap_bin" -verbose "$class_file")"
  if grep -Fq 'java/lang/Process.pid' <<<"$class_dump" || \
      grep -Fq 'java/lang/Process.toHandle' <<<"$class_dump" || \
      grep -Fq 'java/lang/ProcessHandle' <<<"$class_dump"; then
    echo "complete Android source compile emitted an unsupported Process API" >&2
    exit 1
  fi
done < <(find "$work_dir/classes" -type f -name '*.class' -print0 | sort -z)

"$java_bin" -cp "$d8_jar" com.android.tools.r8.D8 --lib "$android_jar" \
  --min-api 31 --output "$work_dir/dex" \
  $(find "$work_dir/classes" -type f -name '*.class' -print | sort)
mapfile -t dex_outputs < <(find "$work_dir/dex" -mindepth 1 -maxdepth 1 -print | sort)
test "${#dex_outputs[@]}" -eq 1
test "$(basename -- "${dex_outputs[0]}")" = classes.dex
"$python_bin" "$dex_guard" "$work_dir/dex/classes.dex"

# Reproduce the old 1787969241 artifact's forbidden method reference through
# the same JDK17 -> D8 path. The DEX gate must reject the APK, not merely the
# source spelling of process.pid().
printf '%s\n' \
  'public final class BadProcessApi {' \
  '  public static long pid(java.lang.Process process) { return process.pid(); }' \
  '}' >"$work_dir/BadProcessApi.java"
"$javac_bin" -source 8 -target 8 -d "$work_dir/bad-classes" "$work_dir/BadProcessApi.java"
"$java_bin" -cp "$d8_jar" com.android.tools.r8.D8 --lib "$android_jar" \
  --min-api 31 --output "$work_dir/bad-dex" \
  "$work_dir/bad-classes/BadProcessApi.class"
mkdir -p "$work_dir/old-1787969241"
cp "$work_dir/bad-dex/classes.dex" "$work_dir/old-1787969241/classes.dex"
(
  cd "$work_dir/old-1787969241"
  "$zip_bin" -q -0 "../sakamoto-runtime-debug-1787969241.apk" classes.dex
)
if "$python_bin" "$dex_guard" "$work_dir/sakamoto-runtime-debug-1787969241.apk"; then
  echo "1787969241-style APK passed the Android Process API gate" >&2
  exit 1
fi

expect_checker_failure() {
  local fixture="$1"
  if "$python_bin" "$dex_guard" "$fixture" >"$work_dir/checker-output.log" 2>&1; then
    echo "checker unexpectedly passed: $fixture" >&2
    cat "$work_dir/checker-output.log" >&2
    exit 1
  fi
}

# Compile real DEX references to both one-dimensional and multidimensional
# ProcessHandle arrays. The gate must normalize every '[' prefix before the
# conservative type-ID rejection; this is not a source-only grep test.
mkdir -p "$work_dir/handle-classes" "$work_dir/handle-dex"
printf '%s\n' \
  'public final class BadProcessHandleArrays {' \
  '  public static java.lang.ProcessHandle[] one(java.lang.ProcessHandle[] value) { return value; }' \
  '  public static java.lang.ProcessHandle[][] two(java.lang.ProcessHandle[][] value) { return value; }' \
  '  public static java.lang.ProcessHandle.Info nested(java.lang.ProcessHandle.Info value) { return value; }' \
  '}' >"$work_dir/BadProcessHandleArrays.java"
"$javac_bin" -source 8 -target 8 -d "$work_dir/handle-classes" \
  "$work_dir/BadProcessHandleArrays.java"
"$java_bin" -cp "$d8_jar" com.android.tools.r8.D8 --lib "$android_jar" \
  --min-api 31 --output "$work_dir/handle-dex" \
  "$work_dir/handle-classes/BadProcessHandleArrays.class" \
  >"$work_dir/handle-d8.log" 2>&1
expect_checker_failure "$work_dir/handle-dex/classes.dex"
grep -Fq 'type [Ljava/lang/ProcessHandle;' "$work_dir/checker-output.log"
grep -Fq 'type [[Ljava/lang/ProcessHandle;' "$work_dir/checker-output.log"
grep -Fq 'type Ljava/lang/ProcessHandle$Info;' "$work_dir/checker-output.log"

# Exercise the structural fail-closed path against the real product DEX. No
# invoke/code-item parser is needed: malformed headers, ID tables, and data
# offsets must never reach the API decision as a PASS.
mkdir -p "$work_dir/malformed"
"$python_bin" - "$work_dir/dex/classes.dex" "$work_dir/malformed" <<'PY'
import pathlib
import struct
import sys

source = pathlib.Path(sys.argv[1]).read_bytes()
output = pathlib.Path(sys.argv[2])


def u32(blob, offset):
    return struct.unpack_from("<I", blob, offset)[0]


def write(name, blob):
    (output / name).write_bytes(blob)


def mutate(name, offset, value):
    blob = bytearray(source)
    struct.pack_into("<I", blob, offset, value)
    write(name, blob)


write("truncated.dex", source[:-1])
empty_header = bytearray(112)
empty_header[:8] = source[:8]
struct.pack_into("<I", empty_header, 32, 112)
struct.pack_into("<I", empty_header, 36, 112)
struct.pack_into("<I", empty_header, 40, 0x12345678)
write("empty-header.dex", empty_header)
bad_magic = bytearray(source)
bad_magic[0] = ord("x")
write("bad-magic.dex", bad_magic)
bad_version = bytearray(source)
bad_version[4:7] = b"999"
write("bad-version.dex", bad_version)
mutate("bad-file-size.dex", 32, len(source) + 1)
mutate("bad-header-size.dex", 36, 0)
mutate("bad-endian.dex", 40, 0x78563412)

for name, count_offset, table_offset in (
    ("bad-string-table.dex", 56, 60),
    ("bad-type-table.dex", 64, 68),
    ("bad-proto-table.dex", 72, 76),
    ("bad-method-table.dex", 88, 92),
):
    if u32(source, count_offset) == 0:
        raise SystemExit(f"fixture unexpectedly has no {name} entries")
    mutate(name, table_offset, len(source) - 1)

if u32(source, 104) == 0:
    raise SystemExit("fixture unexpectedly has no DEX data section")
mutate("bad-data-section.dex", 108, len(source) - 1)

string_ids_offset = u32(source, 60)
data_end = u32(source, 108) + u32(source, 104)
if not u32(source, 56) or not u32(source, 104):
    raise SystemExit("fixture unexpectedly has no string/data entries")
bad_string_data = bytearray(source)
struct.pack_into("<I", bad_string_data, string_ids_offset, data_end)
write("bad-string-data.dex", bad_string_data)

proto_offset = u32(source, 76)
proto_count = u32(source, 72)
for index in range(proto_count):
    parameters_offset = u32(source, proto_offset + index * 12 + 8)
    if parameters_offset:
        bad_parameters = bytearray(source)
        struct.pack_into("<I", bad_parameters, proto_offset + index * 12 + 8, data_end)
        write("bad-proto-parameters.dex", bad_parameters)
        break
else:
    raise SystemExit("fixture unexpectedly has no proto parameter list")
PY
for malformed in "$work_dir"/malformed/*.dex; do
  expect_checker_failure "$malformed"
done

# A classes2.dex entry must be inspected even though the build itself is
# required to publish exactly one classes.dex.
mkdir -p "$work_dir/multi-dex"
cp "$work_dir/dex/classes.dex" "$work_dir/multi-dex/classes.dex"
cp "$work_dir/bad-dex/classes.dex" "$work_dir/multi-dex/classes2.dex"
(
  cd "$work_dir/multi-dex"
  "$zip_bin" -q -0 "$work_dir/multi-dex.apk" classes.dex classes2.dex
)
expect_checker_failure "$work_dir/multi-dex.apk"

# Keep the build-level contracts executable and tied to the same-JDK/single-
# DEX implementation above; the real fixtures provide the behavioral checks.
grep -Fq 'java_home/bin/javac' "$build_script"
grep -Fq 'java_home/bin/jar' "$build_script"
grep -Fq 'java_home/bin/jimage' "$build_script"
grep -Fq 'D8 produced unexpected classes*.dex output' "$build_script"
grep -Fq 'if ((${#d8_outputs[@]} != 1))' "$build_script"

echo "sakamoto-172 Android Process API contract: PASS"
