#!/usr/bin/env python3
"""Fresh HEV/lwIP, experiment plugin, VPP executable and APK; pinned VPP DSOs."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tarfile

HERE = Path(__file__).resolve().parent
POC = HERE.parent
WORK = POC / "work/s245-s246"
BASE_BUILD = POC / "work/vpp-android-configure-probe"
NDK = Path("/home/js/.local/share/android-sdk/ndk/29.0.14206865")
OUT = WORK / "build"
STAGE = WORK / "stage"


def run(args, name, cwd=None, env=None):
    with (OUT / (name + ".log")).open("w") as log:
        p = subprocess.run([str(x) for x in args], cwd=cwd, env=env,
                           stdout=log, stderr=subprocess.STDOUT)
    if p.returncode:
        print((OUT / (name + ".log")).read_text()[-14000:])
        raise RuntimeError(name)


def main():
    OUT.mkdir(exist_ok=True)
    if not STAGE.exists():
        shutil.copytree(POC / "work/android-vpp-oi3-runtime-stage", STAGE)
    commands = subprocess.check_output(["ninja", "-C", str(BASE_BUILD), "-t", "commands",
                                       "hev_external_driver_poc_plugin"], text=True).splitlines()
    compile_lines = [line for line in commands if " -c " in line and
                     "/src/plugins/hev_external_driver_poc/" in line]
    objects = []
    compile_commands = []
    for line in compile_lines:
        argv = shlex.split(line)
        if argv[0].endswith("ccache"):
            argv.pop(0)
        source = Path(argv[argv.index("-c") + 1])
        target = OUT / (source.name + ".o")
        objects.append(target)
        argv[argv.index("-c") + 1] = str(WORK / "plugin" / source.name)
        for flag in ("-o", "-MT", "-MF"):
            argv[argv.index(flag) + 1] = str(target) + (".d" if flag == "-MF" else "")
        compile_commands.append((argv, "compile-" + source.name))
    (OUT / "plugin-compile-commands.json").write_text(json.dumps(compile_commands, indent=2) + "\n")
    print("Building experimental plugin and real HEV/lwIP", flush=True)
    with ThreadPoolExecutor(max_workers=5) as pool:
        jobs = [pool.submit(run, argv, name, BASE_BUILD) for argv, name in compile_commands]
        jobs.append(pool.submit(run, [NDK / "ndk-build",
            "NDK_PROJECT_PATH=" + str(WORK / "hev"),
            "APP_BUILD_SCRIPT=" + str(WORK / "hev/Android.mk"),
            "NDK_OUT=" + str(OUT / "hev-obj"), "NDK_LIBS_OUT=" + str(OUT / "hev-libs"),
            "APP_ABI=arm64-v8a", "APP_PLATFORM=android-31", "-j6"], "hev"))
        for job in jobs:
            job.result()
    clang = NDK / "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang"
    plugin = OUT / "hev_external_driver_poc_plugin.so"
    run([clang, "-shared", "-fPIC", "-Wl,--build-id=sha1", "-Wl,--no-undefined",
         *objects, "-L" + str(STAGE / "lib"), "-lvlib", "-lsvm", "-lvppinfra", "-ldl", "-lm", "-latomic",
         "-o", plugin], "link-plugin")
    # Rebuild the same full executable surface used by the broker harness.
    # vpp-lite omits api-segment registration and cannot consume its startup file.
    runtime_commands = subprocess.check_output(["ninja", "-C", str(BASE_BUILD), "-t", "commands", "vpp"], text=True).splitlines()
    runtime_objects = []
    runtime_compiles = []
    for line in runtime_commands:
        if " -c " not in line or "/src/vpp/" not in line:
            continue
        argv = shlex.split(line)
        if argv[0].endswith("ccache"):
            argv.pop(0)
        source = Path(argv[argv.index("-c") + 1])
        target = OUT / ("vpp-" + source.parent.name + "-" + source.name + ".o")
        runtime_objects.append(target)
        for flag in ("-o", "-MT", "-MF"):
            argv[argv.index(flag) + 1] = str(target) + (".d" if flag == "-MF" else "")
        runtime_compiles.append((argv, "compile-" + target.name))
    with ThreadPoolExecutor(max_workers=5) as pool:
        jobs = [pool.submit(run, argv, name, BASE_BUILD) for argv, name in runtime_compiles]
        for job in jobs:
            job.result()
    run([clang, "-Wl,--build-id=sha1", "-Wl,--export-dynamic", *runtime_objects,
         "-L" + str(STAGE / "lib"), "-lvnet", "-lvlibmemory", "-lvlibapi", "-lvlib", "-lsvm",
         "-lvppinfra", "-ldl", "-lm", "-latomic", "-o", STAGE / "bin/vpp"], "vpp-main")
    env = dict(os.environ, VPP_RUNTIME_STAGE_DIR=str(STAGE),
               HEV_STAGE_DIR=str(OUT / "hev-libs-stage"), VPP_POC_PLUGIN=str(plugin),
               APK_VERSION_NAME="s245-s246-20260907", APK_VERSION_CODE="245246")
    dest = OUT / "hev-libs-stage/lib/arm64-v8a"
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy2(OUT / "hev-libs/arm64-v8a/libhev-socks5-tunnel.so", dest)
    run(["bash", WORK / "app/scripts/build-debug-apk.sh"], "apk", env=env)
    files = [p for root in (STAGE, OUT / "hev-libs-stage", WORK / "plugin", WORK / "hev", WORK / "app")
             for p in root.rglob("*") if p.is_file() and
             not any(part in {"classes", "intermediates", "dex", ".git"} for part in p.parts)]
    manifest = {str(p.relative_to(WORK)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}
    (WORK / "artifact-source-sha256.json").write_text(json.dumps(manifest, indent=2) + "\n")
    apk = WORK / "app/build/outputs/snort-vpn-lite-debug.apk"
    archive = WORK / "artifacts" / hashlib.sha256(apk.read_bytes()).hexdigest()
    archive.mkdir(parents=True, exist_ok=True)
    for name in ("artifact-source-sha256.json", "baseline-files.json", "source-manifest.json"):
        shutil.copy2(WORK / name, archive / name)
    shutil.copy2(apk, archive / "experiment.apk")
    with tarfile.open(archive / "experiment-source.tar.gz", "w:gz") as tar:
        for relative in ("hev", "plugin", "app/src", "app/native", "app/scripts"):
            tar.add(WORK / relative, arcname=relative)
        tar.add(HERE, arcname="s245-s246")
    for label, root in (("repo", POC.parent.parent), ("vpp", POC / "work/vpp")):
        (archive / (label + "-head.txt")).write_bytes(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root))
        (archive / (label + "-dirty.diff")).write_bytes(subprocess.check_output(["git", "diff", "--binary"], cwd=root))
    (archive / "archive-sha256.json").write_text(json.dumps({p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in archive.iterdir() if p.name != "archive-sha256.json"}, indent=2) + "\n")
    print(WORK / "app/build/outputs/snort-vpn-lite-debug.apk", flush=True)


if __name__ == "__main__":
    main()
