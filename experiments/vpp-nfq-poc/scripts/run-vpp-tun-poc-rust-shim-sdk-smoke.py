#!/usr/bin/env python3
"""Build and run the Rust policy client against a staged shim SDK."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess


VPP_CLIENT_LIBS = [
    "libvapiclient.so",
    "libvlibmemoryclient.so",
    "libvlibapi.so",
    "libsvm.so",
    "libvppinfra.so",
]


def load_status_smoke_module():
    script = Path(__file__).with_name("run-vpp-tun-poc-api-status-smoke.py")
    spec = importlib.util.spec_from_file_location("tun_poc_api_status_smoke", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def copy_shared_lib_with_soname(source_link: Path, sdk_lib: Path) -> None:
    if not source_link.exists():
        raise FileNotFoundError(source_link)
    real_source = source_link.resolve()
    real_dest = sdk_lib / real_source.name
    shutil.copy2(real_source, real_dest)
    link_dest = sdk_lib / source_link.name
    if link_dest.exists() or link_dest.is_symlink():
        link_dest.unlink()
    os.symlink(real_dest.name, link_dest)


def stage_runtime_libs(vpp_lib: Path, sdk_lib: Path) -> None:
    for lib in VPP_CLIENT_LIBS:
        copy_shared_lib_with_soname(vpp_lib / lib, sdk_lib)


def build_staged_sdk(poc_dir: Path, sdk_dir: Path) -> None:
    vpp_src = poc_dir / "work" / "vpp"
    vpp_install = vpp_src / "build-root" / "install-vpp-native" / "vpp"
    vpp_build = vpp_src / "build-root" / "build-vpp-native" / "vpp"
    vpp_lib = vpp_install / "lib" / "x86_64-linux-gnu"
    sdk_include = sdk_dir / "include"
    sdk_lib = sdk_dir / "lib"
    shim_source = poc_dir / "clients" / "tun_poc_control_shim.c"
    shim_header = poc_dir / "clients" / "tun_poc_control_shim.h"
    shim_object = sdk_dir / "tun_poc_control_shim.o"
    shim_lib = sdk_lib / "libtun_poc_control_shim.a"

    sdk_include.mkdir(parents=True, exist_ok=True)
    sdk_lib.mkdir(parents=True, exist_ok=True)
    shutil.copy2(shim_header, sdk_include / shim_header.name)
    stage_runtime_libs(vpp_lib, sdk_lib)

    subprocess.run(
        [
            "cc",
            "-D_DEFAULT_SOURCE",
            "-Wall",
            "-Wextra",
            "-Wno-unused-parameter",
            "-Wno-sign-compare",
            "-std=c11",
            "-fPIC",
            "-I",
            str(poc_dir / "clients"),
            "-I",
            str(vpp_install / "include"),
            "-I",
            str(vpp_build / "CMakeFiles" / "vpp-api" / "vapi"),
            "-c",
            str(shim_source),
            "-o",
            str(shim_object),
        ],
        check=True,
    )
    subprocess.run(["ar", "rcs", str(shim_lib), str(shim_object)], check=True)


def build_rust_policy_client(poc_dir: Path, runtime_root: Path, sdk_dir: Path) -> Path:
    rust_source = poc_dir / "clients" / "tun_poc_rust_policy.rs"
    rust_bin = runtime_root / "tun_poc_rust_policy_sdk"
    sdk_lib = sdk_dir / "lib"

    subprocess.run(
        [
            "rustc",
            "--edition=2021",
            str(rust_source),
            "-L",
            f"native={sdk_lib}",
            "-l",
            "static=tun_poc_control_shim",
            "-l",
            "dylib=vapiclient",
            "-l",
            "dylib=vlibmemoryclient",
            "-l",
            "dylib=vlibapi",
            "-l",
            "dylib=svm",
            "-l",
            "dylib=vppinfra",
            "-l",
            "dylib=m",
            "-C",
            "link-arg=-Wl,--disable-new-dtags",
            "-C",
            f"link-arg=-Wl,-rpath,{sdk_lib}",
            "-C",
            f"link-arg=-Wl,-rpath-link,{sdk_lib}",
            "-o",
            str(rust_bin),
        ],
        check=True,
    )
    return rust_bin


def staged_loader_env(sdk_dir: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = str((sdk_dir / "lib").resolve())
    return env


def verify_staged_linkage(
    rust_bin: Path, sdk_dir: Path, env: dict[str, str]
) -> None:
    sdk_lib = (sdk_dir / "lib").resolve()
    result = subprocess.run(
        ["ldd", str(rust_bin)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        env=env,
    )
    for lib in VPP_CLIENT_LIBS:
        prefix = f"{lib}."
        matching_lines = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip().startswith(lib) or line.strip().startswith(prefix)
        ]
        if not matching_lines:
            raise RuntimeError(f"{lib} not found in ldd output\n{result.stdout}")
        line = matching_lines[0]
        marker = "=>"
        if marker not in line:
            raise RuntimeError(f"could not parse ldd line for {lib}: {line}")
        resolved = Path(line.split(marker, 1)[1].split("(", 1)[0].strip()).resolve()
        if not resolved.is_relative_to(sdk_lib):
            raise RuntimeError(
                f"{lib} resolved outside staged SDK: {resolved}\n{result.stdout}"
            )


def main() -> int:
    status_smoke = load_status_smoke_module()
    poc_dir = Path(__file__).resolve().parents[1]
    vpp_src = poc_dir / "work" / "vpp"
    vpp_install = vpp_src / "build-root" / "install-vpp-native" / "vpp"
    vpp_bin = vpp_install / "bin" / "vpp"
    runtime_root = Path("/tmp/sakamoto-vpp-tun-poc-rust-shim-sdk").resolve()
    sdk_dir = runtime_root / "sdk"
    startup_conf = runtime_root / "startup.conf"
    api_sock = runtime_root / "api.sock"
    stdout_log = runtime_root / "vpp-stdout.log"

    shutil.rmtree(runtime_root, ignore_errors=True)
    (runtime_root / "vpp-run").mkdir(parents=True, exist_ok=True)
    build_staged_sdk(poc_dir, sdk_dir)
    rust_bin = build_rust_policy_client(poc_dir, runtime_root, sdk_dir)
    env = staged_loader_env(sdk_dir)
    verify_staged_linkage(rust_bin, sdk_dir, env)
    status_smoke.write_startup_config(startup_conf, runtime_root, api_sock)

    stdout_file = stdout_log.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        [str(vpp_bin), "-c", str(startup_conf)],
        stdout=stdout_file,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        status_smoke.wait_for_socket(proc, api_sock, stdout_log)
        subprocess.run([str(rust_bin), str(api_sock)], check=True, env=env)
        print(f"staged sdk: {sdk_dir}")
        print(f"loader env: LD_LIBRARY_PATH={env['LD_LIBRARY_PATH']}")
        print(f"rust ffi client: {rust_bin}")
        print(f"vpp stdout log: {stdout_log}")
        return 0
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        stdout_file.close()


if __name__ == "__main__":
    raise SystemExit(main())
