#!/usr/bin/env python3
"""Build and run a C VAPI client against the tun_poc status API."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess


def load_status_smoke_module():
    script = Path(__file__).with_name("run-vpp-tun-poc-api-status-smoke.py")
    spec = importlib.util.spec_from_file_location("tun_poc_api_status_smoke", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_client(poc_dir: Path, output: Path) -> None:
    vpp_src = poc_dir / "work" / "vpp"
    vpp_install = vpp_src / "build-root" / "install-vpp-native" / "vpp"
    vpp_build = vpp_src / "build-root" / "build-vpp-native" / "vpp"
    lib_dir = vpp_install / "lib" / "x86_64-linux-gnu"
    source = poc_dir / "clients" / "tun_poc_vapi_status.c"
    cmd = [
        "cc",
        "-D_DEFAULT_SOURCE",
        "-Wall",
        "-Wextra",
        "-Wno-unused-parameter",
        "-Wno-sign-compare",
        "-std=c11",
        "-I",
        str(vpp_install / "include"),
        "-I",
        str(vpp_build / "CMakeFiles" / "vpp-api" / "vapi"),
        str(source),
        "-L",
        str(lib_dir),
        "-Wl,-rpath," + str(lib_dir),
        "-lvapiclient",
        "-o",
        str(output),
    ]
    subprocess.run(cmd, check=True)


def main() -> int:
    status_smoke = load_status_smoke_module()
    poc_dir = Path(__file__).resolve().parents[1]
    vpp_src = poc_dir / "work" / "vpp"
    vpp_install = vpp_src / "build-root" / "install-vpp-native" / "vpp"
    vpp_bin = vpp_install / "bin" / "vpp"
    runtime_root = Path("/tmp/sakamoto-vpp-tun-poc-vapi-c-status").resolve()
    startup_conf = runtime_root / "startup.conf"
    api_sock = runtime_root / "api.sock"
    stdout_log = runtime_root / "vpp-stdout.log"
    client_bin = runtime_root / "tun_poc_vapi_status"

    shutil.rmtree(runtime_root, ignore_errors=True)
    (runtime_root / "vpp-run").mkdir(parents=True, exist_ok=True)
    build_client(poc_dir, client_bin)
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
        subprocess.run([str(client_bin), str(api_sock)], check=True)
        print(f"vapi c client: {client_bin}")
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
