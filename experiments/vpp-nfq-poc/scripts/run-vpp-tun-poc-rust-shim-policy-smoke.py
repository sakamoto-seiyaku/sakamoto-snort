#!/usr/bin/env python3
"""Build and run a Rust client that mutates policy through the C shim."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess


def load_rust_status_smoke_module():
    script = Path(__file__).with_name("run-vpp-tun-poc-rust-shim-status-smoke.py")
    spec = importlib.util.spec_from_file_location("tun_poc_rust_status_smoke", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    rust_status_smoke = load_rust_status_smoke_module()
    status_smoke = rust_status_smoke.load_status_smoke_module()
    poc_dir = Path(__file__).resolve().parents[1]
    vpp_src = poc_dir / "work" / "vpp"
    vpp_install = vpp_src / "build-root" / "install-vpp-native" / "vpp"
    vpp_bin = vpp_install / "bin" / "vpp"
    runtime_root = Path("/tmp/sakamoto-vpp-tun-poc-rust-shim-policy").resolve()
    startup_conf = runtime_root / "startup.conf"
    api_sock = runtime_root / "api.sock"
    stdout_log = runtime_root / "vpp-stdout.log"

    shutil.rmtree(runtime_root, ignore_errors=True)
    (runtime_root / "vpp-run").mkdir(parents=True, exist_ok=True)
    rust_bin = rust_status_smoke.build_shim_and_rust_client(
        poc_dir,
        runtime_root,
        rust_source_name="tun_poc_rust_policy.rs",
        rust_bin_name="tun_poc_rust_policy",
    )
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
        subprocess.run([str(rust_bin), str(api_sock)], check=True)
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
