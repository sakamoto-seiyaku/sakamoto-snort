#!/usr/bin/env python3
"""Verify stale persistent shim handles fail and fresh handles reconnect."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import select
import shutil
import subprocess
import time


def load_rust_status_smoke_module():
    script = Path(__file__).with_name("run-vpp-tun-poc-rust-shim-status-smoke.py")
    spec = importlib.util.spec_from_file_location("tun_poc_rust_status_smoke", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def start_vpp(vpp_bin: Path, startup_conf: Path, log_path: Path):
    stdout_file = log_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        [str(vpp_bin), "-c", str(startup_conf)],
        stdout=stdout_file,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc, stdout_file


def stop_vpp(proc: subprocess.Popen[object] | None, stdout_file) -> None:
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    if stdout_file is not None:
        stdout_file.close()


def wait_for_client_line(
    proc: subprocess.Popen[str], expected: str, timeout: float = 10.0
) -> str:
    assert proc.stdout is not None
    deadline = time.monotonic() + timeout
    lines: list[str] = []
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            rest = proc.stdout.read()
            if rest:
                lines.append(rest)
                print(rest, end="")
            raise RuntimeError(
                f"client exited before {expected!r}\n" + "".join(lines)
            )
        remaining = max(0.0, min(0.25, deadline - time.monotonic()))
        readable, _, _ = select.select([proc.stdout], [], [], remaining)
        if not readable:
            continue
        line = proc.stdout.readline()
        if line == "":
            continue
        lines.append(line)
        print(line, end="")
        if expected in line:
            return line
    raise TimeoutError(f"timed out waiting for {expected!r}\n" + "".join(lines))


def main() -> int:
    rust_status_smoke = load_rust_status_smoke_module()
    status_smoke = rust_status_smoke.load_status_smoke_module()
    poc_dir = Path(__file__).resolve().parents[1]
    vpp_src = poc_dir / "work" / "vpp"
    vpp_install = vpp_src / "build-root" / "install-vpp-native" / "vpp"
    vpp_bin = vpp_install / "bin" / "vpp"
    runtime_root = Path("/tmp/sakamoto-vpp-tun-poc-rust-shim-reconnect").resolve()
    startup_conf = runtime_root / "startup.conf"
    api_sock = runtime_root / "api.sock"
    stale_marker = runtime_root / "probe-stale"
    reopen_marker = runtime_root / "probe-reopen"
    stdout_log_1 = runtime_root / "vpp-stdout-1.log"
    stdout_log_2 = runtime_root / "vpp-stdout-2.log"

    shutil.rmtree(runtime_root, ignore_errors=True)
    (runtime_root / "vpp-run").mkdir(parents=True, exist_ok=True)
    rust_bin = rust_status_smoke.build_shim_and_rust_client(
        poc_dir,
        runtime_root,
        rust_source_name="tun_poc_rust_reconnect.rs",
        rust_bin_name="tun_poc_rust_reconnect",
    )
    status_smoke.write_startup_config(startup_conf, runtime_root, api_sock)

    vpp_proc_1 = None
    vpp_stdout_1 = None
    vpp_proc_2 = None
    vpp_stdout_2 = None
    client_proc = None
    try:
        vpp_proc_1, vpp_stdout_1 = start_vpp(vpp_bin, startup_conf, stdout_log_1)
        status_smoke.wait_for_socket(vpp_proc_1, api_sock, stdout_log_1)

        client_proc = subprocess.Popen(
            [
                str(rust_bin),
                str(api_sock),
                str(stale_marker),
                str(reopen_marker),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        wait_for_client_line(client_proc, "initial_status_ok")

        stop_vpp(vpp_proc_1, vpp_stdout_1)
        vpp_proc_1 = None
        vpp_stdout_1 = None
        api_sock.unlink(missing_ok=True)
        stale_marker.touch()
        wait_for_client_line(client_proc, "stale_status_failed")
        wait_for_client_line(client_proc, "stale_client_close")

        vpp_proc_2, vpp_stdout_2 = start_vpp(vpp_bin, startup_conf, stdout_log_2)
        status_smoke.wait_for_socket(vpp_proc_2, api_sock, stdout_log_2)
        reopen_marker.touch()
        wait_for_client_line(client_proc, "reopen_status_ok")
        rc = client_proc.wait(timeout=5)
        if rc != 0:
            raise RuntimeError(f"client exited with {rc}")

        print(f"rust ffi client: {rust_bin}")
        print(f"vpp first stdout log: {stdout_log_1}")
        print(f"vpp second stdout log: {stdout_log_2}")
        return 0
    finally:
        if client_proc is not None and client_proc.poll() is None:
            client_proc.kill()
            client_proc.wait(timeout=5)
        stop_vpp(vpp_proc_1, vpp_stdout_1)
        stop_vpp(vpp_proc_2, vpp_stdout_2)


if __name__ == "__main__":
    raise SystemExit(main())
