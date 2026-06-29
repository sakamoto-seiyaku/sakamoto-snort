#!/usr/bin/env python3
"""Smoke test the tun_poc VPP binary API status call."""

from __future__ import annotations

import argparse
import glob
from pathlib import Path
import shutil
import subprocess
import sys
import time


def wait_for_socket(proc: subprocess.Popen[object], path: Path, log_path: Path) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if path.exists():
            return
        if proc.poll() is not None:
            log = log_path.read_text(encoding="utf-8", errors="replace")
            raise RuntimeError(f"VPP exited before {path} appeared\n{log}")
        time.sleep(0.1)
    log = log_path.read_text(encoding="utf-8", errors="replace")
    raise TimeoutError(f"VPP socket did not appear: {path}\n{log}")


def load_papi(vpp_src: Path) -> object:
    sys.path.insert(0, str(vpp_src / "src" / "vpp-api" / "python"))
    from vpp_papi import vpp_papi  # pylint: disable=import-outside-toplevel

    return vpp_papi


def api_files(api_dir: Path, tun_poc_api_json: Path) -> list[str]:
    files = sorted(glob.glob(str(api_dir / "*" / "*.api.json")))
    if not tun_poc_api_json.exists():
        raise FileNotFoundError(
            f"tun_poc API JSON not found: {tun_poc_api_json}. "
            "Run make vpp-tun-poc-build first."
        )
    files.append(str(tun_poc_api_json))
    return files


def write_startup_config(path: Path, runtime_root: Path, api_sock: Path) -> None:
    path.write_text(
        f"""unix {{
  nodaemon
  nobanner
  runtime-dir {runtime_root / "vpp-run"}
  poll-sleep-usec 1000
  log {runtime_root / "vpp.log"}
  cli-listen {runtime_root / "cli.sock"}
}}

socksvr {{
  socket-name {api_sock}
}}

api-segment {{
  prefix sakamoto-vpp-tun-poc-api-status
}}

statseg {{
  socket-name {runtime_root / "statseg.sock"}
}}

buffers {{
  page-size default
}}

plugins {{
  plugin default {{ disable }}
  plugin tun_poc_plugin.so {{ enable }}
}}
""",
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--poc-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--runtime-root", type=Path, default=None)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    poc_dir = args.poc_dir.resolve()
    vpp_src = poc_dir / "work" / "vpp"
    vpp_install = vpp_src / "build-root" / "install-vpp-native" / "vpp"
    vpp_bin = vpp_install / "bin" / "vpp"
    api_dir = vpp_install / "share" / "vpp" / "api"
    tun_poc_api_json = (
        vpp_src
        / "build-root"
        / "build-vpp-native"
        / "vpp"
        / "CMakeFiles"
        / "plugins"
        / "tun_poc"
        / "tun_poc.api.json"
    )
    runtime_root = args.runtime_root or (poc_dir / "results" / "vpp-tun-poc-api-status")
    runtime_root = runtime_root.resolve()
    startup_conf = runtime_root / "startup.conf"
    api_sock = runtime_root / "api.sock"
    stdout_log = runtime_root / "vpp-stdout.log"

    if not vpp_bin.exists():
        raise FileNotFoundError(f"VPP binary not found: {vpp_bin}")

    shutil.rmtree(runtime_root, ignore_errors=True)
    (runtime_root / "vpp-run").mkdir(parents=True, exist_ok=True)
    write_startup_config(startup_conf, runtime_root, api_sock)

    stdout_file = stdout_log.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        [str(vpp_bin), "-c", str(startup_conf)],
        stdout=stdout_file,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        wait_for_socket(proc, api_sock, stdout_log)

        vpp_papi = load_papi(vpp_src)
        client = vpp_papi.VPPApiClient(
            apifiles=api_files(api_dir, tun_poc_api_json),
            server_address=str(api_sock),
            read_timeout=5,
        )
        client.connect("tun-poc-api-status-smoke")
        try:
            reply = client.api.tun_poc_status()
        finally:
            client.disconnect()

        if reply.retval != 0:
            raise RuntimeError(f"tun_poc_status retval={reply.retval}")
        if reply.enabled:
            raise RuntimeError(f"expected disabled fresh plugin, got {reply}")
        if reply.rx_packets != 0 or reply.blocked_packets != 0:
            raise RuntimeError(f"expected zero counters on fresh plugin, got {reply}")

        print("tun_poc_status reply:")
        print(f"  retval={reply.retval}")
        print(f"  enabled={int(reply.enabled)} mode={reply.mode}")
        print(
            "  counters "
            f"rx={reply.rx_packets} tx={reply.tx_packets} "
            f"shim_tx={reply.shim_tx_packets} blocked={reply.blocked_packets}"
        )
        print(
            "  owner "
            f"queries={reply.resolver_queries} hits={reply.resolver_hits} "
            f"cache_enabled={int(reply.owner_cache_enabled)} "
            f"cache_hits={reply.owner_cache_hits} "
            f"block_uid_set={int(reply.block_owner_uid_set)} "
            f"block_uid={reply.block_owner_uid} "
            f"uid_blocks={reply.uid_blocked_packets} "
            f"last_uid={reply.last_owner_uid}"
        )
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
