#!/usr/bin/env python3
"""Smoke test mutating tun_poc owner policy through VPP binary API."""

from __future__ import annotations

import importlib.util
from pathlib import Path


def load_status_smoke_module():
    script = Path(__file__).with_name("run-vpp-tun-poc-api-status-smoke.py")
    spec = importlib.util.spec_from_file_location("tun_poc_api_status_smoke", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    status_smoke = load_status_smoke_module()
    poc_dir = Path(__file__).resolve().parents[1]
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
    runtime_root = (poc_dir / "results" / "vpp-tun-poc-api-policy").resolve()
    startup_conf = runtime_root / "startup.conf"
    api_sock = runtime_root / "api.sock"
    stdout_log = runtime_root / "vpp-stdout.log"

    import shutil
    import subprocess

    shutil.rmtree(runtime_root, ignore_errors=True)
    (runtime_root / "vpp-run").mkdir(parents=True, exist_ok=True)
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
        vpp_papi = status_smoke.load_papi(vpp_src)
        client = vpp_papi.VPPApiClient(
            apifiles=status_smoke.api_files(api_dir, tun_poc_api_json),
            server_address=str(api_sock),
            read_timeout=5,
        )
        client.connect("tun-poc-api-policy-smoke")
        try:
            before = client.api.tun_poc_status()
            set_reply = client.api.tun_poc_owner_policy_set(
                owner_cache_enabled=True,
                block_owner_uid_set=True,
                block_owner_uid=4242,
            )
            after = client.api.tun_poc_status()
        finally:
            client.disconnect()

        if before.owner_cache_enabled or before.block_owner_uid_set:
            raise RuntimeError(f"expected policy disabled before set, got {before}")
        if set_reply.retval != 0:
            raise RuntimeError(f"owner policy set retval={set_reply.retval}")
        if not after.owner_cache_enabled:
            raise RuntimeError(f"owner cache not enabled after set: {after}")
        if not after.block_owner_uid_set or after.block_owner_uid != 4242:
            raise RuntimeError(f"block owner UID not applied after set: {after}")

        print("tun_poc_owner_policy_set reply:")
        print(f"  retval={set_reply.retval}")
        print("tun_poc_status after mutation:")
        print(
            f"  owner_cache_enabled={int(after.owner_cache_enabled)} "
            f"block_owner_uid_set={int(after.block_owner_uid_set)} "
            f"block_owner_uid={after.block_owner_uid}"
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
