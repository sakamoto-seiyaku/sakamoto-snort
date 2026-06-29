#!/usr/bin/env python3
"""Smoke test staged owner policy commit/rollback through VPP binary API."""

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


def assert_policy(reply, cache_enabled: bool, block_set: bool, block_uid: int) -> None:
    if bool(reply.owner_cache_enabled) != cache_enabled:
        raise RuntimeError(f"owner_cache_enabled mismatch: {reply}")
    if bool(reply.block_owner_uid_set) != block_set:
        raise RuntimeError(f"block_owner_uid_set mismatch: {reply}")
    if reply.block_owner_uid != block_uid:
        raise RuntimeError(f"block_owner_uid mismatch: {reply}")


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
    runtime_root = Path("/tmp/sakamoto-vpp-tun-poc-api-policy-transaction").resolve()
    startup_conf = runtime_root / "startup.conf"
    api_sock = runtime_root / "api.sock"
    stdout_log = runtime_root / "vpp-stdout.log"

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
        client.connect("tun-poc-api-policy-transaction-smoke")
        try:
            before = client.api.tun_poc_status()
            stage = client.api.tun_poc_owner_policy_stage(
                owner_cache_enabled=True,
                block_owner_uid_set=True,
                block_owner_uid=4242,
            )
            after_stage = client.api.tun_poc_status()
            rollback = client.api.tun_poc_owner_policy_rollback()
            after_rollback = client.api.tun_poc_status()
            stage_again = client.api.tun_poc_owner_policy_stage(
                owner_cache_enabled=True,
                block_owner_uid_set=True,
                block_owner_uid=4242,
            )
            commit = client.api.tun_poc_owner_policy_commit()
            after_commit = client.api.tun_poc_status()
        finally:
            client.disconnect()

        assert_policy(before, False, False, -1)
        if stage.retval != 0:
            raise RuntimeError(f"stage retval={stage.retval}")
        assert_policy(after_stage, False, False, -1)
        if rollback.retval != 0:
            raise RuntimeError(f"rollback retval={rollback.retval}")
        assert_policy(after_rollback, False, False, -1)
        if stage_again.retval != 0:
            raise RuntimeError(f"stage_again retval={stage_again.retval}")
        if commit.retval != 0:
            raise RuntimeError(f"commit retval={commit.retval}")
        assert_policy(after_commit, True, True, 4242)

        print("tun_poc_owner_policy transaction via binary API:")
        print(f"  stage retval={stage.retval}")
        print(
            "  after_stage active "
            f"owner_cache_enabled={int(after_stage.owner_cache_enabled)} "
            f"block_owner_uid_set={int(after_stage.block_owner_uid_set)} "
            f"block_owner_uid={after_stage.block_owner_uid}"
        )
        print(f"  rollback retval={rollback.retval}")
        print(
            "  after_rollback active "
            f"owner_cache_enabled={int(after_rollback.owner_cache_enabled)} "
            f"block_owner_uid_set={int(after_rollback.block_owner_uid_set)} "
            f"block_owner_uid={after_rollback.block_owner_uid}"
        )
        print(f"  commit retval={commit.retval}")
        print(
            "  after_commit active "
            f"owner_cache_enabled={int(after_commit.owner_cache_enabled)} "
            f"block_owner_uid_set={int(after_commit.block_owner_uid_set)} "
            f"block_owner_uid={after_commit.block_owner_uid}"
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
