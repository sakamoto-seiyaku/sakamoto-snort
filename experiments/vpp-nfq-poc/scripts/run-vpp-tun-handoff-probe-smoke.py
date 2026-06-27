#!/usr/bin/env python3
"""PROTOTYPE: verify VPP frame-queue handoff from tun_poc to a worker."""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import time


HELPER_PATH = Path(__file__).with_name("run-vpp-tun-forward-fd-smoke.py")
SPEC = importlib.util.spec_from_file_location("tun_forward_smoke", HELPER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load helper script {HELPER_PATH}")
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


def parse_handoff(show_output: str) -> dict[str, int]:
    match = re.search(
        r"^handoff target-thread (\d+) fq (\d+) enqueued (\d+) bytes (\d+) "
        r"congestion-drops (\d+) alloc-errors (\d+) worker-packets (\d+) bytes (\d+)",
        show_output,
        re.MULTILINE,
    )
    if not match:
        raise RuntimeError(f"could not parse handoff counters:\n{show_output}")
    keys = (
        "target_thread",
        "frame_queue",
        "enqueued_packets",
        "enqueued_bytes",
        "congestion_drops",
        "alloc_errors",
        "worker_packets",
        "worker_bytes",
    )
    return {key: int(value) for key, value in zip(keys, match.groups())}


def parse_thread_hits(show_output: str, name: str) -> dict[str, int]:
    match = re.search(
        rf"^thread-hits {re.escape(name)} last (\d+) "
        r"t0 (\d+) t1 (\d+) t2 (\d+) t3 (\d+)",
        show_output,
        re.MULTILINE,
    )
    if not match:
        raise RuntimeError(f"could not parse {name} thread hits:\n{show_output}")
    keys = ("last", "t0", "t1", "t2", "t3")
    return {key: int(value) for key, value in zip(keys, match.groups())}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ifname", default="tun-poc-handoff0")
    parser.add_argument("--addr", default="198.19.10.1/24")
    parser.add_argument("--remote-ip", default="198.19.10.2")
    parser.add_argument("--tun-fd", type=int, default=53)
    parser.add_argument("--target-thread", type=int, default=1)
    parser.add_argument("--runtime-root", default="/tmp/sakamoto-vpp-nfq-poc")
    parser.add_argument("--vpp-bin", required=True)
    parser.add_argument("--vppctl-bin", required=True)
    parser.add_argument("--vpp-config", required=True)
    parser.add_argument("--log-dir", required=True)
    args = parser.parse_args()

    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = helper.Logger(log_dir / "vpp-tun-handoff-probe-smoke.log")
    vpp_stdout_log = log_dir / "vpp-tun-handoff-probe-smoke-vpp.log"
    runtime_root = Path(args.runtime_root)
    cli_sock = runtime_root / "cli.sock"
    vpp_proc: subprocess.Popen[object] | None = None

    try:
        helper.run_ip(["link", "del", args.ifname], check=False)
        runtime_root.mkdir(parents=True, exist_ok=True)
        (runtime_root / "vpp-run").mkdir(parents=True, exist_ok=True)
        cli_sock.unlink(missing_ok=True)

        actual_ifname = helper.create_tun(args.ifname, args.addr, args.tun_fd)
        logger.log(f"tun ifname={actual_ifname} tun-fd={args.tun_fd}")

        vpp_log_file = vpp_stdout_log.open("w", encoding="utf-8")
        vpp_proc = subprocess.Popen(
            [args.vpp_bin, "-c", args.vpp_config],
            stdout=vpp_log_file,
            stderr=subprocess.STDOUT,
            pass_fds=(args.tun_fd,),
        )
        vpp_log_file.close()

        helper.wait_for_cli(vpp_proc, cli_sock, vpp_stdout_log)
        threads = helper.run_vppctl(Path(args.vppctl_bin), cli_sock, "show", "threads")
        logger.log("show threads:")
        logger.log(threads.rstrip())
        if "vpp_wk_0" not in threads:
            raise RuntimeError("expected at least one VPP worker thread")

        enable = helper.run_vppctl(
            Path(args.vppctl_bin),
            cli_sock,
            "tun-poc",
            "enable",
            "fd",
            str(args.tun_fd),
            "mode",
            "handoff-probe",
            "target-thread",
            str(args.target_thread),
        )
        logger.log("enable output:")
        logger.log(enable.rstrip())

        before = helper.run_vppctl(Path(args.vppctl_bin), cli_sock, "show", "tun-poc")
        logger.log("before ping:")
        logger.log(before.rstrip())

        ping = subprocess.run(
            ["ping", "-I", actual_ifname, "-c", "1", "-W", "1", args.remote_ip],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        logger.log("ping output:")
        logger.log(ping.stdout.rstrip())
        logger.log(f"ping_rc={ping.returncode}")

        deadline = time.monotonic() + 5
        after = ""
        handoff: dict[str, int] | None = None
        worker_hits: dict[str, int] | None = None
        rx_hits: dict[str, int] | None = None
        while time.monotonic() < deadline:
            after = helper.run_vppctl(Path(args.vppctl_bin), cli_sock, "show", "tun-poc")
            handoff = parse_handoff(after)
            worker_hits = parse_thread_hits(after, "worker-probe")
            rx_hits = parse_thread_hits(after, "rx-node")
            target_key = f"t{args.target_thread}"
            if (
                handoff["enqueued_packets"] > 0
                and handoff["worker_packets"] > 0
                and worker_hits.get(target_key, 0) > 0
            ):
                break
            time.sleep(0.1)
        else:
            raise TimeoutError(f"handoff worker counters did not advance:\n{after}")

        logger.log("after ping:")
        logger.log(after.rstrip())

        assert handoff is not None
        assert worker_hits is not None
        assert rx_hits is not None
        if handoff["target_thread"] != args.target_thread:
            raise RuntimeError(f"unexpected target thread counters: {handoff}")
        if handoff["congestion_drops"] != 0 or handoff["alloc_errors"] != 0:
            raise RuntimeError(f"handoff had drops/errors: {handoff}")
        if rx_hits["t0"] <= 0 or rx_hits["t1"] != 0 or rx_hits["t2"] != 0:
            raise RuntimeError(f"expected rx input node to stay on thread 0: {rx_hits}")
        if worker_hits[f"t{args.target_thread}"] <= 0:
            raise RuntimeError(f"expected worker probe on target thread: {worker_hits}")

        logger.log()
        logger.log("ok: tun_poc handed a VPP buffer from rx input node to worker thread")
        logger.log(f"vpp tun handoff probe smoke log: {log_dir / 'vpp-tun-handoff-probe-smoke.log'}")
        logger.log(f"vpp stdout log: {vpp_stdout_log}")
        return 0
    finally:
        try:
            if cli_sock.exists():
                helper.run_vppctl(Path(args.vppctl_bin), cli_sock, "tun-poc", "disable")
        except Exception as exc:  # noqa: BLE001 - cleanup must continue.
            logger.log(f"cleanup disable failed: {exc}")
        if vpp_proc and vpp_proc.poll() is None:
            vpp_proc.terminate()
            try:
                vpp_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                vpp_proc.kill()
                vpp_proc.wait(timeout=5)
        helper.run_ip(["link", "del", args.ifname], check=False)
        os.close(args.tun_fd)
        logger.close()


if __name__ == "__main__":
    sys.exit(main())
