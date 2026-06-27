#!/usr/bin/env python3
"""PROTOTYPE: verify tun_poc worker can query a mock tuple owner resolver."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import re
import select
import socket
import subprocess
import sys
import threading
import time


HELPER_PATH = Path(__file__).with_name("run-vpp-tun-forward-fd-smoke.py")
HELPER_SPEC = importlib.util.spec_from_file_location("tun_forward_smoke", HELPER_PATH)
if HELPER_SPEC is None or HELPER_SPEC.loader is None:
    raise RuntimeError(f"could not load helper script {HELPER_PATH}")
helper = importlib.util.module_from_spec(HELPER_SPEC)
HELPER_SPEC.loader.exec_module(helper)

TUPLE_PATH = Path(__file__).with_name("run-vpp-tun-handoff-tuple-smoke.py")
TUPLE_SPEC = importlib.util.spec_from_file_location("tun_tuple_smoke", TUPLE_PATH)
if TUPLE_SPEC is None or TUPLE_SPEC.loader is None:
    raise RuntimeError(f"could not load tuple script {TUPLE_PATH}")
tuple_smoke = importlib.util.module_from_spec(TUPLE_SPEC)
TUPLE_SPEC.loader.exec_module(tuple_smoke)


def resolver_loop(
    sock: socket.socket,
    logger: object,
    stop_event: threading.Event,
    uid: int,
) -> None:
    buffer = b""
    sock.setblocking(False)
    while not stop_event.is_set():
        readable, _, _ = select.select([sock], [], [], 0.1)
        if not readable:
            continue
        try:
            data = sock.recv(4096)
        except OSError:
            return
        if not data:
            return
        buffer += data
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            text = line.decode("ascii", errors="replace")
            logger.log(f"resolver query: {text}")
            sock.sendall(f"uid {uid}\n".encode("ascii"))


def parse_resolver(show_output: str) -> dict[str, int]:
    match = re.search(
        r"^resolver enabled (\d+) fd (-?\d+) queries (\d+) hits (\d+) "
        r"errors (\d+) last-uid (-?\d+)",
        show_output,
        re.MULTILINE,
    )
    if not match:
        raise RuntimeError(f"could not parse resolver counters:\n{show_output}")
    keys = ("enabled", "fd", "queries", "hits", "errors", "last_uid")
    return {key: int(value) for key, value in zip(keys, match.groups())}


def wait_for_resolver_hits(
    vppctl_bin: Path,
    cli_sock: Path,
    min_hits: int,
    uid: int,
) -> tuple[str, dict[str, int]]:
    deadline = time.monotonic() + 5
    last_output = ""
    while time.monotonic() < deadline:
        last_output = helper.run_vppctl(vppctl_bin, cli_sock, "show", "tun-poc")
        parsed = parse_resolver(last_output)
        if parsed["hits"] >= min_hits and parsed["last_uid"] == uid and parsed["errors"] == 0:
            return last_output, parsed
        time.sleep(0.1)
    raise TimeoutError(f"resolver counters did not reach hits={min_hits} uid={uid}:\n{last_output}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ifname", default="tun-poc-resolve0")
    parser.add_argument("--addr", default="198.19.30.1/24")
    parser.add_argument("--local-ip", default="198.19.30.1")
    parser.add_argument("--remote-ip", default="198.19.30.2")
    parser.add_argument("--tun-fd", type=int, default=53)
    parser.add_argument("--shim-fd", type=int, default=54)
    parser.add_argument("--resolver-fd", type=int, default=55)
    parser.add_argument("--target-thread", type=int, default=1)
    parser.add_argument("--mock-uid", type=int, default=4242)
    parser.add_argument("--runtime-root", default="/tmp/sakamoto-vpp-nfq-poc")
    parser.add_argument("--vpp-bin", required=True)
    parser.add_argument("--vppctl-bin", required=True)
    parser.add_argument("--vpp-config", required=True)
    parser.add_argument("--log-dir", required=True)
    args = parser.parse_args()

    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = helper.Logger(log_dir / "vpp-tun-handoff-resolver-smoke.log")
    vpp_stdout_log = log_dir / "vpp-tun-handoff-resolver-smoke-vpp.log"
    runtime_root = Path(args.runtime_root)
    cli_sock = runtime_root / "cli.sock"
    vpp_proc: subprocess.Popen[object] | None = None
    driver_sock: socket.socket | None = None
    resolver_driver_sock: socket.socket | None = None
    resolver_stop = threading.Event()
    resolver_thread: threading.Thread | None = None

    try:
        helper.run_ip(["link", "del", args.ifname], check=False)
        runtime_root.mkdir(parents=True, exist_ok=True)
        (runtime_root / "vpp-run").mkdir(parents=True, exist_ok=True)
        cli_sock.unlink(missing_ok=True)

        actual_ifname = helper.create_tun(args.ifname, args.addr, args.tun_fd)
        driver_sock, vpp_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        shim_fd = helper.move_fd(vpp_sock.fileno(), args.shim_fd)
        vpp_sock.detach()

        resolver_driver_sock, resolver_vpp_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        resolver_fd = helper.move_fd(resolver_vpp_sock.fileno(), args.resolver_fd)
        resolver_vpp_sock.detach()
        resolver_thread = threading.Thread(
            target=resolver_loop,
            args=(resolver_driver_sock, logger, resolver_stop, args.mock_uid),
            daemon=True,
        )
        resolver_thread.start()

        logger.log(
            f"tun ifname={actual_ifname} tun-fd={args.tun_fd} "
            f"shim-fd={shim_fd} resolver-fd={resolver_fd}"
        )
        vpp_log_file = vpp_stdout_log.open("w", encoding="utf-8")
        vpp_proc = subprocess.Popen(
            [args.vpp_bin, "-c", args.vpp_config],
            stdout=vpp_log_file,
            stderr=subprocess.STDOUT,
            pass_fds=(args.tun_fd, shim_fd, resolver_fd),
        )
        vpp_log_file.close()

        helper.wait_for_cli(vpp_proc, cli_sock, vpp_stdout_log)
        helper.run_vppctl(
            Path(args.vppctl_bin),
            cli_sock,
            "tun-poc",
            "enable",
            "fd",
            str(args.tun_fd),
            "mode",
            "handoff-forward-fd",
            "shim-fd",
            str(shim_fd),
            "resolver-fd",
            str(resolver_fd),
            "target-thread",
            str(args.target_thread),
        )

        tuple_smoke.send_udp("inet", actual_ifname, args.local_ip, 43101, args.remote_ip, 53101)
        udp_show, udp_resolver = wait_for_resolver_hits(
            Path(args.vppctl_bin), cli_sock, 1, args.mock_uid
        )
        logger.log("after udp:")
        logger.log(udp_show.rstrip())
        logger.log(f"udp_resolver={udp_resolver}")

        tuple_smoke.send_tcp_syn("inet", actual_ifname, args.local_ip, 43102, args.remote_ip, 53102)
        tcp_show, tcp_resolver = wait_for_resolver_hits(
            Path(args.vppctl_bin), cli_sock, 2, args.mock_uid
        )
        logger.log("after tcp:")
        logger.log(tcp_show.rstrip())
        logger.log(f"tcp_resolver={tcp_resolver}")
        logger.log()
        logger.log("ok: tun_poc worker queried mock resolver for IPv4 UDP and TCP tuples")
        return 0
    finally:
        resolver_stop.set()
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
        if resolver_driver_sock is not None:
            resolver_driver_sock.close()
        if resolver_thread is not None:
            resolver_thread.join(timeout=1)
        if driver_sock is not None:
            driver_sock.close()
        helper.run_ip(["link", "del", args.ifname], check=False)
        logger.close()


if __name__ == "__main__":
    sys.exit(main())
