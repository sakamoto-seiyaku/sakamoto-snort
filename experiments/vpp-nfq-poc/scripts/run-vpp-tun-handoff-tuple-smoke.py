#!/usr/bin/env python3
"""PROTOTYPE: verify tun_poc worker parses IPv4 TCP/UDP tuples."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import re
import socket
import subprocess
import sys
import time


HELPER_PATH = Path(__file__).with_name("run-vpp-tun-forward-fd-smoke.py")
SPEC = importlib.util.spec_from_file_location("tun_forward_smoke", HELPER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load helper script {HELPER_PATH}")
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)

SO_BINDTODEVICE = 25


def bind_to_device(sock: socket.socket, ifname: str) -> None:
    sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, ifname.encode() + b"\0")


def send_udp(ifname: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        bind_to_device(sock, ifname)
        sock.bind((src_ip, src_port))
        sock.sendto(b"tuple-udp", (dst_ip, dst_port))
    finally:
        sock.close()


def send_tcp_syn(ifname: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        bind_to_device(sock, ifname)
        sock.bind((src_ip, src_port))
        sock.setblocking(False)
        sock.connect_ex((dst_ip, dst_port))
        time.sleep(0.2)
    finally:
        sock.close()


def parse_last_tuple(show_output: str) -> dict[str, object]:
    match = re.search(
        r"^last-tuple ip(\d+) proto (\d+) ([^:]+):(\d+) -> ([^:]+):(\d+)",
        show_output,
        re.MULTILINE,
    )
    if not match:
        raise RuntimeError(f"could not parse last tuple:\n{show_output}")
    return {
        "ip_version": int(match.group(1)),
        "protocol": int(match.group(2)),
        "src": match.group(3),
        "src_port": int(match.group(4)),
        "dst": match.group(5),
        "dst_port": int(match.group(6)),
    }


def wait_for_tuple(
    vppctl_bin: Path,
    cli_sock: Path,
    expected: dict[str, object],
) -> tuple[str, dict[str, object]]:
    deadline = time.monotonic() + 5
    last_output = ""
    while time.monotonic() < deadline:
        last_output = helper.run_vppctl(vppctl_bin, cli_sock, "show", "tun-poc")
        parsed = parse_last_tuple(last_output)
        if all(parsed[key] == value for key, value in expected.items()):
            return last_output, parsed
        time.sleep(0.1)
    raise TimeoutError(f"tuple did not match {expected}:\n{last_output}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ifname", default="tun-poc-tuple0")
    parser.add_argument("--addr", default="198.19.20.1/24")
    parser.add_argument("--local-ip", default="198.19.20.1")
    parser.add_argument("--remote-ip", default="198.19.20.2")
    parser.add_argument("--tun-fd", type=int, default=53)
    parser.add_argument("--shim-fd", type=int, default=54)
    parser.add_argument("--target-thread", type=int, default=1)
    parser.add_argument("--runtime-root", default="/tmp/sakamoto-vpp-nfq-poc")
    parser.add_argument("--vpp-bin", required=True)
    parser.add_argument("--vppctl-bin", required=True)
    parser.add_argument("--vpp-config", required=True)
    parser.add_argument("--log-dir", required=True)
    args = parser.parse_args()

    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = helper.Logger(log_dir / "vpp-tun-handoff-tuple-smoke.log")
    vpp_stdout_log = log_dir / "vpp-tun-handoff-tuple-smoke-vpp.log"
    runtime_root = Path(args.runtime_root)
    cli_sock = runtime_root / "cli.sock"
    vpp_proc: subprocess.Popen[object] | None = None
    driver_sock: socket.socket | None = None

    try:
        helper.run_ip(["link", "del", args.ifname], check=False)
        runtime_root.mkdir(parents=True, exist_ok=True)
        (runtime_root / "vpp-run").mkdir(parents=True, exist_ok=True)
        cli_sock.unlink(missing_ok=True)

        actual_ifname = helper.create_tun(args.ifname, args.addr, args.tun_fd)
        driver_sock, vpp_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        driver_sock.settimeout(0.2)
        shim_fd = helper.move_fd(vpp_sock.fileno(), args.shim_fd)
        vpp_sock.detach()

        logger.log(f"tun ifname={actual_ifname} tun-fd={args.tun_fd} shim-fd={shim_fd}")
        vpp_log_file = vpp_stdout_log.open("w", encoding="utf-8")
        vpp_proc = subprocess.Popen(
            [args.vpp_bin, "-c", args.vpp_config],
            stdout=vpp_log_file,
            stderr=subprocess.STDOUT,
            pass_fds=(args.tun_fd, shim_fd),
        )
        vpp_log_file.close()

        helper.wait_for_cli(vpp_proc, cli_sock, vpp_stdout_log)
        threads = helper.run_vppctl(Path(args.vppctl_bin), cli_sock, "show", "threads")
        logger.log("show threads:")
        logger.log(threads.rstrip())

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
            "target-thread",
            str(args.target_thread),
        )

        udp_src_port = 43001
        udp_dst_port = 53001
        send_udp(actual_ifname, args.local_ip, udp_src_port, args.remote_ip, udp_dst_port)
        udp_show, udp_tuple = wait_for_tuple(
            Path(args.vppctl_bin),
            cli_sock,
            {
                "ip_version": 4,
                "protocol": 17,
                "src": args.local_ip,
                "src_port": udp_src_port,
                "dst": args.remote_ip,
                "dst_port": udp_dst_port,
            },
        )
        logger.log("after udp:")
        logger.log(udp_show.rstrip())
        logger.log(f"udp_tuple={udp_tuple}")

        tcp_src_port = 43002
        tcp_dst_port = 53002
        send_tcp_syn(actual_ifname, args.local_ip, tcp_src_port, args.remote_ip, tcp_dst_port)
        tcp_show, tcp_tuple = wait_for_tuple(
            Path(args.vppctl_bin),
            cli_sock,
            {
                "ip_version": 4,
                "protocol": 6,
                "src": args.local_ip,
                "src_port": tcp_src_port,
                "dst": args.remote_ip,
                "dst_port": tcp_dst_port,
            },
        )
        logger.log("after tcp:")
        logger.log(tcp_show.rstrip())
        logger.log(f"tcp_tuple={tcp_tuple}")
        logger.log()
        logger.log("ok: tun_poc worker parsed IPv4 UDP and TCP tuples")
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
        if driver_sock is not None:
            driver_sock.close()
        helper.run_ip(["link", "del", args.ifname], check=False)
        logger.close()


if __name__ == "__main__":
    sys.exit(main())
