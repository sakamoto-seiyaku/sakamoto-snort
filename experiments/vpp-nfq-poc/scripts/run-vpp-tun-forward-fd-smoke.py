#!/usr/bin/env python3
"""Smoke test tun_poc forward-fd mode with a local socketpair shim."""

from __future__ import annotations

import argparse
import fcntl
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import time


TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
IPPROTO_ICMP = 1
ICMP_ECHO = 8
ICMP_ECHOREPLY = 0


class Logger:
    def __init__(self, path: Path) -> None:
        self._file = path.open("w", encoding="utf-8")

    def close(self) -> None:
        self._file.close()

    def log(self, message: str = "") -> None:
        print(message, flush=True)
        print(message, file=self._file, flush=True)


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) + data[offset + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def run_ip(args: list[str], check: bool = True) -> None:
    subprocess.run(["ip", *args], check=check, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def move_fd(fd: int, target: int) -> int:
    if fd != target:
        os.dup2(fd, target, inheritable=True)
        os.close(fd)
    else:
        os.set_inheritable(fd, True)
    return target


def create_tun(ifname: str, addr: str, fd_number: int) -> str:
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", ifname.encode("ascii"), IFF_TUN | IFF_NO_PI)
    actual = fcntl.ioctl(fd, TUNSETIFF, ifr)[:16].split(b"\0", 1)[0].decode()
    fd = move_fd(fd, fd_number)
    run_ip(["addr", "add", addr, "dev", actual])
    run_ip(["link", "set", actual, "up"])
    return actual


def run_vppctl(vppctl: Path, cli_sock: Path, *command: str) -> str:
    result = subprocess.run(
        [str(vppctl), "-s", str(cli_sock), *command],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode != 0:
        raise RuntimeError(f"vppctl failed rc={result.returncode}: {result.stdout}")
    return result.stdout


def wait_for_cli(proc: subprocess.Popen[object], cli_sock: Path, vpp_log: Path) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if cli_sock.exists():
            return
        if proc.poll() is not None:
            output = vpp_log.read_text(encoding="utf-8", errors="replace")
            raise RuntimeError(f"VPP exited before CLI socket appeared\n{output}")
        time.sleep(0.1)
    output = vpp_log.read_text(encoding="utf-8", errors="replace")
    raise TimeoutError(f"VPP CLI socket did not appear: {cli_sock}\n{output}")


def parse_ip4_icmp(packet: bytes) -> dict[str, object] | None:
    if len(packet) < 28 or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 0x0F) * 4
    if ihl < 20 or len(packet) < ihl + 8 or packet[9] != IPPROTO_ICMP:
        return None
    total_len = struct.unpack("!H", packet[2:4])[0]
    if total_len < ihl + 8 or total_len > len(packet):
        return None
    return {
        "ihl": ihl,
        "total_len": total_len,
        "src": socket.inet_ntoa(packet[12:16]),
        "dst": socket.inet_ntoa(packet[16:20]),
        "icmp_type": packet[ihl],
        "icmp_code": packet[ihl + 1],
        "packet": packet[:total_len],
    }


def build_icmp_reply(request: bytes) -> bytes:
    parsed = parse_ip4_icmp(request)
    if parsed is None:
        raise ValueError("request is not IPv4 ICMP")
    ihl = int(parsed["ihl"])
    total_len = int(parsed["total_len"])
    reply = bytearray(request[:total_len])

    reply[12:16], reply[16:20] = reply[16:20], reply[12:16]
    reply[8] = 64
    reply[10:12] = b"\x00\x00"
    ip_checksum = internet_checksum(bytes(reply[:ihl]))
    reply[10:12] = struct.pack("!H", ip_checksum)

    reply[ihl] = ICMP_ECHOREPLY
    reply[ihl + 2 : ihl + 4] = b"\x00\x00"
    icmp_checksum = internet_checksum(bytes(reply[ihl:total_len]))
    reply[ihl + 2 : ihl + 4] = struct.pack("!H", icmp_checksum)
    return bytes(reply)


def wait_for_echo_request(sock: socket.socket, logger: Logger, remote_ip: str) -> bytes:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        packet = sock.recv(65535)
        parsed = parse_ip4_icmp(packet)
        if parsed is None:
            logger.log(f"shim observed non-icmp packet len={len(packet)}")
            continue
        logger.log(
            "shim observed "
            f"{parsed['src']} -> {parsed['dst']} "
            f"icmp_type={parsed['icmp_type']} len={parsed['total_len']}"
        )
        if parsed["dst"] == remote_ip and parsed["icmp_type"] == ICMP_ECHO:
            return bytes(parsed["packet"])
    raise TimeoutError("timed out waiting for ICMP echo request on shim fd")


def parse_counters(show_output: str) -> tuple[int, int, int, int]:
    rx_match = re.search(r"^rx (\d+) bytes \d+ tx (\d+) bytes", show_output, re.MULTILINE)
    shim_match = re.search(
        r"^shim-rx (\d+) bytes \d+ shim-tx (\d+) bytes", show_output, re.MULTILINE
    )
    if not rx_match or not shim_match:
        raise RuntimeError(f"could not parse show tun-poc output:\n{show_output}")
    return (
        int(rx_match.group(1)),
        int(rx_match.group(2)),
        int(shim_match.group(1)),
        int(shim_match.group(2)),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ifname", default="tun-poc-forward0")
    parser.add_argument("--addr", default="198.19.0.1/24")
    parser.add_argument("--remote-ip", default="198.19.0.2")
    parser.add_argument("--tun-fd", type=int, default=53)
    parser.add_argument("--shim-fd", type=int, default=54)
    parser.add_argument("--runtime-root", default="/tmp/sakamoto-vpp-nfq-poc")
    parser.add_argument("--vpp-bin", required=True)
    parser.add_argument("--vppctl-bin", required=True)
    parser.add_argument("--vpp-config", required=True)
    parser.add_argument("--log-dir", required=True)
    args = parser.parse_args()

    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = Logger(log_dir / "vpp-tun-forward-fd-smoke.log")
    vpp_stdout_log = log_dir / "vpp-tun-forward-fd-smoke-vpp.log"
    runtime_root = Path(args.runtime_root)
    cli_sock = runtime_root / "cli.sock"
    vpp_proc: subprocess.Popen[object] | None = None
    driver_sock: socket.socket | None = None

    try:
        run_ip(["link", "del", args.ifname], check=False)
        runtime_root.mkdir(parents=True, exist_ok=True)
        (runtime_root / "vpp-run").mkdir(parents=True, exist_ok=True)
        cli_sock.unlink(missing_ok=True)

        actual_ifname = create_tun(args.ifname, args.addr, args.tun_fd)
        driver_sock, vpp_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        driver_sock.settimeout(5)
        shim_fd = move_fd(vpp_sock.fileno(), args.shim_fd)
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

        wait_for_cli(vpp_proc, cli_sock, vpp_stdout_log)
        enable = run_vppctl(
            Path(args.vppctl_bin),
            cli_sock,
            "tun-poc",
            "enable",
            "fd",
            str(args.tun_fd),
            "mode",
            "forward-fd",
            "shim-fd",
            str(shim_fd),
        )
        logger.log("enable output:")
        logger.log(enable.rstrip())

        before = run_vppctl(Path(args.vppctl_bin), cli_sock, "show", "tun-poc")
        logger.log("before ping:")
        logger.log(before.rstrip())

        ping = subprocess.Popen(
            ["ping", "-I", actual_ifname, "-c", "1", "-W", "2", args.remote_ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        request = wait_for_echo_request(driver_sock, logger, args.remote_ip)
        reply = build_icmp_reply(request)
        driver_sock.send(reply)
        ping_output, _ = ping.communicate(timeout=5)
        logger.log("ping output:")
        logger.log(ping_output.rstrip())
        if ping.returncode != 0:
            raise RuntimeError(f"ping failed rc={ping.returncode}")

        after = run_vppctl(Path(args.vppctl_bin), cli_sock, "show", "tun-poc")
        logger.log("after ping:")
        logger.log(after.rstrip())
        rx_packets, tx_packets, shim_rx_packets, shim_tx_packets = parse_counters(after)
        if not all(value > 0 for value in (rx_packets, tx_packets, shim_rx_packets, shim_tx_packets)):
            raise RuntimeError(
                "expected all forward-fd counters to increase, got "
                f"rx={rx_packets} tx={tx_packets} "
                f"shim-rx={shim_rx_packets} shim-tx={shim_tx_packets}"
            )

        logger.log()
        logger.log(f"vpp tun forward-fd smoke log: {log_dir / 'vpp-tun-forward-fd-smoke.log'}")
        logger.log(f"vpp stdout log: {vpp_stdout_log}")
        return 0
    finally:
        try:
            if cli_sock.exists():
                run_vppctl(Path(args.vppctl_bin), cli_sock, "tun-poc", "disable")
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
        run_ip(["link", "del", args.ifname], check=False)
        logger.close()


if __name__ == "__main__":
    sys.exit(main())
