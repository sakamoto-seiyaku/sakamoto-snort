#!/usr/bin/env python3
"""Run a Linux TUN -> VPP -> HEV -> SOCKS5 -> VPP -> TUN smoke test."""

from __future__ import annotations

import argparse
import ctypes
import fcntl
import multiprocessing
import os
from pathlib import Path
import queue
import re
import socket
import struct
import subprocess
import sys
import threading
import time


TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


class Logger:
    def __init__(self, path: Path) -> None:
        self._file = path.open("w", encoding="utf-8")

    def close(self) -> None:
        self._file.close()

    def log(self, message: str = "") -> None:
        print(message, flush=True)
        print(message, file=self._file, flush=True)


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


def recv_exact(conn: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise RuntimeError("unexpected EOF from SOCKS client")
        data.extend(chunk)
    return bytes(data)


def create_socks5_listener() -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    return listener


def run_socks5_server(listener: socket.socket, result: queue.Queue[object]) -> None:
    try:
        conn, _ = listener.accept()
        with conn:
            head = recv_exact(conn, 2)
            methods = recv_exact(conn, head[1])
            result.put(("greeting", head + methods))
            conn.sendall(b"\x05\x00")

            request_head = recv_exact(conn, 4)
            atyp = request_head[3]
            if atyp == 1:
                addr = socket.inet_ntoa(recv_exact(conn, 4))
            elif atyp == 3:
                size = recv_exact(conn, 1)[0]
                addr = recv_exact(conn, size).decode("ascii", errors="replace")
            elif atyp == 4:
                addr = socket.inet_ntop(socket.AF_INET6, recv_exact(conn, 16))
            else:
                raise RuntimeError(f"unsupported SOCKS atyp: {atyp}")
            dst_port = struct.unpack("!H", recv_exact(conn, 2))[0]
            result.put(("connect", addr, dst_port))
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

            payload = conn.recv(8192)
            result.put(("payload", payload))
            conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            time.sleep(0.2)
    except BaseException as exc:  # noqa: BLE001 - experiment harness.
        result.put(("error", repr(exc)))
    finally:
        listener.close()


def run_hev_process(lib_path: str, config: bytes, fd: int, log_path: str) -> None:
    log_fd = os.open(log_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o644)
    os.dup2(log_fd, 1)
    os.dup2(log_fd, 2)
    os.close(log_fd)

    lib = ctypes.CDLL(lib_path)
    lib.hev_socks5_tunnel_main_from_str.argtypes = [ctypes.c_char_p, ctypes.c_uint, ctypes.c_int]
    lib.hev_socks5_tunnel_main_from_str.restype = ctypes.c_int
    rc = lib.hev_socks5_tunnel_main_from_str(config, len(config), fd)
    raise SystemExit(rc if rc >= 0 else 128 - rc)


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


def drain_events(events: queue.Queue[object]) -> list[object]:
    drained: list[object] = []
    while not events.empty():
        drained.append(events.get())
    return drained


def require_hev_alive(hev_proc: multiprocessing.Process | None, stage: str) -> None:
    if hev_proc is not None and not hev_proc.is_alive():
        hev_proc.join(timeout=0)
        raise RuntimeError(f"HEV exited before cleanup at {stage}, exitcode={hev_proc.exitcode}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ifname", default="tun-poc-hev0")
    parser.add_argument("--addr", default="10.0.0.2/24")
    parser.add_argument("--remote-ip", default="93.184.216.34")
    parser.add_argument("--tun-fd", type=int, default=53)
    parser.add_argument("--shim-fd", type=int, default=54)
    parser.add_argument("--runtime-root", default="/tmp/sakamoto-vpp-nfq-poc")
    parser.add_argument("--hev-root", required=True)
    parser.add_argument("--vpp-bin", required=True)
    parser.add_argument("--vppctl-bin", required=True)
    parser.add_argument("--vpp-config", required=True)
    parser.add_argument("--log-dir", required=True)
    args = parser.parse_args()

    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = Logger(log_dir / "vpp-tun-hev-smoke.log")
    vpp_stdout_log = log_dir / "vpp-tun-hev-smoke-vpp.log"
    hev_stdout_log = log_dir / "vpp-tun-hev-smoke-hev.log"
    runtime_root = Path(args.runtime_root)
    cli_sock = runtime_root / "cli.sock"
    hev_root = Path(args.hev_root).resolve()
    hev_lib = hev_root / "bin" / "libhev-socks5-tunnel.so"
    if not hev_lib.exists():
        raise FileNotFoundError(hev_lib)

    vpp_proc: subprocess.Popen[object] | None = None
    hev_proc: multiprocessing.Process | None = None
    socks_listener: socket.socket | None = None

    try:
        run_ip(["link", "del", args.ifname], check=False)
        runtime_root.mkdir(parents=True, exist_ok=True)
        (runtime_root / "vpp-run").mkdir(parents=True, exist_ok=True)
        cli_sock.unlink(missing_ok=True)

        socks_events: queue.Queue[object] = queue.Queue()
        socks_listener = create_socks5_listener()
        socks_port = socks_listener.getsockname()[1]
        logger.log(f"SOCKS5 server port={socks_port}")

        actual_ifname = create_tun(args.ifname, args.addr, args.tun_fd)
        run_ip(["route", "add", f"{args.remote_ip}/32", "dev", actual_ifname, "src", args.addr.split("/", 1)[0]])

        vpp_sock, hev_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        shim_fd = move_fd(vpp_sock.fileno(), args.shim_fd)
        vpp_sock.detach()

        hev_config = f"""
tunnel:
  mtu: 1500
socks5:
  address: 127.0.0.1
  port: {socks_port}
  udp: tcp
misc:
  log-file: stderr
  log-level: error
  connect-timeout: 2000
  tcp-read-write-timeout: 5000
  udp-read-write-timeout: 5000
""".encode()

        ctx = multiprocessing.get_context("fork")
        hev_proc = ctx.Process(
            target=run_hev_process,
            args=(str(hev_lib), hev_config, hev_sock.fileno(), str(hev_stdout_log)),
        )
        hev_proc.start()
        hev_sock.close()
        logger.log(f"HEV pid={hev_proc.pid} vpp-shim-fd={args.shim_fd}")

        socks_thread = threading.Thread(target=run_socks5_server, args=(socks_listener, socks_events), daemon=True)
        socks_thread.start()
        socks_listener = None

        vpp_log_file = vpp_stdout_log.open("w", encoding="utf-8")
        vpp_proc = subprocess.Popen(
            [args.vpp_bin, "-c", args.vpp_config],
            stdout=vpp_log_file,
            stderr=subprocess.STDOUT,
            pass_fds=(args.tun_fd, shim_fd),
        )
        vpp_log_file.close()
        os.close(args.tun_fd)
        os.close(shim_fd)

        wait_for_cli(vpp_proc, cli_sock, vpp_stdout_log)
        run_vppctl(
            Path(args.vppctl_bin),
            cli_sock,
            "tun-poc",
            "enable",
            "fd",
            str(args.tun_fd),
            "mode",
            "forward-fd",
            "shim-fd",
            str(args.shim_fd),
        )
        before = run_vppctl(Path(args.vppctl_bin), cli_sock, "show", "tun-poc")
        logger.log("before curl:")
        logger.log(before.rstrip())

        curl = subprocess.run(
            [
                "curl",
                "--noproxy",
                "*",
                "--http1.0",
                "--interface",
                actual_ifname,
                "--connect-timeout",
                "3",
                "--max-time",
                "8",
                "--silent",
                "--show-error",
                f"http://{args.remote_ip}/probe",
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        logger.log("curl output:")
        logger.log(curl.stdout.rstrip())
        if curl.returncode != 0:
            raise RuntimeError(f"curl failed rc={curl.returncode}")
        if "OK" not in curl.stdout:
            raise RuntimeError(f"curl did not receive expected body: {curl.stdout!r}")

        socks_thread.join(timeout=2)
        events = drain_events(socks_events)
        for event in events:
            logger.log(f"SOCKS event: {event!r}")
        if any(isinstance(event, tuple) and event[0] == "error" for event in events):
            raise RuntimeError(f"SOCKS server error: {events!r}")
        if not any(isinstance(event, tuple) and event[0] == "connect" for event in events):
            raise RuntimeError(f"SOCKS connect event missing: {events!r}")
        if not any(isinstance(event, tuple) and event[0] == "payload" and b"/probe" in event[1] for event in events):
            raise RuntimeError(f"SOCKS payload event missing: {events!r}")

        require_hev_alive(hev_proc, "after socks events")

        after = run_vppctl(Path(args.vppctl_bin), cli_sock, "show", "tun-poc")
        logger.log("after curl:")
        logger.log(after.rstrip())
        require_hev_alive(hev_proc, "after show tun-poc")
        hev_log = hev_stdout_log.read_text(encoding="utf-8", errors="replace").strip()
        if hev_log:
            logger.log("HEV stderr/stdout:")
            logger.log(hev_log)
        rx_packets, tx_packets, shim_rx_packets, shim_tx_packets = parse_counters(after)
        if not all(value > 0 for value in (rx_packets, tx_packets, shim_rx_packets, shim_tx_packets)):
            raise RuntimeError(
                "expected all HEV path counters to increase, got "
                f"rx={rx_packets} tx={tx_packets} "
                f"shim-rx={shim_rx_packets} shim-tx={shim_tx_packets}"
            )

        logger.log()
        logger.log(f"vpp tun HEV smoke log: {log_dir / 'vpp-tun-hev-smoke.log'}")
        logger.log(f"HEV stdout log: {hev_stdout_log}")
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
        if hev_proc and hev_proc.is_alive():
            hev_proc.terminate()
            hev_proc.join(timeout=5)
        if socks_listener is not None:
            socks_listener.close()
        run_ip(["link", "del", args.ifname], check=False)
        logger.close()


if __name__ == "__main__":
    sys.exit(main())
