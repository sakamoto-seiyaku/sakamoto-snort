#!/usr/bin/env python3

import argparse
import os
import socket
import sys
from typing import Optional


def _recv_until_nul(sock: socket.socket, *, timeout_s: float, max_size: int) -> bytes:
    sock.settimeout(timeout_s)
    data = bytearray()
    while len(data) < max_size:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if data.endswith(b"\0"):
            data = data[:-1]
            break
    return bytes(data)


def _send_cmd(sock: socket.socket, cmd: str, *, timeout_s: float, max_size: int) -> bytes:
    sock.sendall(cmd.encode("utf-8") + b"\0")
    return _recv_until_nul(sock, timeout_s=timeout_s, max_size=max_size)


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="sucre-snort control client (single connection)")
    p.add_argument("--host", default=os.environ.get("SNORT_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("SNORT_PORT", "60606")))
    p.add_argument("--timeout", type=float, default=float(os.environ.get("SNORT_TIMEOUT", "5")))
    p.add_argument("--max-size", type=int, default=1_000_000, help="Max bytes to read per response")

    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--cmd", help="Send a single command and print its response (raw)")
    g.add_argument(
        "--batch",
        action="store_true",
        help="Read newline-delimited commands from stdin and print one response per command",
    )
    args = p.parse_args(argv)

    addr = (args.host, args.port)
    with socket.create_connection(addr, timeout=args.timeout) as sock:
        if args.cmd is not None:
            out = _send_cmd(sock, args.cmd, timeout_s=args.timeout, max_size=args.max_size)
            sys.stdout.write(out.decode("utf-8", errors="replace"))
            return 0

        for line in sys.stdin:
            cmd = line.strip("\r\n")
            if not cmd:
                continue
            out = _send_cmd(sock, cmd, timeout_s=args.timeout, max_size=args.max_size)
            sys.stdout.write(out.decode("utf-8", errors="replace"))
            sys.stdout.write("\n")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

