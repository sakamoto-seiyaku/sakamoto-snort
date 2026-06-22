#!/usr/bin/env python3
"""Create a Linux TUN fd, configure it, then exec VPP with that fd inherited."""

import argparse
import fcntl
import os
import struct
import subprocess
import sys


TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


def run_ip(args: list[str]) -> None:
    subprocess.run(["ip", *args], check=True)


def create_tun(ifname: str, fd_number: int) -> str:
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", ifname.encode("ascii"), IFF_TUN | IFF_NO_PI)
    actual = fcntl.ioctl(fd, TUNSETIFF, ifr)[:16].split(b"\0", 1)[0].decode()
    if fd != fd_number:
        os.dup2(fd, fd_number)
        os.close(fd)
        fd = fd_number
    os.set_inheritable(fd, True)
    return actual


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ifname", default="tun-poc0")
    parser.add_argument("--addr", default="198.18.0.1/24")
    parser.add_argument("--fd", type=int, default=3)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    if not args.command or args.command[0] != "--" or len(args.command) < 2:
        parser.error("expected: -- <vpp> [args...]")

    actual = create_tun(args.ifname, args.fd)
    run_ip(["addr", "add", args.addr, "dev", actual])
    run_ip(["link", "set", actual, "up"])

    env = os.environ.copy()
    env["TUN_POC_FD"] = str(args.fd)
    env["TUN_POC_IFNAME"] = actual
    os.execvpe(args.command[1], args.command[1:], env)
    return 127


if __name__ == "__main__":
    sys.exit(main())
