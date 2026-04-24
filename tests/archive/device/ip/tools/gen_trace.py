#!/usr/bin/env python3

import argparse
import ipaddress
import random
import struct
from pathlib import Path

MAGIC = b"IPTRCE1\x00"
VERSION = 1
HEADER = struct.Struct("!8sIII")
ENTRY = struct.Struct("!IIHHI")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate a minimal native replay trace")
    p.add_argument("--output", required=True, help="output trace path")
    p.add_argument("--entries", type=int, default=4096, help="number of trace entries")
    p.add_argument("--host-ip", default="10.200.1.1", help="source IPv4")
    p.add_argument("--peer-ip", default="10.200.1.2", help="destination IPv4")
    p.add_argument("--host-ips-csv", default="", help="optional CSV of source IPv4 addresses")
    p.add_argument("--peer-ips-csv", default="", help="optional CSV of destination IPv4 addresses")
    p.add_argument("--dst-port-base", type=int, default=18080, help="base destination port")
    p.add_argument("--dst-port-count", type=int, default=8, help="number of destination ports")
    p.add_argument("--dst-ports-csv", default="", help="optional CSV of destination ports")
    p.add_argument("--src-port-base", type=int, default=20000, help="base source port (0 = kernel auto)")
    p.add_argument("--src-port-span", type=int, default=4096, help="source port span when base != 0")
    p.add_argument("--conn-bytes", type=int, default=256, help="bytes to read per connection")
    p.add_argument("--shuffle", action="store_true", help="shuffle entry order deterministically")
    p.add_argument("--seed", type=int, default=1, help="seed used when --shuffle is set")
    return p.parse_args()


def validate_port(name: str, value: int) -> None:
    if not (0 <= value <= 65535):
        raise SystemExit(f"{name} must be in 0..65535 (got {value})")


def parse_ip_list(csv_value: str, fallback: str) -> list[int]:
    values = [item.strip() for item in csv_value.split(",") if item.strip()]
    if not values:
        values = [fallback]
    return [int(ipaddress.IPv4Address(value)) for value in values]


def parse_port_list(csv_value: str, base: int, count: int) -> list[int]:
    values = [item.strip() for item in csv_value.split(",") if item.strip()]
    if values:
        ports = [int(value) for value in values]
    else:
        ports = [base + i for i in range(count)]
    for idx, port in enumerate(ports):
        validate_port(f"dst-port[{idx}]", port)
    if not ports:
        raise SystemExit("destination ports list must not be empty")
    return ports


def main() -> int:
    args = parse_args()
    if args.entries <= 0:
        raise SystemExit("--entries must be > 0")
    if args.dst_port_count <= 0:
        raise SystemExit("--dst-port-count must be > 0")
    if args.conn_bytes <= 0:
        raise SystemExit("--conn-bytes must be > 0")
    if args.src_port_base != 0 and args.src_port_span <= 0:
        raise SystemExit("--src-port-span must be > 0 when --src-port-base != 0")

    host_ips = parse_ip_list(args.host_ips_csv, args.host_ip)
    peer_ips = parse_ip_list(args.peer_ips_csv, args.peer_ip)
    validate_port("dst-port-base", args.dst_port_base)
    dst_ports = parse_port_list(args.dst_ports_csv, args.dst_port_base, args.dst_port_count)
    validate_port("src-port-base", args.src_port_base)
    if args.src_port_base != 0:
        validate_port("src-port-upper", args.src_port_base + min(args.src_port_span - 1, args.entries - 1))

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    entry_order = list(range(args.entries))
    if args.shuffle:
        random.Random(args.seed).shuffle(entry_order)

    with out.open("wb") as fh:
        fh.write(HEADER.pack(MAGIC, VERSION, args.entries, 0))
        for logical_idx in entry_order:
            host_ip = host_ips[logical_idx % len(host_ips)]
            peer_ip = peer_ips[(logical_idx // len(host_ips)) % len(peer_ips)]
            dst_port = dst_ports[(logical_idx // (len(host_ips) * len(peer_ips))) % len(dst_ports)]
            if args.src_port_base == 0:
                src_port = 0
            else:
                src_port = args.src_port_base + (logical_idx % args.src_port_span)
            fh.write(ENTRY.pack(host_ip, peer_ip, src_port, dst_port, args.conn_bytes))

    print(
        f"trace={out} entries={args.entries} hosts={len(host_ips)} peers={len(peer_ips)} "
        f"dstPorts={len(dst_ports)} shuffle={int(args.shuffle)} seed={args.seed} "
        f"srcPortBase={args.src_port_base} srcPortSpan={args.src_port_span} connBytes={args.conn_bytes}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
