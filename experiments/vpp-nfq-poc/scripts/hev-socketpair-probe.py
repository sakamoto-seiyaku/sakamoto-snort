#!/usr/bin/env python3
"""Probe whether HEV can use a SOCK_SEQPACKET fd as its external TUN fd."""

from __future__ import annotations

import argparse
import ctypes
import multiprocessing
import queue
import socket
import struct
import sys
import threading
import time
from pathlib import Path


TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_PSH = 0x08
TCP_ACK = 0x10


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) + data[offset + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ip4_bytes(addr: str) -> bytes:
    return socket.inet_aton(addr)


def build_tcp_segment(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    data_offset = 5
    window = 65535
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        data_offset << 4,
        flags,
        window,
        0,
        0,
    )
    pseudo = ip4_bytes(src_ip) + ip4_bytes(dst_ip) + struct.pack("!BBH", 0, 6, len(tcp_header) + len(payload))
    checksum = internet_checksum(pseudo + tcp_header + payload)
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        data_offset << 4,
        flags,
        window,
        checksum,
        0,
    )
    return tcp_header + payload


def build_ip4_packet(src_ip: str, dst_ip: str, proto: int, payload: bytes, ident: int) -> bytes:
    version_ihl = 0x45
    total_len = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_len,
        ident,
        0,
        64,
        proto,
        0,
        ip4_bytes(src_ip),
        ip4_bytes(dst_ip),
    )
    checksum = internet_checksum(header)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_len,
        ident,
        0,
        64,
        proto,
        checksum,
        ip4_bytes(src_ip),
        ip4_bytes(dst_ip),
    )
    return header + payload


def build_tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
    ident: int = 1,
) -> bytes:
    segment = build_tcp_segment(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload)
    return build_ip4_packet(src_ip, dst_ip, 6, segment, ident)


def parse_tcp_packet(packet: bytes) -> dict[str, object] | None:
    if len(packet) < 40 or packet[0] >> 4 != 4 or packet[9] != 6:
        return None
    ihl = (packet[0] & 0x0F) * 4
    src_ip = socket.inet_ntoa(packet[12:16])
    dst_ip = socket.inet_ntoa(packet[16:20])
    tcp = packet[ihl:]
    if len(tcp) < 20:
        return None
    src_port, dst_port, seq, ack, off_flags = struct.unpack("!HHIIB", tcp[:13])
    data_offset = (off_flags >> 4) * 4
    flags = tcp[13]
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "flags": flags,
        "payload": tcp[data_offset:],
    }


def recv_exact(conn: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise RuntimeError("unexpected EOF from SOCKS client")
        data.extend(chunk)
    return bytes(data)


def run_socks5_server(result: queue.Queue[object], ready: queue.Queue[int]) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    ready.put(port)

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
            port_bytes = recv_exact(conn, 2)
            dst_port = struct.unpack("!H", port_bytes)[0]
            result.put(("connect", addr, dst_port))
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

            payload = conn.recv(4096)
            result.put(("payload", payload))
            conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            time.sleep(0.2)
    except BaseException as exc:  # noqa: BLE001 - this is an experiment harness.
        result.put(("error", repr(exc)))
    finally:
        listener.close()


def wait_for_packet(sock: socket.socket, predicate, deadline: float) -> dict[str, object]:
    while time.monotonic() < deadline:
        packet = sock.recv(65535)
        parsed = parse_tcp_packet(packet)
        if parsed is None:
            continue
        print(
            "packet "
            f"{parsed['src_ip']}:{parsed['src_port']} -> "
            f"{parsed['dst_ip']}:{parsed['dst_port']} "
            f"flags=0x{parsed['flags']:02x} len={len(parsed['payload'])}"
        )
        if predicate(parsed):
            return parsed
    raise TimeoutError("timed out waiting for expected packet")


def run_hev_process(lib_path: str, config: bytes, fd: int) -> None:
    lib = ctypes.CDLL(lib_path)
    lib.hev_socks5_tunnel_main_from_str.argtypes = [ctypes.c_char_p, ctypes.c_uint, ctypes.c_int]
    lib.hev_socks5_tunnel_main_from_str.restype = ctypes.c_int
    rc = lib.hev_socks5_tunnel_main_from_str(config, len(config), fd)
    raise SystemExit(rc if rc >= 0 else 128 - rc)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hev-root", required=True)
    parser.add_argument("--client-ip", default="10.0.0.2")
    parser.add_argument("--remote-ip", default="93.184.216.34")
    parser.add_argument("--client-port", type=int, default=42424)
    parser.add_argument("--remote-port", type=int, default=80)
    args = parser.parse_args()

    hev_root = Path(args.hev_root).resolve()
    lib_path = hev_root / "bin" / "libhev-socks5-tunnel.so"
    if not lib_path.exists():
        raise FileNotFoundError(lib_path)

    socks_events: queue.Queue[object] = queue.Queue()
    socks_ready: queue.Queue[int] = queue.Queue()
    socks_thread = threading.Thread(target=run_socks5_server, args=(socks_events, socks_ready), daemon=True)
    socks_thread.start()
    socks_port = socks_ready.get(timeout=5)

    client_sock, hev_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client_sock.settimeout(5)

    config = f"""
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
    hev_process = ctx.Process(target=run_hev_process, args=(str(lib_path), config, hev_sock.fileno()))
    hev_process.start()
    hev_sock.close()
    try:
        time.sleep(0.2)

        client_seq = 0x12345678
        syn = build_tcp_packet(
            args.client_ip,
            args.remote_ip,
            args.client_port,
            args.remote_port,
            client_seq,
            0,
            TCP_SYN,
            ident=1,
        )
        client_sock.send(syn)

        syn_ack = wait_for_packet(
            client_sock,
            lambda p: p["src_ip"] == args.remote_ip and p["flags"] & TCP_SYN and p["flags"] & TCP_ACK,
            time.monotonic() + 5,
        )

        server_seq = int(syn_ack["seq"])
        ack = build_tcp_packet(
            args.client_ip,
            args.remote_ip,
            args.client_port,
            args.remote_port,
            client_seq + 1,
            server_seq + 1,
            TCP_ACK,
            ident=2,
        )
        client_sock.send(ack)

        request = b"GET /probe HTTP/1.0\r\nHost: example.test\r\n\r\n"
        data = build_tcp_packet(
            args.client_ip,
            args.remote_ip,
            args.client_port,
            args.remote_port,
            client_seq + 1,
            server_seq + 1,
            TCP_PSH | TCP_ACK,
            request,
            ident=3,
        )
        client_sock.send(data)

        response = wait_for_packet(
            client_sock,
            lambda p: b"OK" in bytes(p["payload"]),
            time.monotonic() + 5,
        )
    finally:
        if hev_process.is_alive():
            hev_process.terminate()
            hev_process.join(timeout=5)
        client_sock.close()
        socks_thread.join(timeout=2)

    print(f"SOCKS port: {socks_port}")
    while not socks_events.empty():
        print(f"SOCKS event: {socks_events.get()!r}")
    print(f"HEV exitcode: {hev_process.exitcode}")
    print(f"response payload: {bytes(response['payload'])!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
