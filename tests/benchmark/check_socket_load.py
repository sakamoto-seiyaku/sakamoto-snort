#!/usr/bin/env python3
"""Loopback correctness checks; these are never Pixel performance results."""
import importlib.util
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("pixel_quick", HERE / "pixel_quick.py")
quick = importlib.util.module_from_spec(spec)
spec.loader.exec_module(quick)


def choose_port():
    for port in range(42000, 64000, 64):
        sockets = []
        try:
            tcp = socket.socket()
            tcp.bind(("127.0.0.1", port))
            sockets.append(tcp)
            for offset in range(64):
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp.bind(("127.0.0.1", port + offset))
                sockets.append(udp)
            return port
        except OSError:
            continue
        finally:
            for endpoint in sockets:
                endpoint.close()
    raise RuntimeError("no free contiguous peer port range")


def main():
    with tempfile.TemporaryDirectory(prefix="sakamoto-socket-check-") as directory:
        binary = Path(directory) / "socket-load"
        subprocess.run(["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread",
                        str(HERE / "socket_load.c"), "-o", str(binary)], check=True)
        port = choose_port()
        peer = subprocess.Popen([str(binary), "server", "127.0.0.1", str(port)],
                                stdout=subprocess.PIPE, text=True)
        try:
            assert json.loads(peer.stdout.readline())["ready"] is True
            for index, case in enumerate(quick.CASES):
                quick.peer_query("127.0.0.1", port, index, "R")
                started = time.monotonic()
                client = json.loads(subprocess.check_output(
                    [str(binary), "client", "127.0.0.1", str(port), str(index), case, "500", "2", "4"],
                    text=True, timeout=2))
                assert .45 <= time.monotonic() - started < 2
                assert client["bytes"] > 0
                stats = quick.peer_query("127.0.0.1", port, index)
                if case.startswith("tcp"):
                    assert client["latency_samples"] > 0 and client["p99_upper_us"] > 0
                    if case == "tcp-new":
                        assert client["attempts"] == sum(client[k] for k in ("completed", "errors", "timeouts", "cancelled_at_deadline"))
                        assert stats["tcp_requests"] >= client["completed"]
                else:
                    assert 0 < stats["udp_received_packets"] <= client["packets"]
                    assert stats["udp_duplicates"] == 0
                    assert stats["underlay_unique_tuples"] <= client["input_unique_udp_tuples"]
                    assert client["input_unique_udp_tuples"] >= 8
                reset = quick.peer_query("127.0.0.1", port, index, "R")
                assert reset["tcp_requests"] == reset["udp_received_packets"] == 0
                print(case + ": PASS", flush=True)
            # The mechanism experiment replays the same UDP five-tuples, so
            # canonical-owner distribution does not change between modes.
            for case_id, stride in ((10, 1), (11, 1), (12, 2), (13, 2)):
                quick.peer_query("127.0.0.1", port, case_id, "R")
                result = json.loads(subprocess.check_output(
                    [str(binary), "client", "127.0.0.1", str(port), str(case_id),
                     "udp-fixed", "250", "2", "4", "38000", str(stride)], text=True, timeout=2))
                stats = quick.peer_query("127.0.0.1", port, case_id)
                assert result["fixed_source_port_base"] == 38000
                assert result["fixed_source_port_stride"] == stride
                assert result["input_unique_udp_tuples"] == 8 and stats["underlay_unique_tuples"] == 8
                # A full-speed nonblocking sender reports unsent datagrams in
                # "errors"; correctness depends on the successfully sent set.
                assert stats["udp_duplicates"] == stats["malformed"] == 0
                assert stats["tuple_capacity_overflow_packets"] == stats["sequence_overflow_packets"] == 0
                assert 0 < stats["udp_received_packets"] <= result["packets"]
            print("fixed UDP tuple replay: PASS", flush=True)
            # Independently inject a duplicate to verify received/lost/duplicate accounting.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
                packet = struct.pack("!IIIIQ", 0x53424e31, 0, ord("U"), 24, 100)
                endpoint.sendto(packet, ("127.0.0.1", port))
                endpoint.sendto(packet, ("127.0.0.1", port))
            until = time.monotonic() + 1
            while time.monotonic() < until:
                stats = quick.peer_query("127.0.0.1", port, 0)
                if stats["udp_received_packets"] == 2:
                    break
            assert stats["udp_received_packets"] == 2
            assert stats["udp_duplicates"] == 1 and stats["underlay_unique_tuples"] == 1
            print("duplicate accounting and per-run reset: PASS")
        finally:
            peer.terminate()
            peer.wait(timeout=2)


if __name__ == "__main__":
    main()
