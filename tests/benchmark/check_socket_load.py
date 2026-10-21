#!/usr/bin/env python3
"""Loopback correctness checks; these are never Pixel performance results."""
import importlib.util
import argparse
import json
import os
from pathlib import Path
import signal
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
        except PermissionError:
            raise
        except OSError:
            continue
        finally:
            for endpoint in sockets:
                endpoint.close()
    raise RuntimeError("no free contiguous peer port range")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, help="reuse an already compiled helper")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="sakamoto-socket-check-") as directory:
        binary = args.binary.resolve() if args.binary else Path(directory) / "socket-load"
        if not args.binary:
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
                assert len(client["worker_tids"]) == client["threads"] == 2
                assert len(set(client["worker_tids"])) == 2
                assert all(tid > 0 and tid != client["pid"] for tid in client["worker_tids"])
                assert client["offered_rate"] == client["pacing_scheduled"] == client["pacing_missed"] == 0
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
            def tcp_source_ports(count, stride=1):
                for base in range(20000, 30000, count * stride):
                    endpoints = []
                    try:
                        for offset in range(count):
                            endpoint = socket.socket()
                            endpoints.append(endpoint)
                            endpoint.bind(("0.0.0.0", base + offset * stride))
                        return base
                    except OSError:
                        continue
                    finally:
                        for endpoint in endpoints:
                            endpoint.close()
                raise RuntimeError("no free TCP source port range")

            tcp_base = tcp_source_ports(10, 2)
            fixed = json.loads(subprocess.check_output(
                [str(binary), "client", "127.0.0.1", str(port), "14", "tcp-fixed",
                 "250", "2", "4", str(tcp_base), "2"], text=True, timeout=2))
            assert fixed["fixed_source_port_base"] == tcp_base and fixed["fixed_source_port_stride"] == 2
            assert fixed["bytes"] > 0 and fixed["latency_samples"] > 0
            assert fixed["attempts"] == 10 and fixed["errors"] == fixed["timeouts"] == 0
            assert quick.peer_query("127.0.0.1", port, 14)["tcp_requests"] >= 10
            # An occupied bulk source port must fail explicitly; falling back
            # to an ephemeral port would silently change canonical ownership.
            with socket.socket() as occupied:
                occupied.bind(("0.0.0.0", tcp_source_ports(2)))
                source = occupied.getsockname()[1]
                collision = json.loads(subprocess.check_output(
                    [str(binary), "client", "127.0.0.1", str(port), "15", "tcp-fixed",
                     "100", "1", "1", str(source), "1"], text=True, timeout=2))
                assert collision["bytes"] == 0 and collision["errors"] == 1, collision
                assert collision["latency_samples"] > 0 and collision["timeouts"] == 0
            print("fixed TCP source ports and bind collision: PASS", flush=True)

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

            def paced(case, rate, duration, case_id, flows=4, source=0):
                quick.peer_query("127.0.0.1", port, case_id, "R")
                result = json.loads(subprocess.check_output(
                    [str(binary), "client", "127.0.0.1", str(port), str(case_id), case,
                     str(duration), "4", str(flows), str(source), "1", str(rate)], text=True, timeout=2))
                target = (rate * duration + 999) // 1000
                offered = result["offered_packets"] if case == "udp-fixed" else result["attempts"]
                assert result["offered_rate"] == rate and result["pacing_scheduled"] == target
                assert offered + result["pacing_missed"] == target
                assert result["pacing_missed"] <= max(4, target // 25), result
                elapsed = (result["end_monotonic_ns"] - result["start_monotonic_ns"]) / 1e9
                assert duration / 1000 <= elapsed < duration / 1000 + .15
                assert result["timeouts"] == 0
                stats = quick.peer_query("127.0.0.1", port, case_id)
                if case == "udp-fixed":
                    until = time.monotonic() + .5
                    while stats["udp_received_packets"] < result["packets"] and time.monotonic() < until:
                        stats = quick.peer_query("127.0.0.1", port, case_id)
                    assert result["packets"] == stats["udp_received_packets"] == offered
                    assert result["udp_send_errors"] == stats["udp_duplicates"] == stats["malformed"] == 0
                    assert result["latency_samples"] >= 4 * duration // 40
                    assert result["probe_requests"] <= 4 * ((duration + 19) // 20 + 1)
                    assert result["cancelled_at_deadline"] <= 4
                else:
                    assert result["attempts"] == result["offered_connections"]
                    assert result["attempts"] == sum(result[k] for k in ("completed", "errors", "timeouts", "cancelled_at_deadline"))
                    assert result["completed"] <= stats["tcp_requests"] <= result["attempts"]
                    assert result["completed"] >= offered - 4
                print(f"paced {case} {rate}/s {duration} ms: scheduled={target} offered={offered} missed={result['pacing_missed']} PASS", flush=True)
                quick.peer_query("127.0.0.1", port, case_id, "R")

            paced("udp-fixed", 8000, 600, 4, source=38000)
            paced("udp-fixed", 100, 500, 5)
            paced("udp-fixed", 137, 175, 6)  # Fractional global schedule + partial deadline.
            paced("tcp-new", 400, 600, 7)
            paced("tcp-new", 137, 175, 8)

            # A stalled peer fills real flow slots. It must consume scheduled
            # misses rather than reconnect early or inflate deadline timeouts.
            with socket.socket() as stalled:
                stalled.bind(("127.0.0.1", 0)); stalled.listen(16)
                stalled_port = stalled.getsockname()[1]
                result = json.loads(subprocess.check_output(
                    [str(binary), "client", "127.0.0.1", str(stalled_port), "9", "tcp-new",
                     "300", "4", "1", "0", "1", "400"], text=True, timeout=2))
                assert result["attempts"] == result["cancelled_at_deadline"] == 4
                assert result["completed"] == result["errors"] == result["timeouts"] == 0
                assert result["pacing_scheduled"] == 120
                assert result["pacing_missed"] == result["pacing_capacity_missed"] == 116
                assert .3 <= (result["end_monotonic_ns"] - result["start_monotonic_ns"]) / 1e9 < .45
            print("paced TCP slots and partial-deadline conservation: PASS", flush=True)

            # Force a real scheduler pause: one wake can issue at most sixteen
            # due payloads per worker, so older debt is counted as missed.
            quick.peer_query("127.0.0.1", port, 9, "R")
            paused = subprocess.Popen([str(binary), "client", "127.0.0.1", str(port), "9",
                                       "udp-fixed", "500", "4", "4", "0", "1", "1000"],
                                      stdout=subprocess.PIPE, text=True)
            try:
                time.sleep(.05)
                os.kill(paused.pid, signal.SIGSTOP)
                time.sleep(.12)
                os.kill(paused.pid, signal.SIGCONT)
                raw, _ = paused.communicate(timeout=2)
                assert paused.returncode == 0
                result = json.loads(raw)
                assert result["offered_packets"] + result["pacing_missed"] == result["pacing_scheduled"] == 500
                assert result["pacing_missed"] > 0 and result["pacing_behind_events"] > 0
                assert result["pacing_max_behind_ns"] >= 100000000
                assert result["timeouts"] == 0
            finally:
                if paused.poll() is None:
                    os.kill(paused.pid, signal.SIGCONT)
                    paused.terminate(); paused.wait(timeout=2)
            print("paced scheduler-pause debt is bounded and audited: PASS", flush=True)

            for case in ("tcp-fixed", "udp-new"):
                unsupported = subprocess.run([str(binary), "client", "127.0.0.1", str(port), "9",
                                              case, "100", "4", "4", "0", "1", "100"],
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
                assert unsupported.returncode == 2 and "supported only" in unsupported.stderr
            print("unsupported paced cases reject explicitly: PASS", flush=True)
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
            # Longer windows must retain exact duplicate accounting beyond
            # the original 2^24 sequence space, including the capacity edge.
            quick.peer_query("127.0.0.1", port, 0, "R")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
                for sequence in ((1 << 24) + 100, (1 << 24) + 100,
                                 (1 << 27) - 1, (1 << 27) - 1, (1 << 27)):
                    endpoint.sendto(struct.pack("!IIIIQ", 0x53424e31, 0, ord("U"), 24, sequence),
                                    ("127.0.0.1", port))
            until = time.monotonic() + 1
            while time.monotonic() < until:
                stats = quick.peer_query("127.0.0.1", port, 0)
                if stats["udp_received_packets"] == 5:
                    break
            assert stats["udp_received_packets"] == 5 and stats["udp_duplicates"] == 2
            assert stats["sequence_overflow_packets"] == 1
            print("long-window sequence boundaries: PASS")
        finally:
            peer.terminate()
            peer.wait(timeout=2)


if __name__ == "__main__":
    main()
