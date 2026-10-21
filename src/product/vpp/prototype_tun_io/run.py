#!/usr/bin/env python3
"""PROTOTYPE — pinned-VPP direct-buffer I/O worker experiment, never Product."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from rebuild_vlib import build as build_patched_vlib, LIBRARY as PATCHED_VLIB


REPO = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent
STAGE = (REPO / "build-output/s220-20260913/host-stage-b/source/build-root/"
         "install-vpp-native/vpp")
VPP = STAGE / "bin/vpp"
VPPCTL = STAGE / "bin/vppctl"
LIB = STAGE / "lib/x86_64-linux-gnu"
INCLUDE = STAGE / "include"
PATCHED_SOURCE = REPO / "build-output/s220-20260913/host-stage-b/source/src"
CACHE = REPO / "build-output/product-build-cache/prototype-tun-io"
PLUGIN = CACHE / "prototype_tun_io_plugin.so"
STAMP = CACHE / "source.sha256"
EVIDENCE = REPO / "build-output/prototype-tun-io-20261021"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_plugin():
    CACHE.mkdir(parents=True, exist_ok=True)
    source = HERE / "prototype_tun_io.c"
    identity = hashlib.sha256((sha(source) + sha(VPP) + sha(LIB / "libvlib.so.26.02")).encode()).hexdigest()
    if PLUGIN.exists() and STAMP.exists() and STAMP.read_text().strip() == identity:
        return False
    subprocess.run([
        "cc", "-std=gnu11", "-O2", "-fPIC", "-shared",
        "-Wno-address-of-packed-member", "-I", str(INCLUDE),
        "-I", str(PATCHED_SOURCE), "-o", str(PLUGIN), str(source),
    ], check=True)
    STAMP.write_text(identity + "\n")
    return True


def cli(vppctl, socket, env, command, raw):
    result = subprocess.run([str(vppctl), "-s", str(socket), *command.split()],
                            text=True, capture_output=True, timeout=8, env=env)
    output = (result.stdout + result.stderr).strip()
    raw.write(json.dumps({"command": command, "exit": result.returncode,
                          "output": output}) + "\n")
    raw.flush()
    if result.returncode or "prototype tun-io send:" in output:
        raise RuntimeError(f"CLI {command!r}: {output}")
    return output


def thread_rows(output):
    rows = {}
    for match in re.finditer(r"prototype\.thread index=(\d+) tid=(\d+) cpu=(\d+) role=(\w+)", output):
        index, tid, cpu, role = match.groups()
        rows[int(index)] = {"tid": int(tid), "startup_cpu": int(cpu), "role": role}
    return rows


def run(args):
    if args.owners < 1:
        raise ValueError("N must be at least one")
    if args.duplicate_startup and args.owners < 2:
        raise ValueError("duplicate-startup needs at least two owners")
    unique_cpus = list(range(args.owners + 2))
    if not set(unique_cpus).issubset(os.sched_getaffinity(0)):
        raise RuntimeError(f"prototype requires available CPUs {unique_cpus}")
    compiled = build_plugin()
    vlib_compiled = build_patched_vlib() if args.duplicate_startup else False
    worker_cpus = unique_cpus[1:]
    if args.duplicate_startup:
        worker_cpus[args.owners - 1] = worker_cpus[0]
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    run_dir = EVIDENCE / (time.strftime("run-%Y%m%dT%H%M%SZ", time.gmtime()) + f"-{os.getpid()}")
    run_dir.mkdir()
    runtime = Path(tempfile.mkdtemp(prefix="sak-tunio-proto-", dir="/tmp"))
    config = f"""cpu {{
  main-core 0
  workers {args.owners + 1}
  ordered-workers {','.join(map(str, worker_cpus))}
}}
unix {{
  nodaemon
  cli-no-pager
  poll-sleep-usec 0
  runtime-dir {runtime}
  cli-listen {runtime / 'cli.sock'}
}}
plugins {{
  path {CACHE}
  plugin default {{ disable }}
  plugin prototype_tun_io_plugin.so {{ enable }}
}}
"""
    (run_dir / "startup.conf").write_text(config)
    (runtime / "startup.conf").write_text(config)
    env = dict(os.environ, LD_LIBRARY_PATH=(str(CACHE) + ":" + str(LIB)
               if args.duplicate_startup else str(LIB)))
    original_env = dict(os.environ, LD_LIBRARY_PATH=str(LIB))
    observations = []
    status = ""
    vpp = None
    try:
        if args.duplicate_startup:
            negative_runtime = Path(tempfile.mkdtemp(prefix="sak-tunio-negative-", dir="/tmp"))
            try:
                negative_config = config.replace(str(runtime), str(negative_runtime))
                (negative_runtime / "startup.conf").write_text(negative_config)
                (run_dir / "original-startup.conf").write_text(negative_config)
                negative = subprocess.run([str(VPP), "-c", str(negative_runtime / "startup.conf")],
                                          text=True, capture_output=True, timeout=8,
                                          env=original_env)
                negative_output = negative.stdout + negative.stderr
                (run_dir / "original-startup.log").write_text(negative_output)
                if negative.returncode == 0 or "duplicate CPU" not in negative_output:
                    raise RuntimeError("original libvlib did not reject the duplicate CPU")
            finally:
                shutil.rmtree(negative_runtime)
        with (run_dir / "vpp.log").open("w") as log, (run_dir / "cli.jsonl").open("w") as raw:
            vpp = subprocess.Popen([str(VPP), "-c", str(runtime / "startup.conf")],
                                   stdout=log, stderr=subprocess.STDOUT, env=env)
            socket = runtime / "cli.sock"
            deadline = time.monotonic() + 8
            while not socket.exists() and time.monotonic() < deadline:
                if vpp.poll() is not None:
                    raise RuntimeError(f"VPP exited {vpp.returncode}; see vpp.log")
                time.sleep(.05)
            if not socket.exists():
                raise RuntimeError("VPP CLI socket did not appear; see vpp.log")
            opened = cli(VPPCTL, socket, env, "prototype tun-io open", raw)
            if f"owners={args.owners} io_thread={args.owners + 1}" not in opened:
                raise RuntimeError(opened)
            status = cli(VPPCTL, socket, env, "prototype tun-io status", raw)
            rows = thread_rows(status)
            if len(rows) != args.owners + 2:
                raise RuntimeError(f"missing VPP thread identities: {rows}")
            if args.owners > 1 and not args.duplicate_startup:
                last = rows[args.owners]["tid"]
                os.sched_setaffinity(last, {1})
                if os.sched_getaffinity(last) != {1}:
                    raise RuntimeError("owner's shared CPU affinity did not apply")
            affinities = {str(index): sorted(os.sched_getaffinity(row["tid"]))
                          for index, row in rows.items()}
            expected_cpus = [0, *worker_cpus]
            if not args.duplicate_startup and args.owners > 1:
                expected_cpus[args.owners] = 1
            for index, cpu in enumerate(expected_cpus):
                if affinities[str(index)] != [cpu]:
                    raise RuntimeError(f"thread {index} affinity {affinities[str(index)]} != {cpu}")

            def send(owner):
                echo = cli(VPPCTL, socket, env, f"prototype tun-io send {owner}", raw)
                match = re.search(
                    r"prototype\.echo owner=(\d+) bytes=(\d+) equal=(\d+) "
                    r"input_thread=(\d+) owner_thread=(\d+) return_thread=(\d+) "
                    r"input_buffer=(\d+) owner_buffer=(\d+) return_buffer=(\d+)", echo)
                if not match:
                    raise RuntimeError(f"missing echo identity: {echo}")
                values = list(map(int, match.groups()))
                if values[:6] != [owner, 32, 1, args.owners + 1, owner + 1,
                                  args.owners + 1] or len(set(values[6:])) != 1:
                    raise RuntimeError(f"thread or buffer identity mismatch: {echo}")
                observations.append(echo)
                return echo

            if args.demo:
                for owner in range(args.owners):
                    print(send(owner), flush=True)
            else:
                last = "Prototype ready. No Product traffic."
                while True:
                    status = cli(VPPCTL, socket, env, "prototype tun-io status", raw)
                    print("\033[2J\033[H", end="")
                    print("PINNED VPP — THROWAWAY TUN I/O PROTOTYPE\n")
                    print(status, "\n")
                    print("Actual affinity:", affinities)
                    print("Last action:", last, "\n")
                    print(f"[0..{args.owners - 1}] send to owner   [s] refresh   [q] quit")
                    action = input("> ").strip()
                    if action == "q":
                        break
                    if action == "s":
                        last = "Refreshed."
                    elif action.isdecimal() and int(action) < args.owners:
                        last = send(int(action))
                    else:
                        last = "Unknown action."
            status = cli(VPPCTL, socket, env, "prototype tun-io status", raw)
            if args.demo and f"failures=0" not in status:
                raise RuntimeError(f"prototype failures: {status}")
            result = {"status": "PASS", "owners": args.owners,
                      "io_thread": args.owners + 1, "compiled": compiled,
                      "duplicate_startup": args.duplicate_startup,
                      "patched_vlib_compiled": vlib_compiled,
                      "runner_sha256": sha(Path(__file__)),
                      "plugin_source_sha256": sha(HERE / "prototype_tun_io.c"),
                      "relink_helper_sha256": sha(HERE / "rebuild_vlib.py"),
                      "plugin_sha256": sha(PLUGIN), "vpp_sha256": sha(VPP),
                      "libvlib_sha256": sha(PATCHED_VLIB if args.duplicate_startup
                                           else LIB / "libvlib.so.26.02"),
                      "plugin_mtime_ns": PLUGIN.stat().st_mtime_ns,
                      "patched_vlib_mtime_ns": (PATCHED_VLIB.stat().st_mtime_ns
                                                if args.duplicate_startup else None),
                      "threads": rows, "actual_affinities": affinities,
                      "observations": observations, "final_status": status,
                      "limit": ("uses throwaway relinked libvlib, not Product VPP"
                                if args.duplicate_startup else
                                "shared owner CPU applied after startup; original VPP rejects duplicates")}
            (run_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
            print(f"Evidence: {run_dir / 'result.json'}", flush=True)
    finally:
        if vpp is not None and vpp.poll() is None:
            vpp.terminate()
            try:
                vpp.wait(timeout=5)
            except subprocess.TimeoutExpired:
                vpp.kill()
                vpp.wait(timeout=5)
        shutil.rmtree(runtime)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owners", type=int, default=3)
    parser.add_argument("--demo", action="store_true", help="run once through every owner")
    parser.add_argument("--duplicate-startup", action="store_true",
                        help="relink a throwaway libvlib and start with repeated owner CPUs")
    run(parser.parse_args())
