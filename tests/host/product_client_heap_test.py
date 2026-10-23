#!/usr/bin/env python3
"""Actual pinned VAPI + observation + fresh-thread RuleConfig regression."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import threading
import selectors

REPO = Path(__file__).resolve().parents[2]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--vpp-prefix", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--positive-only", action="store_true")
    args = parser.parse_args()
    artifact, prefix, output = (x.resolve() for x in (args.artifact, args.vpp_prefix, args.output))
    output.mkdir(parents=True, exist_ok=True)
    runtime = REPO / "build-output" / ("product-vpp-runtime-client-heap-" + str(os.getpid()))
    config = output / "config"
    config.mkdir(exist_ok=True)
    library = artifact / "lib"
    executable = output / "client-heap-test"
    command = ["cc", "-std=gnu11", "-O0", "-g", "-I" + str(REPO / "src/product/include"),
               "-I" + str(prefix / "include"), "-I" + str(artifact / "include"),
               str(REPO / "tests/host/product_client_heap_test.c"),
               str(REPO / "src/product/native/product_observation_transport.c"),
               str(REPO / "src/product/native/sakamoto_product_vapi.c"),
               "-L" + str(library), "-Wl,-rpath," + str(library),
               "-Wl,-rpath-link," + str(library), "-lvapiclient", "-lvlibmemoryclient",
               "-lvlibapi", "-lsvm", "-lvppinfra", "-lpthread", "-lm", "-lrt", "-o", str(executable)]
    heap_source = REPO / "src/product/native/product_client_heap.c"
    if heap_source.exists():
        command.insert(command.index("-L" + str(library)), str(heap_source))
    (output / "compile-command.json").write_text(json.dumps(command, indent=2))
    with (output / "compile.log").open("w") as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    sources = [REPO / name for name in [
        "src/product/native/product_observation_transport.c",
        "src/product/native/sakamoto_product_vapi.c",
        "src/product/native/product_client_heap.h",
        "tests/host/product_client_heap_test.c",
        "tests/host/product_client_heap_test.py",
        "tests/host/product_observation_producer.c"]]
    source_hashes = {str(p.relative_to(REPO)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    (output / "source-hashes.json").write_text(json.dumps(source_hashes, indent=2) + "\n")
    for source in sources:
        destination = output / "source" / source.relative_to(REPO)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
    producer_binary = output / "observation-producer"
    if args.positive_only:
        producer_command = ["cc", "-std=gnu11", "-O0", "-g",
            "-I" + str(REPO / "src/product/include"), "-I" + str(prefix / "include"),
            str(REPO / "tests/host/product_observation_producer.c"),
            str(REPO / "src/product/native/product_observation_transport.c"),
            "-L" + str(library), "-lsvm", "-lvppinfra", "-lpthread", "-ldl", "-lm",
            "-o", str(producer_binary)]
        (output / "producer-command.json").write_text(json.dumps(producer_command, indent=2))
        with (output / "producer-build.log").open("w") as log:
            subprocess.run(producer_command, stdout=log, stderr=subprocess.STDOUT, check=True)
    env = dict(os.environ, PRODUCT_ARTIFACT_DIR=str(artifact), PRODUCT_RUNTIME_DIR=str(runtime),
               PRODUCT_RULE_CONFIG_DIR=str(config), PRODUCT_GENERATION="314001",
               PRODUCT_WORKER_COUNT="1", LD_LIBRARY_PATH=str(library))
    results = []
    cleanup = {}
    with (output / "vpp.log").open("w") as log:
        process = subprocess.Popen([str(REPO / "tools/product/run-host-vpp.sh")], env=env,
                                   stdout=log, stderr=subprocess.STDOUT)
        print("owned_vpp_pid=" + str(process.pid), flush=True)
        try:
            deadline = time.monotonic() + 15
            while not (runtime / "api.sock").exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(.05)
            if not (runtime / "api.sock").exists():
                raise RuntimeError("VPP failed before API readiness; see vpp.log")
            if args.positive_only:
                observation_socket = Path("/tmp") / ("s314-client-heap-" + str(os.getpid()) + ".sock")
                producer = subprocess.Popen([str(producer_binary), str(observation_socket)], env=env,
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1)
                print("owned_producer_pid=" + str(producer.pid), flush=True)
                consumer = None
                def producer_line(expected):
                    with selectors.DefaultSelector() as selector:
                        selector.register(producer.stdout, selectors.EVENT_READ)
                        if not selector.select(timeout=5):
                            raise RuntimeError("producer response deadline: " + expected)
                        line = producer.stdout.readline()
                    producer_log.write(line)
                    producer_log.flush()
                    if line.strip() != expected:
                        raise RuntimeError("producer response: " + repr(line))
                with (output / "producer.log").open("w") as producer_log:
                    try:
                        producer_line("LISTEN")
                        with (output / "positive-lifecycle.log").open("w") as run_log:
                            consumer = subprocess.Popen([str(executable), "vapi-first",
                                str(runtime / "api.sock"), str(observation_socket)], env=env,
                                stdout=run_log, stderr=subprocess.STDOUT)
                            producer_line("CONNECTED")
                            producer.stdin.write("emit 0 1 456 1 1 0\n")
                            producer.stdin.flush()
                            producer_line("EMITTED 1")
                            code = consumer.wait(timeout=15)
                            results.append(dict(label="positive-observation-configuration-restart", exit=code))
                            print("positive-observation-configuration-restart exit=" + str(code), flush=True)
                    finally:
                        if consumer and consumer.poll() is None:
                            consumer.terminate()
                            consumer.wait(timeout=5)
                        if producer.poll() is None:
                            producer.stdin.write("quit\n")
                            producer.stdin.flush()
                            try:
                                producer.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                producer.terminate()
                                producer.wait(timeout=5)
                        cleanup["producer_exit"] = producer.returncode
                        cleanup["producer_socket_absent"] = int(observation_socket.exists())
            for mode in ([] if args.positive_only else ["vapi-only", "vapi-first", "observer-first"]):
                for real in [False, True]:
                    cmd = [str(executable), mode]
                    if real:
                        cmd.append(str(runtime / "api.sock"))
                    label = mode + ("-real" if real else "-capacity")
                    with (output / (label + ".log")).open("w") as run_log:
                        result = subprocess.run(cmd, env=env, stdout=run_log,
                                                stderr=subprocess.STDOUT, timeout=30)
                    results.append(dict(label=label, exit=result.returncode))
                    print(label + " exit=" + str(result.returncode), flush=True)
        finally:
            # Reap our direct child while the existing stopper checks PID absence.
            reaper = threading.Thread(target=process.wait, daemon=True)
            reaper.start()
            for name, script in [("stop", "stop-host-vpp.sh"), ("residue", "host-residue-check.sh")]:
                with (output / (name + ".log")).open("w") as cleanup_log:
                    result = subprocess.run([str(REPO / "tools/product" / script)], env=env,
                                            stdout=cleanup_log, stderr=subprocess.STDOUT, timeout=20)
                cleanup[name] = result.returncode
                if name == "stop":
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        process.wait(timeout=5)
    result = dict(results=results, cleanup=cleanup,
                  status="PASS" if all(x["exit"] == 0 for x in results) and not any(cleanup.values()) else "FAIL")
    result["source_hashes"] = source_hashes
    result["source_unchanged"] = all(hashlib.sha256(p.read_bytes()).hexdigest() == source_hashes[str(p.relative_to(REPO))] for p in sources)
    if not result["source_unchanged"]:
        result["status"] = "FAIL"
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result["status"] != "PASS"

if __name__ == "__main__":
    raise SystemExit(main())
