#!/usr/bin/env python3
"""Actual NFQUEUE → VPP → svm_msg_q → Rust → durable overall minutes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser()
p.add_argument("--build", type=Path, required=True)
p.add_argument("--stage", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
out = a.output.resolve(); out.mkdir(parents=True, exist_ok=False)
b = json.loads(a.build.read_text()); artifact = Path(b["artifact"])
digest = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
for name, expected in b["artifact_hashes"].items(): assert digest(artifact/name) == expected, name
env = dict(os.environ, LD_LIBRARY_PATH=str(artifact/"lib"))
tag = hashlib.sha256(str(out).encode()).hexdigest()[:8]
runtime = ROOT/("build-output/product-vpp-runtime-t22-"+tag)
store_path = out/"observation/overall.json"
vppctl = a.stage.resolve()/"source/build-root/install-vpp-native/vpp/bin/vppctl"
peer = ROOT/"tests/device/helpers/t22_udp_peer.py"
interrupt_source = ROOT/"tests/host/t22_interrupt_store.c"
interrupt_library = out/"interrupt-store.so"
interrupt_marker = out/"interrupt-write.arm"
result = dict(status="HOLD", kind="linux", build=str(a.build.resolve()), build_sha256=digest(a.build),
              source_sha256=b["source_sha256"], profile="root", source="NFQ_CAPTURED",
              started_ns=time.time_ns(), snapshots=[], traffic=[], lifetimes=[])
for path in [Path(__file__), peer, interrupt_source]: (out/path.name).write_bytes(path.read_bytes())

def save(name, text): (out/name).write_text(text); return text
def command(*arguments, check=True):
    r = subprocess.run(list(map(str, arguments)), env=env, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=30)
    if check and r.returncode: raise RuntimeError(r.stdout)
    return r.stdout
def cli(label, text): return save(label+".txt", command(vppctl, "-s", runtime/"cli.sock", text))
def read_line(process, deadline=10):
    end = time.monotonic()+deadline; data = bytearray()
    while time.monotonic() < end:
        assert process.poll() is None, "child exited"
        if select.select([process.stdout], [], [], .1)[0]:
            byte = os.read(process.stdout.fileno(), 1)
            assert byte
            if byte == b"\n": return data.decode()
            data.extend(byte)
    raise RuntimeError("child output deadline: "+data.decode())
def observe(command):
    observer.stdin.write((command+"\n").encode()); observer.stdin.flush()
    return read_line(observer)
def snapshot(label):
    response = observe("query")
    assert response.startswith("observation.response="), response
    value = json.loads(response.split("=", 1)[1])
    save(label+".json", json.dumps(value, indent=2)+"\n")
    assert "error" not in value and value["health"]["generation"] == generation, value
    result["snapshots"].append(dict(label=label, generation=generation, at_ns=time.time_ns()))
    return value
def wait_snapshot(label, predicate):
    end = time.monotonic()+10
    while time.monotonic() < end:
        value = snapshot(label)
        if predicate(value): return value
        time.sleep(.03)
    raise RuntimeError("snapshot deadline: "+label)
def persistent(value): return value["consumer"]["persistent"]
def flow(value):
    return next(r for r in value["consumer"]["overview"]["records"] if r
                and r["ports"][0] == 42132 and not r["ended"])
def send(label, count, size):
    nonce = f"t22-{tag}-{generation}-{label}-{time.time_ns()}"
    client.stdin.write(f"{count} {size} {nonce}\n".encode()); client.stdin.flush()
    row = json.loads(read_line(client)); assert row["count"] == count
    row.update(label=label, generation=generation)
    result["traffic"].append(row); save(label+"-traffic.json", json.dumps(row, indent=2)+"\n")
    return row
def stop_process(child):
    if child is not None and child.poll() is None:
        child.terminate()
        try: child.wait(timeout=10)
        except subprocess.TimeoutExpired: child.kill(); child.wait()
def start_runtime(number):
    global process, observer, generation, runtime
    generation = number
    runtime = ROOT/("build-output/product-vpp-runtime-t22-"+tag+"-"+str(number % 100))
    launch = dict(env, PRODUCT_ARTIFACT_DIR=str(artifact), PRODUCT_RUNTIME_DIR=str(runtime),
                  PRODUCT_RULE_CONFIG_DIR=str(out/"configuration"), PRODUCT_GENERATION=str(generation),
                  PRODUCT_WORKER_COUNT="2", SAKAMOTO_RUNTIME_PROFILE="root",
                  SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID="0", SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES="4",
                  SAKAMOTO_LINUX_NETWORK_SOURCE="external")
    process = subprocess.Popen(["bash", str(ROOT/"tools/product/run-host-vpp.sh")], env=launch,
        stdout=(out/f"vpp-{generation}.log").open("w"), stderr=subprocess.STDOUT)
    end = time.monotonic()+25
    while not (runtime/"api.sock.obs").exists():
        assert process.poll() is None and time.monotonic() < end, "runtime startup"
        time.sleep(.05)
    cli(f"g{generation}-startup", "product packet-trace limit 4096")
    save(f"g{generation}-configuration.txt", command(artifact/"bin/sakamoto-product-core-host",
         "rule-export", runtime/"api.sock", generation))
    consumer_env = dict(env, LD_PRELOAD=str(interrupt_library),
        SAKAMOTO_T22_PENDING_PATH=str(store_path.with_suffix(".pending")),
        SAKAMOTO_T22_INTERRUPT_MARKER=str(interrupt_marker),
        SAKAMOTO_T22_FSYNC_LOG=str(out/"fsync-witness.txt"))
    observer = subprocess.Popen([str(artifact/"bin/sakamoto-product-core-host"), "observation-serve",
        str(runtime/"api.sock"), str(generation), str(store_path)], env=consumer_env, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=(out/f"rust-{generation}.log").open("w"), bufsize=0)
    while not read_line(observer).startswith("observation.ready="): pass
    result["lifetimes"].append(dict(generation=generation, pid=process.pid, observer_pid=observer.pid))
def stop_runtime():
    global process, observer
    if observer is not None:
        observer.stdin.write(b"quit\n"); observer.stdin.flush()
        observer.wait(timeout=10); observer = None
    if process is not None and process.poll() is None:
        cli(f"g{generation}-stop", "product root stop")
        stop_process(process)
    result["lifetimes"][-1]["process_absent"] = not Path(f"/proc/{process.pid}").exists()
    process = None

process = observer = client = server = endpoint_thread = None
hooks = []; generation = 0
try:
    assert os.getuid() == 0
    save("interrupt-build.txt", command("cc", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror",
         interrupt_source, "-ldl", "-o", interrupt_library))
    save("environment.txt", command("uname", "-a")+command("id")+
         "netns="+os.readlink("/proc/self/ns/net")+"\n")
    command("ip", "link", "set", "lo", "up")
    command("ip", "link", "add", "t22dummy", "type", "dummy")
    command("ip", "addr", "add", "10.222.0.1/24", "dev", "t22dummy")
    command("ip", "addr", "add", "10.222.0.2/24", "dev", "t22dummy")
    command("ip", "link", "set", "t22dummy", "up")
    start_runtime(27301)
    baseline = snapshot("baseline"); assert persistent(baseline)["packets"] == [0,0]
    for flag in ["--dport", "--sport"]:
        hook = ["iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "udp", flag, "42131",
                "-j", "NFQUEUE", "--queue-num", "176"]
        command(*hook); hooks.append(hook)
    server = subprocess.Popen(["python3", "-u", str(peer), "server", "--host", "10.222.0.2"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
        user=12002, group=12002, extra_groups=[])
    assert json.loads(read_line(server))["kind"] == "ready"
    def endpoint_log():
        with (out/"endpoint.jsonl").open("wb") as file:
            while True:
                data = server.stdout.read(65536)
                if not data: break
                file.write(data); file.flush()
    endpoint_thread = threading.Thread(target=endpoint_log); endpoint_thread.start()
    client = subprocess.Popen(["python3", "-u", str(peer), "client", "--host", "10.222.0.1",
        "--peer", "10.222.0.2"], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, bufsize=0, user=12001, group=12001, extra_groups=[])
    send("created", 1, 32)
    quiet = wait_snapshot("quiet", lambda s: persistent(s)["packets"] == [1,1]); first = flow(quiet)
    send("tail", 3, 40)
    cli("close-tail", f"product flow-end close owner {first['owner']} slot {first['slot']} generation {generation} incarnation {first['incarnation']}")
    tail = wait_snapshot("end-tail", lambda s: persistent(s)["ended"] == 1)
    assert persistent(tail)["packets"] == [4,4] and persistent(tail)["bytes"] == [264,264]
    send("reused", 1, 32)
    reused = wait_snapshot("reused", lambda s: persistent(s)["packets"] == [5,5])
    second = flow(reused); assert second["incarnation"] > first["incarnation"]
    pending = store_path.with_suffix(".pending"); pending.mkdir()
    send("save-failed", 2, 36)
    failed = wait_snapshot("save-failed", lambda s: bool(s["consumer"]["store_error"]))
    assert persistent(failed)["packets"] == [5,5]
    assert persistent(failed)["save_error"] and persistent(failed)["coverage"]["incomplete"]
    pending.rmdir()
    send("save-recovered", 1, 44)
    recovered = wait_snapshot("save-recovered", lambda s: persistent(s)["packets"] == [8,8])
    assert persistent(recovered)["bytes"] == [524,524]
    second = flow(recovered)
    # END in a different UTC minute must not move the flow's last contribution.
    next_minute_ns = (time.time_ns()//60_000_000_000+1)*60_000_000_000
    while time.time_ns() < next_minute_ns+100_000_000: time.sleep(.1)
    result["late_end_ns"] = time.time_ns()
    cli("close-late", f"product flow-end close owner {second['owner']} slot {second['slot']} generation {generation} incarnation {second['incarnation']}")
    late = wait_snapshot("late-end", lambda s: persistent(s)["ended"] == 2)
    assert persistent(late)["minutes"] == persistent(recovered)["minutes"]
    interrupt_marker.touch()
    send("write-interrupted", 1, 32)
    interrupt_deadline = time.monotonic()+5
    while True:
        status = Path(f"/proc/{observer.pid}/status").read_text()
        if not interrupt_marker.exists() and "\nState:\tT" in status: break
        assert time.monotonic() < interrupt_deadline, "consumer did not stop inside partial snapshot write"
        time.sleep(.02)
    save("consumer-interrupted-status.txt", status)
    (out/"interrupted-pending.json").write_bytes(store_path.with_suffix(".pending").read_bytes())
    (out/"committed-before-kill.json").write_bytes(store_path.read_bytes())
    result["consumer_kill_ns"] = time.time_ns()
    observer.kill(); observer.wait(timeout=5); observer = None
    send("unrecoverable", 1, 32)
    health = command(artifact/"bin/sakamoto-product-core-host", "observation-query", runtime/"api.sock", generation)
    save("consumer-dead.txt", health)
    stop_runtime()
    start_runtime(27302)
    restart = snapshot("restart")
    assert persistent(restart)["packets"] == [8,8] and persistent(restart)["bytes"] == [524,524]
    assert persistent(restart)["coverage"]["recoveries"] == 1
    assert persistent(restart)["coverage"]["incomplete"]
    send("new-generation", 3, 48)
    final = wait_snapshot("new-generation", lambda s: persistent(s)["packets"] == [11,11])
    assert persistent(final)["bytes"] == [752,752]
    third = flow(final)
    cli("close-final", f"product flow-end close owner {third['owner']} slot {third['slot']} generation {generation} incarnation {third['incarnation']}")
    final = wait_snapshot("final", lambda s: persistent(s)["ended"] == 3)
    assert persistent(final)["packets"] == [11,11]
    stop_runtime()
    result["status"] = "RAW_COMPLETE"
except Exception as error:
    result["error"] = repr(error)
    raise
finally:
    for hook in hooks:
        hook[3] = "-D"; command(*hook, check=False)
    stop_process(client); stop_process(server)
    if endpoint_thread is not None: endpoint_thread.join(timeout=5)
    stop_process(observer)
    if process is not None and process.poll() is None:
        try: cli("cleanup-stop", "product root stop")
        finally: stop_process(process)
    result["completed_ns"] = time.time_ns()
    if store_path.is_file():
        (out/"final-store.json").write_bytes(store_path.read_bytes())
        result["final_store_sha256"] = digest(store_path)
        result["final_store_mode"] = oct(store_path.stat().st_mode & 0o777)
    result["files"] = {str(f.relative_to(out)):digest(f) for f in out.rglob("*")
        if f.is_file() and "observation" not in f.relative_to(out).parts}
    save("result.json", json.dumps(result, indent=2)+"\n")
print(json.dumps({k:result[k] for k in ("status", "source_sha256", "lifetimes")}, indent=2))
