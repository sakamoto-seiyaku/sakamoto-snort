#!/usr/bin/env python3
"""Current Product: real UDP → NFQUEUE → VPP svm_msg_q → Rust query."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
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
tag = hashlib.sha256(str(out).encode()).hexdigest()[:10]
runtime = ROOT/("build-output/product-vpp-runtime-t21-" + tag)
generation = 27201
vppctl = a.stage.resolve()/"source/build-root/install-vpp-native/vpp/bin/vppctl"
peer = ROOT/"tests/device/helpers/t21_udp_peer.py"
result = dict(status="HOLD", source_sha256=b["source_sha256"], build=str(a.build.resolve()),
              build_sha256=digest(a.build), generation=generation, profile="root",
              source="NFQ_CAPTURED", started_ns=time.time_ns(), snapshots=[], clients=[])
for path in [Path(__file__), peer]: (out/path.name).write_bytes(path.read_bytes())

def save(name, text): (out/name).write_text(text); return text
def command(*args, check=True):
    r = subprocess.run(list(map(str, args)), env=env, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, timeout=30)
    if check and r.returncode: raise RuntimeError(r.stdout)
    return r.stdout
def cli(name, text): return save(name+".txt", command(vppctl, "-s", runtime/"cli.sock", text))
def api(name, op, *values):
    return save(name+".txt", command(artifact/"bin/sakamoto-product-core-host", op,
                                    runtime/"api.sock", generation, *values))
def read_line(process, deadline=10):
    # unbuffered binary pipes avoid select hiding already-buffered lines.
    end = time.monotonic()+deadline; data = bytearray()
    while time.monotonic() < end:
        assert process.poll() is None, "child exited"
        if select.select([process.stdout], [], [], .1)[0]:
            char = os.read(process.stdout.fileno(), 1)
            assert char
            if char == b"\n": return data.decode()
            data.extend(char)
    raise RuntimeError("child output deadline: "+data.decode())
def observer_command(text):
    observer.stdin.write((text+"\n").encode()); observer.stdin.flush()
    return read_line(observer)
def snapshot(label):
    text = observer_command("query")
    assert text.startswith("observation.response="), text
    state = json.loads(text.split("=", 1)[1])
    assert "error" not in state, state
    save(label+".json", json.dumps(state, indent=2)+"\n")
    result["snapshots"].append(label)
    return state
def wait_snapshot(label, predicate):
    end = time.monotonic()+8
    while time.monotonic() < end:
        state = snapshot(label)
        if predicate(state): return state
        time.sleep(.03)
    raise RuntimeError("observation deadline "+label)
def normal(state): return [state["health"]["channels"][i] for i in (0,2)]
def records(state): return [r for r in state["consumer"]["overview"]["records"] if r]
def one_flow(state, source_port):
    return next(r for r in records(state) if r["ports"][0] == source_port and not r["ended"])
def send(count, size):
    client.stdin.write(f"{count} {size}\n".encode()); client.stdin.flush()
    row = json.loads(read_line(client))
    result["clients"].append(row); return row
def start_peer(mode, host, **kwargs):
    arguments = ["python3", "-u", str(peer), mode, "--host", host]
    for key,value in kwargs.items(): arguments += ["--"+key.replace("_", "-"), str(value)]
    return subprocess.Popen(arguments, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, bufsize=0, user=12001 if mode != "server" else 12002,
                            group=12001 if mode != "server" else 12002, extra_groups=[])

process = observer = client = server = capture = None
hooks = []
try:
    assert os.getuid() == 0
    save("environment.txt", command("uname", "-a")+command("id")+
         "netns="+os.readlink("/proc/self/ns/net")+"\n")
    command("ip", "link", "set", "lo", "up")
    command("ip", "link", "add", "t21dummy", "type", "dummy")
    command("ip", "addr", "add", "10.221.0.1/24", "dev", "t21dummy")
    command("ip", "addr", "add", "10.221.0.2/24", "dev", "t21dummy")
    command("ip", "link", "set", "t21dummy", "up")
    launch = dict(env, PRODUCT_ARTIFACT_DIR=str(artifact), PRODUCT_RUNTIME_DIR=str(runtime),
                  PRODUCT_RULE_CONFIG_DIR=str(out/"configuration"), PRODUCT_GENERATION=str(generation),
                  PRODUCT_WORKER_COUNT="2", SAKAMOTO_RUNTIME_PROFILE="root",
                  SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID="0", SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES="4",
                  SAKAMOTO_LINUX_NETWORK_SOURCE="external")
    log = (out/"vpp.log").open("w")
    process = subprocess.Popen(["bash", str(ROOT/"tools/product/run-host-vpp.sh")], env=launch,
                               stdout=log, stderr=subprocess.STDOUT)
    end = time.monotonic()+20
    while not (runtime/"api.sock.obs").exists():
        assert process.poll() is None, (out/"vpp.log").read_text()
        assert time.monotonic() < end, "observation listener absent"
        time.sleep(.05)
    cli("startup", "show product observation")
    # A same-UID peer that never offers descriptors must not monopolize the
    # unclaimed generation. This exercises the actual VPP main-thread deadline.
    silent = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    silent.connect(str(runtime/"api.sock.obs"))
    silent.settimeout(4)
    pending_start = time.monotonic()
    assert silent.recv(1) == b""
    elapsed = time.monotonic()-pending_start
    assert 1 <= elapsed < 4, elapsed
    silent.close()
    save("pending-timeout.json", json.dumps(dict(elapsed=elapsed, eof=True))+"\n")
    unclaimed = api("unclaimed-query", "observation-query")
    assert '"connected":0' in unclaimed.replace(" ", "")
    cli("trace", "product packet-trace limit 4096")
    observer = subprocess.Popen([str(artifact/"bin/sakamoto-product-core-host"), "observation-serve",
        str(runtime/"api.sock"), str(generation)], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=(out/"rust-stderr.log").open("w"), bufsize=0)
    while not read_line(observer).startswith("observation.ready="): pass
    baseline = snapshot("baseline")
    assert sum(c["basic_packets"][0] for c in normal(baseline)) == 0
    for flag in ["--dport", "--sport"]:
        hook = ["iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "udp", flag, "42121",
                "-j", "NFQUEUE", "--queue-num", "176"]
        command(*hook); hooks.append(hook)
    server = start_peer("server", "10.221.0.2")
    assert json.loads(read_line(server))["kind"] == "ready"
    # Drain the endpoint log independently, without blocking its echo loop.
    import threading
    def endpoint_log():
        with (out/"endpoint.jsonl").open("wb") as f:
            while True:
                data = server.stdout.read(65536)
                if not data: break
                f.write(data); f.flush()
    threading.Thread(target=endpoint_log, daemon=True).start()
    client = start_peer("client", "10.221.0.1", peer="10.221.0.2", source_port=42122)
    send(1, 32)
    before = cli("before-flush-flows", "show product flows")
    time.sleep(1.3)
    quiet = wait_snapshot("quiet-flush", lambda s: s["consumer"]["overview"]["packets"] == [1,1])
    after = cli("after-flush-flows", "show product flows")
    flow = one_flow(quiet, 42122)
    assert flow["bytes"] == [60,60]
    assert flow["addresses"] == [10,221,0,1,10,221,0,2]
    assert sum(c["basic_packets"][0] for c in normal(quiet)) == 2
    assert sum(c["basic_bytes"][0] for c in normal(quiet)) == 120
    assert [l for l in before.splitlines() if l.startswith("flow.timer ")] == [l for l in after.splitlines() if l.startswith("flow.timer ")]
    send(3, 40)
    cli("close-tail", f"product flow-end close owner {flow['owner']} slot {flow['slot']} generation {generation} incarnation {flow['incarnation']}")
    ended = wait_snapshot("end-tail", lambda s: s["consumer"]["overview"]["ended"] == 1)
    assert ended["consumer"]["overview"]["packets"] == [4,4]
    assert ended["consumer"]["overview"]["bytes"] == [264,264]
    send(1, 32)
    reused = wait_snapshot("tuple-reuse", lambda s: any(not r["ended"] and r["incarnation"] > flow["incarnation"] for r in records(s)))
    assert one_flow(reused, 42122)["incarnation"] > flow["incarnation"]
    assert observer_command("pause") == "observation.paused=true"
    paused = snapshot("paused")
    burst = subprocess.run(["python3", str(peer), "burst", "--host", "10.221.0.1", "--peer", "10.221.0.2",
        "--source-port", "43000", "--count", "2400", "--size", "32"], env=env,
        user=12001, group=12001, extra_groups=[], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=120)
    save("burst.jsonl", burst.stdout); save("burst.stderr", burst.stderr)
    assert burst.returncode == 0, burst.stderr
    assert len(burst.stdout.splitlines()) == 2400
    time.sleep(1.3)
    full = snapshot("full")
    assert sum(c["full"] for c in normal(full)) > 0
    assert full["consumer"]["overview"]["accepted"] == paused["consumer"]["overview"]["accepted"]
    assert sum(c["basic_packets"][0] for c in normal(full)) == 4810
    assert sum(c["basic_bytes"][0] for c in normal(full)) == 288648
    assert all(full["health"]["channels"][i]["attempted"] == 0 for i in (1,3))
    cli("capacity-flows", "show product flows")
    assert observer_command("resume") == "observation.paused=false"
    resumed = wait_snapshot("resumed", lambda s: all(c["occupancy"] == 0 for c in normal(s)))
    assert resumed["consumer"]["overview"]["incomplete"]
    observer.kill(); observer.wait(timeout=5); observer = None
    send(1, 32)
    time.sleep(.1)
    health_text = api("consumer-dead", "observation-query")
    health = json.loads(next(l.split("=",1)[1] for l in health_text.splitlines() if l.startswith("observation.response=")))
    assert health["health"]["connected"] == 0
    assert sum(c["basic_packets"][0] for c in normal(health)) == 4812
    # Force real primary-handoff admission bypass. Both local and remote
    # owners must retain basic IP accounting despite no consumer remaining.
    import re
    primary_before = cli("bypass-before", "show product primary")
    assert "capacity.configured" in cli("bypass-on", "product capacity credits 0 primary-slots 64 completion-slots 128")
    bypass = subprocess.run(["python3", str(peer), "burst", "--host", "10.221.0.1", "--peer", "10.221.0.2",
        "--source-port", "46000", "--count", "32", "--size", "32"], env=env,
        user=12001, group=12001, extra_groups=[], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=30)
    save("bypass.jsonl", bypass.stdout); save("bypass.stderr", bypass.stderr)
    assert bypass.returncode == 0 and len(bypass.stdout.splitlines()) == 32
    primary_after = cli("bypass-after", "show product primary")
    def rejected(text): return int(re.search(r"primary.status [^\n]*rejected=(\d+)", text)[1])
    assert rejected(primary_after) > rejected(primary_before)
    bypass_text = api("bypass-health", "observation-query")
    bypass_health = json.loads(next(l.split("=",1)[1] for l in bypass_text.splitlines() if l.startswith("observation.response=")))
    assert sum(c["basic_packets"][0] for c in normal(bypass_health)) == 4876
    assert sum(c["basic_bytes"][0] for c in normal(bypass_health)) == 292608
    assert "capacity.configured" in cli("bypass-off", "product capacity off")
    cli("before-stop", "show product observation")
    result["status"] = "RAW_COMPLETE"
finally:
    for hook in hooks:
        hook[3] = "-D"; command(*hook, check=False)
    for child in [client, server, observer]:
        if child is not None and child.poll() is None:
            child.terminate()
            try: child.wait(timeout=5)
            except subprocess.TimeoutExpired: child.kill(); child.wait()
    if process is not None and process.poll() is None:
        try: cli("stop", "product root stop")
        finally:
            process.terminate()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
    result["completed_ns"] = time.time_ns()
    result["process_absent"] = process is None or not Path(f"/proc/{process.pid}").exists()
    result["files"] = {str(f.relative_to(out)):digest(f) for f in out.rglob("*") if f.is_file()}
    (out/"result.json").write_text(json.dumps(result, indent=2)+"\n")
print(json.dumps({k:result[k] for k in ("status", "source_sha256", "generation", "process_absent")}, indent=2))
