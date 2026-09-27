#!/usr/bin/env python3
"""Real Linux rule rename/revision/deletion and historical Query evidence."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import sqlite3
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser()
p.add_argument("--build", type=Path, required=True)
p.add_argument("--stage", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
out = a.output.resolve(); out.mkdir(parents=True, exist_ok=False)
build = json.loads(a.build.read_text()); artifact = Path(build["artifact"])
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
for name, value in build["artifact_hashes"].items(): assert digest(artifact/name) == value, name
env = dict(os.environ, LD_LIBRARY_PATH=str(artifact/"lib"))
tag = hashlib.sha256(str(out).encode()).hexdigest()[:7]
core = artifact/"bin/sakamoto-product-core-host"
vppctl = a.stage.resolve()/"source/build-root/install-vpp-native/vpp/bin/vppctl"
peer = ROOT/"tests/device/helpers/t23_udp_peer.py"
spec = importlib.util.spec_from_file_location("requests", ROOT/"tests/device/helpers/t23_policy.py")
requests = importlib.util.module_from_spec(spec); spec.loader.exec_module(requests)
store = out/"observation/overall.json"
result = dict(status="HOLD", kind="linux", profile="root", source="NFQ_CAPTURED", task="T26",
    build=str(a.build.resolve()), build_sha256=digest(a.build), source_sha256=build["source_sha256"],
    started_ns=time.time_ns(), lifetimes=[], configurations=[], phases=[], snapshots=[])
for path in (Path(__file__), peer, ROOT/"tests/device/helpers/t23_policy.py"):
    (out/path.name).write_bytes(path.read_bytes())
def save(name, value):
    (out/name).write_text(value if isinstance(value, str) else json.dumps(value, indent=2)+"\n")
    return value

def command(*args, check=True, timeout=40):
    r = subprocess.run(list(map(str, args)), env=env, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=timeout)
    if check and r.returncode: raise RuntimeError(r.stdout)
    return r.stdout

buffers = {}
def line(child, timeout=180):
    until = time.monotonic()+timeout; data = buffers.pop(child.pid, b"")
    while time.monotonic() < until:
        if b"\n" in data:
            answer, remainder = data.split(b"\n", 1); buffers[child.pid] = remainder
            return answer.decode()
        if select.select([child.stdout], [], [], .05)[0]:
            block = os.read(child.stdout.fileno(), 65536)
            if not block: raise RuntimeError("child closed: "+data.decode())
            data += block
    raise RuntimeError("child deadline")

def cli(label, text): return save(label+".txt", command(vppctl, "-s", runtime/"cli.sock", text))
def control(text):
    observer.stdin.write((text+"\n").encode()); observer.stdin.flush(); return line(observer)
def query(label):
    text = control("query"); assert text.startswith("observation.response="), text
    value = json.loads(text.split("=", 1)[1]); assert "error" not in value
    assert value["health"]["generation"] == generation
    save(label+".json", value)
    result["snapshots"].append(dict(label=label, generation=generation))
    return value

def settle(label):
    until = time.monotonic()+10
    while True:
        value = query(label); q = value["consumer"]["persistent"]
        channels = value["health"]["channels"]
        # No interpolation from basic counters: a lossy stream can have an
        # unobserved tail. The caller supplies a later real packet when needed.
        if (not any(c["occupancy"] for c in channels) and q and not q["persistence"]["pending"]
            and not q["persistence"]["maintenance_pending"]): return value
        assert time.monotonic() < until, (label, value["consumer"]["store_error"])
        time.sleep(.03)

def configuration(label, actions=(1, 1), empty=False, condition=False):
    global policy
    document = requests.empty() if empty else requests.document(label, policy, [12001, 12002], actions, (0, 0))
    if condition:
        fields = document["rules"][0]["definition"].split()
        assert fields[10] == "*"
        fields[10] = "10.225.0.1/32"
        fields[11] = "0.0.0.0/0"
        document["rules"][0]["definition"] = " ".join(fields)
    path = out/(label+"-input.json"); save(path.name, document)
    text = save(label+"-apply.txt", command(core, "rule-import", runtime/"api.sock", generation,
        policy.get("saved_revision", 0), path))
    policy = json.loads(next(l.split("=", 1)[1] for l in text.splitlines() if l.startswith("import.response=")))
    assert policy["result"] == 0 and policy["active_revision"] == policy["saved_revision"]
    index = cli(label+"-index", "show product policy-index")
    identity = dict(part.split("=", 1) for part in next(l for l in index.splitlines() if l.startswith("policy.index ")).split()[1:])
    row = dict(label=label, generation=generation, input=path.name, response=label+"-apply.txt",
        revision=policy["active_revision"], snapshot_hash=int(identity["hash"]),
        versions=policy["active_versions"], actions=list(actions), condition_changed=condition, empty=empty)
    result["configurations"].append(row)
    return row

def proc(pid):
    root = Path("/proc")/str(pid)
    def fields(text): return {l.split(":",1)[0]:l.split(":",1)[1].strip() for l in text.splitlines() if ":" in l}
    stat = (root/"stat").read_text().rsplit(")",1)[1].split()
    threads = {}
    for task in (root/"task").iterdir():
        try:
            ts = (task/"stat").read_text().rsplit(")",1)[1].split(); status = fields((task/"status").read_text())
            threads[task.name] = dict(name=status["Name"], cpu_ticks=int(ts[11])+int(ts[12]),
                voluntary=int(status["voluntary_ctxt_switches"]), involuntary=int(status["nonvoluntary_ctxt_switches"]))
        except FileNotFoundError: pass
    return dict(pid=pid, cpu_ticks=int(stat[11])+int(stat[12]), status=fields((root/"status").read_text()),
        io=fields((root/"io").read_text()), threads=threads, at_mono_ns=time.monotonic_ns())
def resources(): return dict(vpp=proc(process.pid), rust=proc(observer.pid), ticks_per_second=os.sysconf("SC_CLK_TCK"))
def send(label, count, size=64, sockets=1, short=False, delay=0, settled=True):
    before = resources()
    request = dict(label=label, count=count, size=size, sockets=sockets, short=short, delayMs=delay,
                   nonce="t26-"+tag+"-"+label+"-"+str(time.time_ns()))
    client.stdin.write((json.dumps(request)+"\n").encode()); client.stdin.flush()
    traffic = json.loads(line(client)); assert traffic["label"] == label and traffic["sent"] == count
    save(label+"-traffic.json", traffic)
    if settled:
        time.sleep(1.1)
        snapshot = settle(label)
    else: snapshot = query(label)
    row = dict(label=label, generation=generation, uid=client_uid,
        configuration=result["configurations"][-1]["label"], traffic=label+"-traffic.json",
        before=before, after=resources(), snapshot=label+".json", request=request)
    result["phases"].append(row)
    return snapshot

def stop(child):
    if child is not None and child.poll() is None:
        child.terminate()
        try: child.wait(timeout=8)
        except subprocess.TimeoutExpired: child.kill(); child.wait()
def start_client(uid):
    global client, client_uid
    stop(client); client_uid = uid
    client = subprocess.Popen(["python3", "-u", str(peer), "client", "--host", "10.225.0.1", "--peer", "10.225.0.2"],
        env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=(out/f"client-{uid}.log").open("a"),
        user=uid, group=uid, extra_groups=[], bufsize=0)
    assert json.loads(line(client))["ready"]
def start(number):
    global generation, runtime, process, observer, policy
    generation = number; runtime = ROOT/("build-output/product-vpp-runtime-t26-"+tag+"-"+str(number))
    launch = dict(env, PRODUCT_ARTIFACT_DIR=str(artifact), PRODUCT_RUNTIME_DIR=str(runtime),
        PRODUCT_RULE_CONFIG_DIR=str(out/"configuration"), PRODUCT_GENERATION=str(generation),
        PRODUCT_WORKER_COUNT="2", SAKAMOTO_RUNTIME_PROFILE="root", SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID="0",
        SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES="4", SAKAMOTO_LINUX_NETWORK_SOURCE="external")
    process = subprocess.Popen(["bash", str(ROOT/"tools/product/run-host-vpp.sh")], env=launch,
        stdout=(out/f"vpp-{generation}.log").open("w"), stderr=subprocess.STDOUT)
    until = time.monotonic()+30
    while not (runtime/"api.sock.obs").exists():
        assert process.poll() is None and time.monotonic()<until, "VPP startup"; time.sleep(.05)
    cli(f"g{generation}-startup", "product packet-trace limit 4096")
    text = save(f"g{generation}-configuration.txt", command(core,"rule-export",runtime/"api.sock",generation))
    policy = json.loads(next(l.split("=",1)[1] for l in text.splitlines() if l.startswith("import.response=")))
    observer = subprocess.Popen([str(core), "observation-serve", str(runtime/"api.sock"), str(generation), str(store)],
        env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=(out/f"rust-{generation}.log").open("w"), bufsize=0)
    while not line(observer).startswith("observation.ready="): pass
    result["lifetimes"].append(dict(generation=generation, pid=process.pid, consumer_pid=observer.pid))
def stop_runtime():
    global process, observer
    if observer is not None and observer.poll() is None:
        observer.stdin.write(b"quit\n"); observer.stdin.flush(); observer.wait(timeout=10)
    observer = None
    if process is not None and process.poll() is None:
        cli(f"g{generation}-stop", "product root stop"); stop(process)
    result["lifetimes"][-1]["process_absent"] = not Path(f"/proc/{process.pid}").exists()
    process = None

def flow(snapshot):
    matches = [r for r in snapshot["consumer"]["overview"]["records"] if r and r["ports"][0]==43500 and not r["ended"]]
    assert len(matches)==1, "one persistent socket Flow"; return matches[0]

process = observer = client = server = capture = None
hooks = []; client_uid = 12001; generation = 0; runtime = None
try:
    assert os.getuid()==0
    host_netns = os.environ["T26_HOST_NETNS"]
    assert os.readlink("/proc/self/ns/net") != host_netns
    links = json.loads(command("ip","-j","link","show")); assert [l["ifname"] for l in links]==["lo"]
    save("environment.txt", command("uname","-a")+command("id")+"netns="+os.readlink("/proc/self/ns/net")+"\n")
    command("ip","link","set","lo","up"); command("ip","link","add","t26dummy","type","dummy")
    for address in ("10.225.0.1/24","10.225.0.2/24"): command("ip","addr","add",address,"dev","t26dummy")
    command("ip","link","set","t26dummy","up")
    store.parent.mkdir()
    server = subprocess.Popen(["python3","-u",str(peer),"server","--host","10.225.0.2"],
        stdout=(out/"endpoint.jsonl").open("w"),stderr=(out/"server.log").open("w"),user=12002,group=12002,extra_groups=[])
    time.sleep(.15); assert server.poll() is None
    capture = subprocess.Popen(["tcpdump","-U","-i","any","-s","0","-w",str(out/"wire.pcap"),"udp port 42151"],
        stdout=(out/"capture.log").open("w"),stderr=subprocess.STDOUT)
    start(27801)
    query("baseline")
    for flag in ("--sport","--dport"):
        hook=["iptables","-t","mangle","-A","OUTPUT","-p","udp",flag,"42151","-j","NFQUEUE","--queue-num","176"]
        command(*hook); hooks.append(hook)
    start_client(12001)
    for label, count in (("original", 2), ("renamed", 2)):
        config=configuration(label)
        observed=send(label,count)
        assert observed["consumer"]["persistent"]["history_source"]["status"] == "available"
        matched=flow(observed)
        cli(label+"-close",f"product flow-end close owner {matched['owner']} slot {matched['slot']} generation {generation} incarnation {matched['incarnation']}")
        settle(label+"-ended")
    original, renamed = result["configurations"][:2]
    assert original["versions"][0] != renamed["versions"][0]
    assert int(original["versions"][0]) >> 16 == int(renamed["versions"][0]) >> 16
    configuration("condition", actions=(2,1), condition=True)
    dropped=send("condition",2)
    assert json.loads((out/"condition-traffic.json").read_text())["received"] == 0
    assert sum(channel["basic_packets"][1] for channel in dropped["health"]["channels"]) >= 2
    assert any(row["attribution"]["name"]=="condition-request"
               and row["attribution"]["actual_action"]==2
               and row["counts"]["packets"][0]==2
               for row in dropped["consumer"]["persistent"]["rule_windows"].values())
    configuration("deleted", empty=True)
    deleted=send("deleted",1)
    assert deleted["consumer"]["persistent"]["history_source"]["status"] == "unavailable"
    before=deleted["consumer"]["persistent"]
    stop_runtime(); start(27802)
    restarted=settle("restarted")
    after=restarted["consumer"]["persistent"]
    for field in ("packets","bytes","rule_windows"):
        assert after[field] == before[field], field
    assert after["history_source"]["status"] == "unavailable"
    result["history_reopened"] = True
    cli("final-flows","show product flows"); cli("final-completion","show product completion")
    stop_runtime(); result["status"]="RAW_COMPLETE"
except Exception as error:
    result["error"]=repr(error); raise
finally:
    for hook in hooks:
        hook[3]="-D"; command(*hook,check=False)
    stop(client);stop(server)
    if observer is not None: stop(observer)
    if process is not None and process.poll() is None:
        try: cli("cleanup-stop","product root stop")
        finally: stop(process)
    if capture is not None and capture.poll() is None:
        capture.send_signal(signal.SIGINT);capture.wait(timeout=10)
    command("ip","link","del","t26dummy",check=False)
    save("final-hooks.txt",command("iptables-save",check=False))
    if store.with_suffix(".sqlite3").is_file():
        db=sqlite3.connect(store.with_suffix(".sqlite3"));save("final-database.json",dict(integrity=db.execute("PRAGMA integrity_check").fetchone()[0],rows=db.execute("SELECT kind,count(*) FROM observation GROUP BY kind").fetchall()));db.close()
    result["completed_ns"]=time.time_ns()
    result["files"]={str(f.relative_to(out)):digest(f) for f in out.rglob("*") if f.is_file()}
    save("result.json",result)
print(json.dumps({k:result[k] for k in ("status","kind","history_reopened","lifetimes")},indent=2))
