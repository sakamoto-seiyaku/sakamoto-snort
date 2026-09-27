#!/usr/bin/env python3
"""Real NFQUEUE/VPP PRE DROP, independent B/F identity, idle and pressure evidence."""
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
digest = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
for name, wanted in build["artifact_hashes"].items():
    assert digest(artifact / name) == wanted, name
env = dict(os.environ, LD_LIBRARY_PATH=str(artifact / "lib"))
tag = hashlib.sha256(str(out).encode()).hexdigest()[:7]
runtime = ROOT / ("build-output/product-vpp-runtime-t24-" + tag)
generation = 27601
core = artifact / "bin/sakamoto-product-core-host"
vppctl = a.stage.resolve() / "source/build-root/install-vpp-native/vpp/bin/vppctl"
peer = ROOT / "tests/device/helpers/t23_udp_peer.py"
spec = importlib.util.spec_from_file_location("requests", ROOT / "tests/device/helpers/t23_policy.py")
requests = importlib.util.module_from_spec(spec); spec.loader.exec_module(requests)
store = out / "observation/overall.json"
result = dict(status="HOLD", profile="root", source="NFQ_CAPTURED", generation=generation,
    source_sha256=build["source_sha256"], build=str(a.build.resolve()), build_sha256=digest(a.build),
    started_ns=time.time_ns(), phases=[], configurations=[], snapshots=[])
for path in (Path(__file__), peer, ROOT / "tests/device/helpers/t23_policy.py"):
    (out / path.name).write_bytes(path.read_bytes())

def save(name, value):
    (out / name).write_text(value if isinstance(value, str) else json.dumps(value, indent=2)+"\n")
    return value
def command(*args, check=True, timeout=45, uid=None):
    kwargs = {} if uid is None else dict(user=uid, group=uid, extra_groups=[])
    r = subprocess.run(list(map(str, args)), env=env, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=timeout, **kwargs)
    if check and r.returncode: raise RuntimeError(r.stdout)
    return r.stdout
def line(child, timeout=30):
    data = bytearray(); until = time.monotonic()+timeout
    while time.monotonic() < until:
        assert child.poll() is None, "child exited: "+data.decode()
        if select.select([child.stdout], [], [], .1)[0]:
            char = os.read(child.stdout.fileno(), 1)
            if char == b"\n": return data.decode()
            assert char
            data.extend(char)
    raise RuntimeError("child deadline: "+data.decode())
def cli(label, text):
    return save(label+".txt", command(vppctl, "-s", runtime / "cli.sock", text))
def control(text):
    observer.stdin.write((text+"\n").encode()); observer.stdin.flush(); return line(observer)
def query(label):
    response = control("query")
    assert response.startswith("observation.response="), response
    value = json.loads(response.split("=", 1)[1])
    assert value["health"]["generation"] == generation
    assert value["consumer"]["query_fresh"] is True
    save(label+".json", value); result["snapshots"].append(label)
    return value
def settled(label):
    until = time.monotonic()+(90 if label == "pressure" else 12)
    while True:
        value = query(label)
        if (not any(c["occupancy"] for c in value["health"]["channels"])
            and not value["consumer"]["persistent"]["persistence"]["pending"]):
            return value
        assert time.monotonic()<until, label
        time.sleep(.2 if label == "pressure" else .05)
def configure(label, drop):
    global policy
    if drop:
        doc = requests.document(label, policy, [12001], actions=(2,1), modes=(0,0))
        # T23's 0e01 expression means Flow ORIG and therefore compiles POST.
        # A device OUTPUT predicate is complete before Flow creation.
        doc["rules"] = doc["rules"][:1]
        doc["rules"][0]["definition"] = doc["rules"][0]["definition"].removesuffix("0e01") + "0603"
        doc["rules"][0]["source"] = "t24-pre-drop"
        doc["bindings"] = [b for b in doc["bindings"] if b[3] == 0]
    else:
        doc = requests.empty()
    save(label+"-input.json", doc)
    text = save(label+"-apply.txt", command(core, "rule-import", runtime / "api.sock",
        generation, policy.get("saved_revision", 0), out / (label+"-input.json")))
    policy = json.loads(next(row.split("=",1)[1] for row in text.splitlines() if row.startswith("import.response=")))
    assert policy["result"] == 0 and policy["active_revision"] == policy["saved_revision"]
    result["configurations"].append(dict(label=label, revision=policy["active_revision"],
        versions=policy["active_versions"], drop=drop))
def send(label, count):
    request = dict(label=label, count=count, size=56,
        nonce="t24-"+tag+"-"+label+"-"+str(time.time_ns()))
    client.stdin.write((json.dumps(request)+"\n").encode()); client.stdin.flush()
    traffic = json.loads(line(client, timeout=max(30,count)))
    assert traffic["sent"] == count
    save(label+"-traffic.json", traffic)
    time.sleep(1.15)
    value = settled(label)
    result["phases"].append(dict(label=label, sent=count, received=traffic["received"],
        configuration=result["configurations"][-1]["label"], traffic=label+"-traffic.json",
        snapshot=label+".json"))
    return value
def records(value, blocked, port=43500):
    field = "blocked_records" if blocked else "records"
    return [r for r in value["consumer"]["overview"][field] if r and r["ports"][0] == port]
def basic(value, outcome):
    return sum(value["health"]["channels"][i]["basic_packets"][outcome] for i in (0,2))
def proc(pid):
    root = Path("/proc") / str(pid)
    stat = (root / "stat").read_text().rsplit(")",1)[1].split()
    status = dict(line.split(":",1) for line in (root / "status").read_text().splitlines() if ":" in line)
    io = dict(line.split(":",1) for line in (root / "io").read_text().splitlines() if ":" in line)
    return dict(pid=pid, cpu_ticks=int(stat[11])+int(stat[12]),
        rss_kib=int(status["VmRSS"].split()[0]), hwm_kib=int(status["VmHWM"].split()[0]),
        write_bytes=int(io["write_bytes"].strip()), read_bytes=int(io["read_bytes"].strip()),
        at_ns=time.monotonic_ns())
def resources():
    return dict(vpp=proc(process.pid), rust=proc(observer.pid), ticks_per_second=os.sysconf("SC_CLK_TCK"))
def fire(label, count, first_port, sockets, pause_ms=0):
    # Independent unprivileged packet sender: one record per real send, no
    # observation API access and no echo wait on policy drops.
    code = """import json,socket,sys,time
host='10.225.0.1'; target=('10.225.0.2',42151)
count=int(sys.argv[1]); first=int(sys.argv[2]); n=int(sys.argv[3]); delay=int(sys.argv[4])
opened=[]
if n!=count:
 for i in range(n):
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind((host,first+i)); opened.append(s)
start=time.monotonic_ns()
for i in range(count):
 if n==count:
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind((host,first+i))
 else:s=opened[i%n]
 s.sendto((i.to_bytes(4,'big')+b'T24'+b'x'*49),target)
 if n==count:s.close()
 if delay: time.sleep(delay/1000)
print(json.dumps({'sent':count,'firstPort':first,'sockets':n,'startMonoNs':start,'endMonoNs':time.monotonic_ns()}))
for s in opened:s.close()
"""
    before = resources()
    info = json.loads(command("python3", "-c", code, count, first_port, sockets, pause_ms,
                              uid=12001, timeout=max(45, count*pause_ms/1000+20)))
    save(label+"-traffic.json", info)
    time.sleep(1.2)
    value = settled(label)
    result["phases"].append(dict(label=label, sent=count, configuration=result["configurations"][-1]["label"],
        traffic=label+"-traffic.json", snapshot=label+".json", before=before, after=resources()))
    return value
def stop(child):
    if child is not None and child.poll() is None:
        child.terminate()
        try: child.wait(timeout=8)
        except subprocess.TimeoutExpired: child.kill(); child.wait()

process = observer = client = server = capture = None
hooks = []
try:
    assert os.getuid() == 0
    assert os.readlink("/proc/self/ns/net") != os.environ["T24_HOST_NETNS"]
    save("environment.txt", command("uname", "-a")+command("id")+
        "netns="+os.readlink("/proc/self/ns/net")+"\n")
    command("ip", "link", "set", "lo", "up")
    command("ip", "link", "add", "t24dummy", "type", "dummy")
    for address in ("10.225.0.1/24", "10.225.0.2/24"):
        command("ip", "addr", "add", address, "dev", "t24dummy")
    command("ip", "link", "set", "t24dummy", "up")
    store.parent.mkdir()
    server = subprocess.Popen(["python3", "-u", str(peer), "server", "--host", "10.225.0.2"],
        stdout=(out/"endpoint.jsonl").open("w"), stderr=(out/"server.log").open("w"),
        user=12002, group=12002, extra_groups=[])
    time.sleep(.15); assert server.poll() is None
    capture = subprocess.Popen(["tcpdump", "-U", "-i", "any", "-s", "0", "-w", str(out/"wire.pcap"), "udp port 42151"],
        stdout=(out/"capture.log").open("w"), stderr=subprocess.STDOUT)
    launch = dict(env, PRODUCT_ARTIFACT_DIR=str(artifact), PRODUCT_RUNTIME_DIR=str(runtime),
        PRODUCT_RULE_CONFIG_DIR=str(out/"configuration"), PRODUCT_GENERATION=str(generation),
        PRODUCT_WORKER_COUNT="2", SAKAMOTO_RUNTIME_PROFILE="root", SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID="0",
        SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES="4", SAKAMOTO_LINUX_NETWORK_SOURCE="external")
    process = subprocess.Popen(["bash", str(ROOT/"tools/product/run-host-vpp.sh")], env=launch,
        stdout=(out/"vpp.log").open("w"), stderr=subprocess.STDOUT)
    until = time.monotonic()+30
    while not (runtime/"api.sock.obs").exists():
        assert process.poll() is None and time.monotonic()<until, "VPP startup"
        time.sleep(.05)
    cli("startup", "product packet-trace limit 4096")
    text = save("initial-configuration.txt", command(core,"rule-export",runtime/"api.sock",generation))
    policy = json.loads(next(row.split("=",1)[1] for row in text.splitlines() if row.startswith("import.response=")))
    observer = subprocess.Popen([str(core),"observation-serve",str(runtime/"api.sock"),str(generation),str(store)],
        env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=(out/"rust.log").open("w"), bufsize=0)
    while not line(observer).startswith("observation.ready="): pass
    for flag in ("--sport", "--dport"):
        hook=["iptables","-t","mangle","-A","OUTPUT","-p","udp",flag,"42151","-j","NFQUEUE","--queue-num","176"]
        command(*hook); hooks.append(hook)
    client = subprocess.Popen(["python3","-u",str(peer),"client","--host","10.225.0.1","--peer","10.225.0.2"],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(out/"client.log").open("w"),
        user=12001,group=12001,extra_groups=[],bufsize=0)
    assert json.loads(line(client))["ready"]
    baseline = settled("baseline")
    configure("allow-a", False)
    allowed = send("allow-a", 2)
    assert result["phases"][-1]["received"] == 2
    flow = records(allowed, False)[0]
    flow_identity = (flow["owner"],flow["slot"],flow["incarnation"])
    flow_packets = flow["packets"]
    configure("drop-a", True)
    first = send("drop-a", 3)
    assert result["phases"][-1]["received"] == 0
    b = records(first, True)[0]
    blocked_identity = (b["owner"],b["slot"],b["incarnation"])
    assert b["packets"] == [3,0] and b["attribution"][0]["actual_action"] == 2
    assert (records(first,False)[0]["owner"],records(first,False)[0]["slot"],records(first,False)[0]["incarnation"]) == flow_identity
    assert records(first,False)[0]["packets"] == flow_packets
    assert basic(first,1)-basic(allowed,1) == 3
    configure("allow-b", False)
    middle = send("allow-b", 2)
    assert result["phases"][-1]["received"] == 2
    assert (records(middle,True)[0]["owner"],records(middle,True)[0]["slot"],records(middle,True)[0]["incarnation"]) == blocked_identity
    assert records(middle,True)[0]["packets"] == [3,0]
    assert records(middle,False)[0]["packets"][0] >= flow_packets[0]+2
    configure("drop-b", True)
    second = send("drop-b", 2)
    assert result["phases"][-1]["received"] == 0
    b2 = records(second,True)[0]
    assert (b2["owner"],b2["slot"],b2["incarnation"]) == blocked_identity
    assert b2["packets"] == [5,0] and b2["attribution"][0]["winner"] != b["attribution"][0]["winner"]
    assert records(second,False)[0]["packets"] == records(middle,False)[0]["packets"]
    assert second["consumer"]["persistent"]["blocked"]["packets"][0] == 5
    assert sum(v["counts"]["packets"][0] for v in second["consumer"]["persistent"]["rule_windows"].values()
               if v["attribution"]["actual_action"] == 2) == 5
    # One burst on a single tuple checks growth coalescing and maintained
    # effect totals against independent basic/drop counts.
    growth = send("growth", 35)
    assert records(growth,True)[0]["packets"] == [40,0]
    assert growth["consumer"]["persistent"]["blocked"]["packets"][0] == 40
    assert basic(growth,1)-basic(second,1) == 35
    # Quiet retirement uses the last actual packet time. There is no FIN/RST.
    time.sleep(31)
    retired = settled("idle-retired")
    assert records(retired,True)[0]["ended"] is True
    assert retired["health"]["blocked_active"] == [0,0]
    assert sum(retired["health"]["blocked_retired"]) >= 1
    again = send("tuple-reuse",1)
    b3 = records(again,True)[0]
    assert b3["incarnation"] > b2["incarnation"] and b3["sequence"] == 1
    assert b3["packets"] == [1,0]
    # Thousands of short blocked tuples exceed the bounded B capacity while
    # ordinary basic accounting continues. Pace sends to avoid NFQUEUE loss.
    pressure_before = settled("pressure-before")
    pressure = fire("pressure", 3000, 50000, 3000, 1)
    misses = sum(pressure["health"]["blocked_capacity_misses"])
    basic_delta = basic(pressure,1)-basic(pressure_before,1)
    blocked_delta = (pressure["consumer"]["persistent"]["blocked"]["packets"][0]
        - pressure_before["consumer"]["persistent"]["blocked"]["packets"][0])
    assert misses > 0 and basic_delta > blocked_delta >= 0
    assert pressure["consumer"]["persistent"]["coverage"]["incomplete"] is True
    result["pressure"] = dict(sent=3000, basic_delta=basic_delta, blocked_delta=blocked_delta,
        capacity_misses=misses, blocked_capacity=pressure["health"]["blocked_capacity"])
    cli("final-flows","show product flows")
    cli("final-completion","show product completion")
    result["status"] = "RAW_COMPLETE"
except Exception as error:
    result["error"] = repr(error)
    raise
finally:
    for hook in hooks:
        hook[3]="-D"; command(*hook,check=False)
    stop(client); stop(server)
    if observer is not None and observer.poll() is None:
        observer.stdin.write(b"quit\n"); observer.stdin.flush(); observer.wait(timeout=10)
    if process is not None and process.poll() is None:
        try: cli("stop","product root stop")
        finally: stop(process)
    if capture is not None and capture.poll() is None:
        capture.send_signal(signal.SIGINT); capture.wait(timeout=10)
    command("ip","link","del","t24dummy",check=False)
    save("final-hooks.txt",command("iptables-save",check=False))
    if store.with_suffix(".sqlite3").is_file():
        db=sqlite3.connect(store.with_suffix(".sqlite3"))
        save("final-database.json",dict(integrity=db.execute("PRAGMA integrity_check").fetchone()[0],
             rows=db.execute("SELECT kind,count(*) FROM observation GROUP BY kind").fetchall()))
        db.close()
    result["completed_ns"] = time.time_ns()
    result["files"] = {str(file.relative_to(out)):digest(file) for file in out.rglob("*") if file.is_file()}
    save("result.json",result)
print(json.dumps({k:result[k] for k in ("status","profile","source","pressure")},indent=2))
