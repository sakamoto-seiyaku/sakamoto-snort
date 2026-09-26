#!/usr/bin/env python3
"""T22 actual Android persistent minutes, background ingestion and controlled service recovery."""
import argparse
import hashlib
import ipaddress
import importlib.util
import json
from pathlib import Path
import re
import shlex
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
PKG = "com.sakamoto.snort.androidruntime"
p = argparse.ArgumentParser()
p.add_argument("--serial-from", type=Path, required=True)
p.add_argument("--build", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
p.add_argument("--endpoint", default="192.168.4.5")
p.add_argument("--profile-scope", choices=["both", "root", "vpn"], default="both")
p.add_argument("--flood", type=int, default=100)
a = p.parse_args()
serial = json.loads(a.serial_from.read_text())["serial"]
b = json.loads(a.build.read_text())
out = a.output.resolve(); out.mkdir(parents=True, exist_ok=False)
digest = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
result = dict(status="HOLD", serial=serial, build=str(a.build.resolve()), build_sha256=digest(a.build),
              source_sha256=b["source_sha256"], started_ns=time.time_ns(), lifetimes=[],
              kind="android", snapshots=[], plans=[], endpoint=a.endpoint)
def save(name, text): (out/name).write_text(text); return text
save("runner.py", Path(__file__).read_text())
def adb(*arguments, check=True, timeout=35):
    started = time.time_ns()
    r = subprocess.run([str(ROOT/"dev/adb"), "-s", serial, *map(str, arguments)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
    with (out/"operations.jsonl").open("a") as f:
        f.write(json.dumps(dict(started_ns=started, completed_ns=time.time_ns(), argv=list(map(str,arguments)),
                                code=r.returncode))+"\n")
    if check and r.returncode: raise RuntimeError(r.stdout)
    return r.stdout.replace("\r", "")
def root(command, check=True): return adb("shell", "su", "-c", shlex.quote(command), check=check)
def app(path, check=True): return adb("shell", "run-as", PKG, "cat", path, check=check)
def props(text): return dict(l.split("=",1) for l in text.splitlines() if "=" in l and not l.startswith("#"))
def action(*args): return adb("shell", "am", "start", "-n", PKG+"/.DebugControlActivity", *args)
def wait_state(label, wanted):
    end = time.monotonic()+35
    while time.monotonic() < end:
        text = app("files/runtime-state/snapshot.properties")
        state = props(text); save(label+"-latest.properties", text)
        if state.get("state") == wanted: return state
        if state.get("errorCode") == "root_authorization_required":
            raise RuntimeError("KernelSU Superuser grant must be restored before Root acceptance")
        time.sleep(.2)
    raise RuntimeError("runtime deadline: "+str(state))
def wait_json(path, label, predicate=lambda x: True, timeout=25):
    end = time.monotonic()+timeout
    while time.monotonic() < end:
        text = app(path, check=False)
        try: value = json.loads(text)
        except json.JSONDecodeError: value = None
        if value is not None and predicate(value):
            save(label+".json", text); return value
        time.sleep(.15)
    raise RuntimeError("JSON deadline "+label+": "+text[:300])

spec = importlib.util.spec_from_file_location("t22_target", ROOT/"tests/device/s233-fail-open.py")
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
module.SERIAL = serial
target = object.__new__(module.Target); target.pixel = True
base = None
previous_final = None
previous_app_pid = None
def cli(label, *commands): return save(label+".txt", target.cli(base+"/runtime", list(commands)))
def observation(label, operation=0):
    nonce = "t22-query-"+str(time.time_ns())
    save(label+"-action.txt", action("--es", "observationNonce", nonce,
        "--ei", "observationOperation", operation))
    value = wait_json("files/product-state/observation-"+nonce+".json", label)
    assert "error" not in value, value
    result["snapshots"].append(dict(label=label, nonce=nonce, profile=current_profile,
                                     operation=operation, generation=life["generation"]))
    return value
def records(value): return [r for r in value["consumer"]["overview"]["records"] if r]
def record(value, incarnation=None):
    return next(r for r in records(value) if r["ports"][0] == source_port
                and (r["incarnation"] == incarnation if incarnation is not None else not r["ended"]))
def import_call(label, document=None, expected=0):
    nonce = "t22-import-"+str(time.time_ns())
    temporary = "/data/local/tmp/"+nonce+".json"
    try:
        if document is not None:
            save(label+"-input.json", json.dumps(document))
            adb("push", out/(label+"-input.json"), temporary)
            adb("shell", "run-as", PKG, "mkdir", "-p", "files/product-import")
            adb("shell", "run-as", PKG, "cp", temporary, "files/product-import/"+nonce+".json")
        action("--es", "ruleImportNonce", nonce, "--ei", "ruleOperation", int(document is not None),
               "--el", "expectedSavedRevision", expected)
        value = wait_json("files/product-state/rule-import-"+nonce+".json", label)
        assert value["stage"] == "vpp" and value["result"] == 0, value
        return value
    finally:
        adb("shell", "rm", "-f", temporary, check=False)
        adb("shell", "run-as", PKG, "rm", "-f", "files/product-import/"+nonce+".json", check=False)
def phase(name):
    value = wait_json("files/product-state/t12-"+nonce+".json", current_profile+"-"+name,
                     lambda x: x.get("phase") == name or bool(x.get("error")), timeout=100)
    assert not value.get("error"), value
    return value
def release(name):
    adb("shell", "run-as", PKG, "touch", "files/product-state/t12-release-"+nonce+"-"+name)
def mapping_evidence(label, pid):
    save(label+"-fds.txt", root("ls -l /proc/"+str(pid)+"/fd"))
    return save(label+"-maps.txt", root("cat /proc/"+str(pid)+"/maps"))

capture_name = "t22-capture-"+hashlib.sha256(str(out).encode()).hexdigest()[:12]
host_capture = None; device_capture_pid = None; capture_dir = None
endpoint = None; started = False; current_profile = None; life = None; nonce = None
previous_power = adb("shell", "settings", "get", "global", "stay_on_while_plugged_in").strip()
try:
    before = props(app("files/runtime-state/snapshot.properties"))
    assert before.get("state") == "stopped" and before.get("mayBeActive") == "false", before
    save("before.properties", app("files/runtime-state/snapshot.properties"))
    prior_store = app("files/observation/overall.json", check=False)
    try: prior_store = json.loads(prior_store)
    except json.JSONDecodeError: prior_store = None
    save("before-store.json", json.dumps(prior_store, indent=2)+"\n")
    assert digest(b["apk"]) == b["apk_sha256"]
    save("install.txt", adb("install", "-r", b["apk"], timeout=60))
    grant = save("root-grant.txt", adb("shell", "run-as", PKG, "su", "-c", "id", check=False))
    assert "uid=0" in grant, "restore KernelSU Superuser grant before acceptance"
    package = save("package.txt", adb("shell", "dumpsys", "package", PKG))
    native = re.search(r"codePath=(\S+)", package)[1]+"/lib/arm64"
    installed = save("installed-native.txt", adb("shell", "sha256sum", *[native+"/"+n for n in sorted(b["native_sha256"])]))
    assert {Path(l.split()[1]).name:l.split()[0] for l in installed.splitlines()} == b["native_sha256"]
    assert save("installed-apk.txt", adb("shell", "sha256sum", native.removesuffix("/lib/arm64")+"/base.apk")).split()[0] == b["apk_sha256"]
    result["apk_sha256"] = b["apk_sha256"]; result["native_sha256"] = b["native_sha256"]
    result["uid"] = int(adb("shell", "run-as", PKG, "id", "-u").strip())
    save("device.txt", adb("shell", "getprop", "ro.product.device")+adb("shell", "uname", "-a"))
    save("network.txt", adb("shell", "ip", "address"))
    peer = ROOT/"tests/device/helpers/t21_udp_peer.py"; save("udp-peer.py", peer.read_text())
    endpoint_log = (out/"endpoint.jsonl").open("w")
    endpoint = subprocess.Popen(["python3", "-u", str(peer), "server", "--host", a.endpoint],
                                stdout=endpoint_log, stderr=subprocess.STDOUT)
    end = time.monotonic()+5
    while '"kind": "ready"' not in (out/"endpoint.jsonl").read_text():
        assert endpoint.poll() is None and time.monotonic() < end
        time.sleep(.05)
    host_capture = subprocess.Popen(["docker", "run", "--rm", "--name", capture_name,
        "--network", "host", "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN",
        "--mount", "type=bind,source="+str(out)+",target=/evidence",
        "sakamoto-vpp-nfq-poc:dev", "tcpdump", "-U", "-i", "any", "-s", "128",
        "-w", "/evidence/host.pcap", "udp port 42121"],
        stdout=(out/"host-capture.log").open("w"), stderr=subprocess.STDOUT)
    capture_dir = root("mktemp -d /data/local/tmp/t22-capture.XXXXXX").strip()
    assert capture_dir.startswith("/data/local/tmp/t22-capture.")
    device_capture_pid = int(root("/system/bin/tcpdump -U -i any -s 128 -w "+capture_dir+
        "/wire.pcap 'udp port 42121' >"+capture_dir+"/capture.log 2>&1 & echo $!").strip())
    time.sleep(.3)
    assert host_capture.poll() is None
    save("device-capture-start.txt", root("cat "+capture_dir+"/capture.log"))
    adb("shell", "settings", "put", "global", "stay_on_while_plugged_in", "3")
    for current_profile, source_port in [("root", 42122), ("vpn", 42123)]:
        if a.profile_scope not in ("both", current_profile): continue
        base = "/data/user/0/"+PKG+"/files/profiles/"+current_profile+"/vpp"
        started = True
        save(current_profile+"-start.txt", action(*(["--ez", "debugVpnHevValidation", "true"] if current_profile == "vpn"
            else ["--ez", "runtimeStart", "true", "--es", "runtimeProfile", "root"])))
        running = wait_state(current_profile+"-running", "running")
        assert running["profile"] == current_profile
        assert running["protectionRunning"] == ("true" if current_profile == "root" else "false")
        process_text = save(current_profile+"-processes.txt", root("ps -A -o PID,UID,ARGS"))
        pids = [int(parts[0]) for line in process_text.splitlines()
                if len(parts:=line.split(None,2)) == 3 and parts[0].isdigit()
                and Path(parts[2].split()[0]).name == "libvpp_runtime.so"]
        assert len(pids) == 1
        app_pid = int(adb("shell", "pidof", PKG+":runtime").strip())
        life = dict(profile=current_profile, generation=int(running["generation"]), pid=pids[0], app_pid=app_pid)
        if previous_app_pid is not None: assert app_pid != previous_app_pid, "service process must recover"
        result["lifetimes"].append(life)
        save(current_profile+"-owner.properties", app("files/profiles/"+current_profile+"/vpp/owner.properties"))
        queried = import_call(current_profile+"-configuration-before")
        import_call(current_profile+"-empty-configuration", dict(format="sakamoto-config-v1", rules=[], groups=[], edges=[], bindings=[], lists=[]), queried["saved_revision"])
        cli(current_profile+"-startup", "product packet-trace limit 4096", "show threads", "show product observation")
        baseline = observation(current_profile+"-baseline")
        assert baseline["consumer"]["live"] and baseline["health"]["connected"] == 1
        assert baseline["health"]["generation"] == life["generation"]
        persisted = baseline["consumer"]["persistent"]
        assert persisted and baseline["consumer"]["store_error"] is None
        life["baseline_packets"] = persisted["packets"]
        life["baseline_bytes"] = persisted["bytes"]
        if previous_final is not None:
            assert persisted["packets"] == previous_final["packets"]
            assert persisted["bytes"] == previous_final["bytes"]
            assert persisted["baselines"] == previous_final["baselines"]
        elif prior_store is not None:
            assert persisted["packets"] == prior_store["totals"]["packets"]
            assert persisted["bytes"] == prior_store["totals"]["bytes"]
        assert "sakamoto-observation" in mapping_evidence(current_profile+"-app-live", app_pid)
        assert "sakamoto-observation" in mapping_evidence(current_profile+"-vpp-live", life["pid"])
        save(current_profile+"-socket-mode.txt", root("stat -c '%u:%g:%a' "+base+"/runtime/api.sock.obs"))
        nonce = "t22-"+current_profile+"-"+str(time.time_ns())
        plan = dict(nonce=nonce, endpoint=a.endpoint, port=42121, source=source_port, mode="udp",
                    bindDefault=current_profile == "root", observationFlood=a.flood, observationBatch=1)
        result["plans"].append(dict(profile=current_profile, generation=life["generation"], plan=plan))
        action("--es", "t12ProbePlan", shlex.quote(json.dumps(plan)))
        created = phase("observation_created")
        adb("shell", "input", "keyevent", "HOME")
        before_flush = cli(current_profile+"-before-flush", "show product flows")
        time.sleep(1.3)
        quiet = observation(current_profile+"-quiet")
        flow = record(quiet)
        assert flow["packets"] == [1,1] and flow["bytes"] == [60,60], flow
        local_address = created["local"].lstrip("/").rsplit(":",1)[0]
        assert flow["addresses"] == list(ipaddress.ip_address(local_address).packed + ipaddress.ip_address(a.endpoint).packed)
        assert flow["origin_device_direction"] == 3 and flow["last_device_direction"] == 1
        after_flush = cli(current_profile+"-after-flush", "show product flows")
        marker = f"worker={flow['owner']} slot={flow['slot']} incarnation={flow['incarnation']} "
        timers = lambda text: [l for l in text.splitlines() if l.startswith("flow.timer ") and marker in l]
        assert timers(before_flush) == timers(after_flush) and len(timers(before_flush)) == 1
        release("observation_created"); phase("observation_tail")
        cli(current_profile+"-close-tail", f"product flow-end close owner {flow['owner']} slot {flow['slot']} generation {life['generation']} incarnation {flow['incarnation']}")
        tail = observation(current_profile+"-end-tail")
        ended = record(tail, flow["incarnation"])
        assert ended["ended"] and ended["packets"] == [4,4] and ended["bytes"] == [264,264], ended
        # CLI round trips can outlast the one-second pending flush. Keep the
        # timing witness without claiming that this END first carried its tail.
        life["early_end_combined"] = ended["sequence"] == flow["sequence"]+1
        release("observation_tail"); phase("observation_reused")
        reused = observation(current_profile+"-reused"); next_flow = record(reused)
        assert next_flow["incarnation"] > flow["incarnation"]
        # No pause: close the foreground Activity, release the socket probe
        # using its file gate, and inspect committed state before reopening UI.
        adb("shell", "input", "keyevent", "HOME")
        save(current_profile+"-background-before.txt", adb("shell", "dumpsys", "activity", "activities"))
        life["background_started_ns"] = time.time_ns()
        release("observation_reused"); flood = phase("observation_full")
        assert flood["sent"] == flood["received"] == a.flood+5
        time.sleep(1.3)
        background = json.loads(save(current_profile+"-background-store.json", app("files/observation/overall.json")))
        save(current_profile+"-background-after.txt", adb("shell", "dumpsys", "activity", "activities"))
        life["background_completed_ns"] = time.time_ns()
        assert background["totals"]["packets"] == [n+a.flood+5 for n in life["baseline_packets"]]
        full = observation(current_profile+"-background-query")
        assert full["consumer"]["persistent"]["packets"] == background["totals"]["packets"]
        assert full["consumer"]["persistent"]["save_error"] is None
        baseline_flow = record(full, next_flow["incarnation"])
        cli(current_profile+"-close-full-tail", f"product flow-end close owner {next_flow['owner']} slot {next_flow['slot']} generation {life['generation']} incarnation {next_flow['incarnation']}")
        full_tail = observation(current_profile+"-full-end-tail")
        ended_flow = record(full_tail, next_flow["incarnation"])
        assert ended_flow["ended"] and ended_flow["packets"] == [a.flood+1]*2, ended_flow
        assert ended_flow["bytes"] == [(a.flood+1)*60]*2
        life["end_only_tail_packets"] = sum(ended_flow["packets"])-sum(baseline_flow["packets"])
        release("observation_full"); phase("observation_final")
        last = observation(current_profile+"-last-reuse")
        last_flow = record(last)
        assert last_flow["incarnation"] > next_flow["incarnation"]
        cli(current_profile+"-close-final", f"product flow-end close owner {last_flow['owner']} slot {last_flow['slot']} generation {life['generation']} incarnation {last_flow['incarnation']}")
        final = observation(current_profile+"-final")
        final_flow = record(final, last_flow["incarnation"])
        assert final_flow["ended"] and final_flow["packets"] == [1,1] and final_flow["bytes"] == [60,60]
        release("observation_final"); phase("finished")
        summary = final["consumer"]["persistent"]
        assert summary["packets"] == [n+a.flood+6 for n in life["baseline_packets"]]
        assert summary["bytes"] == [n+(a.flood+6)*60+24 for n in life["baseline_bytes"]]
        assert summary["save_error"] is None
        previous_final = summary
        save(current_profile+"-vpp.log", app("files/profiles/"+current_profile+"/vpp/logs/vpp-stdout.log"))
        cli(current_profile+"-before-stop", "show product observation", "show product completion")
        action("--ez", "runtimeStop", "true")
        stopped = wait_state(current_profile+"-stopped", "stopped"); started = False
        assert stopped["mayBeActive"] == "false"
        assert root("test ! -d /proc/"+str(life["pid"])+" && echo absent").strip() == "absent"
        life["process_absent"] = True
        assert "sakamoto-observation" not in mapping_evidence(current_profile+"-app-stopped", app_pid)
        life["mapping_released"] = True
        # Normal stop closes ingestion and the durable transaction, then the
        # Android service process is actually replaced before the next start.
        save(current_profile+"-stopped-store.json", app("files/observation/overall.json"))
        save(current_profile+"-service-stop.txt", adb("shell", "am", "force-stop", PKG))
        exit_deadline = time.monotonic()+10
        while root("test ! -d /proc/"+str(app_pid)+" && echo absent", check=False).strip() != "absent":
            assert time.monotonic() < exit_deadline, "old service process has not exited"
            time.sleep(.1)
        life["service_process_absent"] = True
        previous_app_pid = app_pid
    assert len({x["generation"] for x in result["lifetimes"]}) == len(result["lifetimes"])
    result["status"] = "RAW_COMPLETE"
except Exception as error:
    result["error"] = repr(error)
    raise
finally:
    if started:
        save("failure-vpp.log", app("files/profiles/"+current_profile+"/vpp/logs/vpp-stdout.log", check=False))
        action("--ez", "runtimeStop", "true")
        try: wait_state("cleanup-stopped", "stopped")
        except Exception as error: result["cleanup_error"] = repr(error)
    if device_capture_pid is not None:
        root("kill -INT "+str(device_capture_pid), check=False)
        time.sleep(.3)
        save("device-capture.log", root("cat "+capture_dir+"/capture.log", check=False))
        root("chmod 644 "+capture_dir+"/wire.pcap")
        root("chmod 755 "+capture_dir)
        adb("pull", capture_dir+"/wire.pcap", out/"device.pcap")
        root("rm -f "+capture_dir+"/wire.pcap "+capture_dir+"/capture.log; rmdir "+capture_dir)
    if host_capture is not None:
        if host_capture.poll() is None:
            subprocess.run(["docker", "kill", "--signal", "INT", capture_name], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        host_capture.wait(timeout=10)
    adb("shell", "am", "force-stop", PKG, check=False)
    if endpoint is not None:
        endpoint.terminate(); endpoint.wait(timeout=5)
    adb("shell", "settings", "put", "global", "stay_on_while_plugged_in", previous_power, check=False)
    result["completed_ns"] = time.time_ns()
    result["files"] = {str(f.relative_to(out)):digest(f) for f in out.rglob("*") if f.is_file()}
    save("result.json", json.dumps(result, indent=2)+"\n")
print(json.dumps({k:result[k] for k in ("status", "source_sha256", "lifetimes")}, indent=2))
