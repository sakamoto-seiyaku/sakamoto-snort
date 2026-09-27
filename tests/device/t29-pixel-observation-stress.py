#!/usr/bin/env python3
"""T29 current APK Root/VPN channel stress with independent wire captures."""
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
p.add_argument("--flood", type=int, default=10000)
p.add_argument("--representative", action="store_true", help="bound device run; full-queue acceptance stays in Linux")
p.add_argument("--allow-underlay-loss", action="store_true", help="continue bounded echo timeouts and verify actual ingress later")
p.add_argument("--background-probe", action="store_true", help="exercise Android cached-process freezing separately")
a = p.parse_args()
serial = json.loads(a.serial_from.read_text())["serial"]
b = json.loads(a.build.read_text())
out = a.output.resolve(); out.mkdir(parents=True, exist_ok=False)
digest = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
result = dict(status="HOLD", serial=serial, build=str(a.build.resolve()), build_sha256=digest(a.build),
              source_sha256=b["source_sha256"], started_ns=time.time_ns(), lifetimes=[],
              snapshots=[], plans=[], endpoint=a.endpoint, requires_full_queue=not a.representative)
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
def ordinary_hashes(label):
    values = {}
    for path in ("files/observation/overall.sqlite3", "files/observation/overall.json"):
        read = subprocess.run([str(ROOT/"dev/adb"), "-s", serial, "exec-out", "run-as", PKG, "cat", path],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45, check=True)
        values[path] = hashlib.sha256(read.stdout).hexdigest()
    save(label+"-ordinary-hashes.json", json.dumps(values,indent=2)+"\n")
    return values
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

spec = importlib.util.spec_from_file_location("t21_target", ROOT/"tests/device/s233-fail-open.py")
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
module.SERIAL = serial
target = object.__new__(module.Target); target.pixel = True
base = None
def cli(label, *commands): return save(label+".txt", target.cli(base+"/runtime", list(commands)))
def observation(label, operation=0):
    nonce = "t21-query-"+str(time.time_ns())
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
    nonce = "t21-import-"+str(time.time_ns())
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
                     lambda x: x.get("phase") == name or bool(x.get("error")),
                     timeout=1200 if name == "observation_full" else 100)
    assert not value.get("error"), value
    return value
def release(name):
    adb("shell", "run-as", PKG, "touch", "files/product-state/t12-release-"+nonce+"-"+name)
def mapping_evidence(label, pid):
    save(label+"-fds.txt", root("ls -l /proc/"+str(pid)+"/fd"))
    return save(label+"-maps.txt", root("cat /proc/"+str(pid)+"/maps"))

capture_name = "t21-capture-"+hashlib.sha256(str(out).encode()).hexdigest()[:12]
host_capture = None; device_capture_pid = None; capture_dir = None
endpoint = None; started = False; current_profile = None; life = None; nonce = None
previous_power = adb("shell", "settings", "get", "global", "stay_on_while_plugged_in").strip()
previous_screen_timeout = adb("shell", "settings", "get", "system", "screen_off_timeout").strip()
try:
    before = props(app("files/runtime-state/snapshot.properties"))
    assert before.get("state") == "stopped" and before.get("mayBeActive") == "false", before
    save("before.properties", app("files/runtime-state/snapshot.properties"))
    ordinary_before = ordinary_hashes("before")
    assert (app("files/observation/t27-test.enabled", check=False).find("No such file") >= 0), "stale test selector"
    assert digest(b["apk"]) == b["apk_sha256"]
    save("install.txt", adb("install", "-r", b["apk"], timeout=60))
    grant = save("root-grant.txt", adb("shell", "run-as", PKG, "su", "-c", "id", check=False))
    assert "uid=0" in grant, "restore KernelSU Superuser grant before acceptance"
    adb("shell", "run-as", PKG, "rm", "-rf", "files/observation/t27-test")
    adb("shell", "run-as", PKG, "mkdir", "-p", "files/observation/t27-test")
    adb("shell", "run-as", PKG, "touch", "files/observation/t27-test.enabled")
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
    capture_dir = root("mktemp -d /data/local/tmp/t21-capture.XXXXXX").strip()
    assert capture_dir.startswith("/data/local/tmp/t21-capture.")
    device_capture_pid = int(root("/system/bin/tcpdump -U -i any -s 128 -w "+capture_dir+
        "/wire.pcap 'udp port 42121' >"+capture_dir+"/capture.log 2>&1 & echo $!").strip())
    time.sleep(.3)
    assert host_capture.poll() is None
    save("device-capture-start.txt", root("cat "+capture_dir+"/capture.log"))
    adb("shell", "settings", "put", "global", "stay_on_while_plugged_in", "3")
    adb("shell", "settings", "put", "system", "screen_off_timeout", "1800000")
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
        result["lifetimes"].append(life)
        save(current_profile+"-owner.properties", app("files/profiles/"+current_profile+"/vpp/owner.properties"))
        queried = import_call(current_profile+"-configuration-before")
        import_call(current_profile+"-empty-configuration", dict(format="sakamoto-config-v1", rules=[], groups=[], edges=[], bindings=[], lists=[]), queried["saved_revision"])
        cli(current_profile+"-startup", "product packet-trace limit 4096", "show threads", "show product observation")
        baseline = observation(current_profile+"-baseline")
        assert baseline["consumer"]["live"] and baseline["health"]["connected"] == 1
        assert baseline["health"]["generation"] == life["generation"]
        assert "sakamoto-observation" in mapping_evidence(current_profile+"-app-live", app_pid)
        assert "sakamoto-observation" in mapping_evidence(current_profile+"-vpp-live", life["pid"])
        save(current_profile+"-socket-mode.txt", root("stat -c '%u:%g:%a' "+base+"/runtime/api.sock.obs"))
        nonce = "t21-"+current_profile+"-"+str(time.time_ns())
        plan = dict(nonce=nonce, endpoint=a.endpoint, port=42121, source=source_port, mode="udp",
                    bindDefault=current_profile == "root", observationFlood=a.flood, observationBatch=1)
        if a.allow_underlay_loss:
            plan.update(observationTolerateLoss=True, observationMaxTimeouts=256)
        result["plans"].append(dict(profile=current_profile, generation=life["generation"], plan=plan))
        action("--es", "t12ProbePlan", shlex.quote(json.dumps(plan)))
        created = phase("observation_created")
        if a.background_probe:
            adb("shell", "input", "keyevent", "HOME")
        else:
            adb("shell", "input", "keyevent", "224")
            adb("shell", "wm", "dismiss-keyguard")
            save(current_profile+"-foreground.txt", action())
            activity=save(current_profile+"-foreground-activity.txt",
                          adb("shell", "dumpsys", "activity", "activities"))
            assert any("topResumedActivity=" in line and PKG+"/.DebugControlActivity" in line
                       for line in activity.splitlines()), "diagnostic Activity must own long probe foreground"
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
        # CLI round trips can outlast the one-second pending flush. Keep this
        # timing witness; the full-queue arm below proves END-only tail delivery
        # deterministically after pending UPDATEs have been rejected.
        life["early_end_combined"] = ended["sequence"] == flow["sequence"]+1
        release("observation_tail"); phase("observation_reused")
        reused = observation(current_profile+"-reused"); next_flow = record(reused)
        assert next_flow["incarnation"] > flow["incarnation"]
        paused = observation(current_profile+"-paused", 1)
        if not a.background_probe:
            adb("shell", "input", "keyevent", "224")
            adb("shell", "wm", "dismiss-keyguard")
            save(current_profile+"-flood-foreground.txt", action())
            activity=save(current_profile+"-flood-activity.txt",
                          adb("shell", "dumpsys", "activity", "activities"))
            assert any("topResumedActivity=" in line and PKG+"/.DebugControlActivity" in line
                       for line in activity.splitlines()), "flood Activity is not foreground"
        release("observation_reused"); flood = phase("observation_full")
        assert flood["sent"] == a.flood+5
        if a.allow_underlay_loss:
            assert 0 <= flood["sent"]-flood["received"] <= flood["transportTimeouts"] <= 256, flood
        else:
            assert flood["received"] == flood["sent"]
        time.sleep(1.3)  # pending tail attempt fails while capacity is still full
        full = observation(current_profile+"-full")
        cli(current_profile+"-full-resources", "show product flows", "show product completion",
            "show product observation")
        save(current_profile+"-full-vpp-process.txt", root("cat /proc/"+str(life["pid"])+"/status /proc/"+
             str(life["pid"])+"/io"))
        save(current_profile+"-full-app-process.txt", root("cat /proc/"+str(app_pid)+"/status /proc/"+
             str(app_pid)+"/io"))
        assert full["consumer"]["overview"]["accepted"] == paused["consumer"]["overview"]["accepted"]
        loss = sum(c["full"] for c in full["health"]["channels"]) - sum(c["full"] for c in paused["health"]["channels"])
        if not a.representative: assert loss > 0
        assert all(c["attempted"] == 0 for c in full["health"]["channels"][1::2])
        resumed = observation(current_profile+"-resume", 2)
        end = time.monotonic()+8
        while any(c["occupancy"] for c in resumed["health"]["channels"]):
            assert time.monotonic() < end
            resumed = observation(current_profile+"-resume-drained")
        baseline_flow = record(resumed, next_flow["incarnation"])
        if not a.representative: assert sum(baseline_flow["packets"]) < (a.flood+1)*2
        cli(current_profile+"-close-full-tail", f"product flow-end close owner {next_flow['owner']} slot {next_flow['slot']} generation {life['generation']} incarnation {next_flow['incarnation']}")
        full_tail = observation(current_profile+"-full-end-tail")
        ended_flow = record(full_tail, next_flow["incarnation"])
        assert ended_flow["ended"] and ended_flow["packets"][0] == a.flood+1, ended_flow
        if a.allow_underlay_loss:
            assert a.flood+1-256 <= ended_flow["packets"][1] <= a.flood+1, ended_flow
        else:
            assert ended_flow["packets"][1] == a.flood+1, ended_flow
        assert ended_flow["bytes"] == [count*60 for count in ended_flow["packets"]]
        life["full_tail_packets"] = ended_flow["packets"]
        if not a.representative: assert full_tail["consumer"]["overview"]["incomplete"]
        life["end_only_tail_packets"] = sum(ended_flow["packets"])-sum(baseline_flow["packets"])
        release("observation_full"); phase("observation_final")
        last = observation(current_profile+"-last-reuse")
        last_flow = record(last)
        assert last_flow["incarnation"] > next_flow["incarnation"]
        cli(current_profile+"-close-final", f"product flow-end close owner {last_flow['owner']} slot {last_flow['slot']} generation {life['generation']} incarnation {last_flow['incarnation']}")
        final = observation(current_profile+"-final")
        final_flow = record(final, last_flow["incarnation"])
        assert final_flow["ended"] and final_flow["packets"][0] == 1
        assert final_flow["packets"][1] in ((0,1) if a.allow_underlay_loss else (1,))
        assert final_flow["bytes"] == [count*60 for count in final_flow["packets"]]
        release("observation_final"); phase("finished")
        save(current_profile+"-vpp.log", app("files/profiles/"+current_profile+"/vpp/logs/vpp-stdout.log"))
        cli(current_profile+"-before-stop", "show product observation", "show product completion")
        action("--ez", "runtimeStop", "true")
        stopped = wait_state(current_profile+"-stopped", "stopped"); started = False
        assert stopped["mayBeActive"] == "false"
        assert root("test ! -d /proc/"+str(life["pid"])+" && echo absent").strip() == "absent"
        life["process_absent"] = True
        assert "sakamoto-observation" not in mapping_evidence(current_profile+"-app-stopped", app_pid)
        life["mapping_released"] = True
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
    adb("shell", "run-as", PKG, "rm", "-f", "files/observation/t27-test.enabled", check=False)
    if "ordinary_before" in locals():
        try:
            result["ordinary_history_unchanged"] = ordinary_hashes("after") == ordinary_before
        except Exception as error:
            result["ordinary_history_check_error"] = repr(error)
    if endpoint is not None:
        endpoint.terminate(); endpoint.wait(timeout=5)
    adb("shell", "settings", "put", "global", "stay_on_while_plugged_in", previous_power, check=False)
    adb("shell", "settings", "put", "system", "screen_off_timeout", previous_screen_timeout, check=False)
    result["completed_ns"] = time.time_ns()
    result["files"] = {str(f.relative_to(out)):digest(f) for f in out.rglob("*") if f.is_file()}
    save("result.json", json.dumps(result, indent=2)+"\n")
print(json.dumps({k:result[k] for k in ("status", "source_sha256", "lifetimes")}, indent=2))
