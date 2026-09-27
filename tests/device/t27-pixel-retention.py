#!/usr/bin/env python3
"""Serialized Pixel retention and restart evidence on an isolated Product store."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import shlex
import signal
import sqlite3
import subprocess
import time
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[2]; PKG="com.sakamoto.snort.androidruntime"
p=argparse.ArgumentParser()
p.add_argument("--serial-from",type=Path,required=True);p.add_argument("--build",type=Path,required=True)
p.add_argument("--probe-build",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
p.add_argument("--profile",choices=("root","vpn"),required=True)
p.add_argument("--skip-install",action="store_true")
p.add_argument("--endpoint",default="192.168.4.5")
a=p.parse_args();serial=json.loads(a.serial_from.read_text())["serial"];build=json.loads(a.build.read_text())
probe_build=json.loads(a.probe_build.read_text());out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
tag=hashlib.sha256(str(out).encode()).hexdigest()[:9]
result=dict(status="HOLD",kind="android",profile=a.profile,scenario="retention",task="T27",serial=serial,
    build=str(a.build.resolve()),build_sha256=digest(a.build),source_sha256=build["source_sha256"],
    probe_build=str(a.probe_build.resolve()),probe_build_sha256=digest(a.probe_build),
    started_ns=time.time_ns(),configurations=[],phases=[],snapshots=[],lifetimes=[])
for path in (Path(__file__),ROOT/"tests/device/helpers/t23_policy.py",ROOT/"tests/device/helpers/t23_udp_peer.py",ROOT/"tests/device/helpers/T23Probe.java",ROOT/"tests/device/s233-fail-open.py"):
    (out/path.name).write_bytes(path.read_bytes())
def save(name,value):
    (out/name).write_text(value if isinstance(value,str) else json.dumps(value,indent=2)+"\n");return value

def adb(*args,check=True,timeout=45,binary=False):
    start=time.time_ns();r=subprocess.run([str(ROOT/"dev/adb"),"-s",serial,*map(str,args)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    with (out/"operations.jsonl").open("a") as f:f.write(json.dumps(dict(start_ns=start,end_ns=time.time_ns(),argv=list(map(str,args)),code=r.returncode))+"\n")
    if check and r.returncode:raise RuntimeError(r.stdout.decode(errors="replace")+r.stderr.decode(errors="replace"))
    return r.stdout if binary else (r.stdout+r.stderr).decode(errors="replace").replace("\r","")
def root(command,check=True):return adb("shell","su","-c",shlex.quote(command),check=check)
def app(path,check=True):return adb("shell","run-as",PKG,"cat",path,check=check)
def props(text):return dict(l.split("=",1) for l in text.splitlines() if "=" in l and not l.startswith("#"))
def action(*args):return adb("shell","am","start","-n",PKG+"/.DebugControlActivity",*args)
def state(label,wanted):
    until=time.monotonic()+40
    while time.monotonic()<until:
        text=app("files/runtime-state/snapshot.properties");value=props(text)
        if value.get("state")==wanted:save(label+".properties",text);return value
        assert value.get("errorCode")!="root_authorization_required","KernelSU grant required before acceptance"
        time.sleep(.15)
    raise RuntimeError("state deadline: "+str(value))
def wait_json(path,label):
    until=time.monotonic()+30
    while time.monotonic()<until:
        text=app(path,check=False)
        try:value=json.loads(text)
        except json.JSONDecodeError:value=None
        if value is not None:save(label+".json",value);return value
        time.sleep(.1)
    raise RuntimeError("query deadline "+label)

spec=importlib.util.spec_from_file_location("request",ROOT/"tests/device/helpers/t23_policy.py")
requests=importlib.util.module_from_spec(spec);spec.loader.exec_module(requests)
spec=importlib.util.spec_from_file_location("target",ROOT/"tests/device/s233-fail-open.py")
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);module.SERIAL=serial
target=object.__new__(module.Target);target.pixel=True
base="/data/user/0/"+PKG+"/files/profiles/"+a.profile+"/vpp"
owned=[]
def cli(label,text):return save(label+".txt",target.cli(base+"/runtime",[text]))
def query(label):
    nonce="t23q-"+tag+"-"+str(time.time_ns());path="files/product-state/observation-"+nonce+".json"
    action("--es","observationNonce",nonce,"--ei","observationOperation",0)
    value=wait_json(path,label);owned.append(path)
    assert "error" not in value and value["health"]["generation"]==generation,value
    result["snapshots"].append(dict(label=label,generation=generation));return value

def settle(label):
    until=time.monotonic()+12
    while True:
        value=query(label);q=value["consumer"]["persistent"]
        assert value["consumer"]["store_error"] is None,value["consumer"]["store_error"]
        if q and not q["persistence"]["pending"] and not q["persistence"]["maintenance_pending"] and not any(c["occupancy"] for c in value["health"]["channels"]):return value
        assert time.monotonic()<until,"durability deadline";time.sleep(.15)

def import_call(label,document=None,expected=0):
    nonce="t23i-"+tag+"-"+str(time.time_ns());temporary="/data/local/tmp/"+nonce+".json"
    destination="files/product-import/"+nonce+".json";response="files/product-state/rule-import-"+nonce+".json"
    try:
        if document is not None:
            save(label+"-input.json",document);adb("push",out/(label+"-input.json"),temporary)
            adb("shell","run-as",PKG,"mkdir","-p","files/product-import")
            adb("shell","run-as",PKG,"cp",temporary,destination)
        action("--es","ruleImportNonce",nonce,"--ei","ruleOperation",int(document is not None),"--el","expectedSavedRevision",expected)
        value=wait_json(response,label+"-apply");owned.append(response)
        assert value["stage"]=="vpp" and value["result"]==0,value
        return value
    finally:
        adb("shell","rm","-f",temporary,check=False);adb("shell","run-as",PKG,"rm","-f",destination,check=False)
def configuration(label,actions=(1,1),empty=False,condition=False):
    global policy
    document=requests.empty() if empty else requests.document(label,policy,[uid],actions,(0,0))
    if condition:
        fields=document["rules"][0]["definition"].split();assert fields[10]=="*"
        fields[10]="0.0.0.0/0";fields[11]="0.0.0.0/0"
        fields[12]="44500";fields[13]="44500"
        document["rules"][0]["definition"]=" ".join(fields)
    policy=import_call(label,document,policy["saved_revision"])
    index=cli(label+"-index","show product policy-index")
    line=next(l for l in index.splitlines() if l.startswith("policy.index "))
    identity=dict(part.split("=",1) for part in line.split()[1:])
    row=dict(label=label,generation=generation,input=label+"-input.json",response=label+"-apply.json",
        revision=policy["active_revision"],snapshot_hash=int(identity["hash"]),versions=policy["active_versions"],
        actions=list(actions),condition_changed=condition,empty=empty)
    result["configurations"].append(row);return row

def proc(pid,label):
    text=root(f"cat /proc/{pid}/stat /proc/{pid}/status /proc/{pid}/io /proc/{pid}/task/*/stat /proc/{pid}/task/*/status")
    save(label+".txt",text);stats=[]
    for line in text.splitlines():
        match=re.match(r"^(\d+) \((.*?)\) (.*)$",line)
        if match:
            fields=match[3].split();stats.append(dict(tid=int(match[1]),name=match[2],cpu_ticks=int(fields[11])+int(fields[12])))
    first=text.split("Name:",1)[1].split("Name:",1)[0]
    fields={l.split(":",1)[0]:l.split(":",1)[1].strip() for l in first.splitlines() if ":" in l}
    threads={}
    for block in text.split("Name:")[2:]:
        values={l.split(":",1)[0]:l.split(":",1)[1].strip() for l in block.splitlines() if ":" in l}
        if "Pid" in values:threads[values["Pid"]]=dict(name=block.splitlines()[0].strip(),voluntary=int(values["voluntary_ctxt_switches"]),involuntary=int(values["nonvoluntary_ctxt_switches"]))
    return dict(pid=pid,at_host_ns=time.time_ns(),stats=stats,fields=fields,threads=threads)
def resources(label):return dict(vpp=proc(vpp_pid,label+"-vpp"),rust=proc(service_pid,label+"-rust"),ticks_per_second=100)

buffer=b""
def probe_line(timeout=180):
    global buffer
    until=time.monotonic()+timeout
    while time.monotonic()<until:
        if b"\n" in buffer:
            line,buffer=buffer.split(b"\n",1)
            if line.strip():return json.loads(line.decode())
        if select.select([probe.stdout],[],[],.05)[0]:
            data=os.read(probe.stdout.fileno(),65536)
            if not data:raise RuntimeError("probe closed: "+buffer.decode())
            buffer+=data
    raise RuntimeError("probe deadline")
def send(label,count,size=64,sockets=1,short=False,delay=0):
    before=resources(label+"-before")
    command=dict(label=label,count=count,size=size,sockets=sockets,short=short,delayMs=delay,nonce="t26-"+tag+"-"+label+"-"+str(time.time_ns()))
    probe.stdin.write((json.dumps(command)+"\n").encode());probe.stdin.flush()
    traffic=probe_line();assert traffic["label"]==label and traffic["sent"]==count
    save(label+"-traffic.json",traffic);time.sleep(1.1);snapshot=settle(label)
    result["phases"].append(dict(label=label,generation=generation,uid=uid,configuration=result["configurations"][-1]["label"],
        request=command,traffic=label+"-traffic.json",snapshot=label+".json",before=before,after=resources(label+"-after")))
    return snapshot

def ui_query_history():
    directory="/data/user/0/"+PKG+"/files/product-state/"
    action()
    size=adb("shell","wm","size");height=int(re.search(r"(\d+)x(\d+)",size)[2])
    chosen=None
    for attempt in range(16):
        adb("shell","uiautomator","dump","/sdcard/t26-window.xml",timeout=20)
        xml=adb("shell","cat","/sdcard/t26-window.xml")
        save("ui-before-"+str(attempt)+".xml",xml)
        for node in ET.fromstring(xml).iter("node"):
            if node.get("content-desc")=="Query history" or node.get("text")=="Query history":
                match=re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]",node.get("bounds",""))
                if match:
                    x1,y1,x2,y2=map(int,match.groups())
                    if 0<=y1<y2<=height and y2-y1>10:
                        chosen=((x1+x2)//2,(y1+y2)//2);break
        if chosen:break
        adb("shell","input","swipe","500",str(height*3//4),"500",str(height//4),"400")
    assert chosen,"Query history button not visible"
    adb("shell","input","tap",*chosen)
    until=time.monotonic()+12;projection=""
    while time.monotonic()<until:
        adb("shell","uiautomator","dump","/sdcard/t26-window.xml",timeout=20)
        xml=adb("shell","cat","/sdcard/t26-window.xml")
        for node in ET.fromstring(xml).iter("node"):
            if node.get("content-desc")=="History result":
                projection=node.get("text","")
        if projection.startswith("Recent history"):
            save("ui-history.xml",xml)
            (out/"ui-history.png").write_bytes(adb("exec-out","screencap","-p",binary=True))
            break
        time.sleep(.2)
    assert projection.startswith("Recent history"),projection
    remaining=root("ls "+directory+"observation-history-*.json",check=False).splitlines()
    assert not any(line.startswith(directory) and line.endswith(".json") for line in remaining),remaining
    value=query("ui-history-readback")
    for name in ("original-request","renamed-request","condition-request"):
        assert name in projection and name in json.dumps(value["consumer"]["persistent"]["rule_windows"])
    assert "conditions unavailable" in projection
    result["ui_projection"]={"button_bounds":chosen,"query_path":"ui-history-readback.json",
        "text":projection,"source_status":value["consumer"]["persistent"]["history_source"]["status"]}
    return value

def flow(snapshot):
    rows=[r for r in snapshot["consumer"]["overview"]["records"] if r and r["ports"][0]==44500 and not r["ended"]]
    assert len(rows)==1,"one persistent app socket Flow";return rows[0]
TEST_STORE="files/observation/t27-test/overall"
def copy_database(label):
    wal=adb("shell","run-as",PKG,"sh","-c",shlex.quote("if [ -f "+TEST_STORE+".sqlite3-wal ]; then stat -c %s "+TEST_STORE+".sqlite3-wal; else echo 0; fi"))
    assert int(wal.strip())==0,"stopped writer has pending WAL"
    data=adb("exec-out","run-as",PKG,"cat",TEST_STORE+".sqlite3",binary=True)
    path=out/(label+".sqlite3");path.write_bytes(data)
    db=sqlite3.connect(path);assert db.execute("PRAGMA integrity_check").fetchone()[0]=="ok"
    metrics={name:db.execute("PRAGMA "+name).fetchone()[0] for name in ("page_count","page_size","freelist_count","auto_vacuum")}
    metrics["database_and_index_bytes"]=metrics["page_count"]*metrics["page_size"]
    save(label+"-storage.json",metrics)
    state={str(kind)+":"+key:bytes(value) for kind,key,value in db.execute("SELECT kind,key,value FROM observation")};db.close()
    save(label+"-store-hashes.json",{key:hashlib.sha256(value).hexdigest() for key,value in state.items()})
    return state

def start_runtime(label):
    global started,generation,vpp_pid,service_pid,policy
    started=True
    action(*(["--ez","debugVpnHevValidation","true"] if a.profile=="vpn" else ["--ez","runtimeStart","true","--es","runtimeProfile","root"]))
    running=state(label+"-running","running");generation=int(running["generation"])
    assert running["profile"]==a.profile and running["protectionRunning"]==("true" if a.profile=="root" else "false")
    process_text=save(label+"-processes.txt",root("ps -A -o PID,UID,ARGS"))
    pids=[int(parts[0]) for line in process_text.splitlines() if len(parts:=line.split(None,2))==3 and parts[0].isdigit() and Path(parts[2].split()[0]).name=="libvpp_runtime.so"]
    assert len(pids)==1;vpp_pid=pids[0];service_pid=int(adb("shell","pidof",PKG+":runtime").strip())
    result["lifetimes"].append(dict(generation=generation,pid=vpp_pid,service_pid=service_pid))
    cli(label+"-trace","product packet-trace limit 4096")
    policy=import_call(label+"-configuration-before")
    return settle(label+"-baseline")
def stop_runtime(label):
    global started
    save(label+"-vpp.log",app("files/profiles/"+a.profile+"/vpp/logs/vpp-stdout.log"))
    cli(label+"-completion","show product completion")
    action("--ez","runtimeStop","true");stopped=state(label+"-stopped","stopped");started=False
    assert stopped["mayBeActive"]=="false"
    assert root(f"test ! -d /proc/{vpp_pid} && echo absent").strip()=="absent"
    result["lifetimes"][-1]["process_absent"]=True
    adb("shell","am","force-stop",PKG)
    assert not adb("shell","pidof",PKG+":runtime",check=False).strip()
    result["lifetimes"][-1]["service_process_absent"]=True
    return copy_database(label)

probe=endpoint=host_capture=None;capture_dir=None;capture_pid=None;started=False
remote="/data/local/tmp/t27-"+tag+".dex";destination="files/t27-"+tag+".dex"
capture_name="t27-cap-"+tag
previous_power=adb("shell","settings","get","global","stay_on_while_plugged_in").strip()
original_paths=("files/observation/overall.sqlite3","files/observation/overall.json")
def original_hashes(label):
    values={}
    for path in original_paths:
        text=adb("shell","run-as",PKG,"sha256sum",path,check=False)
        values[path]=text.split()[0] if re.fullmatch(r"[0-9a-f]{64}",text.split()[0] if text.split() else "") else None
    return save(label+"-original-hashes.json",values)

def test_config(label,offset,budget=256*1024):
    config=dict(minute_age_us=60*1_000_000,hour_age_us=2*60*60*1_000_000,
        day_age_us=2*24*60*60*1_000_000,end_age_us=60*1_000_000,
        budget_bytes=budget,working_reserve_bytes=0,clock_offset_us=offset)
    path=out/(label+"-retention-test.json");save(path.name,config)
    temporary="/data/local/tmp/t27-config-"+tag+".json"
    adb("push",path,temporary)
    adb("shell","run-as",PKG,"cp",temporary,TEST_STORE+".retention-test.json")
    adb("shell","rm","-f",temporary)
    assert json.loads(app(TEST_STORE+".retention-test.json"))==config
    result.setdefault("test_parameters",[]).append(dict(label=label,**config))
    return config

def snapshot_counts(value):
    q=value["consumer"]["persistent"]
    assert q["limits"]["scaled_test"] and q["storage_space"]["within_budget"],q
    assert q["save_error"] is None and value["consumer"]["store_error"] is None,q
    return q

def side_ge(left,right):return all(left[i]>=right[i] for i in (0,1))

try:
    before=props(save("before.properties",app("files/runtime-state/snapshot.properties")))
    assert before.get("state")=="stopped" and before.get("mayBeActive")=="false"
    original=original_hashes("before")
    if not a.skip_install:save("install.txt",adb("install","-r",build["apk"],timeout=60))
    assert "uid=0" in save("root-grant.txt",adb("shell","run-as",PKG,"su","-c","id"))
    package=save("package.txt",adb("shell","dumpsys","package",PKG));native=re.search(r"codePath=(\S+)",package)[1]+"/lib/arm64"
    installed=save("installed-native.txt",adb("shell","sha256sum",*[native+"/"+n for n in sorted(build["native_sha256"])]))
    assert {Path(l.split()[1]).name:l.split()[0] for l in installed.splitlines()}==build["native_sha256"]
    assert save("installed-apk.txt",adb("shell","sha256sum",native.removesuffix("/lib/arm64")+"/base.apk")).split()[0]==build["apk_sha256"]
    result.update(apk_sha256=build["apk_sha256"],native_sha256=build["native_sha256"])
    uid=int(adb("shell","run-as",PKG,"id","-u").strip());result["uid"]=uid
    save("device.txt",adb("shell","getprop","ro.product.device")+adb("shell","uname","-a"))
    dex=a.probe_build.parent/"classes.dex";assert digest(dex)==probe_build["dex_sha256"]
    adb("push",dex,remote);adb("shell","run-as",PKG,"cp",remote,destination);adb("shell","run-as",PKG,"chmod","444",destination)
    adb("shell","run-as",PKG,"rm","-rf","files/observation/t27-test")
    adb("shell","run-as",PKG,"mkdir","-p","files/observation/t27-test")
    adb("shell","run-as",PKG,"touch","files/observation/t27-test.enabled")
    test_config("initial",0)
    endpoint=subprocess.Popen(["python3","-u",str(ROOT/"tests/device/helpers/t23_udp_peer.py"),"server","--host",a.endpoint],stdout=(out/"endpoint.jsonl").open("w"),stderr=(out/"endpoint.log").open("w"))
    time.sleep(.2);assert endpoint.poll() is None
    host_capture=subprocess.Popen(["docker","run","--rm","--name",capture_name,"--network","host","--cap-add","NET_RAW","--cap-add","NET_ADMIN",
        "--mount","type=bind,source="+str(out)+",target=/evidence","sakamoto-vpp-nfq-poc:dev","tcpdump","-U","-i","any","-s","0","-w","/evidence/host.pcap","udp port 42151"],stdout=(out/"host-capture.log").open("w"),stderr=subprocess.STDOUT)
    capture_dir=root("mktemp -d /data/local/tmp/t27-capture.XXXXXX").strip();assert capture_dir.startswith("/data/local/tmp/t27-capture.")
    capture_pid=int(root("/system/bin/tcpdump -U -i any -s 0 -w "+capture_dir+"/wire.pcap 'udp port 42151' >"+capture_dir+"/capture.log 2>&1 & echo $!").strip())
    adb("shell","settings","put","global","stay_on_while_plugged_in","3")
    initial=start_runtime("initial");snapshot_counts(initial)
    local="10.111.0.2" if a.profile=="vpn" else "0.0.0.0"
    command="CLASSPATH="+shlex.quote("/data/user/0/"+PKG+"/"+destination)+" /system/bin/app_process / T23Probe "+shlex.join([a.endpoint,"42151","44500",local])
    probe=subprocess.Popen([str(ROOT/"dev/adb"),"-s",serial,"shell","-T","run-as",PKG,"sh","-c",shlex.quote(command)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(out/"probe.log").open("w"),bufsize=0)
    ready=save("probe-ready.json",probe_line());assert ready["ready"] and ready["uid"]==uid
    config=configuration("allow")
    allowed=send("allow",2,size=64);allowed_q=snapshot_counts(allowed)
    assert json.loads((out/"allow-traffic.json").read_text())["received"]==2
    assert allowed_q["packets"][0]>=2 and allowed_q["stored_minute_count"]>=1
    item=flow(allowed)
    cli("allow-close",f"product flow-end close owner {item['owner']} slot {item['slot']} generation {generation} incarnation {item['incarnation']}")
    ended=settle("allow-ended");ended_q=snapshot_counts(ended);assert ended_q["recent_count"]>=1
    configuration("drop",actions=(2,1))
    dropped=send("drop",2,size=64);dropped_q=snapshot_counts(dropped)
    assert json.loads((out/"drop-traffic.json").read_text())["received"]==0
    assert any(row["attribution"]["name"]=="drop-request" and row["counts"]["packets"][0]>=2
        for row in dropped_q["rule_windows"].values())
    selected_name="allow-request"
    selected=sum(row["counts"]["packets"][0] for row in dropped_q["rule_windows"].values()
        if row["attribution"]["name"]==selected_name)
    assert selected==2,selected
    result["selected_rule_packets"]=selected
    configuration("empty",empty=True)
    probe.stdin.write(b'{"quit":true}\n');probe.stdin.flush();probe.wait(timeout=10);probe=None
    before_idle=settle("idle-before");before_waits=before_idle["consumer"]["waits"]
    before_resource=resources("idle-before")
    time.sleep(5)
    after_idle=settle("idle-after");after_resource=resources("idle-after")
    result["idle_wake_cost"]=dict(seconds=5,waits_delta=after_idle["consumer"]["waits"]-before_waits,
        before=before_resource,after=after_resource)
    initial_db=stop_runtime("initial")
    initial_size=(out/"initial.sqlite3").stat().st_size
    test_config("pressure",0,max(64*1024,3*initial_size))
    pressured=start_runtime("pressure");pressure_q=snapshot_counts(pressured)
    assert side_ge(pressure_q["packets"],dropped_q["packets"])
    assert pressure_q["recent_count"]<ended_q["recent_count"] or pressure_q["hour_windows"]["counts"]["overall"]>0 or pressure_q["coverage"]["evicted"]["packets"][0]>0,pressure_q
    result["pressure_reclaimed"]=True
    stop_runtime("pressure")
    test_config("hour",3*60*1_000_000)
    hourly=start_runtime("hour");hour_q=snapshot_counts(hourly)
    assert hour_q["stored_minute_count"]==0 and hour_q["hour_windows"]["counts"]["overall"]>=1,hour_q
    assert side_ge(hour_q["packets"],pressure_q["packets"])
    assert sum(row["counts"]["packets"][0] for row in hour_q["hour_windows"]["rule_windows"].values()
        if row["attribution"]["name"]==selected_name)==selected
    stop_runtime("hour")
    test_config("day",4*60*60*1_000_000)
    daily=start_runtime("day");day_q=snapshot_counts(daily)
    assert day_q["hour_windows"]["counts"]["overall"]==0 and day_q["day_windows"]["counts"]["overall"]>=1,day_q
    assert side_ge(day_q["packets"],hour_q["packets"])
    assert sum(row["counts"]["packets"][0] for row in day_q["day_windows"]["rule_windows"].values()
        if row["attribution"]["name"]==selected_name)==selected
    stop_runtime("day")
    test_config("expired",4*24*60*60*1_000_000)
    expired=start_runtime("expired");expired_q=snapshot_counts(expired)
    assert expired_q["day_windows"]["counts"]["overall"]==0 and expired_q["coverage"]["evicted"]["packets"][0]>=selected,expired_q
    assert side_ge(expired_q["packets"],day_q["packets"])
    stop_runtime("expired")
    assert original_hashes("after")==original,"ordinary history changed"
    result["status"]="RAW_COMPLETE"
except Exception as error:
    result["error"]=repr(error);raise
finally:
    if probe is not None:
        try:probe.stdin.write(b'{"quit":true}\n');probe.stdin.flush();probe.wait(timeout=8)
        except Exception:probe.terminate();probe.wait(timeout=5)
    if started:
        try:
            if 'policy' in globals() and policy.get('saved_revision'):
                import_call("failure-cleanup-empty",requests.empty(),policy["saved_revision"])
        except Exception as error:result["cleanup_config_error"]=repr(error)
        save("failure-vpp.log",app("files/profiles/"+a.profile+"/vpp/logs/vpp-stdout.log",check=False))
        action("--ez","runtimeStop","true")
        try:state("cleanup-stopped","stopped")
        except Exception as error:result["cleanup_error"]=repr(error)
    if capture_pid is not None:
        root("kill -INT "+str(capture_pid),check=False);time.sleep(.3)
        save("device-capture.log",root("cat "+capture_dir+"/capture.log",check=False))
        root("chmod 644 "+capture_dir+"/wire.pcap; chmod 755 "+capture_dir)
        adb("pull",capture_dir+"/wire.pcap",out/"device.pcap")
        root("rm -f "+capture_dir+"/wire.pcap "+capture_dir+"/capture.log; rmdir "+capture_dir)
    if host_capture is not None:
        if host_capture.poll() is None:subprocess.run(["docker","kill","--signal","INT",capture_name],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=True)
        host_capture.wait(timeout=10)
    if endpoint is not None:endpoint.terminate();endpoint.wait(timeout=5)
    adb("shell","am","force-stop",PKG,check=False)
    adb("shell","run-as",PKG,"rm","-f","files/observation/t27-test.enabled",check=False)
    adb("shell","rm","-f",remote,check=False)
    adb("shell","run-as",PKG,"rm","-f",destination,*owned,check=False)
    adb("shell","settings","put","global","stay_on_while_plugged_in",previous_power,check=False)
    result["completed_ns"]=time.time_ns()
    result["files"]={str(path.relative_to(out)):digest(path) for path in out.rglob("*") if path.is_file()}
    save("result.json",result)
print(json.dumps({key:result.get(key) for key in ("status","profile","selected_rule_packets","pressure_reclaimed","lifetimes")},indent=2))
