#!/usr/bin/env python3
"""Independent packet/configuration oracle for T23. No Product aggregation code.

Checks real admission bytes and identities, logical outcomes, directional segment
boundaries, maintained API views, committed recovery, and retained network loss.
Mutations repair file seals so rejection must come from semantic checks.
"""
import argparse
from collections import Counter, defaultdict
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import zipfile

ROOT=Path(__file__).resolve().parents[2]
E02="5f0e31d428b24f10e788a08979003ed5348b91a75795bd6016c4f4f88ed57722"
PRE_QUERY="ba403a559afcf99397766e17f6d1cd137bb269f4820b3e3c89600c24d136c234"
HISTORICAL_PRE_QUERY=False
BUILD_CACHE=set()
CAPTURE_CACHE={}
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def records(text,prefix):
    return [dict(p.split("=",1) for p in line.split() if "=" in p) for line in text.splitlines() if line.startswith(prefix)]
def counts():return [0,0,0,0]
def count_of(value):return [*value["packets"],*value["bytes"]]
def plus(left,right):return [a+b for a,b in zip(left,right)]
def minus(left,right):return [a-b for a,b in zip(left,right)]
def window_counts(summary,kind,minute=False):
    answer=defaultdict(counts)
    for value in summary.get(kind,{}).values():
        if kind=="application_windows":key=(int(value["uid"]),int(value["actual_action"]))
        else:
            a=value["attribution"]
            key=tuple(int(a[k]) for k in ("policy_generation","policy_revision","policy_hash","winner","uid","network","declared_action","actual_action","mode"))+(a["name"],)
        if minute:key=(int(value["minute"]),*key)
        answer[key]=plus(answer[key],count_of(value["counts"]))
    return dict(answer)
def difference(after,before):return {key:minus(after.get(key,counts()),before.get(key,counts())) for key in after.keys()|before.keys() if after.get(key,counts())!=before.get(key,counts())}
def total(mapping):
    value=counts()
    for row in mapping.values():value=plus(value,row)
    return value

def capture(path):
    key=(str(path),digest(path))
    if key in CAPTURE_CACHE:return CAPTURE_CACHE[key]
    fields=("ip.src","ip.dst","udp.srcport","udp.dstport","ip.len","udp.payload")
    command=["tshark","-r",str(path),"-Y","udp.port==42151","-T","fields"]
    for field in fields:command.extend(["-e",field])
    text=subprocess.check_output(command,text=True,stderr=subprocess.DEVNULL)
    answer=defaultdict(list)
    for line in text.splitlines():
        parts=line.split("\t")
        if len(parts)==6 and parts[5]:answer[parts[5].replace(":","")].append(dict(zip(fields,parts)))
    CAPTURE_CACHE[key]=answer;return answer

def build_closure(result):
    path=Path(result["build"]);b=json.loads(path.read_text())
    assert digest(path)==result["build_sha256"],"build manifest identity"
    assert result["source_sha256"]==b["source_sha256"],"run source identity"
    if result["baseline"]:assert b["source_sha256"]==E02,"only accepted E02 comparator"
    elif HISTORICAL_PRE_QUERY:
        assert result["scenario"]=="benchmark" and b["source_sha256"]==PRE_QUERY,"only pinned pre-query benchmark comparator"
    else:
        spec=importlib.util.spec_from_file_location("chain",ROOT/"tests/evidence/product_chain.py")
        chain=importlib.util.module_from_spec(spec);spec.loader.exec_module(chain)
        assert chain.source_files()==b["files"],"current Product differs from accepted artifact"
    key=(str(path),digest(path))
    if key not in BUILD_CACHE:
        encoded=json.dumps(b["files"],sort_keys=True,separators=(",",":")).encode()
        assert hashlib.sha256(encoded).hexdigest()==b["source_sha256"],"source closure"
        for name,value in b["files"].items():
            if value is not None:assert digest(path.parent/"source"/name)==value,"source snapshot: "+name
        assert digest(path.parent/"dirty.diff")==b["dirty_diff_sha256"],"source diff witness"
        if result["kind"]=="linux":
            for name,value in b["artifact_hashes"].items():assert digest(Path(b["artifact"])/name)==value,"Host artifact: "+name
        else:
            assert digest(b["apk"])==b["apk_sha256"],"APK identity"
            with zipfile.ZipFile(b["apk"]) as archive:
                native={Path(name).name:hashlib.sha256(archive.read(name)).hexdigest() for name in archive.namelist() if name.startswith("lib/arm64-v8a/") and name.endswith(".so")}
            assert native==b["native_sha256"],"APK native closure"
        BUILD_CACHE.add(key)
    assert b["completed_ns"]<result["started_ns"],"build precedes execution"
    return b

def verify(directory,overrides=None):
    directory=Path(directory);overrides=overrides or {}
    def read(name):return overrides[name] if name in overrides else (directory/name).read_text()
    def data(name):return json.loads(read(name))
    try:
        result=data("result.json")
        assert result["status"]=="RAW_COMPLETE" and result["completed_ns"]>result["started_ns"],"collector incomplete"
        for name,expected in result["files"].items():
            actual=hashlib.sha256(overrides[name].encode()).hexdigest() if name in overrides else digest(directory/name)
            assert actual==expected,"run closure: "+name
        build=build_closure(result)
        baseline_name="baseline" if result["kind"]=="linux" else "first-baseline"
        initial=data(baseline_name+".json")["consumer"]["persistent"]
        first_generation=result["lifetimes"][0]["generation"]
        assert all(life["process_absent"] for life in result["lifetimes"]),"VPP cleanup"
        if result["kind"]=="android":
            assert all(life["service_process_absent"] for life in result["lifetimes"]),"Service process replacement"
            assert len({life["service_pid"] for life in result["lifetimes"]})==len(result["lifetimes"])
            assert result["apk_sha256"]==build["apk_sha256"] and result["native_sha256"]==build["native_sha256"]
            assert read("installed-apk.txt").split()[0]==build["apk_sha256"]
            assert {Path(l.split()[1]).name:l.split()[0] for l in read("installed-native.txt").splitlines()}==build["native_sha256"]
            assert data("probe-ready.json")["uid"]==result["uid"],"real application identity"
            assert read("legacy-before-sha256.txt")==read("legacy-after-sha256.txt"),"original JSON preserved"
            prior=data("before-store.json");stopped=data("first-store.json")
            assert result["preexisting_rows_preserved"]==len(prior)-1
            for key,value in prior.items():
                if key=="0:":continue
                after=stopped[key];kind=int(key.split(":",1)[0])
                if kind in (3,6):assert all(a>=b for a,b in zip(count_of(after),count_of(value))),"pre-existing minute contribution"
                elif kind in (4,5):
                    assert {k:v for k,v in after.items() if k!="counts"}=={k:v for k,v in value.items() if k!="counts"},"historical window identity"
                    assert all(a>=b for a,b in zip(count_of(after["counts"]),count_of(value["counts"]))),"pre-existing effect contribution"
                else:assert after==value,"pre-existing committed identity: "+key
            assert "state=stopped" in read("cleanup-state.txt") and "mayBeActive=false" in read("cleanup-state.txt")
            assert not any(Path(parts[2].split()[0]).name=="libvpp_runtime.so" for line in read("cleanup-processes.txt").splitlines() if len(parts:=line.split(None,2))==3 and parts[0].isdigit()),"no remaining VPP"
            assert "0 packets dropped by kernel" in read("device-capture.log") and "0 packets dropped by kernel" in read("host-capture.log"),"capture loss"
        else:
            assert "0 packets dropped by kernel" in read("capture.log"),"capture loss"
            assert "42151" not in read("final-hooks.txt"),"owned hooks removed"
            assert data("final-database.json")["integrity"]=="ok"

        configs={}
        for item in result["configurations"]:
            submitted=data(item["input"])
            text=read(item["response"])
            response=json.loads(text.split("import.response=",1)[1]) if item["response"].endswith(".txt") else json.loads(text)
            assert response["result"]==0 and response["saved_revision"]==response["active_revision"]==item["revision"],"saved/applied complete configuration"
            configured=response["configuration"]
            assert configured["bindings"]==submitted["bindings"] and configured["groups"]==configured["edges"]==configured["lists"]==[]
            rules=[]
            for side,rule in enumerate(configured["rules"]):
                fields=rule["definition"].split();source=submitted["rules"][side]
                assert fields[2:]==source["definition"].split()[2:] and rule["name"]==source["name"],"import content/name"
                assert fields[2:10]==["4294967295","4294967295","4294967295","10",str(side),"17","0",str(item["actions"][side])]
                assert fields[10:]==["*","*","0","65535","0","65535",f"0e0{side+1}"],"independent directional policy domain"
                assert int(fields[0])!=0 and int(fields[0])&65535!=0
                rules.append(dict(version=int(fields[0]),name=rule["name"],action=int(fields[9])))
            assert len(rules)==(0 if item["empty"] else 2),"NoMatch has no invented source rule"
            bindings={}
            for _,uid,kind,target,mode in configured["bindings"]:
                assert kind==1 and target in (0,1) and mode==item["modes"][target]
                key=(uid,target);assert key not in bindings or bindings[key]==mode
                bindings[key]=mode
            configs[item["label"]]=dict(**item,rules=rules,bindings=bindings)

        payloads={};phase_by_name={}
        for phase in result["phases"]:
            traffic=data(phase["traffic"]);assert traffic["label"]==phase["label"]
            assert traffic["startedMonoNs"]<traffic["completedMonoNs"]
            assert len(traffic["exchanges"])==traffic["sent"]==phase["request"]["count"]
            assert sum(x["echoed"] for x in traffic["exchanges"])==traffic["received"]
            phase_by_name[phase["label"]]=phase
            for row in traffic["exchanges"]:
                payload=row["payload"];assert payload not in payloads,"unique packet payload"
                assert len(bytes.fromhex(payload))==phase["request"]["size"]
                assert row["sentMonoNs"]<=row["endMonoNs"] and 43500<=row["sourcePort"]<46000
                payloads[payload]=dict(phase=phase,row=row,observed=True,packets={})
        if result["kind"]=="linux" and result["scenario"]=="semantic":
            dead=data("consumer-dead-traffic.json");assert dead["sent"]==dead["received"]==2
            phase=dict(label="consumer-dead",generation=first_generation,uid=12003,configuration="after-gap")
            for row in dead["exchanges"]:
                assert row["payload"] not in payloads
                payloads[row["payload"]]=dict(phase=phase,row=row,observed=False,packets={})
            health=json.loads(read("consumer-dead-health.txt").split("observation.response=",1)[1])
            assert health["health"]["connected"]==0,"disconnected consumer does not stop packets"

        histories=defaultdict(dict);packet_rows=[];native_packets=0;native_bytes=0;cache_hits=0;background=[]
        logs=[(life["generation"],f"vpp-{life['generation']}.log") for life in result["lifetimes"]] if result["kind"]=="linux" else [(life["generation"],("first" if i==0 else "restart")+"-vpp.log") for i,life in enumerate(result["lifetimes"])]
        for generation,name in logs:
            text=read(name)
            stages={stage:{r["token"]:r for r in records(text,"s216 ") if r["stage"]==stage and r["protocol"]=="17" and ("42151" in (r["src_port"],r["dst_port"]) or (result["kind"]=="android" and result["profile"]=="root" and r["dst_port"]=="1900"))} for stage in ("admit","policy","terminal")}
            assert stages["admit"].keys()==stages["policy"].keys()==stages["terminal"].keys(),"complete native packet lifecycle"
            decisions={r["token"]:r for r in records(text,"s209 ") if r["event"]=="l4"}
            updates={r["token"]:r for r in records(text,"s223 ") if r["event"]=="udp_update"}
            cache={r["token"]:r for r in records(text,"t11 ") if r["event"]=="cache" and r["position"]=="2"}
            for token,admit in stages["admit"].items():
                raw=bytes.fromhex(admit["raw"]);length=int(admit["packet_length"]);offset=int(admit["transport_offset"])
                assert len(raw)==length and raw[0]>>4==4 and raw[9]==17
                assert int.from_bytes(raw[2:4],"big")==length and int.from_bytes(raw[offset+4:offset+6],"big")==length-offset
                payload=raw[offset+8:].hex()
                is_background=payload not in payloads
                if is_background:
                    # Root also observes unsolicited LAN discovery. Keep this
                    # separately identified real NFQUEUE capture, not a fake
                    # extra echo or an application-owned rule contribution.
                    assert result["kind"]=="android" and result["profile"]=="root" and admit["dst_port"]=="1900" and raw[offset+8:].startswith(b"M-SEARCH * HTTP/1.1\r\n"),"unclassified background packet"
                    assert not int(admit["availability"])&1,"background application is unavailable"
                    d=decisions[token];u=updates[token]
                    cfg=next(c for c in configs.values() if c["generation"]==generation and c["revision"]==int(d["revision"]) and c["snapshot_hash"]==int(d["snapshot_hash"]))
                    info=dict(phase=dict(label="background-ssdp",generation=generation,configuration=cfg["label"]),row=dict(sourcePort=int(admit["src_port"])),observed=True,packets={})
                    side=int(u["flow_dir"])-1
                    background.append(dict(generation=generation,token=int(token),packet_bytes=length,uid=4294967295,source="NFQ_CAPTURED",payload_sha256=hashlib.sha256(raw[offset+8:]).hexdigest()))
                else:
                    info=payloads[payload];side=0 if admit["dst_port"]=="42151" else 1
                phase=info["phase"];assert phase["generation"]==generation
                assert side not in info["packets"],"one logical packet per direction"
                assert int(admit["src_port"] if side==0 else admit["dst_port"])==info["row"]["sourcePort"]
                assert length==len(bytes.fromhex(payload))+28,"IP header byte accounting"
                policy=stages["policy"][token];terminal=stages["terminal"][token]
                for row in (policy,terminal):
                    assert all(row[k]==admit[k] for k in ("generation","token","src","dst","src_port","dst_port","packet_length","source")),"native identity stable through graph"
                assert int(admit["generation"])==generation
                expected_source="NFQ_CAPTURED" if result["profile"]=="root" else ("TUN_CAPTURED" if side==0 else "FLOW_STACK_RETURN")
                assert admit["source"]==expected_source,"real adapter source"
                d=decisions[token];u=updates[token];cfg=configs[phase["configuration"]]
                assert int(d["generation"])==generation and int(d["revision"])==cfg["revision"] and int(d["snapshot_hash"])==cfg["snapshot_hash"],"one complete protected policy version"
                assert int(d["flow_dir"])==side+1 and int(u["flow_dir"])==side+1,"ORIG/REPLY differs from device direction"
                uid=int(policy["uid"]) if int(policy["availability"])&1 else 4294967295
                network=int(policy["context"]) if int(policy["availability"])&4 else 4294967295
                # Unavailable network context retains the existing explicit sentinel.
                selected=cfg["rules"][side] if cfg["rules"] and (uid,side) in cfg["bindings"] else None
                winner=selected["version"] if selected else 0
                declared=selected["action"] if selected else 1
                mode=cfg["bindings"][(uid,side)] if selected else 0
                actual=1 if mode else declared
                assert int(d["rule"])==winner and int(d["status"])==0,"logical winner independent oracle"
                assert int(d["mode"])==mode and int(d["action"])==(declared if selected else 0) and int(d["actual_action"])==(actual if selected else 0),"NoMatch/observe semantics"
                assert int(terminal["intent"])==actual,"declared action differs from actual policy outcome"
                if result["scenario"]=="semantic" and phase["label"] not in ("nomatch","consumer-dead","background-ssdp"):
                    assert selected is not None,"required app attribution available for rule acceptance"
                context=(generation,cfg["revision"],cfg["snapshot_hash"],winner,uid,network,declared,actual,mode,selected["name"] if selected else "")
                identity=(generation,int(u["owner"]),int(u["slot"]),int(u["incarnation"]))
                row=dict(identity=identity,context=context,side=side,length=length,at=int(d["mono_ns"]),
                    observed=info["observed"],phase=phase["label"],payload=payload,device_direction=int(policy["direction"]))
                packet_rows.append(row);info["packets"][side]=row
                native_packets+=1;native_bytes+=length;cache_hits+=int(cache[token]["hit"])
            assert "stop_native_zero" in text or result["kind"]=="android","native shutdown settlement"
        assert cache_hits>0,"warm cache uses same logical accounting"
        for info in payloads.values():assert 0 in info["packets"],"every sent request reached actual Product"

        # Reconstruct segments from independent admitted packets + public source
        # rules. This does not read exporter counters or reproduce its wire code.
        running={}
        for packet in sorted(packet_rows,key=lambda r:r["at"]):
            identity=packet["identity"];side=packet["side"]
            current=running.setdefault(identity,dict(packets=[0,0],bytes=[0,0],segments=[None,None]))
            previous=current["segments"][side]
            if previous is None or previous["context"]!=packet["context"]:
                current["segments"][side]=dict(number=1 if previous is None else previous["number"]+1,
                    start_packets=current["packets"][side],start_bytes=current["bytes"][side],context=packet["context"])
            current["packets"][side]+=1;current["bytes"][side]+=packet["length"]
            current["last_direction"]=packet["device_direction"];current["last_side"]=side
            histories[identity][sum(current["packets"])]=copy.deepcopy(current)

        expected_apps=defaultdict(counts);expected_rules=defaultdict(counts);gap_rules=set();expected_total=counts()
        for packet in packet_rows:
            if not packet["observed"]:continue
            side=packet["side"];delta=counts();delta[side]=1;delta[side+2]=packet["length"]
            expected_total=plus(expected_total,delta);context=packet["context"]
            app=(context[4],context[7]);expected_apps[app]=plus(expected_apps[app],delta)
            if context[3]:expected_rules[context]=plus(expected_rules[context],delta)
            if packet["phase"].startswith("gap-"):gap_rules.add(context)
        assert any(key[3]>2**53 for key in expected_rules),"full rule versions beyond JS exact-number range are retained"

        for snapshot_item in result["snapshots"]:
            value=data(snapshot_item["label"]+".json");health=value["health"];consumer=value["consumer"];q=consumer["persistent"]
            assert health["generation"]==snapshot_item["generation"] and health["version"]==(2 if result["baseline"] else 3)
            assert health["mapping_bytes"]==(332544 if result["baseline"] else 922368)
            assert health["flow_capacity"]==1024 and health["owners"]==2
            for i,channel in enumerate(health["channels"]):
                assert channel["capacity"]==512 and channel["occupancy"]<=512
                assert channel["oversize"]==channel["notify_errors"]==0
                if i%2:assert channel["attempted"]==0,"debug channel independent"
            if not result["baseline"] and not HISTORICAL_PRE_QUERY:
                assert consumer["query_fresh"] is True and consumer["query_error"] is None,"fresh owner query required"
            assert consumer["malformed"]==0 and consumer["error"] is None and consumer["store_error"] is None
            assert q["storage"]=="sqlite" and q["visibility"]=="live_including_pending" and q["save_error"] is None
            assert q["persistence"]["pending_rows"]<=4096
            assert total({k:count_of(v) for k,v in q["minutes"].items()})==count_of(q),"overall maintained minutes"
            nonzero=[int(k) for k,v in q["minutes"].items() if any(count_of(v))]
            if nonzero:
                assert q["coverage"]["first_activity_us"]//60000000*60<=min(nonzero),"coverage includes earliest retained minute"
                assert q["coverage"]["last_activity_us"]//60000000*60>=max(nonzero),"coverage includes latest retained minute"
            if not result["baseline"]:
                assert not q["application_query_truncated"] and not q["rule_query_truncated"] and not q["unknown_query_truncated"]
                app_counts=window_counts(q,"application_windows")
                assert plus(total(app_counts),count_of(q["attribution_unknown"]))==count_of(q),"application + unknown = overall exactly once"
                unknown=total({k:count_of(v) for k,v in q["attribution_unknown_minutes"].items()})
                assert plus(unknown,count_of(q["legacy_unattributed"]))==count_of(q["attribution_unknown"]),"legacy is explicit, not latest attribution"
                overall_delta=difference({int(k):count_of(v) for k,v in q["minutes"].items()},{int(k):count_of(v) for k,v in initial["minutes"].items()})
                window_delta=defaultdict(counts)
                for summary,sign in ((q,1),(initial,-1)):
                    for window in summary["application_windows"].values():
                        minute=window["minute"];window_delta[minute]=plus(window_delta[minute],[sign*x for x in count_of(window["counts"])])
                    for minute,window in summary["attribution_unknown_minutes"].items():
                        window_delta[int(minute)]=plus(window_delta[int(minute)],[sign*x for x in count_of(window)])
                assert {k:v for k,v in window_delta.items() if any(v)}==overall_delta,"same-consumption minute/view consistency"
                for rule,value in window_counts(q,"rule_windows").items():
                    assert rule[3]!=0,"default ALLOW never becomes a rule hit"
                    if rule[0]>=first_generation:
                        assert rule in expected_rules,"full historical snapshot/version/name reference"
                        assert all(x<=y for x,y in zip(value,expected_rules[rule])),"no duplicated logical winner or latest-rule backfill"
                for record in consumer["overview"]["records"]:
                    if record is None:continue
                    identity=tuple(record[k] for k in ("generation","owner","slot","incarnation"))
                    # Non-UDP control observations are outside this workload.
                    if record["protocol"]!=17 or identity not in histories:continue
                    expected=histories[identity][sum(record["packets"])]
                    assert record["packets"]==expected["packets"] and record["bytes"]==expected["bytes"],"directional cumulative packet oracle"
                    assert record["last_device_direction"]==expected["last_direction"] and record["last_flow_direction"]==expected["last_side"]+1
                    for side,context in enumerate(record["attribution"]):
                        segment=expected["segments"][side]
                        if segment is None:assert context["segment"]==0;continue
                        assert context["valid"] and context["segment"]==segment["number"],"direction-local segment boundaries"
                        assert context["start_packets"]==segment["start_packets"] and context["start_bytes"]==segment["start_bytes"],"boundary precedes first contribution"
                        actual=tuple(int(context[k]) for k in ("policy_generation","policy_revision","policy_hash","winner","uid","network","declared_action","actual_action","mode"))+(context["name"],)
                        assert actual==segment["context"],"context belongs to that direction and exact version"
        final=data("final.json")["consumer"]["persistent"]
        assert minus(count_of(final),count_of(initial))==expected_total,"real C packet totals equal maintained API growth"
        assert final["persistence"]["packets"]==final["packets"] and final["persistence"]["bytes"]==final["bytes"] and not final["persistence"]["pending"],"durable final tail"
        if not result["baseline"]:
            actual_apps=difference(window_counts(final,"application_windows"),window_counts(initial,"application_windows"))
            actual_rules=difference(window_counts(final,"rule_windows"),window_counts(initial,"rule_windows"))
            unknown_delta=minus(count_of(final["attribution_unknown"]),count_of(initial["attribution_unknown"]))
            for key,value in expected_rules.items():
                actual=actual_rules.get(key,counts())
                if key not in gap_rules:assert actual==value,"exact rule effects outside known export gap"
                else:assert all(0<=x<=y for x,y in zip(actual,value)),"missing boundary cannot move to latest winner"
            assert actual_rules.keys()<=expected_rules.keys()
            assert all(all(0<=x<=y for x,y in zip(value,expected_apps[key])) for key,value in actual_apps.items()),"application association is historical"
            assert minus(expected_total,total(actual_apps))==unknown_delta,"all unattributable differences explicit"
            if not gap_rules:assert unknown_delta==counts() and actual_apps==dict(expected_apps),"complete directional application effects"
            else:assert unknown_delta[0]>0 and unknown_delta[1]>0 and final["coverage"]["incomplete"]
        if result["scenario"]=="semantic":
            names=set(phase_by_name);assert {"nomatch","request-allow","request-observe","request-drop","reply-drop","both-observe","end-tail"}<=names
            assert len([n for n in names if n.startswith("switch-")])==6
            ended=data("ended.json");r=next(r for r in ended["consumer"]["overview"]["records"] if r and r["ports"][0] in (43500,44500))
            assert r["ended"] and all(r[k]==result["first_identity"][k] for k in ("owner","slot","incarnation")),"winner changes preserve Flow identity through END"
            if result["kind"]=="linux":
                assert r["sequence"]==result["end_previous_sequence"]+1,"combined END carries unexported tail"
                assert sum(c["full"] for c in data("full.json")["health"]["channels"])>0
                restored=data("restart.json")["consumer"]["persistent"]
                for field in ("packets","bytes","minutes","application_windows","rule_windows","attribution_unknown"):
                    assert restored[field]==ended["consumer"]["persistent"][field],"committed multi-view restart"
                assert restored["coverage"]["recoveries"]>initial["coverage"]["recoveries"]
            else:
                restored=data("restart-baseline.json")["consumer"]["persistent"]
                for field in ("packets","bytes","minutes","application_windows","rule_windows","attribution_unknown"):
                    assert restored[field]==final[field],"physical Service replacement preserves history"
        else:
            assert [(phase["label"],phase["request"]["count"]) for phase in result["phases"]]==[("low",20),("burst",256),("sustained",1000),("active",512),("short",128)],"E01 representative workload"

        endpoints={row["payload"]:row for row in map(json.loads,read("endpoint.jsonl").splitlines()) if "payload" in row}
        assert endpoints.keys()<=payloads.keys(),"endpoint identity"
        host_capture=capture(directory/("host.pcap" if result["kind"]=="android" else "wire.pcap"))
        device_capture=capture(directory/"device.pcap") if result["kind"]=="android" else None
        network_losses=[];policy_drops=0
        for payload,info in payloads.items():
            request=info["packets"][0];reply=info["packets"].get(1);echoed=info["row"]["echoed"]
            if request["context"][7]==2:
                assert payload not in endpoints and reply is None and not echoed,"actual request DROP"
                policy_drops+=1;continue
            if reply is not None and reply["context"][7]==2:
                assert payload in endpoints and not echoed,"actual reply DROP"
                policy_drops+=1;continue
            if echoed:
                assert payload in endpoints and reply is not None,"delivered echo crossed both Product directions"
                assert any(row["udp.srcport"]=="42151" for row in host_capture[payload]),"remote reply capture"
                continue
            assert result["kind"]=="android","unexpected Linux packet loss"
            host_replies=[row for row in host_capture[payload] if row["udp.srcport"]=="42151"]
            device_replies=[row for row in device_capture[payload] if row["udp.srcport"]=="42151"]
            assert payload in endpoints and host_replies and not device_replies and reply is None,"unclassified allowed-packet failure"
            network_losses.append(dict(phase=info["phase"]["label"],payload=payload,classification="host_egress_to_device_ingress",native_reply=False))
        if result["scenario"]=="semantic":assert policy_drops==4,"actual directional blocking witnessed"
        return dict(status="VALID",scope="E02 matched comparator" if result["baseline"] else ("historical pre-query T23 benchmark comparator" if HISTORICAL_PRE_QUERY else "T23 directional attribution"),
            kind=result["kind"],profile=result["profile"],scenario=result["scenario"],source_sha256=result["source_sha256"],
            native_packets=native_packets,native_bytes=native_bytes,maintained_growth=expected_total,background_packets=background,
            cache_hits=cache_hits,policy_drop_packets=policy_drops,network_losses=network_losses,
            rule_effect_classes=len(expected_rules),flow_instances=len(histories),error=None)
    except (AssertionError,KeyError,ValueError,IndexError,StopIteration,TypeError) as error:
        return dict(status="INVALID",error=str(error) or type(error).__name__)


def mutations(directory):
    directory=Path(directory);result=json.loads((directory/"result.json").read_text());cases={}
    def changed(name,edit):
        value=json.loads((directory/name).read_text());edit(value);return {name:json.dumps(value)}
    def first_rule(value):return next(iter(value["consumer"]["persistent"]["rule_windows"].values()))
    if not result["baseline"]:
        cases["winner-version"]=changed("final.json",lambda v:first_rule(v)["attribution"].__setitem__("winner",int(first_rule(v)["attribution"]["winner"])+1))
        cases["snapshot-hash"]=changed("final.json",lambda v:first_rule(v)["attribution"].__setitem__("policy_hash",0))
        cases["historical-name"]=changed("final.json",lambda v:first_rule(v)["attribution"].__setitem__("name","latest renamed rule"))
        cases["observe-collapse"]=changed("final.json",lambda v:first_rule(v)["attribution"].__setitem__("actual_action",2))
        cases["application-uid"]=changed("final.json",lambda v:next(iter(v["consumer"]["persistent"]["application_windows"].values())).__setitem__("uid",1))
        cases["duplicate-logical-hit"]=changed("final.json",lambda v:first_rule(v)["counts"]["packets"].__setitem__(0,first_rule(v)["counts"]["packets"][0]+1))
        sample=result["phases"][-1]["snapshot"]
        def segment(v):
            r=next(r for r in v["consumer"]["overview"]["records"] if r and r["protocol"]==17 and 42151 in r["ports"])
            r["attribution"][0]["start_packets"]+=1
        cases["segment-start"]=changed(sample,segment)
    if not result["baseline"] and not HISTORICAL_PRE_QUERY:
        cases["stale-query"]=changed("final.json",lambda v:v["consumer"].__setitem__("query_fresh",False))
    cases["packet-total"]=changed("final.json",lambda v:v["consumer"]["persistent"]["packets"].__setitem__(0,v["consumer"]["persistent"]["packets"][0]+1))
    cases["byte-total"]=changed("final.json",lambda v:v["consumer"]["persistent"]["bytes"].__setitem__(1,v["consumer"]["persistent"]["bytes"][1]+1))
    cases["wrong-generation"]=changed("final.json",lambda v:v["health"].__setitem__("generation",0))
    cases["uncommitted-is-durable"]=changed("final.json",lambda v:v["consumer"]["persistent"]["persistence"].__setitem__("pending",True))
    if result["scenario"]=="semantic":
        cases["end-lost"]=changed("ended.json",lambda v:next(r for r in v["consumer"]["overview"]["records"] if r and 42151 in r["ports"]).__setitem__("ended",False))
        if result["kind"]=="linux":
            cases["gap-erased"]=changed("final.json",lambda v:v["consumer"]["persistent"]["attribution_unknown"].__setitem__("packets",[0,0]))
            cases["queue-loss-hidden"]=changed("full.json",lambda v:[c.__setitem__("full",0) for c in v["health"]["channels"]])
    answers={}
    for label,override in cases.items():
        sealed=copy.deepcopy(result)
        for name,text in override.items():sealed["files"][name]=hashlib.sha256(text.encode()).hexdigest()
        override["result.json"]=json.dumps(sealed)
        answer=verify(directory,override);answers[label]=answer
        assert answer["status"]=="INVALID",("insensitive semantic mutation",label,answer)
    return answers

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("directory",type=Path);p.add_argument("--output",type=Path);p.add_argument("--mutations",action="store_true");p.add_argument("--historical-pre-query",action="store_true");a=p.parse_args()
    HISTORICAL_PRE_QUERY=a.historical_pre_query
    answer=verify(a.directory)
    if answer["status"]=="VALID" and a.mutations:answer["negative_witnesses"]=mutations(a.directory)
    text=json.dumps(answer,indent=2)+"\n"
    if a.output:a.output.write_text(text)
    print(text,end="");raise SystemExit(0 if answer["status"]=="VALID" else 1)
