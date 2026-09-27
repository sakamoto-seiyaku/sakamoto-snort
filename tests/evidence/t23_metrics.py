#!/usr/bin/env python3
"""Recompute scoped T23 export/consumer costs from sealed process snapshots."""
import argparse
import hashlib
import json
from pathlib import Path


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def summarize(directory,verification):
    directory=Path(directory);verification=Path(verification)
    verdict=json.loads(verification.read_text());result=json.loads((directory/"result.json").read_text())
    assert verdict["status"]=="VALID" and result["scenario"]=="benchmark"
    assert verdict["source_sha256"]==result["source_sha256"]
    for name,expected in result["files"].items():assert digest(directory/name)==expected
    def summary(label):return json.loads((directory/(label+".json")).read_text())
    previous=summary("baseline" if result["kind"]=="linux" else "first-baseline")
    def cpu(sample):
        if "cpu_ticks" in sample:return sample["cpu_ticks"]
        return sample["stats"][0]["cpu_ticks"]
    def consumer_cpu(sample):
        rows=sample["stats"] if "stats" in sample else sample["threads"].values()
        found=[row for row in rows if row["name"].startswith("flow-observ")]
        assert len(found)==1,"one measured observation consumer thread"
        return found[0]["cpu_ticks"]
    def field(sample,name):
        if "fields" in sample:return sample["fields"][name]
        return (sample["io"] if name in sample["io"] else sample["status"])[name]
    rows=[]
    for phase in result["phases"]:
        before=phase["before"];after=phase["after"];hz=before["ticks_per_second"]
        assert hz==after["ticks_per_second"]
        value=summary(phase["label"]);q=value["consumer"]["persistent"]
        assert not q["persistence"]["pending"] and not q["persistence"]["maintenance_pending"]
        assert q["persistence"]["packets"]==q["packets"]
        row={"phase":phase["label"],"packets":[q["packets"][i]-previous["consumer"]["persistent"]["packets"][i] for i in (0,1)],
            "vpp_cpu_ms":(cpu(after["vpp"])-cpu(before["vpp"]))*1000/hz,
            "consumer_cpu_ms":(consumer_cpu(after["rust"])-consumer_cpu(before["rust"]))*1000/hz,
            "service_process_cpu_ms":(cpu(after["rust"])-cpu(before["rust"]))*1000/hz,
            "process_write_bytes":int(field(after["rust"],"write_bytes"))-int(field(before["rust"],"write_bytes")),
            "process_wchar":int(field(after["rust"],"wchar"))-int(field(before["rust"],"wchar")),
            "service_hwm_kib":int(field(after["rust"],"VmHWM").split()[0]),
            "service_rss_kib":int(field(after["rust"],"VmRSS").split()[0]),
            "vpp_hwm_kib":int(field(after["vpp"],"VmHWM").split()[0]),
            "commits":q["persistence"]["commits"]-previous["consumer"]["persistent"]["persistence"]["commits"],
            "checkpoints":q["persistence"]["checkpoints"]-previous["consumer"]["persistent"]["persistence"]["checkpoints"],
            "export_attempts":sum(value["health"]["channels"][i]["attempted"]-previous["health"]["channels"][i]["attempted"] for i in (0,2)),
            "export_full":sum(value["health"]["channels"][i]["full"]-previous["health"]["channels"][i]["full"] for i in (0,2)),
            "notifications":sum(value["health"]["channels"][i]["notifications"]-previous["health"]["channels"][i]["notifications"] for i in (0,2)),
            "api_file_bytes":(directory/phase["snapshot"]).stat().st_size}
        assert all(row[key]>=0 for key in ("vpp_cpu_ms","consumer_cpu_ms","service_process_cpu_ms","process_write_bytes","commits","export_attempts","export_full"))
        rows.append(row);previous=value
    summed={key:sum(row[key] for row in rows) for key in ("vpp_cpu_ms","consumer_cpu_ms","service_process_cpu_ms","process_write_bytes","process_wchar","commits","checkpoints","export_attempts","export_full","notifications")}
    database=directory/("observation/overall.sqlite3" if result["kind"]=="linux" else "first.sqlite3")
    return dict(kind=result["kind"],profile=result["profile"],baseline=result["baseline"],seed_baselines=result.get("seed_baselines"),
        source_sha256=result["source_sha256"],verification_sha256=digest(verification),result_sha256=digest(directory/"result.json"),
        rows=rows,sums=summed,service_hwm_kib=max(row["service_hwm_kib"] for row in rows),vpp_hwm_kib=max(row["vpp_hwm_kib"] for row in rows),
        final_database_bytes=database.stat().st_size,network_losses=verdict["network_losses"],
        limits="Single runs, process CPU in 10ms ticks; normal traffic windows include final persistence and ordinary query work, exclude preceding configuration apply. Process write_bytes is not NAND/energy. Phone inherited history grows between runs; no engine-only, latency-SLO, power/thermal or strict randomized A/B claim.")

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("directory",type=Path);p.add_argument("--verification",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    value=summarize(a.directory,a.verification);a.output.write_text(json.dumps(value,indent=2)+"\n");print(json.dumps({k:value[k] for k in ("kind","baseline","seed_baselines","sums","service_hwm_kib","final_database_bytes")},indent=2))
