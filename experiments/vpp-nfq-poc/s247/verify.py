#!/usr/bin/env python3
"""S247: classify observed live-object bounds, not assumed minimum capacity."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys


def rows(path):
    result = []
    for number, line in enumerate(path.read_text().splitlines()):
        if re.search(r"s24[567] event=", line):
            d = dict(re.findall(r"([a-zA-Z_]+)=([^\s]+)", line))
            d["line"] = number
            result.append(d)
    return result


def verify(path):
    path = Path(path)
    config = json.loads((path / "manifest.json").read_text())
    pool_limit, credit_limit = config["pbuf_limit"], config["credit_limit"]
    pattern = config["pattern"]
    log = (path / "vpp.log").read_text()
    events = rows(path / "vpp.log")
    app = rows(path / "app.log")
    errors = []
    def require(ok, message):
        if not ok:
            errors.append(message)
    def selected(name, sequence=None):
        return [d for d in events if d.get("event") == name and (sequence is None or d.get("seq") == str(sequence))]
    def single(name, sequence):
        result = selected(name, sequence)
        require(len(result) == 1, f"{name} seq={sequence}: expected one, got {len(result)}")
        return result[0] if result else {"line": -1}

    expected_inputs = 4 if pattern == "burst" else 2 if pattern == "stop" else 3
    results = [d for d in app if d.get("event") == "app_result"]
    require(len(results) == expected_inputs, "complete real app packet set required")
    require(any(d.get("event") == "app_done" for d in app), "bounded app completion required")
    require(not any(d.get("result") == "MISMATCH" for d in app), "unexpected or duplicate app payload")
    require(len({d.get("local_port") for d in results}) == 1, "same app UDP socket required")
    require(len(selected("input_enter")) == expected_inputs, "all registered app packets reach real boundary")
    require({d.get("owner") for d in selected("input_enter")} == {"1"}, "single actual VPP owner required")
    require(len({d.get("generation") for d in selected("input_enter")}) == 1, "same owner generation across pressure/recovery")
    actual_config = selected("config")
    require(len(actual_config) == 1 and actual_config[0].get("pbuf_limit") == str(pool_limit) and
            actual_config[0].get("credit_limit") == str(credit_limit), "runtime configuration provenance")

    accepted = []
    for seq in range(1, expected_inputs + 1):
        trace = [single(name, seq) for name in ("input_enter", "lwip_input_enter", "input_return", "adapter_completion", "input_free", "input_reuse")]
        require(all(a["line"] < b["line"] for a, b in zip(trace, trace[1:])), f"input settlement order seq={seq}")
        require(trace[-1].get("matched") == "1", f"native reuse seq={seq}")
        if trace[2].get("rc") == "0":
            accepted.append(seq)
            copy = single("input_copy", seq)
            require(trace[1]["line"] < copy["line"] < trace[2]["line"], f"input copy interval seq={seq}")
        else:
            require(not selected("input_copy", seq), f"rejected admission must not copy seq={seq}")
        require(trace[3].get("policy") == "ALLOW", "resource rejection must not become Policy DROP")

    live = {}
    lifetimes = []
    allocs, frees, used, peak = Counter(), Counter(), Counter(), Counter()
    joint_peak = overlap_peak = stop_overlap_pbufs = 0
    for d in events:
        event = d.get("event")
        if event in ("pool_alloc", "pool_free"):
            key = (d["context"], d["pool"], d["object"])
            category = d["pool"]
            if event == "pool_alloc":
                require(key not in live, f"double allocation {key}")
                live[key] = d["line"]
                allocs[category] += 1
                used[category] += 1
                peak[category] = max(peak[category], used[category])
            else:
                require(key in live, f"unowned/double free {key}")
                if key in live:
                    lifetimes.append((key, live.pop(key), d["line"]))
                frees[category] += 1
                used[category] -= 1
            total = used["4"] + used["5"]
            joint_peak = max(joint_peak, total)
            if used["4"] and used["5"]:
                overlap_peak = max(overlap_peak, total)
            require(total <= pool_limit, "live pbuf ceiling exceeded")
        elif event == "stop_overlap_request":
            stop_overlap_pbufs = used["4"] + used["5"]
            require(used["4"] > 0 and used["5"] > 0, "stop request must occur in actual input/output pbuf overlap")
    require(bool(allocs) and allocs == frees and not live, "pool conservation at stop")
    frames = set()
    for d in events:
        if d.get("event") == "udp_frame_alloc":
            require(d["frame"] not in frames, "duplicate UDP frame")
            frames.add(d["frame"])
        elif d.get("event") == "udp_frame_free":
            require(d["frame"] in frames, "unowned UDP frame free")
            frames.discard(d["frame"])
    require(not frames, "UDP frame residue")
    require(len({d.get("session") for d in selected("udp_frame_alloc")}) == 1, "same HEV session across recovery")
    credits = [d for d in selected("credit") if d.get("phase") == "after-stop"]
    require(len(credits) == 4 and all(d["used"] == "0" and d["alloc"] == d["free"] for d in credits), "all credits settle")
    pbuf_credit = next((d for d in credits if d["category"] == "1"), {})
    require(int(pbuf_credit.get("peak", credit_limit + 1)) <= credit_limit, "input pbuf-credit ceiling exceeded")
    native = selected("final_buffers")
    require(len(native) == 1 and native[0]["input_alloc"] == native[0]["input_free"] and
            native[0]["output_alloc"] == native[0]["output_free"], "native allocation/free totals")

    require("underflows=0" in log, "credit underflow status required")
    native_live = set()
    native_peak = 0
    for d in events:
        name = d.get("event")
        if name in ("input_enter", "copy"):
            key = d.get("buffer")
            require(key not in native_live, "duplicate live native buffer")
            native_live.add(key)
            native_peak = max(native_peak, len(native_live))
        elif name in ("input_free", "output_free"):
            key = d.get("buffer")
            require(key in native_live, "unowned native buffer free")
            native_live.discard(key)
    require(not native_live, "native per-buffer residue")

    endpoint_ids = []
    for d in selected("endpoint_receive"):
        payload = d.get("payload", "")
        require(re.fullmatch(r"s245-payload-[1-4]", payload) is not None, "exact endpoint payload")
        if payload.startswith("s245-payload-"):
            seq = int(payload.rsplit("-", 1)[1])
            endpoint_ids.append(seq)
            require(seq in accepted, "rejected input reached transport")
            require(single("input_reuse", seq)["line"] < d["line"], "native input already reused before endpoint delivery")
    if pattern != "stop":
        require(sorted(endpoint_ids) == accepted, "every accepted input reaches actual UDP endpoint")
    else:
        require(endpoint_ids == [1], "overlap stop must settle queued input without sending it")

    for start in selected("lwip_output_enter"):
        seq = int(start["seq"])
        cb, accepted_frame, end, lwip_end, graph = [single(name, seq) for name in (
            "callback_enter", "frame_accept", "callback_return", "lwip_output_return", "graph_enter")]
        require(start["line"] < cb["line"] < accepted_frame["line"] < end["line"] < lwip_end["line"] < graph["line"], f"deferred native graph seq={seq}")
        require(end.get("rc") == "0" and graph.get("valid") == "1", "output copy/owner/generation validity")
        lifetime = [(k, a, b) for k, a, b in lifetimes if k[2] == start.get("pbuf") and a < start["line"] < b]
        require(len(lifetime) == 1 and lwip_end["line"] < lifetime[0][2] < graph["line"], "independent pbuf/VPP graph lifetime")

    if pattern == "burst":
        require(accepted[:min(pool_limit, credit_limit, 3)] == list(range(1, min(pool_limit, credit_limit, 3) + 1)), "registered batch admission")
        require(len([n for n in accepted if n <= 3]) == min(pool_limit, credit_limit, 3), "exact burst boundary")
        require(4 in accepted, "recovery input accepted at unchanged limits")
        recovery = next((d for d in results if d.get("seq") == "4"), {})
        if pool_limit >= 2:
            require(recovery.get("result") == "EXACT", "round-trip recovery after pressure drains")
    elif pattern == "stop":
        require(len(selected("stop_overlap_request")) == 1 and stop_overlap_pbufs >= 3, "actual overlap stop request")
        require(len(selected("stop_overlap_deferred")) == 1, "stop deferred out of active callback/input")
    elif pool_limit >= 2:
        require(all(d.get("result") == "EXACT" for d in results), "viable single-packet path must deliver")
    if pool_limit == 1:
        require(all(d.get("result") == "TIMEOUT" for d in results), "one-pbuf limit is recorded as no-delivery boundary")
        require(len(selected("pbuf_limit_reject")) > 0, "actual allocator rejection at one-pbuf limit")
    if pattern == "sync":
        if pool_limit >= 4:
            require(overlap_peak >= 3 and bool(selected("controlled_sync_completion")), "controlled real lwIP overlap")
        elif pool_limit == 2:
            require(any(d.get("err") == "-1" for d in selected("sync_result")), "synchronous header allocation boundary")
        else:
            require(bool(selected("sync_payload_reject")), "synchronous payload allocation boundary")
    if pattern == "delay":
        for seq in range(1, 4):
            require(int(single("lwip_output_enter", seq).get("ns", 0)) - int(single("input_reuse", seq).get("ns", 0)) >= 200_000_000,
                    "delayed reply preserves input independence")

    consecutive = max_zero = 0
    for quanta in re.findall(r"^oi3_drive .*?quanta=(\d+)", log, re.M):
        consecutive = consecutive + 1 if quanta == "0" else 0
        max_zero = max(max_zero, consecutive)
    require(max_zero < 32, "no-progress wake loop")
    require(re.search(r"^oi3_cleanup .*residue=0 error=(?:none)?$", log, re.M) is not None, "bounded cleanup with no error")
    require("broker=1/1" in log, "actual bind/protect result")
    after = (path / "process-after.txt").read_text()
    require(not any("libvpppoc.so" in l or l.split()[1:2] in (["vpp"], ["vpp_main"]) for l in after.splitlines()), "no VPP process residue")
    result = dict(status="HOLD" if errors else "PASS", errors=errors, pattern=pattern,
        pbuf_limit=pool_limit, credit_limit=credit_limit, accepted_input_sequences=accepted,
        endpoint_sequences=endpoint_ids, app_results={d["seq"]: d["result"] for d in results},
        pbuf_joint_peak=joint_peak, input_output_overlap_peak=overlap_peak,
        pool_peak=dict(peak), native_boundary_peak=native_peak,
        input_copy_calls=len(selected("input_copy")),
        input_copy_bytes=sum(int(d["bytes"]) for d in selected("input_copy")),
        output_copy_calls=sum(int(d["calls"]) for d in selected("copy")),
        output_copy_bytes=sum(int(d["bytes"]) for d in selected("copy")),
        stop_overlap_pbufs=stop_overlap_pbufs, pool_alloc=dict(allocs), pool_free=dict(frees),
        pbuf_credit_peak=pbuf_credit.get("peak"), pbuf_credit_rejects=pbuf_credit.get("reject"),
        allocator_rejects=len(selected("pbuf_limit_reject")), max_consecutive_zero_quanta=max_zero,
        verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    (path / "verification.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    results = [verify(p) for p in sys.argv[1:]]
    print(json.dumps(results, indent=2))
    raise SystemExit(any(d["status"] != "PASS" for d in results))
