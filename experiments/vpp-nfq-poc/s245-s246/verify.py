#!/usr/bin/env python3
"""Validate actual event causality and conservation, not historical PASS strings."""
from collections import Counter, defaultdict
import json
import hashlib
from pathlib import Path
import re
import sys


def records(path):
    result = []
    for number, line in enumerate(path.read_text().splitlines()):
        if "s245 event=" in line or "s246 event=" in line:
            record = dict(re.findall(r"([a-zA-Z_]+)=([^\s]+)", line))
            record["line"] = number
            result.append(record)
    return result


def verify(directory):
    directory = Path(directory)
    mode = json.loads((directory / "manifest.json").read_text())["mode"]
    rows = records(directory / "vpp.log")
    app = records(directory / "app.log")
    errors = []
    def require(test, message):
        if not test:
            errors.append(message)
    def events(name, seq=None):
        return [r for r in rows if r.get("event") == name and (seq is None or r.get("seq") == str(seq))]
    def one(name, seq):
        found = events(name, seq)
        require(len(found) == 1, f"{name} seq={seq}: expected one, got {len(found)}")
        return found[0] if found else {"line": -1}

    require(len(app) == 3, "three application results required")
    for seq in range(1, 4):
        expected = "TIMEOUT" if seq == 2 and 2 <= mode <= 8 else "EXACT"
        matches = [r for r in app if r.get("seq") == str(seq)]
        require(len(matches) == 1 and matches[0].get("result") == expected, f"application seq={seq} expected {expected}")
    require(len({r.get("local_port") for r in app}) == 1, "same application UDP socket required")
    require(len(events("input_enter")) == 3, "three real input calls required")
    for seq in range(1, 4):
        names = ["input_enter", "lwip_input_enter", "input_return", "adapter_completion", "input_free", "input_reuse"]
        trace = [one(name, seq) for name in names]
        require(all(a["line"] < b["line"] for a, b in zip(trace, trace[1:])), f"input ownership order seq={seq}")
        require(trace[0].get("parser") == "1", f"input parser seq={seq}")
        require(trace[-1].get("matched") == "1", f"same native buffer reuse seq={seq}")
        expected_rc = "0" if not (2 <= mode <= 4 and seq == 2) else None
        rc = trace[2].get("rc")
        require(rc == expected_rc if expected_rc is not None else rc is not None and int(rc) < 0,
                f"input return status seq={seq}")
        if expected_rc == "0":
            copy = one("input_copy", seq)
            require(trace[1]["line"] < copy["line"] < trace[2]["line"], f"copy within input call seq={seq}")
    require(len({r.get("generation") for r in events("input_enter")}) == 1, "input failures must not replace the owner generation")
    require({r.get("owner") for r in events("input_enter")} == {"1"}, "single actual VPP worker 1 required")
    expected_endpoint = 2 if mode in (2, 3, 4) else 3
    expected_replies = 4 if mode == 10 else expected_endpoint
    require(len(events("endpoint_receive")) == expected_endpoint, "real endpoint received count")
    for endpoint in events("endpoint_receive"):
        payload = endpoint.get("payload", "")
        require(payload in {"s245-payload-1", "s245-payload-2", "s245-payload-3"}, "endpoint payload mismatch")
        if payload.startswith("s245-payload-"):
            seq = int(payload.rsplit("-", 1)[1])
            reuse = one("input_reuse", seq)
            require(reuse["line"] < endpoint["line"], f"native reuse precedes real endpoint delivery seq={seq}")

    live = set()
    allocation_line = {}
    lifetimes = []
    pool_alloc = Counter()
    pool_free = Counter()
    pool_live = Counter()
    pool_peak = Counter()
    for r in rows:
        event = r.get("event")
        if event not in ("pool_alloc", "pool_free"):
            continue
        key = (r.get("context"), r.get("pool"), r.get("object"))
        category = r["pool"]
        if event == "pool_alloc":
            require(key not in live, f"duplicate live pool allocation {key}")
            live.add(key)
            allocation_line[key] = r["line"]
            pool_alloc[category] += 1
            pool_live[category] += 1
            pool_peak[category] = max(pool_peak[category], pool_live[category])
        else:
            require(key in live, f"unowned/double pool free {key}")
            if key in live:
                lifetimes.append((key, allocation_line.pop(key), r["line"]))
            live.discard(key)
            pool_free[category] += 1
            pool_live[category] -= 1
    require(bool(pool_alloc) and not live and pool_alloc == pool_free, "all pool objects must settle exactly once")
    frame_live = set()
    for r in rows:
        if r.get("event") == "udp_frame_alloc":
            require(r["frame"] not in frame_live, "duplicate UDP frame")
            frame_live.add(r["frame"])
        elif r.get("event") == "udp_frame_free":
            require(r["frame"] in frame_live, "unowned UDP frame free")
            frame_live.discard(r["frame"])
    require(not frame_live, "UDP frame residue")
    require(len({r.get("session") for r in events("udp_frame_alloc")}) == 1,
            "the same HEV UDP session must survive packet faults")
    credits = [r for r in events("credit") if r.get("phase") == "after-stop"]
    require(len(credits) == 4 and all(r.get("used") == "0" and r.get("alloc") == r.get("free") for r in credits), "credit conservation at bounded stop")
    final = events("final_buffers")
    require(len(final) == 1 and final[0].get("input_alloc") == final[0].get("input_free") and
            final[0].get("output_alloc") == final[0].get("output_free"), "native input/output conservation")
    input_live = input_peak = output_live = output_peak = 0
    for r in rows:
        if r.get("event") == "input_enter":
            input_live += 1
            input_peak = max(input_peak, input_live)
        elif r.get("event") == "input_free":
            input_live -= 1
        elif r.get("event") == "input_reuse":
            input_peak = max(input_peak, input_live + int(r["allocations"]))
        elif r.get("event") == "copy":
            output_live += 1
            output_peak = max(output_peak, output_live)
        elif r.get("event") == "output_free":
            output_live -= 1
    require(input_live == 0 and output_live == 0, "native object live count at stop")
    require(len(events("callback_enter")) == expected_replies, "real lwIP output count")
    if mode == 1:
        for seq in range(1, 4):
            reuse, output = one("input_reuse", seq), one("lwip_output_enter", seq)
            require(int(output.get("ns", 0)) - int(reuse.get("ns", 0)) >= 200_000_000,
                    f"controlled delayed reply after native reuse seq={seq}")
    for seq in range(1, expected_replies + 1):
        begin = one("lwip_output_enter", seq)
        callback = one("callback_enter", seq)
        end = one("callback_return", seq)
        lwip_end = one("lwip_output_return", seq)
        require(begin["line"] < callback["line"] < end["line"] < lwip_end["line"], f"callback borrow interval seq={seq}")
        rejected = seq == 2 and mode in (6, 7)
        require(end.get("rc") == ("-1" if mode == 6 else "-2") if rejected else end.get("rc") == "0", f"callback rc seq={seq}")
        if not rejected:
            accepted = one("frame_accept", seq)
            graph = one("graph_enter", seq)
            require(callback["line"] < accepted["line"] < end["line"] < lwip_end["line"] < graph["line"], f"native frame deferred scheduling seq={seq}")
            require(graph.get("valid") == "1" and graph.get("owner") == "1", f"independent graph bytes/owner seq={seq}")
            # An address can be reallocated and freed again before this frame
            # runs. Correlate the allocation interval enclosing the callback,
            # not all frees of that raw address in the scheduling interval.
            lifetime = [(key, start, end) for key, start, end in lifetimes
                        if key[2] == begin.get("pbuf") and start < begin["line"] < end]
            require(len(lifetime) == 1 and lwip_end["line"] < lifetime[0][2] < graph["line"],
                    f"lwIP output pbuf released/poisoned before independent graph seq={seq}")
            completion = events("tun_completion", seq)
            if mode == 10 and seq == 2:
                require(not completion and len(events("controlled_sync_completion", seq)) == 1, "controlled synchronous output remains separate from real Direct replies")
                input_return = one("input_return", 2)
                input_enter = one("input_enter", 2)
                require(input_enter["line"] < begin["line"] < lwip_end["line"] < input_return["line"] < graph["line"], "synchronous lwIP output must defer graph until the active input call returns")
            elif mode == 5 and seq == 2:
                require(not completion and one("policy", seq).get("verdict") == "DROP", "policy DROP must not write TUN")
            else:
                complete = one("tun_completion", seq)
                require(complete.get("result") == "-1" if mode == 8 and seq == 2 else complete.get("result") == complete.get("bytes"), f"TUN completion seq={seq}")
    if mode == 9:
        require(one("callback_enter", 2).get("spans") == "2" and one("lwip_output_enter", 2).get("controlled_chain") == "1", "explicit controlled two-span chain required")
    cleanup = (directory / "vpp.log").read_text()
    require("broker=1/1" in cleanup, "successful Android bind/protect completion required")
    after = (directory / "process-after.txt").read_text()
    require(not any("libvpppoc.so" in line or line.split()[1:2] in (["vpp"], ["vpp_main"])
                    for line in after.splitlines()), "VPP process residue")
    max_zero = consecutive_zero = 0
    for quanta in re.findall(r"^oi3_drive .*?quanta=(\d+)", cleanup, re.M):
        consecutive_zero = consecutive_zero + 1 if quanta == "0" else 0
        max_zero = max(max_zero, consecutive_zero)
    require(max_zero < 32, "readable-socket no-progress wake loop")
    require(re.search(r"^oi3_cleanup .*residue=0 error=(?:none)?$", cleanup, re.M) is not None, "bounded cleanup evidence required")
    result = {"status": "HOLD" if errors else "PASS", "mode": mode, "errors": errors,
              "verifier_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "pool_alloc": dict(pool_alloc), "pool_free": dict(pool_free), "pool_peak": dict(pool_peak),
              "native_input_peak": input_peak, "native_output_peak": output_peak,
              "max_consecutive_zero_quanta": max_zero,
              "input_copy_bytes": sum(int(r["bytes"]) for r in events("input_copy")),
              "output_copy_bytes": sum(int(r["bytes"]) for r in events("copy"))}
    (directory / "verification.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    results = [verify(path) for path in sys.argv[1:]]
    print(json.dumps(results, indent=2))
    raise SystemExit(any(r["status"] != "PASS" for r in results))
