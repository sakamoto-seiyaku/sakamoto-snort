#!/usr/bin/env python3
"""Scoped normal Root/VPN shared-query and validation-UI acceptance.

Uses an explicitly selected device and isolated existing test-store selector.
The production store/rules are restored byte for byte. Host packet capture is
not claimed: the supplied Host artifact only reopens the same committed store.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import socket
import struct
import subprocess
import time
import traceback
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
PKG = "com.sakamoto.snort.androidruntime"


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Acceptance:
    def __init__(self, args):
        self.args, self.out = args, args.output.resolve()
        self.out.mkdir(parents=True, exist_ok=True)
        self.owned, self.moved, self.original, self.peers = [], [], {}, []
        self.active = False
        self.result = {"status": "HOLD", "runs": [], "source": "normal Root/VPN Product queries"}

    def save(self, name, value):
        (self.out / name).write_bytes(value if isinstance(value, bytes)
                                    else (json.dumps(value, indent=2) + "\n").encode())

    def adb(self, *args, binary=False, check=True):
        result = subprocess.run([str(ROOT / "dev/adb"), "-s", self.args.serial,
                                 *map(str, args)], capture_output=True, timeout=45)
        with (self.out / "device-operations.jsonl").open("a") as log:
            log.write(json.dumps({"at": time.time(), "args": list(map(str, args)),
                                  "code": result.returncode}) + "\n")
        if check and result.returncode:
            raise RuntimeError((result.stdout + result.stderr).decode(errors="replace"))
        return result.stdout if binary else (result.stdout + result.stderr).decode().replace("\r", "")

    def shell(self, *args, check=True):
        return self.adb("shell", "run-as", PKG, *args, check=check)

    def app(self, path, binary=False, check=True):
        return self.adb("exec-out", "run-as", PKG, "cat", path, binary=binary, check=check)

    @staticmethod
    def properties(raw):
        return dict(line.split("=", 1) for line in raw.splitlines()
                    if "=" in line and not line.startswith("#"))

    def action(self, *args, fresh=False):
        flags = ["-f", "0x10008000"] if fresh else []
        return self.adb("shell", "am", "start", *flags, "-n", PKG + "/.DebugControlActivity", *args)

    @staticmethod
    def wait(read, predicate, timeout=35):
        end = time.monotonic() + timeout
        value = None
        while time.monotonic() < end:
            value = read()
            if predicate(value):
                return value
            time.sleep(.15)
        raise RuntimeError("wait deadline: " + str(value)[:2000])

    def state(self, wanted):
        def read():
            value = self.properties(self.app("files/runtime-state/snapshot.properties"))
            if value.get("state") == "error":
                raise RuntimeError("runtime state " + str(value))
            return value
        return self.wait(read, lambda value: value.get("state") == wanted)

    def query(self, label, cursor=0):
        nonce = "s332-" + label + "-" + str(time.monotonic_ns())
        path = "files/product-state/observation-" + nonce + ".json"
        self.owned.append(path)
        self.action("--es", "observationNonce", nonce, "--ei", "observationOperation", 0,
                    "--ei", "observationCursor", cursor)
        def read():
            try:
                return json.loads(self.app(path, binary=True, check=False))
            except (ValueError, UnicodeError):
                return None
        query = self.wait(read, lambda value: value is not None, 20)
        self.save(label + ".json", query)
        assert "error" not in query, query
        consumer = query["consumer"]
        assert consumer["query_fresh"] and consumer["query_error"] is None, consumer
        assert consumer["persistent"]["save_error"] is None, consumer["persistent"]["save_error"]
        return query

    def dump(self):
        remote = "/sdcard/s332-ui.xml"
        self.adb("shell", "uiautomator", "dump", remote)
        raw = self.adb("exec-out", "cat", remote)
        return raw, list(ET.fromstring(raw).iter("node"))

    def tap(self, label):
        for _ in range(12):
            _, nodes = self.dump()
            for node in nodes:
                if label not in (node.get("text"), node.get("content-desc")):
                    continue
                x1, y1, x2, y2 = map(int, re.findall(r"\d+", node.get("bounds")))
                if node.get("enabled") == "true" and y2 - y1 >= 45 and 0 <= y1 and y2 <= 2300:
                    self.adb("shell", "input", "tap", (x1 + x2) // 2, (y1 + y2) // 2)
                    return
            self.adb("shell", "input", "swipe", 550, 1700, 550, 1000, 250)
        raise RuntimeError("missing visible button " + label)

    def ui_query(self, label, history):
        # Existing scrolling scripts could begin below the controls and skip the
        # clipped result. Recreate only the Activity, then inspect actual bounds.
        self.action(fresh=True)
        self.tap("Query history" if history else "Query health and flows")
        description = "History result" if history else "Health and flow result"
        for _ in range(12):
            raw, nodes = self.dump()
            node = next((node for node in nodes if node.get("content-desc") == description), None)
            text = "" if node is None else node.get("text", "")
            if text and not text.startswith("Querying"):
                (self.out / (label + "-ui.xml")).write_text(raw)
                (self.out / (label + "-ui.txt")).write_text(text)
                self.save(label + "-ui.png", self.adb("exec-out", "screencap", "-p", binary=True))
                return text
            if node is None:
                self.adb("shell", "input", "swipe", 550, 1700, 550, 1000, 250)
        raise RuntimeError("query result not visible: " + description)

    def ui_history(self, label):
        text = self.ui_query(label, True)
        for token in ["Recent Flow / independent Blocked", "Target names / Recognition", "DNS details",
                      "Application statistics", "Rule statistics", "Protocol statistics",
                      "hour statistics", "day statistics", "Coverage:", "Retention limits:"]:
            assert token in text, (token, text)
        assert "query unavailable" not in text.lower() and "query error:" not in text.lower(), text
        # Compare the displayed immutable recent rows with the actual shared
        # query, including u64 values. Python retains their native integer value;
        # Android display must preserve its decimal spelling rather than round.
        persistent = self.query(label + "-display-source")["consumer"]["persistent"]
        for grain in ["hour", "day"]:
            windows = persistent[grain + "_windows"]
            # JSONObject may reorder keys; compare the actual typed flags and
            # limits in that section without relying on object key order.
            line = next(line for line in text.splitlines() if line.startswith(grain + " statistics:"))
            assert " · truncated " + str(windows["truncated"]).lower() in line, line
            assert " · query limit " + str(windows["query_limit"]) in line, line
        source = persistent["recent"]
        def display_value(value):
            if isinstance(value, dict):
                return {key: display_value(item) for key, item in value.items()}
            if isinstance(value, list):
                return [display_value(item) for item in value]
            if isinstance(value, int) and value > 9223372036854775807:
                return str(value)
            return value
        details = text.split("Recent details:", 1)[1].split("\nDNS:", 1)[0]
        displayed = 0
        for line in details.splitlines():
            if " = " not in line:
                continue
            key, raw = line.split(" = ", 1)
            assert json.loads(raw) == display_value(source[key]), (key, raw, source[key])
            displayed += 1
        declared = re.search(r"Recent details: showing ([0-9]+)/([0-9]+) returned records", text)
        assert declared and displayed == int(declared.group(1)) <= 8, displayed
        return text

    def stopped(self, label):
        state = self.state("stopped")
        assert state["mayBeActive"] == state["protectionRunning"] == "false", state
        path = "files/observation/t27-test/overall.sqlite3"
        before = self.app(path, binary=True)
        query = self.query(label)
        assert query["capture_state"] == query["current_flows"]["state"] == "stopped", query
        persistent = query["consumer"]["persistent"]
        assert persistent["visibility"] == "saved_committed" and not persistent["open_session"]
        assert not persistent["persistence"]["pending"]
        assert before == self.app(path, binary=True), "stopped read changed SQLite"
        assert self.state("stopped")["generation"] == state["generation"]
        return query, before

    def host_saved(self, label, data, expected):
        path = self.out / (label + ".sqlite3")
        path.write_bytes(data)
        artifact = self.args.host_artifact.resolve()
        result = subprocess.run([str(artifact / "bin/sakamoto-product-core-host"), "saved-history",
                                 str(path.with_suffix(".json"))],
                                env=dict(os.environ, LD_LIBRARY_PATH=str(artifact / "lib")),
                                capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, result.stderr
        actual = json.loads(result.stdout.split("dashboard.response=", 1)[1])
        self.save(label + "-host.json", actual)
        assert actual["capture_state"] == actual["current_flows"]["state"] == "stopped"
        for field in ["packets", "bytes", "recent", "dns", "minutes", "hour_windows", "day_windows",
                      "application_windows", "protocol_windows", "rule_windows"]:
            assert actual["consumer"]["persistent"][field] == expected["consumer"]["persistent"][field], field
        assert path.read_bytes() == data, "Host saved query changed SQLite"

    def rules(self, label, uid):
        path = "files/product-state/complete-rule-config.properties"
        self.action(fresh=True)
        old = self.properties(self.app(path, check=False)).get("queryElapsedMillis")
        self.tap("Query all rules")
        baseline = self.wait(lambda: self.properties(self.app(path, check=False)),
                             lambda value: value.get("queryElapsedMillis") not in (None, old))
        assert baseline["result"] == "0" and baseline["generation"] == self.state("running")["generation"]
        self.save(label + "-baseline-rules.json", baseline)
        # Ordinary direct rules have an implicit application binding. The UDP
        # rule can refuse before Flow allocation once attribution is available.
        lines = ["lists 1", "domain 0 exact blocked.http.test",
                 f"0 0 {uid} 4294967295 4294967295 5 0 17 0 2 * * 0 65535 44445 44445",
                 f"0 0 {uid} 4294967295 4294967295 10 0 0 0 2 * * 0 65535 0 65535 1100",
                 f"0 0 {uid} 4294967295 4294967295 1000 0 0 0 1 * * 0 65535 0 65535"]
        request = self.out / "controlled-rules.txt"
        request.write_text("\n".join(lines) + "\n")
        remote = "/data/local/tmp/s332-rules.txt"
        self.adb("push", request, remote)
        command = f'am start -n {PKG}/.DebugControlActivity --es completeRuleText "$(cat {remote})"'
        self.adb("shell", "sh", "-c", shlex.quote(command))
        self.adb("shell", "rm", remote)
        old = self.properties(self.app(path, check=False)).get("queryElapsedMillis")
        self.tap("Replace all rules")
        applied = self.wait(lambda: self.properties(self.app(path, check=False)),
                            lambda value: value.get("queryElapsedMillis") not in (None, old))
        self.save(label + "-rules.json", applied)
        assert all(applied[key] == "0" for key in ["transportCode", "result", "saveError", "compileError"]), applied
        assert applied["count"] == applied["activeCount"] == "3", applied
        return applied

    def probe(self, label, plan):
        nonce = "s332-" + label + "-" + str(time.monotonic_ns())
        plan = dict(plan, nonce=nonce, bindDefault=True)
        path = "files/product-state/t12-" + nonce + ".json"
        self.owned.append(path)
        self.save(label + "-plan.json", plan)
        self.action("--es", "t12ProbePlan", shlex.quote(json.dumps(plan)))
        return path

    def probe_result(self, path, phase="finished", timeout=45):
        def read():
            try:
                return json.loads(self.app(path, binary=True, check=False))
            except (ValueError, UnicodeError):
                return None
        result = self.wait(read, lambda value: value is not None and value.get("phase") == phase, timeout)
        assert not result.get("error"), result
        return result

    def selected_flow(self, label, source):
        def read():
            cursor = 0
            while True:
                query = self.query(label, cursor)
                for row in query["current_flows"]["entries"]:
                    if source in (row["port_a"], row["port_b"]):
                        return query, row
                if query["current_flows"]["done"]:
                    return None
                cursor = query["current_flows"]["next_cursor"]
        return self.wait(read, lambda value: value is not None, 15)

    def run(self):
        http = load("s332_http", "tests/device/helpers/s325_http_peer.py")
        endpoint = self.args.endpoint
        # RST leaves the Product's existing TIME_WAIT/CLOSED aging contract in
        # charge. STOP is never used to manufacture an END.
        class HttpPeer(http.HttpPeer):
            def __init__(self, *args, **kwargs):
                self.connections = {}
                super().__init__(*args, **kwargs)

            def serve(self, connection, peer):
                self.connections[peer[1]] = connection
                try:
                    super().serve(connection, peer)
                finally:
                    self.connections.pop(peer[1], None)

            def reset(self, source):
                connection = self.connections.get(source)
                if connection:
                    connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    connection.close()

        try:
            assert self.state("stopped")["mayBeActive"] == "false"
            self.original = {path: self.app(path, binary=True) for path in
                             ["files/observation/overall.json", "files/observation/overall.sqlite3",
                              "files/rule-configuration/rules.conf"]}
            self.save("install.txt", self.adb("install", "-r", self.args.apk))
            self.adb("shell", "input", "keyevent", "224")
            self.adb("shell", "wm", "dismiss-keyguard")
            assert "uid=0" in self.shell("su", "-c", "id"), "KernelSU grant required"
            uid = int(self.shell("id", "-u").strip())
            for path in ["files/rule-configuration", "files/observation/t27-test"]:
                backup = path + ".s332-preserved"
                self.shell("sh", "-c", shlex.quote("test ! -e " + backup))
                self.shell("mv", path, backup)
                self.moved.append((path, backup))
            self.shell("mkdir", "-p", "files/rule-configuration", "files/observation/t27-test")
            self.shell("touch", "files/observation/t27-test.enabled")
            directory = self.out / "peer-http"
            directory.mkdir()
            peer = HttpPeer([endpoint], directory, time.monotonic() + 900, port=18080)
            self.peers.append(peer)
            sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sink.bind((endpoint, 44445))
            self.peers.append(sink)
            previous = None
            for index, profile in enumerate(["root", "vpn"]):
                self.active = True
                self.action("--ez", "runtimeStart", "true", "--es", "runtimeProfile", profile, fresh=True)
                state = self.state("running")
                generation = int(state["generation"])
                assert state["profile"] == profile and state["protectionRunning"] == "true", state
                if previous:
                    assert generation > int(previous["runtime"]["generation"])
                    baseline = self.query(profile + "-restart")
                    old = previous["consumer"]["persistent"]
                    new = baseline["consumer"]["persistent"]
                    assert all(key in new["recent"] for key in old["recent"])
                    assert all(key in new["dns"]["recent"] for key in old["dns"]["recent"])
                rule = self.rules(profile, uid)
                source = 57200 + index * 10
                request = (f"GET /s332-{profile} HTTP/1.1\r\nHost: allowed.http.test\r\n\r\n").encode()
                client_path = self.probe(profile + "-http", dict(endpoint=endpoint, source=source, port=18080,
                    httpRequests=[request.hex()] * 16, httpSplit=[1] * 16, httpDelayMs=2000,
                    httpTimeoutMs=1000, httpConnectDelayMs=1500 if profile == "vpn" else 0))
                def named_flow():
                    query, row = self.selected_flow(profile + "-live", source)
                    names = row.get("target_names")
                    return (query, row) if names and names["request"]["name"] == "allowed.http.test" else None
                live, flow = self.wait(named_flow, lambda value: value is not None, 12)
                assert flow["recognition"]["state"] == "identified", flow
                assert flow["recognition"]["sequence"] and sum(flow["recognition"]["payload_packets"]) > 0, flow
                dashboard = self.ui_query(profile + "-dashboard", False)
                assert "Target names:" in dashboard and "allowed.http.test" in dashboard and "Recognition:" in dashboard, dashboard
                assert "Rust consumer:" in dashboard and "Current flows:" in dashboard, dashboard
                peer.reset(source)
                http_client = self.probe_result(client_path)
                assert http_client["httpResponses"][0]["status"] == "answered", http_client
                self.save(profile + "-http-result.json", http_client)
                # Real denied target and separate latest target in one supplied
                # request buffer, as qualified by S331. Keep this representative.
                denied = ("GET /s332-denied HTTP/1.1\r\nHost: blocked.http.test\r\n\r\n"
                          "GET http://later.http.test/s332-later HTTP/1.1\r\n\r\n").encode()
                denied_path = self.probe(profile + "-denied", dict(endpoint=endpoint, source=source + 1, port=18080,
                    httpRequests=[denied.hex()], httpTimeoutMs=1000, httpHoldMs=500, httpGate=True,
                    httpAfterMs=10000, httpConnectDelayMs=1500 if profile == "vpn" else 0))
                denied_client = self.probe_result(denied_path, "http_done")
                assert denied_client["httpResponses"][0]["status"] == "timeout", denied_client
                denied_live, denied_flow = self.selected_flow(profile + "-denied-live", source + 1)
                names = denied_flow["target_names"]
                assert names["request"]["name"] == "later.http.test" and names["denied"]["name"] == "blocked.http.test", names
                assert names["denied_rule"]["winner"] == rule["rule.1.version"], (names, rule)
                peer.reset(source + 1)
                self.action()
                self.probe_result(denied_path)
                # App UDP refusal can be a pre-Flow Blocked record, or a Flow
                # after asynchronous VPN attribution. Preserve their true kind.
                blocked_path = self.probe(profile + "-blocked", dict(endpoint=endpoint, source=source + 2, port=44445,
                    udpSteps=[{"send": "73333332", "pauseMs": 1500}, {"send": "73333332", "pauseMs": 1500}], udpTimeoutMs=300))
                blocked_client = self.probe_result(blocked_path)
                assert all(row["status"] == "timeout" for row in blocked_client["udpReplies"]), blocked_client
                self.save(profile + "-blocked-result.json", blocked_client)
                wire = f"{0x3320 + index:04x}" + "01000001000000000000076578616d706c6503636f6d0000010001"
                dns_path = self.probe(profile + "-dns", dict(endpoint="1.1.1.1", source=source + 3, port=53,
                    dnsQueries=[wire], dnsTimeoutMs=3000, dnsInitialDelayMs=3000))
                self.adb("shell", "input", "keyevent", "HOME")
                self.state("running")
                dns_client = self.probe_result(dns_path)
                assert dns_client["dnsExchanges"][0].get("replyHex"), dns_client
                self.save(profile + "-dns-result.json", dns_client)
                # The DNS worker finished while the page was in the background;
                # reopen it and read facts from the service-owned observer.
                self.action(fresh=True)
                self.state("running")
                def ended():
                    query = self.query(profile + "-ended")
                    rows = query["consumer"]["persistent"]["recent"]
                    return query if all(any(source_port in row["record"]["ports"]
                           and row["record"]["generation"] == generation
                           for row in rows.values()) for source_port in [source, source + 1, source + 2]) else None
                ended_query = self.wait(ended, lambda value: value is not None, 50)
                persistent = ended_query["consumer"]["persistent"]
                rows = [value["record"] for value in persistent["recent"].values() if value["record"]["generation"] == generation]
                blocked_rows = [row for row in rows if source + 2 in row["ports"]]
                assert blocked_rows, rows
                if profile == "root":
                    assert any(row["blocked"] for row in blocked_rows), blocked_rows
                else:
                    assert any(row["blocked"] or any(fact["valid"] and fact["actual_action"] == 2
                               for fact in row["attribution"]) for row in blocked_rows), blocked_rows
                for source_port in [source, source + 1]:
                    row = next(row for row in rows if source_port in row["ports"])
                    assert not row["blocked"] and row["recognition"]["sequence"], row
                    assert row["target_names"] is not None, row
                dns_rows = [row["record"] for row in persistent["dns"]["recent"].values()
                            if row["record"]["generation"] == generation and row["record"]["source_port"] == source + 3]
                assert {row["stage"] for row in dns_rows} >= {1, 2}, dns_rows
                assert persistent["visibility"] == "live_including_pending"
                assert all(persistent[key] for key in ["minutes", "application_windows", "rule_windows", "protocol_windows"])
                self.ui_history(profile + "-history-live")
                self.action("--ez", "debugExportReleaseDiagnostics", "true", fresh=True)
                diagnostics = self.wait(lambda: self.app("files/debug/release-diagnostics.properties", check=False),
                                        lambda value: "privacy=desensitized_no_payload_no_keys" in value)
                assert "health.category=" in diagnostics and "appDetail.activity" not in diagnostics, diagnostics
                (self.out / (profile + "-diagnostics.txt")).write_text(diagnostics)
                self.action("--ez", "runtimeStop", "true", fresh=True)
                saved, data = self.stopped(profile + "-stopped")
                self.active = False
                assert all(key in saved["consumer"]["persistent"]["recent"] for key in persistent["recent"])
                self.ui_history(profile + "-history-stopped")
                stopped_dashboard = self.ui_query(profile + "-dashboard-stopped", False)
                assert "Current flows: stopped" in stopped_dashboard, stopped_dashboard
                self.host_saved(profile + "-saved", data, saved)
                self.result["runs"].append(dict(profile=profile, generation=generation,
                    ui_current_names_recognition=True, normal_recent_flow_blocked_dns=True,
                    ui_live_and_saved_history=True, page_close_runtime_continues=True,
                    stopped_sqlite_unchanged=True, host_saved_equivalent=True,
                    recent=saved["consumer"]["persistent"]["recent_count"],
                    dns=saved["consumer"]["persistent"]["dns"]["retained_count"]))
                previous = saved
            self.result["status"] = "PASS"
        except BaseException as error:
            self.result.update(error=repr(error), traceback=traceback.format_exc())
            raise
        finally:
            errors = []
            if self.active:
                try:
                    self.action("--ez", "runtimeStop", "true", fresh=True)
                    self.state("stopped")
                    self.active = False
                except BaseException as error:
                    errors.append("stop " + repr(error))
            for peer in self.peers:
                peer.close()
            if not self.active:
                try:
                    self.shell("rm", "-f", "files/observation/t27-test.enabled")
                    for path, backup in reversed(self.moved):
                        self.shell("rm", "-rf", path)
                        self.shell("mv", backup, path)
                    for path, original in self.original.items():
                        assert self.app(path, binary=True) == original, path + " changed"
                    for path in self.owned:
                        self.shell("rm", "-f", path, check=False)
                    self.adb("shell", "rm", "-f", "/sdcard/s332-ui.xml")
                    self.result["restoration"] = dict(original_bytes_unchanged=True,
                        directories_restored=True, final_state=self.state("stopped"))
                except BaseException as error:
                    errors.append("restore " + repr(error))
            if errors:
                self.result.update(status="HOLD", cleanup_errors=errors)
            self.save("device-result.json", self.result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--apk", type=Path)
    parser.add_argument("--host-artifact", type=Path)
    parser.add_argument("--endpoint")
    parser.add_argument("--ui-only", action="store_true", help="read stopped validation UI without modifying configuration")
    args = parser.parse_args()
    test = Acceptance(args)
    if args.ui_only:
        assert test.state("stopped")["mayBeActive"] == "false"
        test.ui_history("stopped")
        print("Stopped shared-query validation UI: PASS")
        return
    if not args.apk or not args.host_artifact or not args.endpoint:
        parser.error("full acceptance requires --apk, --host-artifact and --endpoint")
    test.run()
    print(json.dumps(test.result))


if __name__ == "__main__":
    main()
