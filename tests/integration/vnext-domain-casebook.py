#!/usr/bin/env python3
"""Domain casebook smoke checks for sucre-snort vNext control."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable


class SmokeFailure(RuntimeError):
    pass


class SmokeBlocked(RuntimeError):
    pass


def log_pass(check_id: str, message: str) -> None:
    print(f"✓ {check_id} {message}", flush=True)


def log_info(message: str) -> None:
    print(f"[INFO] {message}", flush=True)


def encode_netstring(payload: bytes) -> bytes:
    return str(len(payload)).encode("ascii") + b":" + payload + b","


def read_exact(sock: socket.socket, length: int) -> bytes:
    out = bytearray()
    while len(out) < length:
        chunk = sock.recv(length - len(out))
        if not chunk:
            raise EOFError("eof while reading payload")
        out += chunk
    return bytes(out)


def read_netstring(sock: socket.socket) -> bytes:
    header = bytearray()
    while True:
        ch = sock.recv(1)
        if not ch:
            raise EOFError("eof while reading netstring header")
        if ch == b":":
            break
        header += ch
        if len(header) > 32:
            raise ValueError("netstring header too long")
    if not header:
        raise ValueError("empty netstring length")
    if header.startswith(b"0") and header != b"0":
        raise ValueError("leading zero in netstring length")
    length = int(header.decode("ascii"))
    payload = read_exact(sock, length)
    comma = read_exact(sock, 1)
    if comma != b",":
        raise ValueError("netstring missing trailing comma")
    return payload


class RpcClient:
    def __init__(self, port: int) -> None:
        self.port = port
        self.next_id = 1
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.sock.settimeout(5)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def call(self, cmd: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        req_id = self.next_id
        self.next_id += 1
        req = {"id": req_id, "cmd": cmd, "args": args or {}}
        payload = json.dumps(req, separators=(",", ":")).encode("utf-8")
        self.sock.sendall(encode_netstring(payload))
        while True:
            resp = json.loads(read_netstring(self.sock))
            if resp.get("id") == req_id and "ok" in resp:
                return resp


class DnsStream:
    def __init__(self, port: int) -> None:
        self.client = RpcClient(port)
        self.sock = self.client.sock
        self.events_seen: list[dict[str, Any]] = []

    def close(self) -> None:
        self.client.close()

    def start(self) -> None:
        require_ok(self.client.call("HELLO"), "stream HELLO failed")
        require_ok(
            self.client.call("STREAM.START", {"type": "dns", "horizonSec": 0, "minSize": 0}),
            "STREAM.START(type=dns) failed",
        )
        started = self.read_event(timeout_sec=5)
        if (
            started.get("type") != "notice"
            or started.get("notice") != "started"
            or started.get("stream") != "dns"
        ):
            raise SmokeFailure(f"unexpected dns stream start notice: {started}")

    def stop(self) -> None:
        try:
            require_ok(self.client.call("STREAM.STOP"), "STREAM.STOP failed")
        finally:
            self.close()

    def read_event(self, timeout_sec: float) -> dict[str, Any]:
        deadline = time.time() + timeout_sec
        last_timeout = None
        while time.time() < deadline:
            self.sock.settimeout(max(0.05, min(0.5, deadline - time.time())))
            try:
                ev = json.loads(read_netstring(self.sock))
            except socket.timeout as exc:
                last_timeout = exc
                continue
            if not isinstance(ev, dict):
                raise SmokeFailure(f"stream frame is not an object: {ev!r}")
            if "id" in ev or "ok" in ev:
                continue
            self.events_seen.append(ev)
            return ev
        raise SmokeFailure(f"timed out waiting for dns stream event: {last_timeout}")

    def collect(
        self,
        trigger: Callable[[], None],
        timeout_sec: float,
        predicate: Callable[[dict[str, Any]], bool],
        required: int = 1,
    ) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        trigger()
        deadline = time.time() + timeout_sec
        while time.time() < deadline and len(found) < required:
            try:
                ev = self.read_event(timeout_sec=max(0.05, min(0.5, deadline - time.time())))
            except SmokeFailure:
                continue
            if predicate(ev):
                found.append(ev)
        return found


@dataclass
class Adb:
    adb: str
    serial: str

    def _base(self) -> list[str]:
        cmd = [self.adb]
        if self.serial:
            cmd.extend(["-s", self.serial])
        return cmd

    def run(self, args: list[str], timeout: int = 15) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self._base() + args,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )

    def shell(self, command: str, timeout: int = 15) -> subprocess.CompletedProcess[str]:
        return self.run(["shell", command], timeout=timeout)

    def su(self, command: str, timeout: int = 15) -> subprocess.CompletedProcess[str]:
        return self.shell(f"su 0 sh -c {shlex.quote(command)}", timeout=timeout)


def require_ok(resp: dict[str, Any], message: str) -> dict[str, Any]:
    if not resp.get("ok", False):
        raise SmokeFailure(f"{message}: {json.dumps(resp, separators=(',', ':'))}")
    return resp


def require_error(resp: dict[str, Any], code: str, message: str) -> dict[str, Any]:
    if resp.get("ok", True):
        raise SmokeFailure(f"{message}: expected error {code}, got ok response")
    got = resp.get("error", {}).get("code")
    if got != code:
        raise SmokeFailure(f"{message}: expected error {code}, got {got}: {resp}")
    return resp


def require_dns_event(ev: dict[str, Any], uid: int, domain: str, **expected: Any) -> None:
    required_fields = {
        "uid": int,
        "userId": int,
        "app": str,
        "domain": str,
        "domMask": int,
        "appMask": int,
        "blocked": bool,
        "policySource": str,
        "useCustomList": bool,
        "scope": str,
        "getips": bool,
    }
    if ev.get("type") != "dns":
        raise SmokeFailure(f"expected dns event, got {ev}")
    if int(ev.get("uid", -1)) != uid or ev.get("domain") != domain:
        raise SmokeFailure(f"dns event identity mismatch: {ev}")
    for key, typ in required_fields.items():
        if not isinstance(ev.get(key), typ):
            raise SmokeFailure(f"dns event field {key} has wrong type: {ev}")
    for key, val in expected.items():
        if ev.get(key) != val:
            raise SmokeFailure(f"dns event expected {key}={val!r}, got {ev.get(key)!r}: {ev}")


def traffic_dns_counts(resp: dict[str, Any]) -> tuple[int, int]:
    traffic = resp["result"]["traffic"]["dns"]
    return int(traffic.get("allow", 0)), int(traffic.get("block", 0))


def source_counts(resp: dict[str, Any], source: str) -> tuple[int, int]:
    sources = resp["result"]["sources"]
    if source not in sources:
        raise SmokeFailure(f"domainSources missing {source}: {sources}")
    bucket = sources[source]
    return int(bucket.get("allow", 0)), int(bucket.get("block", 0))


class DomainCasebook:
    def __init__(self, port: int, app_uid: int, adb: Adb, injector: str) -> None:
        self.port = port
        self.rpc = RpcClient(port)
        self.app_uid = app_uid
        self.app = {"uid": app_uid}
        self.adb = adb
        self.injector = injector
        self.created_lists: list[str] = []
        self.extra_app_configs: dict[int, dict[str, int]] = {}
        self.baseline: dict[str, Any] = {}
        self.token = f"{int(time.time())}-{os.getpid()}"

    def close(self) -> None:
        self.rpc.close()

    def domain(self, label: str) -> str:
        safe = label.replace("_", "-")
        return f"dx-domain-{safe}-{self.token}.example.test"

    def guid(self) -> str:
        return str(uuid.uuid4())

    def snapshot(self) -> None:
        self.baseline["device_config"] = self.config_get(
            "device", ["block.enabled"], None
        )
        self.baseline["app_config"] = self.config_get(
            "app", ["tracked", "domain.custom.enabled", "block.mask"], self.app
        )
        self.baseline["device_policy"] = self.policy_get("device", None)
        self.baseline["app_policy"] = self.policy_get("app", self.app)
        self.baseline["rules"] = self.rules_get()

    def restore(self) -> None:
        errors: list[str] = []

        def attempt(desc: str, fn: Callable[[], None]) -> None:
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 - cleanup must collect all failures
                errors.append(f"{desc}: {exc}")

        if "app_policy" in self.baseline:
            attempt("restore app policy", lambda: self.policy_apply("app", self.baseline["app_policy"], self.app))
        if "device_policy" in self.baseline:
            attempt("restore device policy", lambda: self.policy_apply("device", self.baseline["device_policy"], None))
        if "rules" in self.baseline:
            attempt("restore domain rules", lambda: self.rules_apply(self.baseline["rules"]))
        if self.created_lists:
            ids = list(dict.fromkeys(self.created_lists))
            attempt(
                "remove temporary domain lists",
                lambda: require_ok(
                    self.rpc.call("DOMAINLISTS.APPLY", {"upsert": [], "remove": ids}),
                    "DOMAINLISTS.APPLY cleanup failed",
                ),
            )
        if "app_config" in self.baseline:
            attempt("restore app config", lambda: self.config_set("app", self.baseline["app_config"], self.app))
        for uid, config in self.extra_app_configs.items():
            attempt(f"restore app config uid={uid}", lambda uid=uid, config=config: self.config_set("app", config, {"uid": uid}))
        if "device_config" in self.baseline:
            attempt("restore device config", lambda: self.config_set("device", self.baseline["device_config"], None))

        if errors:
            raise SmokeFailure("cleanup failed: " + "; ".join(errors))

    def config_get(self, scope: str, keys: list[str], app: dict[str, Any] | None) -> dict[str, int]:
        args: dict[str, Any] = {"scope": scope, "keys": keys}
        if app is not None:
            args["app"] = app
        resp = require_ok(self.rpc.call("CONFIG.GET", args), f"CONFIG.GET {scope} failed")
        return dict(resp["result"]["values"])

    def config_set(self, scope: str, values: dict[str, int], app: dict[str, Any] | None) -> None:
        args: dict[str, Any] = {"scope": scope, "set": values}
        if app is not None:
            args["app"] = app
        require_ok(self.rpc.call("CONFIG.SET", args), f"CONFIG.SET {scope} failed")

    def policy_get(self, scope: str, app: dict[str, Any] | None) -> dict[str, Any]:
        args: dict[str, Any] = {"scope": scope}
        if app is not None:
            args["app"] = app
        resp = require_ok(self.rpc.call("DOMAINPOLICY.GET", args), f"DOMAINPOLICY.GET {scope} failed")
        return dict(resp["result"]["policy"])

    def policy_apply(self, scope: str, policy: dict[str, Any], app: dict[str, Any] | None) -> None:
        args: dict[str, Any] = {"scope": scope, "policy": policy}
        if app is not None:
            args["app"] = app
        require_ok(self.rpc.call("DOMAINPOLICY.APPLY", args), f"DOMAINPOLICY.APPLY {scope} failed")

    def rules_get(self) -> list[dict[str, Any]]:
        resp = require_ok(self.rpc.call("DOMAINRULES.GET"), "DOMAINRULES.GET failed")
        return list(resp["result"]["rules"])

    def rules_apply(self, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
        resp = require_ok(self.rpc.call("DOMAINRULES.APPLY", {"rules": rules}), "DOMAINRULES.APPLY failed")
        return list(resp["result"]["rules"])

    def reset_app_metrics(self) -> None:
        require_ok(
            self.rpc.call("METRICS.RESET", {"name": "traffic", "app": self.app}),
            "METRICS.RESET traffic(app) failed",
        )
        require_ok(
            self.rpc.call("METRICS.RESET", {"name": "domainSources", "app": self.app}),
            "METRICS.RESET domainSources(app) failed",
        )

    def get_app_traffic_dns(self) -> tuple[int, int]:
        resp = require_ok(
            self.rpc.call("METRICS.GET", {"name": "traffic", "app": self.app}),
            "METRICS.GET traffic(app) failed",
        )
        return traffic_dns_counts(resp)

    def get_app_source(self, source: str) -> tuple[int, int]:
        resp = require_ok(
            self.rpc.call("METRICS.GET", {"name": "domainSources", "app": self.app}),
            "METRICS.GET domainSources(app) failed",
        )
        return source_counts(resp, source)

    def inject(self, domain: str, uid: int | None = None) -> None:
        target_uid = self.app_uid if uid is None else uid
        result = self.adb.su(f"{shlex.quote(self.injector)} --uid {target_uid} --domain {shlex.quote(domain)}")
        if result.returncode != 0:
            raise SmokeBlocked(f"dx-netd-inject failed for {domain}: {result.stdout.strip()}")

    def capture_dns(
        self,
        domains: list[str],
        trigger: Callable[[], None],
        timeout_sec: float = 6.0,
        uid: int | None = None,
    ) -> dict[str, dict[str, Any]]:
        target_uid = self.app_uid if uid is None else uid
        wanted = set(domains)
        found: dict[str, dict[str, Any]] = {}
        stream = DnsStream(self.port)
        try:
            stream.start()

            def predicate(ev: dict[str, Any]) -> bool:
                if ev.get("type") != "dns":
                    return False
                if int(ev.get("uid", -1)) != target_uid:
                    return False
                domain = ev.get("domain")
                if domain in wanted:
                    found[domain] = ev
                return len(found) == len(wanted)

            stream.collect(trigger, timeout_sec=timeout_sec, predicate=predicate, required=1)
            if set(found) != wanted:
                samples = [
                    {"type": e.get("type"), "uid": e.get("uid"), "domain": e.get("domain"), "notice": e.get("notice")}
                    for e in stream.events_seen[-8:]
                ]
                raise SmokeFailure(f"missing dns events for {sorted(wanted - set(found))}; samples={samples}")
            return found
        finally:
            stream.stop()

    def run_case1_negative_contracts(self) -> None:
        unknown = "00000000-0000-0000-0000-00000000fffe"
        resp = self.rpc.call(
            "DOMAINLISTS.IMPORT",
            {"listId": unknown, "listKind": "block", "mask": 1, "clear": 1, "domains": [self.domain("unknown-list")]},
        )
        require_error(resp, "INVALID_ARGUMENT", "DOMAINLISTS.IMPORT unknown listId should fail")
        if "hint" not in resp.get("error", {}):
            raise SmokeFailure(f"DOMAINLISTS.IMPORT unknown listId missing hint: {resp}")
        log_pass("VNT-DOM-01a", "DOMAINLISTS.IMPORT unknown listId rejects with hint")

        baseline_rules = self.rules_get()
        device_policy = self.policy_get("device", None)
        pattern = self.domain("conflict-rule")
        desired = baseline_rules + [{"type": "domain", "pattern": pattern}]
        rules_after = self.rules_apply(desired)
        temp_rule = next((r for r in rules_after if r.get("pattern") == pattern), None)
        if temp_rule is None:
            raise SmokeFailure("temporary conflict rule not returned by DOMAINRULES.APPLY")
        temp_rule_id = int(temp_rule["ruleId"])
        self.policy_apply(
            "device",
            {"allow": {"domains": [], "ruleIds": [temp_rule_id]}, "block": {"domains": [], "ruleIds": []}},
            None,
        )
        resp = self.rpc.call("DOMAINRULES.APPLY", {"rules": baseline_rules})
        require_error(resp, "INVALID_ARGUMENT", "DOMAINRULES.APPLY removing referenced rule should fail")
        err = resp.get("error", {})
        if "conflicts" not in err or "hint" not in err:
            raise SmokeFailure(f"DOMAINRULES.APPLY conflict missing conflicts/hint: {resp}")
        self.policy_apply("device", device_policy, None)
        self.rules_apply(baseline_rules)
        log_pass("VNT-DOM-01b", "DOMAINRULES.APPLY rejects removal of referenced rule")

    def run_case3_inject_e2e(self) -> None:
        allow_domain = self.domain("inject-allow")
        block_domain = self.domain("inject-block")
        self.config_set("device", {"block.enabled": 1}, None)
        self.config_set("app", {"tracked": 1, "domain.custom.enabled": 1}, self.app)
        self.policy_apply(
            "app",
            {
                "allow": {"domains": [allow_domain], "ruleIds": []},
                "block": {"domains": [block_domain], "ruleIds": []},
            },
            self.app,
        )
        self.reset_app_metrics()
        events = self.capture_dns(
            [allow_domain, block_domain],
            lambda: (self.inject(allow_domain), self.inject(block_domain)),
        )
        require_dns_event(
            events[allow_domain],
            self.app_uid,
            allow_domain,
            blocked=False,
            getips=True,
            policySource="CUSTOM_WHITELIST",
            scope="APP",
            useCustomList=True,
        )
        require_dns_event(
            events[block_domain],
            self.app_uid,
            block_domain,
            blocked=True,
            getips=False,
            policySource="CUSTOM_BLACKLIST",
            scope="APP",
            useCustomList=True,
        )
        allow_count, block_count = self.get_app_traffic_dns()
        if allow_count < 1 or block_count < 1:
            raise SmokeFailure(f"traffic.dns did not grow for allow/block: allow={allow_count} block={block_count}")
        custom_allow, _ = self.get_app_source("CUSTOM_WHITELIST")
        _, custom_block = self.get_app_source("CUSTOM_BLACKLIST")
        if custom_allow < 1 or custom_block < 1:
            raise SmokeFailure("domainSources CUSTOM_WHITELIST/CUSTOM_BLACKLIST buckets did not grow")
        log_pass("VNT-DOM-03", "DNS netd inject e2e covers stream fields, traffic.dns, and domainSources")

    def run_case4_suppressed(self) -> None:
        domain = self.domain("suppressed")
        self.config_set("device", {"block.enabled": 1}, None)
        self.config_set("app", {"tracked": 0, "domain.custom.enabled": 1}, self.app)
        self.policy_apply(
            "app",
            {"allow": {"domains": [], "ruleIds": []}, "block": {"domains": [domain], "ruleIds": []}},
            self.app,
        )
        self.reset_app_metrics()
        stream = DnsStream(self.port)
        notice = None
        matching_dns = None
        try:
            stream.start()
            self.inject(domain)
            deadline = time.time() + 3.0
            while time.time() < deadline:
                try:
                    ev = stream.read_event(timeout_sec=0.5)
                except SmokeFailure:
                    continue
                if ev.get("type") == "dns" and ev.get("domain") == domain and int(ev.get("uid", -1)) == self.app_uid:
                    matching_dns = ev
                if ev.get("type") == "notice" and ev.get("notice") == "suppressed" and ev.get("stream") == "dns":
                    notice = ev
                    break
        finally:
            stream.stop()
        if matching_dns is not None:
            raise SmokeFailure(f"tracked=0 emitted dns event: {matching_dns}")
        if notice is None:
            raise SmokeFailure("tracked=0 did not emit dns suppressed notice")
        traffic = notice.get("traffic", {}).get("dns", {})
        if int(traffic.get("allow", 0)) + int(traffic.get("block", 0)) <= 0:
            raise SmokeFailure(f"suppressed notice missing dns traffic snapshot: {notice}")
        if "tracked" not in str(notice.get("hint", "")):
            raise SmokeFailure(f"suppressed notice missing tracked hint: {notice}")
        _, block_count = self.get_app_traffic_dns()
        _, source_block = self.get_app_source("CUSTOM_BLACKLIST")
        if block_count < 1 or source_block < 1:
            raise SmokeFailure("tracked=0 traffic/domainSources did not grow")
        log_pass("VNT-DOM-04", "tracked=0 produces suppressed notice and keeps metrics")

    def run_case5_custom_toggle(self) -> None:
        domain = self.domain("custom-toggle")
        self.config_set("device", {"block.enabled": 1}, None)
        self.policy_apply(
            "app",
            {"allow": {"domains": [], "ruleIds": []}, "block": {"domains": [domain], "ruleIds": []}},
            self.app,
        )
        require_ok(
            self.rpc.call("METRICS.RESET", {"name": "domainSources", "app": self.app}),
            "reset domainSources(app) failed",
        )
        self.config_set("app", {"domain.custom.enabled": 1}, self.app)
        enabled = require_ok(
            self.rpc.call("DEV.DOMAIN.QUERY", {"app": self.app, "domain": domain}),
            "DEV.DOMAIN.QUERY custom enabled failed",
        )["result"]
        self.config_set("app", {"domain.custom.enabled": 0}, self.app)
        disabled = require_ok(
            self.rpc.call("DEV.DOMAIN.QUERY", {"app": self.app, "domain": domain}),
            "DEV.DOMAIN.QUERY custom disabled failed",
        )["result"]
        if enabled.get("policySource") != "CUSTOM_BLACKLIST" or enabled.get("blocked") is not True:
            raise SmokeFailure(f"custom enabled verdict mismatch: {enabled}")
        if disabled.get("policySource") != "MASK_FALLBACK":
            raise SmokeFailure(f"custom disabled did not fall back: {disabled}")
        _, custom_block = self.get_app_source("CUSTOM_BLACKLIST")
        fallback_allow, fallback_block = self.get_app_source("MASK_FALLBACK")
        if custom_block < 1 or fallback_allow + fallback_block < 1:
            raise SmokeFailure("custom toggle did not grow CUSTOM_BLACKLIST and MASK_FALLBACK buckets")
        log_pass("VNT-DOM-05", "domain.custom.enabled toggles custom policy vs fallback")

    def run_case6_policy_priority(self) -> None:
        d1 = self.domain("prio-app-allow")
        d2 = self.domain("prio-app-block")
        d3 = self.domain("prio-device-only")
        self.config_set("device", {"block.enabled": 1}, None)
        self.config_set("app", {"tracked": 1, "domain.custom.enabled": 1}, self.app)
        self.policy_apply(
            "device",
            {
                "allow": {"domains": [d2], "ruleIds": []},
                "block": {"domains": [d1, d3], "ruleIds": []},
            },
            None,
        )
        self.policy_apply(
            "app",
            {
                "allow": {"domains": [d1], "ruleIds": []},
                "block": {"domains": [d2], "ruleIds": []},
            },
            self.app,
        )
        self.reset_app_metrics()
        events = self.capture_dns([d1, d2, d3], lambda: (self.inject(d1), self.inject(d2), self.inject(d3)))
        require_dns_event(events[d1], self.app_uid, d1, blocked=False, policySource="CUSTOM_WHITELIST", scope="APP")
        require_dns_event(events[d2], self.app_uid, d2, blocked=True, policySource="CUSTOM_BLACKLIST", scope="APP")
        require_dns_event(events[d3], self.app_uid, d3, blocked=True, policySource="GLOBAL_BLOCKED", scope="DEVICE_WIDE")
        allow_count, block_count = self.get_app_traffic_dns()
        if allow_count < 1 or block_count < 2:
            raise SmokeFailure(f"policy priority traffic mismatch: allow={allow_count} block={block_count}")
        if self.get_app_source("GLOBAL_BLOCKED")[1] < 1:
            raise SmokeFailure("GLOBAL_BLOCKED.block did not grow")
        log_pass("VNT-DOM-06", "APP policy priority and DEVICE_WIDE fallback are observable")

    def apply_list(self, list_id: str, kind: str, enabled: int) -> None:
        require_ok(
            self.rpc.call(
                "DOMAINLISTS.APPLY",
                {
                    "upsert": [
                        {
                            "listId": list_id,
                            "listKind": kind,
                            "mask": 1,
                            "enabled": enabled,
                            "url": f"https://example.test/{list_id}",
                            "name": f"dx-domain-{kind}",
                            "updatedAt": "2026-04-25_00:00:00",
                            "etag": "dx-domain",
                            "outdated": 0,
                            "domainsCount": 0,
                        }
                    ],
                    "remove": [],
                },
            ),
            f"DOMAINLISTS.APPLY {kind} failed",
        )
        if list_id not in self.created_lists:
            self.created_lists.append(list_id)

    def import_list(self, list_id: str, kind: str, domain: str) -> None:
        require_ok(
            self.rpc.call(
                "DOMAINLISTS.IMPORT",
                {"listId": list_id, "listKind": kind, "mask": 1, "clear": 1, "domains": [domain]},
            ),
            f"DOMAINLISTS.IMPORT {kind} failed",
        )

    def run_case7_domain_lists(self) -> None:
        domain = self.domain("list")
        block_list = self.guid()
        allow_list = self.guid()
        self.config_set("device", {"block.enabled": 1}, None)
        self.config_set("app", {"tracked": 1, "domain.custom.enabled": 0, "block.mask": 1}, self.app)
        self.policy_apply("app", {"allow": {"domains": [], "ruleIds": []}, "block": {"domains": [], "ruleIds": []}}, self.app)
        self.policy_apply("device", {"allow": {"domains": [], "ruleIds": []}, "block": {"domains": [], "ruleIds": []}}, None)
        self.apply_list(block_list, "block", 1)
        self.import_list(block_list, "block", domain)
        self.reset_app_metrics()

        events1 = self.capture_dns([domain], lambda: self.inject(domain))
        ev1 = events1[domain]
        require_dns_event(
            ev1,
            self.app_uid,
            domain,
            blocked=True,
            policySource="MASK_FALLBACK",
            scope="FALLBACK",
            useCustomList=False,
        )
        if int(ev1.get("domMask", 0)) & 1 == 0 or int(ev1.get("appMask", 0)) & 1 == 0:
            raise SmokeFailure(f"block list event missing dom/app mask bit: {ev1}")

        self.apply_list(block_list, "block", 0)
        events2 = self.capture_dns([domain], lambda: self.inject(domain))
        ev2 = events2[domain]
        require_dns_event(ev2, self.app_uid, domain, blocked=False, policySource="MASK_FALLBACK", useCustomList=False)
        if int(ev2.get("domMask", 0)) != 0:
            raise SmokeFailure(f"disabled block list still contributes domMask: {ev2}")

        self.apply_list(block_list, "block", 1)
        self.apply_list(allow_list, "allow", 1)
        self.import_list(allow_list, "allow", domain)
        events3 = self.capture_dns([domain], lambda: self.inject(domain))
        ev3 = events3[domain]
        require_dns_event(ev3, self.app_uid, domain, blocked=False, policySource="MASK_FALLBACK", useCustomList=False)
        if int(ev3.get("domMask", 0)) != 0:
            raise SmokeFailure(f"allow list did not clear domMask: {ev3}")
        fallback_allow, fallback_block = self.get_app_source("MASK_FALLBACK")
        if fallback_allow < 2 or fallback_block < 1:
            raise SmokeFailure(f"MASK_FALLBACK buckets did not grow for list case: allow={fallback_allow} block={fallback_block}")
        log_pass("VNT-DOM-07", "DomainLists enable/disable and allow-over-block affect DNS verdict")
        log_pass("VNT-DOM-02", "domainSources bucket coverage includes APP, DEVICE_WIDE, and FALLBACK")

    def resolver_hook_active(self) -> bool:
        result = self.adb.su(
            "nsenter -t 1 -m -- mount 2>/dev/null | grep libnetd_resolv.so || mount | grep libnetd_resolv.so || true"
        )
        return bool(result.stdout.strip())

    def shell_dns_trigger_command(self, domain: str) -> str:
        quoted = shlex.quote(domain)
        if self.adb.shell("command -v nc >/dev/null 2>&1").returncode == 0:
            return f"nc -z -w 1 {quoted} 80 >/dev/null 2>&1 || true"
        if self.adb.shell("command -v ping >/dev/null 2>&1").returncode == 0:
            return f"ping -c 1 -W 1 {quoted} >/dev/null 2>&1 || true"
        raise SmokeBlocked("Domain Case 8 blocked: no shell DNS trigger command (need nc or ping)")

    def run_case8_real_resolver(self) -> None:
        if not self.resolver_hook_active():
            raise SmokeBlocked(
                "Domain Case 8 blocked: netd resolv hook inactive; run bash dev/dev-netd-resolv.sh status|prepare"
            )
        shell_uid = 2000
        warmup = self.domain("real-warmup")
        warmup_cmd = self.shell_dns_trigger_command(warmup)
        self.adb.shell(warmup_cmd, timeout=10)
        try:
            self.extra_app_configs[shell_uid] = self.config_get(
                "app", ["tracked", "domain.custom.enabled"], {"uid": shell_uid}
            )
            self.config_set("app", {"tracked": 1, "domain.custom.enabled": 1}, {"uid": shell_uid})
        except SmokeFailure as exc:
            raise SmokeBlocked(f"Domain Case 8 blocked: shell uid app not visible after warmup: {exc}") from exc

        domain = self.domain("real-block")
        trigger_cmd = self.shell_dns_trigger_command(domain)
        self.config_set("device", {"block.enabled": 1}, None)
        self.policy_apply(
            "device",
            {"allow": {"domains": [], "ruleIds": []}, "block": {"domains": [domain], "ruleIds": []}},
            None,
        )
        require_ok(self.rpc.call("METRICS.RESET", {"name": "traffic", "app": {"uid": shell_uid}}), "reset shell traffic failed")
        require_ok(
            self.rpc.call("METRICS.RESET", {"name": "domainSources", "app": {"uid": shell_uid}}),
            "reset shell domainSources failed",
        )
        events = self.capture_dns(
            [domain],
            lambda: self.adb.shell(trigger_cmd, timeout=10),
            timeout_sec=8.0,
            uid=shell_uid,
        )
        require_dns_event(events[domain], shell_uid, domain, blocked=True, getips=False)
        traffic = require_ok(
            self.rpc.call("METRICS.GET", {"name": "traffic", "app": {"uid": shell_uid}}),
            "shell traffic get failed",
        )
        _, block_count = traffic_dns_counts(traffic)
        if block_count < 1:
            raise SmokeFailure("Case 8 real resolver did not grow traffic.dns.block")
        sources = require_ok(
            self.rpc.call("METRICS.GET", {"name": "domainSources", "app": {"uid": shell_uid}}),
            "shell domainSources get failed",
        )
        if source_counts(sources, "GLOBAL_BLOCKED")[1] < 1:
            raise SmokeFailure("Case 8 real resolver did not grow GLOBAL_BLOCKED.block")
        log_pass("VNT-DOM-08", "true resolver DNS e2e is observable when netd hook is active")

    def run_case9_ruleids(self) -> None:
        allow_domain = self.domain("rule-allow")
        block_domain = self.domain("rule-block")
        baseline_rules = self.rules_get()
        block_pattern = "^" + block_domain.replace(".", r"\.") + "$"
        desired = baseline_rules + [
            {"type": "domain", "pattern": allow_domain},
            {"type": "regex", "pattern": block_pattern},
        ]
        rules = self.rules_apply(desired)
        allow_rule = next((r for r in rules if r.get("pattern") == allow_domain), None)
        block_rule = next((r for r in rules if r.get("pattern") == block_pattern), None)
        if allow_rule is None or block_rule is None:
            raise SmokeFailure("Case 9 ruleIds were not returned after DOMAINRULES.APPLY")
        self.config_set("device", {"block.enabled": 1}, None)
        self.config_set("app", {"tracked": 1, "domain.custom.enabled": 1}, self.app)
        self.policy_apply(
            "app",
            {
                "allow": {"domains": [], "ruleIds": [int(allow_rule["ruleId"])]},
                "block": {"domains": [], "ruleIds": [int(block_rule["ruleId"])]},
            },
            self.app,
        )
        self.reset_app_metrics()
        events = self.capture_dns(
            [allow_domain, block_domain],
            lambda: (self.inject(allow_domain), self.inject(block_domain)),
        )
        require_dns_event(
            events[allow_domain],
            self.app_uid,
            allow_domain,
            blocked=False,
            getips=True,
            policySource="CUSTOM_RULE_WHITE",
            scope="APP",
        )
        require_dns_event(
            events[block_domain],
            self.app_uid,
            block_domain,
            blocked=True,
            getips=False,
            policySource="CUSTOM_RULE_BLACK",
            scope="APP",
        )
        if self.get_app_source("CUSTOM_RULE_WHITE")[0] < 1 or self.get_app_source("CUSTOM_RULE_BLACK")[1] < 1:
            raise SmokeFailure("Case 9 CUSTOM_RULE domainSources buckets did not grow")
        log_pass("VNT-DOM-09", "DOMAINRULES(ruleIds) e2e covers CUSTOM_RULE buckets")

    def run(self) -> None:
        self.snapshot()
        try:
            self.run_case1_negative_contracts()
            self.run_case3_inject_e2e()
            self.run_case4_suppressed()
            self.run_case5_custom_toggle()
            self.run_case6_policy_priority()
            self.run_case7_domain_lists()
            self.run_case9_ruleids()
            self.run_case8_real_resolver()
        finally:
            self.restore()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run vNext Domain casebook smoke checks")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--adb", required=True)
    parser.add_argument("--serial", default="")
    parser.add_argument("--injector", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    runner = DomainCasebook(args.port, args.uid, Adb(args.adb, args.serial), args.injector)
    try:
        runner.run()
        log_pass("VNT-DOM", "Domain casebook Case 1-9 checks complete")
        return 0
    except SmokeBlocked as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 77
    except Exception as exc:  # noqa: BLE001 - print concise smoke failure
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    finally:
        runner.close()


if __name__ == "__main__":
    raise SystemExit(main())
