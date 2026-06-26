#!/usr/bin/env python3
"""PROTOTYPE: convert one tiny POC rules JSON file into nfqueue-poc CLI."""

from __future__ import annotations

import argparse
import ipaddress
import json
import shlex
import sys
from pathlib import Path


def normalize_family(value: str | None) -> str:
    if value in (None, "", "ip6", "ipv6", "inet6"):
        return "ip6"
    if value in ("ip4", "ipv4", "inet"):
        return "ip4"
    raise ValueError(f"unsupported family: {value}")


def load_single_rule(path: Path) -> tuple[dict, dict]:
    root = json.loads(path.read_text(encoding="utf-8"))
    rules = root.get("rules")
    if not isinstance(rules, list) or len(rules) != 1:
        raise ValueError("POC supports exactly one rule in rules[]")
    rule = rules[0]
    if not isinstance(rule, dict):
        raise ValueError("rules[0] must be an object")
    if rule.get("enabled", True) is False:
        raise ValueError("POC rule must be enabled")
    if rule.get("action", "block") not in ("allow", "block"):
        raise ValueError("POC supports only action=allow|block")
    return root, rule


def rule_to_cli(root: dict, rule: dict, event_log: str | None) -> list[str]:
    queue = int(root.get("queue", 42))
    family = normalize_family(rule.get("family", root.get("family")))

    cmd = ["nfqueue-poc", "enable", "queue", str(queue), "family", family]

    action = rule.get("action", "block")
    if "uid" not in rule and "dst" not in rule:
        raise ValueError("POC rule needs uid or dst")

    if action == "allow":
        if "uid" not in rule or "dst" in rule:
            raise ValueError("POC allow rule supports uid only")
        cmd += ["mode", "allow-uid", str(int(rule["uid"]))]
    elif "uid" in rule and "dst" not in rule:
        cmd += ["mode", "block-uid", str(int(rule["uid"]))]
    elif "dst" in rule:
        network = ipaddress.ip_network(str(rule["dst"]), strict=False)
        if network.version != 6 or network.prefixlen != 128:
            raise ValueError("POC exact dst supports only IPv6 /128")
        cmd += ["mode", "block-ip6-dst", str(network.network_address)]

    event_log = event_log or root.get("eventLog")
    if event_log:
        cmd += ["event-log", str(event_log)]

    return cmd


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("rules_json", type=Path)
    parser.add_argument("--event-log", default=None)
    parser.add_argument("--shell-quote", action="store_true")
    args = parser.parse_args()

    try:
        root, rule = load_single_rule(args.rules_json)
        cmd = rule_to_cli(root, rule, args.event_log)
    except Exception as exc:  # noqa: BLE001 - prototype CLI should print direct errors.
        print(f"poc-rules-to-vppctl: {exc}", file=sys.stderr)
        return 2

    if args.shell_quote:
        print(" ".join(shlex.quote(part) for part in cmd))
    else:
        print(" ".join(cmd))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
