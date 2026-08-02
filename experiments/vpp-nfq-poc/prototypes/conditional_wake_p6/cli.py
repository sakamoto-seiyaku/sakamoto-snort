#!/usr/bin/env python3
"""Thin terminal shell for the throwaway P6 wake state model."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from .model import (
    Action,
    Protocol,
    State,
    apply_action,
    enabled_actions,
    enumerate_campaign,
    initial_state,
    violations,
)


def render(state: State, clear: bool = True) -> None:
    if clear:
        print("\033[2J\033[H", end="")
    bold, dim, reset = "\033[1m", "\033[2m", "\033[0m"
    print(f"{bold}P6 conditional-wake prototype{reset}  {dim}{state.protocol.value}{reset}")
    rows = (
        ("phase", state.phase.value),
        ("queue work", state.queue_work),
        ("terminal work", state.terminal_work),
        ("producers published", state.published),
        ("producer notify done", state.notify_done),
        ("notification claimed", state.notification_claimed),
        ("eventfd count", state.eventfd_count),
        ("write required/attempts", f"{state.write_required}/{state.write_attempts}"),
        ("write history", state.write_history or "none"),
        ("last outcome/fault", f"{state.last_write_outcome}/{state.channel_fault}"),
        ("epoch announce/recheck/block", f"{state.epoch}/{state.announced_epoch}/{state.recheck_epoch}/{state.blocked_epoch}"),
        ("sleep flag / blocked", f"{state.sleep_flag}/{state.blocked}"),
        ("worker pc", state.worker_pc),
        ("teardown required/stage/done", f"{state.teardown_required}/{state.teardown_stage}/{state.teardown_complete}"),
        ("violations", violations(state) or "none"),
    )
    for name, value in rows:
        print(f"{bold}{name:28}{reset} {value}")
    print(f"\n{bold}trace{reset}")
    print(" -> ".join(state.trace) if state.trace else f"{dim}(empty){reset}")
    print(f"\n{bold}enabled{reset}")
    print("  ".join(str(action) for action in enabled_actions(state)) or f"{dim}(terminal){reset}")


def parse_action(value: str) -> Action:
    kind, separator, argument = value.strip().partition(":")
    return Action(kind, argument if separator else "")


def run_script(protocol: str, script: str) -> int:
    state = initial_state(protocol)
    render(state, clear=False)
    for item in filter(None, (part.strip() for part in script.split(","))):
        state = apply_action(state, parse_action(item))
        render(state, clear=False)
    return 1 if violations(state) else 0


def interactive(protocol: str) -> int:
    state = initial_state(protocol)
    while True:
        render(state)
        if state.teardown_complete:
            input("\nterminal; press Enter to exit ")
            return 1 if violations(state) else 0
        value = input("\naction ([q] quit): ").strip()
        if value in ("q", "quit"):
            return 0
        try:
            state = apply_action(state, parse_action(value))
        except ValueError as error:
            input(f"{error}\npress Enter ")


def enumerate_all() -> int:
    rows = []
    candidate_ok = True
    for result in enumerate_campaign():
        payload = asdict(result)
        payload["protocol"] = result.protocol.value
        payload["counterexamples"] = {
            name: list(trace) for name, trace in result.counterexamples.items()
        }
        payload["eligible"] = result.eligible
        rows.append(payload)
        if result.protocol is Protocol.EPOCH_STATE and not result.eligible:
            candidate_ok = False
    print(json.dumps({"candidate_eligible": candidate_ok, "explorations": rows}, indent=2))
    return 0 if candidate_ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", choices=[item.value for item in Protocol], default="epoch_state")
    parser.add_argument("--script", help="comma-separated actions, for example announce,recheck,block")
    parser.add_argument("--enumerate", action="store_true", help="exhaust all frozen bounded scenarios")
    args = parser.parse_args()
    if args.enumerate:
        return enumerate_all()
    if args.script is not None:
        return run_script(args.protocol, args.script)
    return interactive(args.protocol)


if __name__ == "__main__":
    raise SystemExit(main())
