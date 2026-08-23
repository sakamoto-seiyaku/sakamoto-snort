#!/usr/bin/env python3
"""THROWAWAY full-redraw TUI for the A2 cell verdict model."""
import json
import sys

from model import Action, initial, reduce_state, scenario, view


def render(state):
    print("\033[2J\033[H", end="")
    print("\033[1mA2 CELL VERDICT — THROWAWAY\033[0m")
    print(json.dumps(view(state), indent=2, sort_keys=True))
    print("\n\033[1mkeys\033[0m: 1-7 select  j join  v instrumentation  e decisive  b falsifier")
    print("      h PASS  f FAIL  m invalid-provenance  i invalid-instrumentation")
    print("      z INCONCLUSIVE  o empty-logcat  d deadline  c clean  x dirty")
    print("      n/p next/previous  r reset-cell  R reset-all  q quit")


def step(state, key):
    if key.isdigit() and 1 <= int(key) <= len(state.cells):
        return reduce_state(state, Action("select", amount=int(key) - 1))
    if key == "n":
        return reduce_state(state, Action("next"))
    if key == "p":
        return reduce_state(state, Action("previous"))
    if key == "R":
        return reduce_state(state, Action("reset-all"))
    if key in {"h", "f", "m", "i", "z", "o"}:
        return scenario(state, {"h": "pass", "f": "fail", "m": "invalid-provenance",
                                "i": "invalid-instrumentation", "z": "inconclusive",
                                "o": "empty-logcat"}[key])
    cell = state.cells[state.selected]
    if key == "j":
        req = cell.manifest.joins[len(cell.joins) % len(cell.manifest.joins)]
        return reduce_state(state, Action("join", req.name, req.expected))
    if key == "v":
        name = cell.manifest.instrumentation[len(cell.instruments) % len(cell.manifest.instrumentation)]
        return reduce_state(state, Action("instrument", name))
    if key == "e":
        return reduce_state(state, Action("event", cell.manifest.decisive))
    if key == "b":
        return reduce_state(state, Action("event", cell.manifest.falsifier))
    if key == "d":
        return reduce_state(state, Action("tick", amount=max(1, cell.manifest.deadline - cell.tick)))
    if key in {"c", "x"}:
        return reduce_state(state, Action("cleanup", actual="CLEAN" if key == "c" else "DIRTY"))
    if key == "r":
        return reduce_state(state, Action("reset"))
    return state


def demo():
    expected = {"pass": "PASS", "fail": "FAIL", "invalid-provenance": "INVALID",
                "invalid-instrumentation": "INVALID", "inconclusive": "INCONCLUSIVE",
                "empty-logcat": "PASS"}
    result = {}
    if view(initial())["aggregate"]["status"] != "A2_INCOMPLETE":
        raise AssertionError("initial aggregate must be A2_INCOMPLETE")
    for mode, want in expected.items():
        got = view(scenario(initial(), mode))["cells"][0]["status"]
        if got != want:
            raise AssertionError(f"{mode}: got {got}, want {want}")
        result[mode] = got
    all_pass = initial()
    for index in range(len(all_pass.cells)):
        all_pass = reduce_state(all_pass, Action("select", amount=index))
        all_pass = scenario(all_pass, "pass")
    aggregate_status = view(all_pass)["aggregate"]["status"]
    if aggregate_status != "PASS":
        raise AssertionError(f"all required cells: got {aggregate_status}")
    print(json.dumps({"smoke": "ok", "initial_aggregate": "A2_INCOMPLETE",
                      "all_pass_aggregate": aggregate_status, "cell_verdicts": result},
                     sort_keys=True))


def main():
    if "--demo" in sys.argv:
        demo()
        return 0
    state = initial()
    while True:
        render(state)
        try:
            key = input("\ncommand> ").strip()
        except EOFError:
            return 0
        if key in {"q", "quit"}:
            return 0
        state = step(state, key)


if __name__ == "__main__":
    raise SystemExit(main())
