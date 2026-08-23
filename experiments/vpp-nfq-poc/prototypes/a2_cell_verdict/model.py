"""THROWAWAY pure model for the A2 manifest-verdict question."""
from dataclasses import dataclass, replace

PASS = "PASS"
FAIL = "FAIL"
INVALID = "INVALID"
INCONCLUSIVE = "INCONCLUSIVE"
PENDING = "PENDING"
A2_INCOMPLETE = "A2_INCOMPLETE"
CLEAN = "CLEAN"
DIRTY = "DIRTY"
UNSETTLED = "UNSETTLED"


@dataclass(frozen=True)
class Requirement:
    name: str
    expected: str


@dataclass(frozen=True)
class Manifest:
    cell_id: str
    joins: tuple[Requirement, ...]
    instrumentation: tuple[str, ...]
    decisive: str
    falsifier: str
    deadline: int = 3
    required: bool = True


@dataclass(frozen=True)
class Join:
    name: str
    actual: str
    durable: bool = True


@dataclass(frozen=True)
class Instrument:
    name: str
    valid: bool


@dataclass(frozen=True)
class Event:
    name: str
    tick: int
    durable: bool = True


@dataclass(frozen=True)
class Cell:
    manifest: Manifest
    joins: tuple[Join, ...] = ()
    instruments: tuple[Instrument, ...] = ()
    events: tuple[Event, ...] = ()
    tick: int = 0
    cleanup: str = UNSETTLED


@dataclass(frozen=True)
class Action:
    kind: str
    name: str = ""
    actual: str = ""
    durable: bool = True
    valid: bool = True
    amount: int = 1


def reduce_cell(cell: Cell, action: Action) -> Cell:
    """Pure reducer; no evidence I/O, logging, device calls, or persistence."""
    if action.kind == "join":
        return replace(cell, joins=cell.joins + (Join(action.name, action.actual, action.durable),))
    if action.kind == "instrument":
        return replace(cell, instruments=cell.instruments + (Instrument(action.name, action.valid),))
    if action.kind == "event":
        return replace(cell, events=cell.events + (Event(action.name, cell.tick, action.durable),))
    if action.kind == "tick":
        return replace(cell, tick=cell.tick + max(1, action.amount))
    if action.kind == "cleanup":
        if action.actual not in (CLEAN, DIRTY, UNSETTLED):
            raise ValueError(action.actual)
        return replace(cell, cleanup=action.actual)
    if action.kind == "reset":
        return Cell(cell.manifest)
    raise ValueError(action.kind)


def _requirements(cell: Cell) -> dict[str, str]:
    state = {}
    for requirement in cell.manifest.joins:
        seen = [x for x in cell.joins if x.name == requirement.name]
        state[requirement.name] = (
            "missing" if not seen else
            "invalid" if any(not x.durable or x.actual != requirement.expected for x in seen)
            else "valid"
        )
    for name in cell.manifest.instrumentation:
        seen = [x for x in cell.instruments if x.name == name]
        state["instrumentation:" + name] = (
            "missing" if not seen else
            "invalid" if any(not x.valid for x in seen) else "valid"
        )
    return state


def _seen(cell: Cell, name: str) -> bool:
    return any(x.name == name and x.durable and x.tick <= cell.manifest.deadline for x in cell.events)


def verdict(cell: Cell) -> tuple[str, str]:
    """Evaluate one cell; PENDING is only an in-progress display state."""
    requirements = _requirements(cell)
    invalid = [k for k, v in requirements.items() if v == "invalid"]
    missing = [k for k, v in requirements.items() if v == "missing"]
    if invalid:
        return INVALID, "invalid-evidence:" + ",".join(invalid)
    if cell.cleanup == DIRTY:
        return INVALID, "cleanup-dirty"
    if cell.tick >= cell.manifest.deadline and (missing or cell.cleanup == UNSETTLED):
        return INVALID, "deadline-with-unsettled-evidence"
    if _seen(cell, cell.manifest.falsifier):
        return FAIL, "behavior-falsifier:" + cell.manifest.falsifier
    if not _seen(cell, cell.manifest.decisive):
        return (
            (INCONCLUSIVE, "deadline-without-decisive-event")
            if cell.tick >= cell.manifest.deadline
            else (PENDING, "waiting-for-decisive-event:" + cell.manifest.decisive)
        )
    if missing or cell.cleanup != CLEAN:
        return PENDING, "waiting-for-evidence-or-cleanup"
    return PASS, "all-registered-assertions-pass"


def cell_view(cell: Cell) -> dict:
    status, reason = verdict(cell)
    return {
        "cell_id": cell.manifest.cell_id, "status": status, "reason": reason,
        "tick": cell.tick, "deadline": cell.manifest.deadline, "cleanup": cell.cleanup,
        "requirements": _requirements(cell),
        "joins": [(x.name, x.actual, x.durable) for x in cell.joins],
        "instrumentation": [(x.name, x.valid) for x in cell.instruments],
        "events": [(x.name, x.tick, x.durable) for x in cell.events],
    }


def aggregate(cells: tuple[Cell, ...]) -> dict:
    statuses = {x.manifest.cell_id: verdict(x)[0] for x in cells}
    required = [x.manifest.cell_id for x in cells if x.manifest.required]
    return {
        "status": PASS if required and all(statuses[x] == PASS for x in required) else A2_INCOMPLETE,
        "required": required,
        "not_passed": [x for x in required if statuses[x] != PASS],
        "cell_statuses": statuses,
    }


@dataclass(frozen=True)
class State:
    cells: tuple[Cell, ...]
    selected: int = 0
    actions: int = 0
    last: str = "initial"


def manifests() -> tuple[Manifest, ...]:
    q = lambda *xs: tuple(Requirement(*x) for x in xs)
    return (
        Manifest("A2-0", q(("package_uid", "com.poc.app=12629"), ("vpn_builder", "builder-digest"), ("allowed_scope", "uids=[12629]")), ("stage-ledger",), "SESSION_CORRELATED", "PROVENANCE_MISMATCH"),
        Manifest("A2-1", q(("app_uids", "12629,12630"), ("tuple_matrix", "v4/v6 x tcp/udp")), ("uid-contract",), "UID_CACHE_HIT", "WRONG_UID"),
        Manifest("A2-2", q(("cache_scope", "per-app"), ("bounds", "pending/cache bounded")), ("concurrency-ledger",), "CONCURRENCY_BOUNDED", "CROSS_APP_HIT"),
        Manifest("A2-3", q(("canonical_key", "same-key"), ("return_provenance", "flow-stack-return")), ("return-ledger",), "RETURN_DELIVERED", "OWNER_MISMATCH"),
        Manifest("A2-4", q(("app_epoch", "joined"), ("runtime_generation", "joined")), ("lifecycle-stage-ledger",), "LIFECYCLE_JOINED", "STALE_COMPLETION_ACCEPTED"),
        Manifest("A2-5", q(("allow_ledger", "real-broker-socket"), ("drop_ledger", "fresh-key-zero-downstream")), ("admission-ledger",), "SOCKET_SETTLED", "DROP_DOWNSTREAM_WORK"),
        Manifest("A2-6", q(("replay", "generation+duplicate"), ("cleanup", "zero-residue")), ("settlement-ledger",), "SETTLEMENT_COMPLETE", "STALE_COMPLETION_ACCEPTED"),
    )


def initial() -> State:
    return State(tuple(Cell(x) for x in manifests()))


def reduce_state(state: State, action: Action) -> State:
    if action.kind == "select":
        i = action.amount % len(state.cells)
        return replace(state, selected=i, actions=state.actions + 1, last="select:" + state.cells[i].manifest.cell_id)
    if action.kind == "next":
        return reduce_state(state, Action("select", amount=state.selected + 1))
    if action.kind == "previous":
        return reduce_state(state, Action("select", amount=state.selected - 1))
    if action.kind == "reset-all":
        return replace(initial(), selected=state.selected, actions=state.actions + 1, last="reset-all")
    i = state.selected
    cells = list(state.cells)
    cells[i] = reduce_cell(cells[i], action)
    return replace(state, cells=tuple(cells), actions=state.actions + 1, last=action.kind + ":" + cells[i].manifest.cell_id)


def seed(cell: Cell, mode: str) -> Cell:
    """Small scenario helper used by the TUI; still pure and in-memory."""
    for r in cell.manifest.joins:
        cell = reduce_cell(cell, Action("join", r.name, r.expected))
    for name in cell.manifest.instrumentation:
        cell = reduce_cell(cell, Action("instrument", name))
    if mode != "inconclusive":
        cell = reduce_cell(cell, Action("event", cell.manifest.decisive))
    cell = reduce_cell(cell, Action("cleanup", actual=CLEAN))
    if mode == "fail":
        cell = reduce_cell(cell, Action("event", cell.manifest.falsifier))
    if mode == "invalid-provenance":
        r = cell.manifest.joins[0]
        cell = reduce_cell(cell, Action("join", r.name, "MISMATCH"))
    if mode == "invalid-instrumentation":
        cell = reduce_cell(cell, Action("instrument", cell.manifest.instrumentation[0], valid=False))
    if mode == "inconclusive":
        cell = reduce_cell(cell, Action("tick", amount=cell.manifest.deadline))
    if mode == "empty-logcat":
        cell = reduce_cell(cell, Action("event", "LOGCAT_EMPTY", durable=False))
    return cell


def scenario(state: State, mode: str) -> State:
    cells = list(state.cells)
    cells[state.selected] = seed(Cell(cells[state.selected].manifest), mode)
    return replace(state, cells=tuple(cells), actions=state.actions + 1, last="scenario:" + mode)


def view(state: State) -> dict:
    return {"aggregate": aggregate(state.cells), "selected": state.cells[state.selected].manifest.cell_id, "actions": state.actions, "last": state.last, "cells": [cell_view(x) for x in state.cells]}
