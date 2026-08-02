"""Pure bounded state model for the P6 conditional-wake design question.

PROTOTYPE — throw away after P6.  This module compares only the corrected P5
flag protocol and the pre-registered epoch/state-word candidate.  It answers
whether a legal bounded interleaving can strand published work behind a
blocked worker or strand notification ownership after a write failure/drain.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, fields, replace
from enum import Enum
from typing import Iterable


class Protocol(str, Enum):
    CORRECTED_FLAG = "corrected_flag"
    EPOCH_STATE = "epoch_state"


class Phase(str, Enum):
    AWAKE = "AWAKE"
    PREPARING = "PREPARING_TO_SLEEP"
    SLEEPING = "SLEEPING"
    NOTIFIED = "NOTIFIED"
    DRAINING = "DRAINING"


@dataclass(frozen=True, order=True)
class Action:
    kind: str
    argument: str = ""

    def __str__(self) -> str:
        return f"{self.kind}:{self.argument}" if self.argument else self.kind


@dataclass(frozen=True)
class State:
    protocol: Protocol
    phase: Phase = Phase.AWAKE
    queue_work: int = 0
    terminal_work: int = 0
    published: tuple[bool, bool] = (False, False)
    notify_done: tuple[bool, bool] = (False, False)
    notification_claimed: bool = False
    eventfd_count: int = 0
    write_required: bool = False
    write_attempts: int = 0
    successful_writes_since_drain: int = 0
    last_write_outcome: str = "none"
    write_history: tuple[str, ...] = ()
    channel_fault: str = "none"
    epoch: int = 0
    announced_epoch: int = -1
    recheck_epoch: int = -1
    blocked_epoch: int = -1
    recheck_empty: bool = False
    sleep_flag: bool = False
    blocked: bool = False
    worker_pc: int = 0
    teardown_required: bool = False
    teardown_stage: int = 0
    teardown_complete: bool = False
    trace: tuple[str, ...] = ()

    @property
    def published_work(self) -> int:
        return sum(self.published)


def initial_state(protocol: Protocol | str) -> State:
    return State(protocol=Protocol(protocol))


def _set_tuple(value: tuple[bool, bool], index: int, item: bool) -> tuple[bool, bool]:
    result = list(value)
    result[index] = item
    return tuple(result)  # type: ignore[return-value]


def _finish(state: State, action: Action, **changes: object) -> State:
    return replace(state, trace=state.trace + (str(action),), **changes)


def apply_action(state: State, action: Action) -> State:
    """Apply one legal atomic model action and return a new state."""
    if action not in enabled_actions(state):
        raise ValueError(f"illegal action {action}; enabled={enabled_actions(state)}")

    if action.kind == "publish":
        producer = int(action.argument)
        changes: dict[str, object] = {
            "published": _set_tuple(state.published, producer, True),
            "queue_work": state.queue_work + 1,
        }
        if state.protocol is Protocol.EPOCH_STATE:
            changes["epoch"] = state.epoch + 1
        return _finish(state, action, **changes)

    if action.kind == "notify_claim":
        producer = int(action.argument)
        changes = {"notify_done": _set_tuple(state.notify_done, producer, True)}
        if state.notification_claimed:
            return _finish(state, action, **changes)

        if state.protocol is Protocol.CORRECTED_FLAG:
            if state.sleep_flag and state.phase in (
                Phase.PREPARING,
                Phase.SLEEPING,
                Phase.NOTIFIED,
            ):
                changes.update(
                    notification_claimed=True,
                    write_required=True,
                    phase=Phase.NOTIFIED,
                )
            return _finish(state, action, **changes)

        if state.phase is Phase.PREPARING:
            changes.update(notification_claimed=True, phase=Phase.NOTIFIED)
        elif state.phase is Phase.SLEEPING:
            changes.update(
                notification_claimed=True,
                write_required=True,
                phase=Phase.NOTIFIED,
            )
        return _finish(state, action, **changes)

    if action.kind == "announce":
        return _finish(
            state,
            action,
            phase=Phase.PREPARING,
            sleep_flag=state.protocol is Protocol.CORRECTED_FLAG,
            announced_epoch=state.epoch,
            worker_pc=1,
        )

    if action.kind == "recheck":
        empty = state.queue_work == 0
        if not empty or state.phase is Phase.NOTIFIED:
            return _finish(
                state,
                action,
                phase=Phase.DRAINING,
                recheck_empty=empty,
                recheck_epoch=state.epoch,
                blocked=False,
                worker_pc=4,
            )
        return _finish(
            state,
            action,
            recheck_empty=True,
            recheck_epoch=state.epoch,
            worker_pc=2,
        )

    if action.kind == "block":
        if state.phase is Phase.NOTIFIED:
            return _finish(state, action, phase=Phase.DRAINING, worker_pc=4)
        if state.protocol is Protocol.EPOCH_STATE and state.epoch != state.recheck_epoch:
            return _finish(state, action, phase=Phase.DRAINING, worker_pc=4)
        return _finish(
            state,
            action,
            phase=Phase.SLEEPING,
            blocked=True,
            blocked_epoch=state.recheck_epoch,
            worker_pc=3,
        )

    if action.kind == "write":
        outcome = action.argument
        attempts = state.write_attempts + 1
        history = state.write_history + (outcome,)
        if outcome == "success":
            return _finish(
                state,
                action,
                eventfd_count=state.eventfd_count + 1,
                write_required=False,
                write_attempts=attempts,
                successful_writes_since_drain=state.successful_writes_since_drain + 1,
                last_write_outcome=outcome,
                write_history=history,
            )
        if outcome == "eagain":
            return _finish(
                state,
                action,
                eventfd_count=max(1, state.eventfd_count),
                write_required=False,
                write_attempts=attempts,
                last_write_outcome=outcome,
                write_history=history,
            )
        if state.protocol is Protocol.CORRECTED_FLAG:
            return _finish(
                state,
                action,
                write_required=False,
                write_attempts=attempts,
                last_write_outcome=outcome,
                write_history=history,
            )
        if outcome == "eintr" and attempts < 3:
            return _finish(
                state,
                action,
                write_attempts=attempts,
                last_write_outcome=outcome,
                write_history=history,
            )
        fault = "EINTR_EXHAUSTED" if outcome == "eintr" else outcome.upper()
        return _finish(
            state,
            action,
            notification_claimed=False,
            write_required=False,
            write_attempts=attempts,
            last_write_outcome=outcome,
            write_history=history,
            channel_fault=fault,
            teardown_required=True,
        )

    if action.kind == "epoll_return":
        return _finish(state, action, phase=Phase.DRAINING, blocked=False, worker_pc=4)

    if action.kind == "spurious_wake":
        return _finish(state, action, phase=Phase.DRAINING, blocked=False, worker_pc=4)

    if action.kind == "drain":
        return _finish(
            state,
            action,
            eventfd_count=0,
            successful_writes_since_drain=0,
            worker_pc=5,
        )

    if action.kind == "clear":
        return _finish(
            state,
            action,
            notification_claimed=False,
            sleep_flag=False,
            phase=Phase.DRAINING if state.queue_work else Phase.AWAKE,
            worker_pc=6,
        )

    if action.kind == "process":
        return _finish(
            state,
            action,
            terminal_work=state.terminal_work + state.queue_work,
            queue_work=0,
            phase=Phase.AWAKE,
            sleep_flag=False,
            worker_pc=7,
        )

    if action.kind == "teardown_begin":
        return _finish(state, action, teardown_required=True, teardown_stage=1)

    if action.kind == "teardown_unblock":
        return _finish(
            state,
            action,
            blocked=False,
            phase=Phase.DRAINING,
            teardown_stage=2,
        )

    if action.kind == "teardown_drain":
        return _finish(
            state,
            action,
            eventfd_count=0,
            write_required=False,
            successful_writes_since_drain=0,
            teardown_stage=3,
        )

    if action.kind == "teardown_settle":
        return _finish(
            state,
            action,
            terminal_work=state.terminal_work + state.queue_work,
            queue_work=0,
            teardown_stage=4,
        )

    if action.kind == "teardown_clear":
        return _finish(
            state,
            action,
            notification_claimed=False,
            sleep_flag=False,
            phase=Phase.AWAKE,
            teardown_stage=5,
        )

    if action.kind == "teardown_finish":
        return _finish(
            state,
            action,
            teardown_required=False,
            teardown_stage=6,
            teardown_complete=True,
        )

    raise AssertionError(action)


def enabled_actions(state: State) -> tuple[Action, ...]:
    if state.teardown_complete:
        return ()
    if state.teardown_stage == 1:
        return (Action("teardown_unblock"),)
    if state.teardown_stage == 2:
        return (Action("teardown_drain"),)
    if state.teardown_stage == 3:
        return (Action("teardown_settle"),)
    if state.teardown_stage == 4:
        return (Action("teardown_clear"),)
    if state.teardown_stage == 5:
        return (Action("teardown_finish"),)
    if state.teardown_required:
        return (Action("teardown_begin"),)

    actions: list[Action] = []
    for producer in range(2):
        if not state.published[producer]:
            actions.append(Action("publish", str(producer)))
        elif not state.notify_done[producer]:
            actions.append(Action("notify_claim", str(producer)))

    if state.write_required:
        actions.extend(Action("write", outcome) for outcome in (
            "success", "eintr", "eagain", "ebadf", "einval"
        ))

    if state.worker_pc == 0 and state.phase is Phase.AWAKE:
        actions.append(Action("announce"))
    elif state.worker_pc == 1 and state.phase in (Phase.PREPARING, Phase.NOTIFIED):
        actions.append(Action("recheck"))
    elif state.worker_pc == 2 and state.phase in (Phase.PREPARING, Phase.NOTIFIED):
        actions.append(Action("block"))
    elif state.worker_pc == 3 and state.blocked:
        if state.eventfd_count:
            actions.append(Action("epoll_return"))
        actions.append(Action("spurious_wake"))
    elif state.worker_pc == 4 and not state.blocked and not state.write_required:
        actions.append(Action("drain"))
    elif (
        state.worker_pc == 5
        and not state.blocked
        and not state.write_required
        and state.eventfd_count == 0
    ):
        actions.append(Action("clear"))
    elif state.worker_pc == 6:
        actions.append(Action("process"))
    actions.append(Action("teardown_begin"))
    return tuple(sorted(actions))


def violations(state: State) -> tuple[str, ...]:
    result: list[str] = []
    notifier_outstanding = any(
        published and not done for published, done in zip(state.published, state.notify_done)
    )
    if (
        state.queue_work > 0
        and state.blocked
        and state.eventfd_count == 0
        and not state.write_required
        and not notifier_outstanding
        and not state.teardown_required
    ):
        result.append("lost_wake")
    if (
        state.notification_claimed
        and not state.write_required
        and state.eventfd_count == 0
        and state.last_write_outcome in ("eintr", "ebadf", "einval")
        and not state.teardown_required
    ):
        result.append("orphaned_claim")
    if state.successful_writes_since_drain > 1:
        result.append("double_notification")
    if state.eventfd_count > 0 and state.published_work == 0:
        result.append("publish_order")
    if state.blocked and (
        not state.recheck_empty
        or state.blocked_epoch < 0
        or state.blocked_epoch != state.recheck_epoch
    ):
        result.append("illegal_block")
    if state.teardown_stage >= 3 and state.eventfd_count:
        result.append("teardown_residue")
    if state.teardown_stage >= 4 and state.queue_work:
        result.append("teardown_residue")
    if state.teardown_stage >= 5 and (
        state.notification_claimed
        or state.write_required
        or state.sleep_flag
        or state.blocked
        or state.phase is not Phase.AWAKE
    ):
        result.append("teardown_residue")
    if state.teardown_complete and (
        state.queue_work
        or state.notification_claimed
        or state.eventfd_count
        or state.write_required
        or state.blocked
        or state.phase is not Phase.AWAKE
    ):
        result.append("teardown_residue")
    if (
        state.queue_work < 0
        or state.terminal_work < 0
        or state.queue_work + state.terminal_work != state.published_work
    ):
        result.append("ledger")
    return tuple(result)


def semantic_key(state: State) -> tuple[object, ...]:
    return tuple(getattr(state, field.name) for field in fields(State) if field.name != "trace")


@dataclass(frozen=True)
class Exploration:
    protocol: Protocol
    explored_states: int
    terminal_states: int
    write_sequences_seen: tuple[tuple[str, ...], ...]
    counterexamples: dict[str, tuple[str, ...]]

    @property
    def eligible(self) -> bool:
        return not self.counterexamples


def enumerate_interleavings(protocol: Protocol | str) -> Exploration:
    """Breadth-first enumeration yields the shortest trace per invariant."""
    start = initial_state(protocol)
    pending = deque([start])
    seen = {semantic_key(start)}
    counterexamples: dict[str, tuple[str, ...]] = {}
    terminal_states = 0
    write_sequences_seen: set[tuple[str, ...]] = set()

    while pending:
        state = pending.popleft()
        if state.write_history:
            write_sequences_seen.add(state.write_history)
        found = violations(state)
        for invariant in found:
            sequence = ",".join(state.write_history) or "none"
            counterexamples.setdefault(f"{invariant}:{sequence}", state.trace)
        if found:
            continue
        if state.teardown_complete:
            terminal_states += 1
            continue
        actions = enabled_actions(state)
        if not actions:
            counterexamples.setdefault("teardown_residue:deadlock", state.trace)
            continue
        for action in actions:
            next_state = apply_action(state, action)
            key = semantic_key(next_state)
            if key not in seen:
                seen.add(key)
                pending.append(next_state)

    return Exploration(
        protocol=Protocol(protocol),
        explored_states=len(seen),
        terminal_states=terminal_states,
        write_sequences_seen=tuple(sorted(write_sequences_seen)),
        counterexamples=counterexamples,
    )


def enumerate_campaign() -> Iterable[Exploration]:
    for protocol in Protocol:
        yield enumerate_interleavings(protocol)
