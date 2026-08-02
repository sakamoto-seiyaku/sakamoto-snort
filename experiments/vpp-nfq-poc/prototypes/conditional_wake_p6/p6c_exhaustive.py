#!/usr/bin/env python3
"""Exhaust the bounded P6 epoch-wake interleavings at atomic-step granularity."""

from __future__ import annotations

import argparse
import json
from collections import deque
from dataclasses import dataclass, fields, replace
from typing import Iterable

AWAKE, PREPARING, SLEEPING, NOTIFIED, DRAINING, NOTIFYING = range(6)
PHASE_NAMES = ("AWAKE", "PREPARING", "SLEEPING", "NOTIFIED", "DRAINING", "NOTIFYING")


@dataclass(frozen=True)
class State:
    phase: int = AWAKE
    epoch: int = 0
    state_hb: int = 0
    payload: tuple[bool, bool] = (False, False)
    frame: tuple[bool, bool] = (False, False)
    queued: tuple[bool, bool] = (False, False)
    consumed: tuple[bool, bool] = (False, False)
    p_pc: tuple[int, int] = (0, 0)
    p_expected_phase: tuple[int, int] = (AWAKE, AWAKE)
    p_expected_epoch: tuple[int, int] = (0, 0)
    p_expected_hb: tuple[int, int] = (0, 0)
    p_retire_phase: tuple[int, int] = (AWAKE, AWAKE)
    p_retire_epoch: tuple[int, int] = (0, 0)
    p_retire_hb: tuple[int, int] = (0, 0)
    p_owns: tuple[bool, bool] = (False, False)
    p_write_done: tuple[bool, bool] = (False, False)
    w_pc: int = 0
    w_expected_phase: int = AWAKE
    w_expected_epoch: int = 0
    w_expected_hb: int = 0
    w_seen_frames: int = 0
    w_seen_payload: int = 0
    blocked: bool = False
    readable: bool = False
    notification_owner: int = -1
    notification_coverage: int = 0
    notify_claims: int = 0
    successful_writes: int = 0
    successes_since_drain: int = 0
    spurious_used: bool = False
    epoll_eintr_used: bool = False
    epoll_result: str = "none"
    eintr_without_owner_seen: bool = False
    eintr_concurrent_notifying_seen: bool = False
    eintr_next_poll_rejection_seen: bool = False
    eintr_recovery_active: bool = False
    teardown_stage: int = 0
    trace: tuple[str, ...] = ()


def tuple_set(value: tuple, index: int, item: object) -> tuple:
    result = list(value)
    result[index] = item
    return tuple(result)


def finish(state: State, label: str, **changes: object) -> State:
    return replace(state, trace=state.trace + (label,), **changes)


def producer_steps(state: State, producer: int) -> Iterable[State]:
    pc = state.p_pc[producer]
    label = f"p{producer}"
    if pc == 0:
        yield finish(state, f"{label}.payload", payload=tuple_set(state.payload, producer, True),
                     p_pc=tuple_set(state.p_pc, producer, 1))
    elif pc == 1:
        # Queue/frame publication is the real VPP release publication.
        yield finish(state, f"{label}.frame_release", frame=tuple_set(state.frame, producer, True),
                     queued=tuple_set(state.queued, producer, True),
                     p_pc=tuple_set(state.p_pc, producer, 2))
    elif pc == 2:
        yield finish(
            state, f"{label}.epoch_load",
            p_expected_phase=tuple_set(state.p_expected_phase, producer, state.phase),
            p_expected_epoch=tuple_set(state.p_expected_epoch, producer, state.epoch),
            p_expected_hb=tuple_set(state.p_expected_hb, producer, state.state_hb),
            p_pc=tuple_set(state.p_pc, producer, 3),
        )
    elif pc == 3:
        expected = (state.p_expected_phase[producer], state.p_expected_epoch[producer])
        actual = (state.phase, state.epoch)
        if expected != actual:
            yield finish(
                state, f"{label}.epoch_cas_fail",
                p_expected_phase=tuple_set(state.p_expected_phase, producer, state.phase),
                p_expected_epoch=tuple_set(state.p_expected_epoch, producer, state.epoch),
                p_expected_hb=tuple_set(state.p_expected_hb, producer, state.state_hb),
            )
            return
        phase = state.phase
        desired_phase = NOTIFIED if phase == PREPARING else NOTIFYING if phase == SLEEPING else phase
        owns = phase == SLEEPING
        bit = 1 << producer
        coverage = state.notification_coverage
        if phase in (SLEEPING, NOTIFYING):
            coverage |= bit
        yield finish(
            state, f"{label}.epoch_cas_release",
            phase=desired_phase, epoch=state.epoch + 1, state_hb=state.state_hb | bit,
            p_owns=tuple_set(state.p_owns, producer, owns),
            p_pc=tuple_set(state.p_pc, producer, 4 if owns else 7),
            notification_owner=producer if owns else state.notification_owner,
            notification_coverage=coverage,
            notify_claims=state.notify_claims + int(owns),
        )
    elif pc == 4:
        # The exhaustive normal path uses a successful eventfd write. Frozen
        # failures are covered separately by fault_scenarios.py.
        yield finish(
            state, f"{label}.write_success", readable=True,
            successful_writes=state.successful_writes + 1,
            successes_since_drain=state.successes_since_drain + 1,
            p_write_done=tuple_set(state.p_write_done, producer, True),
            p_pc=tuple_set(state.p_pc, producer, 5),
        )
    elif pc == 5:
        yield finish(
            state, f"{label}.retire_load_acquire",
            p_retire_phase=tuple_set(state.p_retire_phase, producer, state.phase),
            p_retire_epoch=tuple_set(state.p_retire_epoch, producer, state.epoch),
            p_retire_hb=tuple_set(state.p_retire_hb, producer, state.state_hb),
            p_pc=tuple_set(state.p_pc, producer, 6),
        )
    elif pc == 6:
        expected = (state.p_retire_phase[producer], state.p_retire_epoch[producer])
        actual = (state.phase, state.epoch)
        if expected != actual:
            yield finish(
                state, f"{label}.retire_cas_fail_acquire",
                p_retire_phase=tuple_set(state.p_retire_phase, producer, state.phase),
                p_retire_epoch=tuple_set(state.p_retire_epoch, producer, state.epoch),
                p_retire_hb=tuple_set(state.p_retire_hb, producer, state.state_hb),
            )
        elif state.phase == NOTIFYING and state.notification_owner == producer:
            # Desired is built from the freshly observed word, preserving every
            # concurrent producer epoch increment.
            yield finish(state, f"{label}.retire_cas_success_acq_rel", phase=NOTIFIED,
                         p_pc=tuple_set(state.p_pc, producer, 7))


def worker_steps(state: State) -> Iterable[State]:
    if state.w_pc == 0:
        yield finish(state, "w.announce_load_acquire", w_expected_phase=state.phase,
                     w_expected_epoch=state.epoch, w_expected_hb=state.state_hb, w_pc=1)
    elif state.w_pc == 1:
        if (state.w_expected_phase, state.w_expected_epoch) != (state.phase, state.epoch):
            yield finish(state, "w.announce_cas_fail_acquire", w_expected_phase=state.phase,
                         w_expected_epoch=state.epoch, w_expected_hb=state.state_hb, w_pc=0)
        elif state.phase == AWAKE:
            yield finish(state, "w.announce_cas_acq_rel", phase=PREPARING,
                         w_expected_phase=PREPARING, w_expected_hb=state.state_hb, w_pc=2)
        else:
            yield finish(state, "w.announce_observes_service", w_pc=6)
    elif state.w_pc in (2, 3):
        producer = state.w_pc - 2
        bit = 1 << producer
        seen_frames = state.w_seen_frames | (bit if state.frame[producer] else 0)
        seen_payload = state.w_seen_payload | (bit if state.frame[producer] and state.payload[producer] else 0)
        yield finish(state, f"w.recheck{producer}_acquire", w_seen_frames=seen_frames,
                     w_seen_payload=seen_payload, w_pc=state.w_pc + 1)
    elif state.w_pc == 4:
        if state.w_seen_frames:
            yield finish(state, "w.recheck_nonempty", w_pc=6)
        elif (state.phase, state.epoch) == (PREPARING, state.w_expected_epoch):
            yield finish(state, "w.sleep_confirm_cas_acq_rel", phase=SLEEPING,
                         blocked=True, w_pc=5)
        else:
            yield finish(state, "w.sleep_confirm_cas_fail_acquire",
                         w_expected_hb=state.state_hb, w_pc=6)
    elif state.w_pc == 5:
        if state.readable:
            yield finish(state, "w.epoll_return_readable", blocked=False,
                         epoll_result="readable", w_pc=6)
        if not state.spurious_used:
            yield finish(state, "w.epoll_return_spurious", blocked=False,
                         epoll_result="spurious", spurious_used=True, w_pc=6)
        if not state.epoll_eintr_used:
            yield finish(state, "w.epoll_return_eintr", blocked=False,
                         epoll_result="eintr", epoll_eintr_used=True, w_pc=6)
    elif state.w_pc == 6:
        yield finish(state, "w.begin_draining_load_acquire", w_expected_phase=state.phase,
                     w_expected_epoch=state.epoch, w_expected_hb=state.state_hb, w_pc=7)
    elif state.w_pc == 7:
        expected = (state.w_expected_phase, state.w_expected_epoch)
        actual = (state.phase, state.epoch)
        if expected != actual:
            yield finish(state, "w.begin_draining_cas_fail_acquire",
                         w_expected_phase=state.phase, w_expected_epoch=state.epoch,
                         w_expected_hb=state.state_hb)
        elif state.phase == NOTIFYING:
            # begin_draining is called once per file_poll. A rejection never
            # waits and retries inside this invocation. EINTR returns at once;
            # normal returns may run only the callbacks present in that epoll
            # result, but cannot clear because epoch_draining is false.
            readable = state.readable
            coverage = state.notification_coverage
            successes = state.successes_since_drain
            if state.epoll_result == "readable":
                readable = False
                coverage = 0
                successes = 0
            initial_eintr = state.epoll_result == "eintr"
            yield finish(
                state,
                "w.begin_draining_reject_return_current_poll",
                readable=readable,
                notification_coverage=coverage,
                successes_since_drain=successes,
                epoll_result="none",
                eintr_concurrent_notifying_seen=(state.eintr_concurrent_notifying_seen
                                                  or initial_eintr),
                eintr_next_poll_rejection_seen=(state.eintr_next_poll_rejection_seen
                                                 or state.eintr_recovery_active),
                eintr_recovery_active=(state.eintr_recovery_active or initial_eintr),
                w_pc=13,
            )
        else:
            yield finish(state, "w.begin_draining_cas_success_acq_rel", phase=DRAINING,
                         blocked=False, w_expected_hb=state.w_expected_hb | state.state_hb,
                         eintr_without_owner_seen=(state.eintr_without_owner_seen
                                                   or (state.epoll_result == "eintr"
                                                       and not state.eintr_concurrent_notifying_seen)),
                         w_pc=8)
    elif state.w_pc == 8:
        if state.epoll_result == "eintr":
            # file.c returns immediately for n_fds_ready < 0: no callback and
            # no clear. The next non-AWAKE poll is a zero-timeout service pass.
            yield finish(state, "w.eintr_return_without_drain_or_clear",
                         epoll_result="none", eintr_recovery_active=True, w_pc=13)
        elif state.epoll_result == "readable":
            yield finish(state, "w.eventfd_callback_drain", readable=False,
                         notification_coverage=0, successes_since_drain=0,
                         epoll_result="none", w_pc=9)
        else:
            yield finish(state, "w.no_eventfd_callback", epoll_result="none", w_pc=9)
    elif state.w_pc == 9:
        yield finish(state, "w.clear_load_acquire", w_expected_phase=state.phase,
                     w_expected_epoch=state.epoch, w_expected_hb=state.state_hb, w_pc=10)
    elif state.w_pc == 10:
        expected = (state.w_expected_phase, state.w_expected_epoch)
        actual = (state.phase, state.epoch)
        if expected != actual:
            yield finish(state, "w.clear_cas_fail_acquire", w_expected_phase=state.phase,
                         w_expected_epoch=state.epoch, w_expected_hb=state.state_hb)
        else:
            yield finish(state, "w.clear_cas_success_acq_rel", phase=AWAKE,
                         notification_owner=-1, notification_coverage=0,
                         p_owns=(False, False),
                         eintr_recovery_active=False, w_pc=11)
    elif state.w_pc == 11:
        # file.c only services file descriptors. Frame queues are consumed by
        # the subsequent awake main-loop dispatch.
        consumed = tuple(a or q for a, q in zip(state.consumed, state.queued))
        seen_frames = sum((1 << i) for i, item in enumerate(state.frame) if item)
        seen_payload = sum((1 << i) for i, item in enumerate(state.payload) if item)
        yield finish(state, "w.awake_dispatch_acquire", queued=(False, False), consumed=consumed,
                     w_seen_frames=state.w_seen_frames | seen_frames,
                     w_seen_payload=state.w_seen_payload | seen_payload, w_pc=12)
    elif state.w_pc == 12:
        if any(state.queued):
            consumed = tuple(a or q for a, q in zip(state.consumed, state.queued))
            seen_frames = sum((1 << i) for i, item in enumerate(state.frame) if item)
            seen_payload = sum((1 << i) for i, item in enumerate(state.payload) if item)
            yield finish(state, "w.later_awake_dispatch_acquire", queued=(False, False),
                         consumed=consumed, w_seen_frames=state.w_seen_frames | seen_frames,
                         w_seen_payload=state.w_seen_payload | seen_payload)
        elif state.p_pc == (7, 7):
            if state.readable:
                # A spurious return can race a writer. The old epoll result has
                # no eventfd callback, so a later poll drains the retained event.
                yield finish(state, "w.retained_event_next_poll", phase=SLEEPING,
                             epoll_result="readable", w_pc=6)
            else:
                yield finish(state, "w.epoch_complete", w_pc=14)
    elif state.w_pc == 13:
        # Initial non-AWAKE check in the next file_poll forces a zero-timeout
        # service. A retained readable event wins over the timeout.
        result = "readable" if state.readable else "timeout"
        yield finish(state, f"w.next_nonawake_poll_{result}", epoll_result=result, w_pc=6)


def teardown_steps(state: State) -> Iterable[State]:
    stage = state.teardown_stage
    if stage == 0:
        # Both producers still publish exactly one item in every explored epoch.
        # Once both frames exist, branch teardown at every transition/queue state.
        if state.frame == (True, True) and (state.phase != AWAKE or any(state.queued)):
            yield finish(state, "t.request", teardown_stage=1)
    elif stage == 1:
        yield finish(state, "t.unblock", blocked=False, teardown_stage=2)
    elif stage == 2:
        yield finish(state, "t.drain_eventfd", readable=False, successes_since_drain=0,
                     teardown_stage=3)
    elif stage == 3:
        consumed = tuple(a or q for a, q in zip(state.consumed, state.queued))
        seen_frames = sum((1 << i) for i, item in enumerate(state.frame) if item)
        seen_payload = sum((1 << i) for i, item in enumerate(state.payload) if item)
        yield finish(state, "t.settle_queue", queued=(False, False), consumed=consumed,
                     w_seen_frames=state.w_seen_frames | seen_frames,
                     w_seen_payload=state.w_seen_payload | seen_payload,
                     teardown_stage=4)
    elif stage == 4:
        yield finish(state, "t.clear_claim", phase=AWAKE, notification_owner=-1,
                     notification_coverage=0, p_owns=(False, False), teardown_stage=5)
    elif stage == 5:
        yield finish(state, "t.finish", teardown_stage=6)


def successors(state: State) -> Iterable[State]:
    if state.teardown_stage:
        yield from teardown_steps(state)
        return
    for producer in range(2):
        yield from producer_steps(state, producer)
    yield from worker_steps(state)
    yield from teardown_steps(state)


def is_terminal(state: State) -> bool:
    return state.teardown_stage == 6 or state.w_pc == 14


def violations(state: State) -> tuple[str, ...]:
    found: list[str] = []
    for producer, queued in enumerate(state.queued):
        if not queued:
            continue
        own_publish_pending = state.p_pc[producer] <= 3
        own_active_writer = (
            state.phase == NOTIFYING
            and state.notification_owner >= 0
            and bool(state.notification_coverage & (1 << producer))
            and state.p_pc[state.notification_owner] in (4, 5, 6)
        )
        if (state.blocked and not state.readable and not own_publish_pending
                and not own_active_writer and state.teardown_stage == 0):
            found.append("lost_wake")
            break
    if state.successes_since_drain > 1 or state.successful_writes > state.notify_claims:
        found.append("double_notification")
    if state.notification_owner >= 0 and state.phase not in (NOTIFYING, NOTIFIED, DRAINING):
        found.append("notification_ownership")
    for producer in range(2):
        bit = 1 << producer
        if state.consumed[producer] and not (state.w_seen_frames & bit and state.w_seen_payload & bit):
            found.append("publish_visibility")
            break
    if any(q and c for q, c in zip(state.queued, state.consumed)):
        found.append("ledger")
    if is_terminal(state):
        if state.teardown_stage == 6:
            residue = (any(state.queued) or state.blocked or state.readable or
                       state.notification_owner >= 0 or state.notification_coverage
                       or state.phase != AWAKE)
            if residue:
                found.append("zero_residue")
        else:
            if state.p_pc != (7, 7) or state.consumed != (True, True) or any(state.queued):
                found.append("ledger")
            if state.blocked and any(state.queued) and not state.readable:
                found.append("lost_wake")
            if (state.blocked or state.readable or state.notification_owner >= 0
                    or state.notification_coverage or state.phase != AWAKE):
                found.append("zero_residue")
    return tuple(sorted(set(found)))


def semantic_key(state: State) -> tuple[object, ...]:
    # Deliberately retains both producer PCs, worker PC, expected-CAS snapshots,
    # and HB visibility masks. Only the explanatory trace is omitted.
    return tuple(getattr(state, item.name) for item in fields(State) if item.name != "trace")


def enumerate_all(max_states: int) -> dict[str, object]:
    initial = State()
    pending = deque([initial])
    seen = {semantic_key(initial)}
    terminals = 0
    normal_terminals = 0
    teardown_terminals = 0
    counterexamples: dict[str, tuple[str, ...]] = {}
    action_edges = 0
    eintr_without_owner_seen = False
    eintr_concurrent_notifying_seen = False
    eintr_next_poll_rejection_seen = False
    while pending:
        state = pending.popleft()
        eintr_without_owner_seen |= state.eintr_without_owner_seen
        eintr_concurrent_notifying_seen |= state.eintr_concurrent_notifying_seen
        eintr_next_poll_rejection_seen |= state.eintr_next_poll_rejection_seen
        found = violations(state)
        for invariant in found:
            counterexamples.setdefault(invariant, state.trace)
        if found:
            continue
        if is_terminal(state):
            terminals += 1
            normal_terminals += int(state.w_pc == 14)
            teardown_terminals += int(state.teardown_stage == 6)
            continue
        next_states = list(successors(state))
        if not next_states:
            counterexamples.setdefault("deadlock", state.trace)
            continue
        for next_state in next_states:
            action_edges += 1
            key = semantic_key(next_state)
            if key not in seen:
                seen.add(key)
                if len(seen) > max_states:
                    raise RuntimeError(f"state limit {max_states} exceeded")
                pending.append(next_state)
    return {
        "schema": "p6c-exhaustive-v1",
        "eligible": not counterexamples,
        "explored_states": len(seen),
        "action_edges": action_edges,
        "terminal_states": terminals,
        "normal_terminal_states": normal_terminals,
        "teardown_terminal_states": teardown_terminals,
        "counterexamples": {name: list(trace) for name, trace in sorted(counterexamples.items())},
        "coverage": {
            "eintr_without_owner": eintr_without_owner_seen,
            "eintr_concurrent_notifying": eintr_concurrent_notifying_seen,
            "eintr_next_poll_rejection": eintr_next_poll_rejection_seen,
        },
        "model": {
            "worker_count": 1,
            "producer_count": 2,
            "items_per_producer": 1,
            "phases": list(PHASE_NAMES),
            "normal_write_outcome": "success",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-states", type=int, default=2_000_000)
    args = parser.parse_args()
    try:
        result = enumerate_all(args.max_states)
    except RuntimeError as error:
        print(json.dumps({"eligible": False, "error": str(error)}, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["eligible"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
