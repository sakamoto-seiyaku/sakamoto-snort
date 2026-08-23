#!/usr/bin/env python3
"""Throwaway OI-2 async broker contract model.

The model is intentionally small and deterministic.  It answers only whether
the request/completion contract has enough identity to keep the owner non-
blocking and to settle every original socket and SCM_RIGHTS duplicate once.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field, replace
import json
import sys


SUCCESS = "SUCCESS"
FAILURE = "FAILURE"
RUNNABLE = "RUNNABLE"
WAITING = "WAITING"
STOPPED = "STOPPED"


@dataclass(frozen=True)
class Request:
    token: int
    generation: int
    owner: int
    shard: int
    fd: int
    family: str
    sock_type: str
    epoch: int


@dataclass(frozen=True)
class Completion:
    request: Request
    result: str
    fault: str = ""


@dataclass
class SocketLedger:
    request: Request
    original_closed: int = 0
    duplicate_closed: int = 0
    connected: int = 0
    first_sent: int = 0
    outcome: str = "PENDING"


@dataclass
class Broker:
    capacity: int = 8
    available: bool = True
    delay: int = 0
    actions: dict[tuple[str, str], str] = field(default_factory=dict)
    queue: deque[Request] = field(default_factory=deque)
    due: list[tuple[int, Completion]] = field(default_factory=list)
    tick_count: int = 0
    order: list[str] = field(default_factory=list)
    submitted: int = 0
    rejected_unavailable: int = 0
    rejected_queue_full: int = 0
    duplicate_completions: int = 0
    duplicate_fds_closed: int = 0

    def submit(self, request: Request) -> bool:
        if not self.available:
            self.rejected_unavailable += 1
            return False
        if len(self.queue) >= self.capacity:
            self.rejected_queue_full += 1
            return False
        self.queue.append(request)
        self.submitted += 1
        return True

    def step(self) -> None:
        self.tick_count += 1
        if self.queue:
            request = self.queue.popleft()
            action = self.actions.get((request.family, request.sock_type), SUCCESS)
            self.order.append(f"bind:{request.token}")
            self.order.append(f"protect:{request.token}")
            self.order.append(f"close-duplicate:{request.token}")
            result = SUCCESS if action == SUCCESS else FAILURE
            fault = "" if result == SUCCESS else action
            self.due.append((self.tick_count + self.delay,
                             Completion(request, result, fault)))

    def completions(self) -> list[Completion]:
        ready = [item for item in self.due if item[0] <= self.tick_count]
        self.due = [item for item in self.due if item[0] > self.tick_count]
        return [completion for _, completion in ready]


@dataclass
class Owner:
    broker: Broker
    owner: int = 1
    shard: int = 3
    epoch: int = 7
    generation: int = 1
    state: str = RUNNABLE
    next_token: int = 1
    next_fd: int = 100
    sockets: dict[int, SocketLedger] = field(default_factory=dict)
    accepted: set[int] = field(default_factory=set)
    completed: set[int] = field(default_factory=set)
    stale: int = 0
    duplicate: int = 0
    wrong_owner: int = 0
    wrong_epoch: int = 0
    queue_rejects: int = 0
    unavailable_rejects: int = 0
    owner_ticks: int = 0
    sentinel_ticks: int = 0
    first_send_before_completion: int = 0
    transport_failures: int = 0
    infrastructure_faults: int = 0
    stop_count: int = 0

    def request(self, family: str, sock_type: str) -> int | None:
        token = self.next_token
        self.next_token += 1
        request = Request(token, self.generation, self.owner, self.shard,
                          self.next_fd, family, sock_type, self.epoch)
        self.next_fd += 1
        self.sockets[token] = SocketLedger(request)
        if not self.broker.submit(request):
            self._close_original(token)
            if self.broker.available:
                self.queue_rejects += 1
            else:
                self.unavailable_rejects += 1
            return None
        self.accepted.add(token)
        return token

    def tick(self) -> None:
        # This is the owner graph turn.  It never waits for broker completion.
        self.owner_ticks += 1
        self.sentinel_ticks += 1
        self.broker.step()
        for completion in self.broker.completions():
            self.complete(completion)
        if self.state not in (STOPPED,):
            self.state = WAITING if self.broker.due or self.broker.queue else RUNNABLE

    def complete(self, completion: Completion) -> None:
        request = completion.request
        ledger = self.sockets.get(request.token)
        if request.generation != self.generation or ledger is None:
            self.stale += 1
            self.broker.duplicate_fds_closed += 1
            return
        if request.owner != self.owner or request.shard != self.shard:
            self.wrong_owner += 1
            self._close_original(request.token)
            return
        if request.epoch != self.epoch:
            self.wrong_epoch += 1
            self._close_original(request.token)
            return
        if request.token in self.completed:
            self.duplicate += 1
            self.broker.duplicate_fds_closed += 1
            return
        self.completed.add(request.token)
        if completion.result == SUCCESS:
            # Connect/first-send are legal only after completion.
            ledger.connected += 1
            ledger.first_sent += 1
            ledger.outcome = "SUCCEEDED"
        else:
            self.infrastructure_faults += 1
            self.transport_failures += 1
            ledger.outcome = "FAILED_DEFINITE"
            self._close_original(request.token)

    def stop(self) -> None:
        if self.state == STOPPED:
            return
        self.stop_count += 1
        self.state = STOPPED
        self.generation += 1
        for token, ledger in self.sockets.items():
            if ledger.outcome == "PENDING":
                self._close_original(token)

    def _close_original(self, token: int) -> None:
        ledger = self.sockets[token]
        if ledger.original_closed == 0:
            ledger.original_closed = 1

    def evidence(self) -> dict:
        return {
            "state": self.state,
            "generation": self.generation,
            "owner_ticks": self.owner_ticks,
            "sentinel_ticks": self.sentinel_ticks,
            "accepted": sorted(self.accepted),
            "completed": sorted(self.completed),
            "stale": self.stale,
            "duplicate": self.duplicate,
            "wrong_owner": self.wrong_owner,
            "wrong_epoch": self.wrong_epoch,
            "queue_rejects": self.queue_rejects,
            "unavailable_rejects": self.unavailable_rejects,
            "infrastructure_faults": self.infrastructure_faults,
            "transport_failures": self.transport_failures,
            "sockets": {
                str(token): {
                    "family": ledger.request.family,
                    "type": ledger.request.sock_type,
                    "original_closed": ledger.original_closed,
                    "duplicate_closed": ledger.duplicate_closed,
                    "connected": ledger.connected,
                    "first_sent": ledger.first_sent,
                    "outcome": ledger.outcome,
                }
                for token, ledger in sorted(self.sockets.items())
            },
            "broker": {
                "submitted": self.broker.submitted,
                "queue_full": self.broker.rejected_queue_full,
                "unavailable": self.broker.rejected_unavailable,
                "duplicate_fds_closed": self.broker.duplicate_fds_closed,
                "order": self.broker.order,
            },
        }


def run_until(owner: Owner, ticks: int = 8) -> None:
    for _ in range(ticks):
        owner.tick()


def assert_invariants(name: str, owner: Owner, *, min_sentinel: int = 0) -> None:
    assert owner.sentinel_ticks >= min_sentinel, (name, "sentinel-starved")
    for ledger in owner.sockets.values():
        assert ledger.original_closed <= 1, (name, ledger.request.token, "double-close")
        assert ledger.duplicate_closed <= 1, (name, ledger.request.token, "duplicate-fd-close")
        assert not (ledger.first_sent and ledger.outcome == "PENDING"), (name, "early-send")
        if ledger.outcome in ("SUCCEEDED", "FAILED_DEFINITE"):
            assert ledger.original_closed in (0, 1)


def cell_families() -> dict:
    broker = Broker()
    owner = Owner(broker)
    for family in ("ipv4", "ipv6"):
        for sock_type in ("tcp", "udp"):
            owner.request(family, sock_type)
    run_until(owner, 8)
    assert {ledger.outcome for ledger in owner.sockets.values()} == {"SUCCEEDED"}
    assert all(ledger.connected == ledger.first_sent == 1
               for ledger in owner.sockets.values())
    assert_invariants("families", owner, min_sentinel=1)
    return owner.evidence()


def cell_failures() -> dict:
    broker = Broker(actions={("ipv4", "tcp"): "BIND_FAILED",
                             ("ipv6", "udp"): "PROTECT_FAILED"})
    owner = Owner(broker)
    owner.request("ipv4", "tcp")
    owner.request("ipv6", "udp")
    run_until(owner, 4)
    assert owner.infrastructure_faults == owner.transport_failures == 2
    assert all(ledger.outcome == "FAILED_DEFINITE"
               for ledger in owner.sockets.values())
    assert_invariants("failures", owner)
    return owner.evidence()


def cell_unavailable_and_full() -> dict:
    unavailable = Owner(Broker(available=False))
    assert unavailable.request("ipv4", "tcp") is None
    assert unavailable.unavailable_rejects == 1
    full = Owner(Broker(capacity=1))
    assert full.request("ipv4", "tcp") is not None
    assert full.request("ipv6", "udp") is None
    run_until(full, 4)
    assert full.queue_rejects == 1
    assert_invariants("unavailable", unavailable)
    assert_invariants("queue-full", full)
    return {"unavailable": unavailable.evidence(), "queue_full": full.evidence()}


def cell_delay_and_stop() -> dict:
    delayed = Owner(Broker(delay=5))
    delayed.request("ipv4", "tcp")
    for _ in range(3):
        delayed.tick()
    assert delayed.owner_ticks == delayed.sentinel_ticks == 3
    assert delayed.sockets[1].outcome == "PENDING"
    delayed.stop()
    for _ in range(6):
        delayed.tick()
    # The late completion belongs to the previous generation and cannot revive.
    assert delayed.stale == 1
    assert delayed.state == STOPPED
    assert delayed.sockets[1].original_closed == 1
    assert_invariants("delay-stop", delayed, min_sentinel=3)
    return delayed.evidence()


def cell_completion_tripwires() -> dict:
    owner = Owner(Broker())
    owner.request("ipv4", "tcp")
    owner.tick()
    request = owner.sockets[1].request
    success = Completion(request, SUCCESS)
    owner.complete(success)
    owner.complete(replace(success, request=replace(request, owner=9)))
    owner.complete(replace(success, request=replace(request, generation=0)))
    assert owner.duplicate == 1
    assert owner.wrong_owner == 1
    assert owner.stale == 1
    assert owner.sockets[1].first_sent == 1
    assert_invariants("completion-tripwires", owner)
    return owner.evidence()


def main() -> int:
    cells = {
        "families": cell_families(),
        "failures": cell_failures(),
        "unavailable_and_queue_full": cell_unavailable_and_full(),
        "delayed_and_stop": cell_delay_and_stop(),
        "completion_tripwires": cell_completion_tripwires(),
    }
    print(json.dumps({"schema": "oi2-broker-model/v1", "cells": cells},
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"OI2 model invariant failed: {error}", file=sys.stderr)
        raise
