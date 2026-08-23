#!/usr/bin/env python3
"""Throwaway OI-5 generation/epoch and teardown model."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import sys


RUNNABLE = "RUNNABLE"
WAITING = "WAITING"
STOPPING = "STOPPING"
STOPPED = "STOPPED"


@dataclass(frozen=True)
class Token:
    kind: str
    generation: int
    epoch: int
    sequence: int


@dataclass
class Session:
    transport: str
    generation: int
    epoch: int
    state: str
    socket_live: int = 1
    pcb_live: int = 1
    timer_live: int = 1
    buffer_residue: int = 1
    packet_lease_live: int = 1
    pbuf_live: int = 1
    vpp_buffer_live: int = 1
    socket_request_live: int = 1
    socket_completion_live: int = 1
    output_live: int = 1
    released: bool = False
    reconnects: int = 0
    udp_reuses: int = 0


@dataclass
class OwnerLifecycle:
    owner: int
    generation: int = 1
    epoch: int = 1
    state: str = RUNNABLE
    next_sequence: int = 1
    sessions: list[Session] = field(default_factory=list)
    tokens: list[Token] = field(default_factory=list)
    stale_events: int = 0
    late_wake_rejects: int = 0
    late_timer_rejects: int = 0
    late_fd_wake_rejects: int = 0
    late_stale_rejects: int = 0
    late_duplicate_broker_rejects: int = 0
    late_broker_rejects: int = 0
    late_output_rejects: int = 0
    late_tun_rejects: int = 0
    old_tcp_reconnects: int = 0
    old_udp_reuses: int = 0
    old_tcp_reconnect_attempts: int = 0
    old_udp_reuse_attempts: int = 0
    stop_calls: int = 0
    restart_calls: int = 0
    resources_released: int = 0
    buffer_residue: int = 0
    underlay_invalidations: int = 0
    flow_stack_faults: int = 0
    flow_stack_restarts: int = 0
    fresh_successes: int = 0
    resource_allocated: dict[str, int] = field(default_factory=lambda: {
        "packet_lease": 0, "pbuf": 0, "vpp_buffer": 0,
        "socket_request": 0, "socket_completion": 0, "output": 0,
    })
    resource_released: dict[str, int] = field(default_factory=lambda: {
        "packet_lease": 0, "pbuf": 0, "vpp_buffer": 0,
        "socket_request": 0, "socket_completion": 0, "output": 0,
    })
    quiesce_deadlines: int = 0
    history: list[str] = field(default_factory=list)

    def token(self, kind: str) -> Token:
        value = Token(kind, self.generation, self.epoch, self.next_sequence)
        self.next_sequence += 1
        self.tokens.append(value)
        return value

    def open_session(self, transport: str, state: str) -> Session:
        session = Session(transport, self.generation, self.epoch, state)
        self.sessions.append(session)
        self.buffer_residue += session.buffer_residue
        for resource in self.resource_allocated:
            self.resource_allocated[resource] += 1
        self.history.append(f"open:{transport}:g{self.generation}:e{self.epoch}")
        return session

    def release_session(self, session: Session, reason: str) -> None:
        if session.released:
            return
        session.socket_live = 0
        session.pcb_live = 0
        session.timer_live = 0
        session.buffer_residue = 0
        session.packet_lease_live = 0
        session.pbuf_live = 0
        session.vpp_buffer_live = 0
        session.socket_request_live = 0
        session.socket_completion_live = 0
        session.output_live = 0
        session.released = True
        for resource in self.resource_released:
            self.resource_released[resource] += 1
        self.resources_released += 1

    def accept(self, token: Token, action: str) -> bool:
        if token.generation != self.generation or token.epoch != self.epoch:
            self.stale_events += 1
            counters = {
                "wake": "late_wake_rejects",
                "timer": "late_timer_rejects",
                "fd-wake": "late_fd_wake_rejects",
                "stale": "late_stale_rejects",
                "duplicate-broker": "late_duplicate_broker_rejects",
                "broker": "late_broker_rejects",
                "output": "late_output_rejects",
                "tun": "late_tun_rejects",
            }
            setattr(self, counters.get(token.kind, "late_wake_rejects"),
                    getattr(self, counters.get(token.kind, "late_wake_rejects")) + 1)
            if action == "tcp-reconnect":
                self.old_tcp_reconnect_attempts += 1
            if action == "udp-reuse":
                self.old_udp_reuse_attempts += 1
            return False
        if self.state in (STOPPING, STOPPED):
            self.stale_events += 1
            return False
        self.history.append(f"accept:{token.kind}:g{token.generation}:e{token.epoch}")
        return True

    def stop(self) -> None:
        if self.state == STOPPED:
            return
        self.stop_calls += 1
        self.state = STOPPING
        self.history.append(f"stop:g{self.generation}:e{self.epoch}")
        self.quiesce_deadlines += 1
        self.history.append(f"quiesce:begin:g{self.generation}:e{self.epoch}:deadline=bounded")
        self.history.append(f"drain:late-events:g{self.generation}:e{self.epoch}:reject-only")
        old_generation = self.generation
        old_epoch = self.epoch
        self.generation += 1
        self.epoch += 1
        for session in self.sessions:
            self.history.append(f"close:{session.transport}:g{session.generation}:e{session.epoch}")
            self.release_session(session, "stop")
        self.buffer_residue = 0
        self.history.append(f"settle:g{old_generation}->g{self.generation}:e{old_epoch}->e{self.epoch}:residue=0")
        self.state = STOPPED
        self.history.append(f"stopped:g{old_generation}->g{self.generation}:e{old_epoch}->e{self.epoch}")

    def restart(self) -> Session:
        assert self.state == STOPPED
        self.restart_calls += 1
        self.flow_stack_restarts += 1
        self.state = RUNNABLE
        session = self.open_session("tcp", "SYN_SENT")
        self.history.append(f"restart:g{self.generation}:e{self.epoch}")
        return session

    def invalidate_underlay(self) -> None:
        assert self.state not in (STOPPING, STOPPED)
        old_epoch = self.epoch
        self.epoch += 1
        self.underlay_invalidations += 1
        self.history.append(f"underlay-invalidate:e{old_epoch}->e{self.epoch}")
        for session in self.sessions:
            if session.released or session.epoch != old_epoch:
                continue
            if session.transport == "tcp":
                session.state = "TERMINATED"
            else:
                session.state = "MAPPING_INVALIDATED"
            self.release_session(session, "underlay-epoch")
        self.history.append(f"underlay-snapshot:fresh-epoch=e{self.epoch}")

    def flow_stack_fault(self, reason: str = "forced") -> None:
        assert self.state not in (STOPPING, STOPPED)
        self.flow_stack_faults += 1
        self.state = "FAULT"
        self.history.append(f"fault:flow-stack:{reason}:g{self.generation}:e{self.epoch}")

    def release_current(self) -> None:
        for session in self.sessions:
            if session.generation == self.generation:
                self.release_session(session, "current")
        self.buffer_residue = sum(x.buffer_residue for x in self.sessions)
        if self.buffer_residue < 0:
            self.buffer_residue = 0

    def evidence(self) -> dict:
        return {
            "owner": self.owner,
            "state": self.state,
            "generation": self.generation,
            "epoch": self.epoch,
            "stale_events": self.stale_events,
            "late": {
                "wake": self.late_wake_rejects,
                "timer": self.late_timer_rejects,
                "fd-wake": self.late_fd_wake_rejects,
                "stale": self.late_stale_rejects,
                "duplicate-broker": self.late_duplicate_broker_rejects,
                "broker": self.late_broker_rejects,
                "output": self.late_output_rejects,
                "tun": self.late_tun_rejects,
            },
            "old_tcp_reconnects": self.old_tcp_reconnects,
            "old_udp_reuses": self.old_udp_reuses,
            "old_tcp_reconnect_attempts": self.old_tcp_reconnect_attempts,
            "old_udp_reuse_attempts": self.old_udp_reuse_attempts,
            "stop_calls": self.stop_calls,
            "restart_calls": self.restart_calls,
            "resources_released": self.resources_released,
            "resources": {
                resource: [self.resource_allocated[resource],
                           self.resource_released[resource]]
                for resource in self.resource_allocated
            },
            "underlay_invalidations": self.underlay_invalidations,
            "flow_stack_faults": self.flow_stack_faults,
            "flow_stack_restarts": self.flow_stack_restarts,
            "fresh_successes": self.fresh_successes,
            "quiesce_deadlines": self.quiesce_deadlines,
            "buffer_residue": self.buffer_residue,
            "history": self.history,
            "sessions": [
                {"transport": x.transport, "generation": x.generation,
                 "epoch": x.epoch, "state": x.state,
                 "socket_live": x.socket_live, "pcb_live": x.pcb_live,
                 "timer_live": x.timer_live, "buffer_residue": x.buffer_residue,
                 "packet_lease_live": x.packet_lease_live,
                 "pbuf_live": x.pbuf_live,
                 "vpp_buffer_live": x.vpp_buffer_live,
                 "socket_request_live": x.socket_request_live,
                 "socket_completion_live": x.socket_completion_live,
                 "output_live": x.output_live,
                 "released": x.released}
                for x in self.sessions
            ],
        }


def late_event_matrix(owner: OwnerLifecycle) -> None:
    old_tokens = [owner.token(kind) for kind in (
        "wake", "timer", "fd-wake", "stale", "broker",
        "duplicate-broker", "output", "tun")]
    owner.stop()
    for token in old_tokens:
        action = "tcp-reconnect" if token.kind == "output" else \
            "udp-reuse" if token.kind == "tun" else "late"
        assert not owner.accept(token, action)


def assert_zero(name: str, owner: OwnerLifecycle) -> None:
    assert owner.state == STOPPED, (name, "not-stopped")
    assert owner.buffer_residue == 0, (name, "owner-buffer-residue")
    assert all(x.socket_live == x.pcb_live == x.timer_live == x.buffer_residue == 0
               for x in owner.sessions), (name, "resource-residue")
    assert owner.old_tcp_reconnects == 0, (name, "old-tcp-reconnected")
    assert owner.old_udp_reuses == 0, (name, "old-udp-reused")
    assert all(owner.resource_allocated[key] == owner.resource_released[key]
               for key in owner.resource_allocated), (name, "resource-ledger")
    for phase in ("quiesce:", "drain:", "close:", "settle:"):
        assert any(item.startswith(phase) for item in owner.history), \
            (name, "missing-phase", phase)


def cell_stop_matrix() -> dict:
    owner = OwnerLifecycle(0, state=WAITING)
    owner.open_session("tcp", "ESTABLISHED")
    owner.open_session("tcp", "FIN_WAIT")
    owner.open_session("udp", "ACTIVE")
    late_event_matrix(owner)
    owner.stop()  # idempotent stop
    assert owner.generation == 2 and owner.epoch == 2
    assert owner.stale_events == 8
    assert owner.old_tcp_reconnect_attempts == 1
    assert owner.old_udp_reuse_attempts == 1
    assert_zero("stop-matrix", owner)
    return owner.evidence()


def cell_restart_generation() -> dict:
    owner = OwnerLifecycle(0, state=RUNNABLE)
    old = owner.open_session("tcp", "ESTABLISHED")
    old_token = owner.token("broker")
    owner.stop()
    fresh = owner.restart()
    assert fresh.generation == 2 and fresh.epoch == 2
    assert owner.accept(old_token, "tcp-reconnect") is False
    assert owner.old_tcp_reconnects == 0
    assert owner.old_tcp_reconnect_attempts == 1
    # The stale event was rejected, but old resource state remains dead; the
    # fresh generation can complete without reviving the old TCP session.
    owner.release_current()
    owner.stop()
    assert_zero("restart-generation", owner)
    evidence = owner.evidence()
    evidence["old_generation"] = {"generation": old.generation, "epoch": old.epoch,
                                   "socket_live": old.socket_live}
    return evidence


def cell_underlay_epoch_invalidation() -> dict:
    owner = OwnerLifecycle(0, state=RUNNABLE)
    old_tcp = owner.open_session("tcp", "ESTABLISHED")
    old_udp = owner.open_session("udp", "ACTIVE")
    old_token = owner.token("duplicate-broker")
    owner.invalidate_underlay()
    assert owner.generation == 1 and owner.epoch == 2
    assert old_tcp.state == "TERMINATED" and old_udp.state == "MAPPING_INVALIDATED"
    assert old_tcp.socket_live == old_udp.socket_live == 0
    fresh = owner.open_session("udp", "ACTIVE")
    assert fresh.epoch == 2 and fresh.generation == 1
    assert not owner.accept(old_token, "udp-reuse")
    assert owner.old_udp_reuses == 0 and owner.old_udp_reuse_attempts == 1
    owner.stop()
    assert_zero("underlay-epoch-invalidation", owner)
    evidence = owner.evidence()
    evidence["fresh_snapshot"] = {"generation": fresh.generation,
                                   "epoch": fresh.epoch}
    return evidence


def cell_fault_restart() -> dict:
    owner = OwnerLifecycle(0, state=RUNNABLE)
    old = owner.open_session("udp", "ACTIVE")
    owner.flow_stack_fault("forced-driver-fault")
    owner.stop()
    fresh = owner.restart()
    fresh.state = "ESTABLISHED"
    owner.fresh_successes += 1
    owner.history.append(f"fresh-flow-success:g{fresh.generation}:e{fresh.epoch}")
    owner.release_current()
    owner.stop()
    assert old.socket_live == 0 and fresh.socket_live == 0
    assert owner.flow_stack_faults == 1 and owner.flow_stack_restarts == 1
    assert owner.fresh_successes == 1
    assert_zero("fault-restart", owner)
    return owner.evidence()


def cell_two_shard_teardown() -> dict:
    owners = [OwnerLifecycle(0, state=RUNNABLE), OwnerLifecycle(1, state=WAITING)]
    owners[0].open_session("tcp", "ESTABLISHED")
    owners[0].open_session("udp", "ACTIVE")
    owners[1].open_session("tcp", "FIN_WAIT")
    owners[1].open_session("udp", "ACTIVE")
    old_tokens = [[owner.token(k) for k in (
        "wake", "timer", "fd-wake", "stale", "broker",
        "duplicate-broker", "output", "tun")]
                  for owner in owners]
    for owner in owners:
        owner.stop()
    # A late event on shard A cannot mutate shard B, and vice versa.
    for index, owner in enumerate(owners):
        for token in old_tokens[index]:
            assert not owner.accept(token, "late")
    for owner in owners:
        assert_zero("two-shard-teardown", owner)
    return {str(owner.owner): owner.evidence() for owner in owners}


def main() -> int:
    cells = {
        "stop_matrix": cell_stop_matrix(),
        "restart_generation": cell_restart_generation(),
        "underlay_epoch_invalidation": cell_underlay_epoch_invalidation(),
        "fault_restart": cell_fault_restart(),
        "two_shard_teardown": cell_two_shard_teardown(),
    }
    print(json.dumps({"schema": "owner-inline-oi5-generation-epoch/v2", "cells": cells},
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"OI5 model invariant failed: {error}", file=sys.stderr)
        raise
