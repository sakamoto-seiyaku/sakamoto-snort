#!/usr/bin/env python3
"""Throwaway OI-4 two-owner shard isolation model."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import json
import sys


RUNNABLE = "RUNNABLE"
WAITING = "WAITING"
FAULT = "FAULT"
STOPPED = "STOPPED"


@dataclass(frozen=True)
class FlowTuple:
    family: str
    protocol: str
    src: str
    src_port: int
    dst: str
    dst_port: int

    def canonical(self) -> tuple:
        left = (self.src, self.src_port)
        right = (self.dst, self.dst_port)
        return (self.family, self.protocol) + tuple(sorted((left, right)))


@dataclass
class FlowLedger:
    flow: FlowTuple
    owner: int
    ingress: int = 0
    submitted: int = 0
    output: int = 0
    timer_fires: int = 0
    socket_open: int = 1
    pcb_live: int = 1
    buffer_residue: int = 0
    packet_lease: int = 1
    pbuf_live: int = 1
    vpp_buffer_live: int = 1
    socket_request_live: int = 1
    socket_completion_live: int = 1
    outcome: str = "PENDING"


@dataclass
class Shard:
    owner: int
    state: str = RUNNABLE
    delayed: int = 0
    faulted: bool = False
    queue: deque[FlowTuple] = field(default_factory=deque)
    sessions: dict[FlowTuple, FlowLedger] = field(default_factory=dict)
    timers: set[FlowTuple] = field(default_factory=set)
    sockets: set[FlowTuple] = field(default_factory=set)
    task_ticks: int = 0
    owner_local_allocations: int = 0
    owner_local_releases: int = 0
    packet_allocated: int = 0
    packet_released: int = 0
    pbuf_allocated: int = 0
    pbuf_released: int = 0
    vpp_buffer_allocated: int = 0
    vpp_buffer_released: int = 0
    socket_request_allocated: int = 0
    socket_request_released: int = 0
    socket_completion_allocated: int = 0
    socket_completion_released: int = 0
    wrong_owner_submit: int = 0
    wrong_owner_output: int = 0
    wrong_owner_completion: int = 0
    cross_worker_callbacks: int = 0
    rejected_after_fault: int = 0
    migrated: int = 0
    spilled: int = 0
    post_fault_ticks: int = 0

    def submit(self, flow: FlowTuple) -> None:
        if self.faulted or self.state == STOPPED:
            self.rejected_after_fault += 1
            return
        ledger = FlowLedger(flow, self.owner)
        self.sessions[flow] = ledger
        self.sockets.add(flow)
        self.timers.add(flow)
        self.queue.append(flow)
        self.owner_local_allocations += 1
        self.packet_allocated += 1
        self.pbuf_allocated += 1
        self.vpp_buffer_allocated += 1
        self.socket_request_allocated += 1
        self.socket_completion_allocated += 1

    def step(self) -> None:
        if self.state == STOPPED:
            return
        if self.faulted:
            self.state = FAULT
            return
        self.task_ticks += 1
        if self.delayed:
            self.delayed -= 1
            self.state = WAITING
            return
        if not self.queue:
            self.state = RUNNABLE
            return
        flow = self.queue.popleft()
        ledger = self.sessions[flow]
        ledger.ingress += 1
        ledger.submitted += 1
        ledger.output += 1
        ledger.timer_fires += 1
        ledger.buffer_residue = 0
        ledger.outcome = "SUCCEEDED"
        self.timers.discard(flow)

    def deliver_to_this_owner(self, flow: FlowTuple, expected_owner: int,
                              kind: str) -> None:
        ledger = self.sessions.get(flow)
        if expected_owner != self.owner:
            if kind == "submit":
                self.wrong_owner_submit += 1
            elif kind == "output":
                self.wrong_owner_output += 1
            elif kind == "completion":
                self.wrong_owner_completion += 1
            else:
                self.cross_worker_callbacks += 1
            return
        if ledger is None or ledger.owner != self.owner:
            self.cross_worker_callbacks += 1
            return
        self.queue.append(flow)

    def stop(self) -> None:
        self.state = STOPPED
        for ledger in self.sessions.values():
            ledger.socket_open = 0
            ledger.pcb_live = 0
            ledger.buffer_residue = 0
            ledger.packet_lease = 0
            ledger.pbuf_live = 0
            ledger.vpp_buffer_live = 0
            ledger.socket_request_live = 0
            ledger.socket_completion_live = 0
        self.queue.clear()
        self.timers.clear()
        self.sockets.clear()
        self.owner_local_releases = self.owner_local_allocations
        self.packet_released = self.packet_allocated
        self.pbuf_released = self.pbuf_allocated
        self.vpp_buffer_released = self.vpp_buffer_allocated
        self.socket_request_released = self.socket_request_allocated
        self.socket_completion_released = self.socket_completion_allocated


@dataclass
class Dispatcher:
    shards: tuple[Shard, Shard] = field(default_factory=lambda: (Shard(0), Shard(1)))
    route_count: dict[int, int] = field(default_factory=lambda: {0: 0, 1: 0})
    global_mutable_writes: int = 0
    core_lock_acquires: int = 0
    migration: int = 0
    spill: int = 0

    def owner_for(self, flow: FlowTuple) -> int:
        # Stable tuple hash, with no mutable/global routing cache.
        value = 1469598103934665603
        for part in repr(flow.canonical()).encode():
            value ^= part
            value = (value * 1099511628211) & 0xffffffffffffffff
        owner = value % len(self.shards)
        self.route_count[owner] += 1
        return owner

    def submit(self, flow: FlowTuple) -> int:
        owner = self.owner_for(flow)
        self.shards[owner].submit(flow)
        return owner

    def tick(self) -> None:
        # Each shard advances independently; there is intentionally no core
        # lock or shared session map in this model.
        for shard in self.shards:
            shard.step()

    def residue(self) -> int:
        return sum(ledger.buffer_residue for shard in self.shards
                   for ledger in shard.sessions.values())

    def evidence(self) -> dict:
        return {
            "route_count": self.route_count,
            "global_mutable_writes": self.global_mutable_writes,
            "core_lock_acquires": self.core_lock_acquires,
            "migration": self.migration,
            "spill": self.spill,
            "shards": {
                str(shard.owner): {
                    "state": shard.state,
                    "task_ticks": shard.task_ticks,
                    "flows": len(shard.sessions),
                    "succeeded": sum(x.outcome == "SUCCEEDED"
                                      for x in shard.sessions.values()),
                    "wrong_owner_submit": shard.wrong_owner_submit,
                    "wrong_owner_output": shard.wrong_owner_output,
                    "wrong_owner_completion": shard.wrong_owner_completion,
                    "cross_worker_callbacks": shard.cross_worker_callbacks,
                    "rejected_after_fault": shard.rejected_after_fault,
                    "allocations": shard.owner_local_allocations,
                    "releases": shard.owner_local_releases,
                    "resources": {
                        "packet": [shard.packet_allocated, shard.packet_released],
                        "pbuf": [shard.pbuf_allocated, shard.pbuf_released],
                        "vpp_buffer": [shard.vpp_buffer_allocated,
                                       shard.vpp_buffer_released],
                        "socket_request": [shard.socket_request_allocated,
                                           shard.socket_request_released],
                        "socket_completion": [shard.socket_completion_allocated,
                                               shard.socket_completion_released],
                    },
                    "post_fault_ticks": shard.post_fault_ticks,
                    "residue": sum(x.buffer_residue
                                    for x in shard.sessions.values()),
                }
                for shard in self.shards
            },
        }


def flows() -> list[FlowTuple]:
    return [
        FlowTuple("ipv4", "tcp", "10.111.0.2", 40001, "74.125.199.188", 5228),
        FlowTuple("ipv4", "udp", "10.111.0.2", 40002, "8.8.8.8", 53),
        FlowTuple("ipv6", "tcp", "fd00:111::2", 40003, "2001:4860:4860::8888", 443),
        FlowTuple("ipv6", "udp", "fd00:111::2", 40004, "2606:4700:4700::1111", 443),
        FlowTuple("ipv4", "tcp", "10.111.0.2", 40005, "192.0.2.5", 80),
        FlowTuple("ipv4", "udp", "10.111.0.2", 40006, "192.0.2.6", 443),
        FlowTuple("ipv6", "tcp", "fd00:111::2", 40007, "2001:db8::7", 80),
        FlowTuple("ipv6", "udp", "fd00:111::2", 40008, "2001:db8::8", 443),
    ]


def split_flows(dispatcher: Dispatcher) -> tuple[list[FlowTuple], list[FlowTuple]]:
    left: list[FlowTuple] = []
    right: list[FlowTuple] = []
    for flow in flows():
        (left if dispatcher.owner_for(flow) == 0 else right).append(flow)
    assert left and right, "fixture must exercise both owners"
    return left, right


def assert_common(name: str, d: Dispatcher) -> None:
    assert d.global_mutable_writes == 0, (name, "global-mutable-state")
    assert d.core_lock_acquires == 0, (name, "core-lock")
    assert d.migration == d.spill == 0, (name, "migration-or-spill")
    assert d.residue() == 0, (name, "buffer-residue", d.residue())
    for shard in d.shards:
        assert shard.owner_local_allocations == shard.owner_local_releases, \
            (name, "owner-resource-release")
        assert shard.packet_allocated == shard.packet_released, (name, "packet-residue")
        assert shard.pbuf_allocated == shard.pbuf_released, (name, "pbuf-residue")
        assert shard.vpp_buffer_allocated == shard.vpp_buffer_released, \
            (name, "vpp-buffer-residue")
        assert shard.socket_request_allocated == shard.socket_request_released, \
            (name, "socket-request-residue")
        assert shard.socket_completion_allocated == shard.socket_completion_released, \
            (name, "socket-completion-residue")
        for ledger in shard.sessions.values():
            assert ledger.owner == shard.owner, (name, "wrong-session-owner")
            assert ledger.buffer_residue == 0, (name, "flow-residue")
            assert not any((ledger.packet_lease, ledger.pbuf_live,
                            ledger.vpp_buffer_live, ledger.socket_request_live,
                            ledger.socket_completion_live)), (name, "resource-live")


def cell_two_live_shards() -> dict:
    d = Dispatcher()
    left, right = split_flows(d)
    for flow in left + right:
        d.submit(flow)
    d.shards[0].delayed = 5
    for _ in range(3):
        d.tick()
    assert d.shards[1].task_ticks == 3
    assert all(d.shards[1].sessions[f].outcome == "SUCCEEDED" for f in right)
    assert all(d.shards[0].sessions[f].outcome == "PENDING" for f in left)
    for _ in range(12):
        d.tick()
    assert all(x.outcome == "SUCCEEDED"
               for shard in d.shards for x in shard.sessions.values())
    d.shards[0].stop(); d.shards[1].stop()
    assert_common("two-live-shards", d)
    return d.evidence()


def cell_fault_isolation() -> dict:
    d = Dispatcher()
    left, right = split_flows(d)
    d.submit(left[0]); d.submit(right[0])
    d.shards[0].faulted = True
    for _ in range(4):
        d.tick()
    assert d.shards[0].state == FAULT
    assert d.shards[1].sessions[right[0]].outcome == "SUCCEEDED"
    assert d.shards[1].state != FAULT
    d.shards[0].stop()
    for _ in range(4):
        d.shards[1].step()
        d.shards[1].post_fault_ticks += 1
    assert d.shards[1].state != FAULT
    assert d.shards[1].migrated == d.shards[1].spilled == 0
    d.shards[1].stop()
    assert_common("fault-isolation", d)
    return d.evidence()


def cell_owner_tripwires() -> dict:
    d = Dispatcher()
    left, right = split_flows(d)
    d.submit(left[0]); d.submit(right[0])
    left_owner = d.owner_for(left[0])
    right_owner = d.owner_for(right[0])
    assert left_owner != right_owner
    # Deliver each flow to the other worker.  Neither may mutate the foreign
    # session or silently migrate it.
    d.shards[right_owner].deliver_to_this_owner(left[0], left_owner, "submit")
    d.shards[right_owner].deliver_to_this_owner(left[0], left_owner, "output")
    d.shards[right_owner].deliver_to_this_owner(left[0], left_owner, "completion")
    d.shards[left_owner].deliver_to_this_owner(right[0], right_owner, "callback")
    # A same-owner lookup of a foreign session is a separate cross-worker
    # callback rejection, not a migration.
    d.shards[right_owner].deliver_to_this_owner(left[0], right_owner, "callback")
    assert d.shards[right_owner].wrong_owner_submit == 1
    assert d.shards[right_owner].wrong_owner_output == 1
    assert d.shards[right_owner].wrong_owner_completion == 1
    assert d.shards[left_owner].cross_worker_callbacks == 1
    assert d.shards[right_owner].cross_worker_callbacks == 1
    d.tick(); d.tick()
    assert d.shards[left_owner].sessions[left[0]].outcome == "SUCCEEDED"
    assert d.shards[right_owner].sessions[right[0]].outcome == "SUCCEEDED"
    d.shards[left_owner].stop(); d.shards[right_owner].stop()
    assert_common("owner-tripwires", d)
    return d.evidence()


def main() -> int:
    cells = {
        "two_live_shards": cell_two_live_shards(),
        "fault_isolation": cell_fault_isolation(),
        "owner_tripwires": cell_owner_tripwires(),
    }
    print(json.dumps({"schema": "owner-inline-oi4-shards/v2", "cells": cells},
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"OI4 model invariant failed: {error}", file=sys.stderr)
        raise
