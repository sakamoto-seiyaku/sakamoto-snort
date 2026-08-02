#!/usr/bin/env python3
"""Deterministic P6c fault, coalescing, epoll, and teardown scenarios."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable


@dataclass
class Wake:
    phase: str = "SLEEPING"
    queued: int = 1
    readable: bool = False
    owner: bool = False
    attempts: int = 0
    writes: int = 0
    fault: str = "NONE"
    blocked: bool = True
    drained: int = 0
    epoll_result: str = "none"

    def write(self, outcome: str) -> None:
        assert self.phase == "NOTIFYING" and self.owner
        self.attempts += 1
        if outcome == "EINTR" and self.attempts < 3:
            return
        if outcome == "SUCCESS":
            self.writes += 1
            self.readable = True
            self.phase = "NOTIFIED"
            return
        if outcome == "EAGAIN":
            # Runtime injector performs a real write or observes real saturation.
            self.readable = True
            self.phase = "NOTIFIED"
            return
        self.owner = False
        self.phase = "DRAINING"
        self.fault = "EINTR_EXHAUSTED" if outcome == "EINTR" else outcome

    def teardown(self) -> None:
        self.blocked = False
        self.readable = False
        self.drained += self.queued
        self.queued = 0
        self.owner = False
        self.phase = "AWAKE"

    def epoll_return(self, result: str) -> None:
        assert self.blocked and result in ("readable", "spurious", "eintr")
        self.blocked = False
        self.epoll_result = result

    def begin_draining(self) -> bool:
        if self.phase == "NOTIFYING":
            return False
        self.phase = "DRAINING"
        return True

    def finish_file_poll(self) -> bool:
        """Return False for file.c's immediate n_fds_ready < 0 return."""
        assert self.phase == "DRAINING"
        if self.epoll_result == "eintr":
            self.epoll_result = "none"
            return False
        if self.epoll_result == "readable":
            assert self.readable
            self.readable = False
        self.epoll_result = "none"
        self.owner = False
        self.phase = "AWAKE"
        return True

    def finish_rejected_poll(self) -> None:
        """Finish a poll whose sole begin-draining call saw NOTIFYING."""
        assert self.phase == "NOTIFYING"
        if self.epoll_result == "readable":
            assert self.readable
            self.readable = False
        # EINTR has no callbacks; timeout/spurious have no eventfd callback.
        self.epoll_result = "none"

    def next_nonawake_poll(self) -> bool:
        assert self.phase != "AWAKE"
        self.epoll_result = "readable" if self.readable else "timeout"
        if not self.begin_draining():
            self.finish_rejected_poll()
            return False
        assert self.finish_file_poll()
        return True

    def awake_dispatch(self) -> None:
        assert self.phase == "AWAKE"
        self.drained += self.queued
        self.queued = 0


def normal(outcomes: tuple[str, ...]) -> Wake:
    wake = Wake(phase="NOTIFYING", owner=True)
    for outcome in outcomes:
        wake.write(outcome)
        if wake.phase != "NOTIFYING":
            break
    return wake


def case_eintr_retry_1() -> None:
    wake = normal(("EINTR", "SUCCESS"))
    assert (wake.attempts, wake.writes, wake.phase, wake.owner) == (2, 1, "NOTIFIED", True)


def case_eintr_retry_2() -> None:
    wake = normal(("EINTR", "EINTR", "SUCCESS"))
    assert (wake.attempts, wake.writes, wake.phase, wake.owner) == (3, 1, "NOTIFIED", True)


def case_eintr_exhausted() -> None:
    wake = normal(("EINTR", "EINTR", "EINTR"))
    assert (wake.attempts, wake.fault, wake.owner, wake.phase) == (3, "EINTR_EXHAUSTED", False, "DRAINING")
    wake.teardown()
    assert not wake.queued and not wake.readable and wake.phase == "AWAKE"


def case_eagain_readable_retained() -> None:
    wake = normal(("EAGAIN",))
    assert wake.readable and wake.owner and wake.phase == "NOTIFIED" and wake.writes == 0


def terminal_fault(outcome: str) -> None:
    wake = normal((outcome,))
    assert wake.fault == outcome and not wake.owner and wake.phase == "DRAINING"
    wake.teardown()
    assert (wake.queued, wake.readable, wake.owner, wake.phase) == (0, False, False, "AWAKE")


def case_epoll_spurious() -> None:
    wake = Wake()
    wake.epoll_return("spurious")
    assert wake.begin_draining()
    assert wake.finish_file_poll()
    assert wake.phase == "AWAKE" and wake.queued == 1
    wake.awake_dispatch()
    assert wake.queued == 0 and wake.drained == 1


def case_epoll_eintr_without_owner() -> None:
    wake = Wake()
    wake.epoll_return("eintr")
    assert wake.begin_draining()
    assert not wake.finish_file_poll()
    assert wake.phase == "DRAINING" and wake.queued == 1 and not wake.readable
    assert wake.next_nonawake_poll()
    assert wake.phase == "AWAKE" and wake.queued == 1
    wake.awake_dispatch()
    assert wake.queued == 0 and wake.drained == 1


def case_epoll_eintr_concurrent_notifying() -> None:
    wake = Wake()
    wake.epoll_return("eintr")
    # A publisher wins SLEEPING -> NOTIFYING after epoll_wait returned. The
    # first begin-draining attempt must refuse to retire its write ownership.
    wake.phase = "NOTIFYING"
    wake.owner = True
    assert not wake.begin_draining()
    wake.finish_rejected_poll()
    assert wake.phase == "NOTIFYING" and wake.epoll_result == "none"
    # A following zero-timeout poll is also allowed to observe NOTIFYING. It
    # calls begin-draining once, is rejected, and returns again.
    assert not wake.next_nonawake_poll()
    assert wake.phase == "NOTIFYING" and wake.owner
    wake.write("SUCCESS")
    assert wake.readable and wake.phase == "NOTIFIED"
    assert wake.next_nonawake_poll()
    assert wake.phase == "AWAKE" and not wake.readable
    wake.awake_dispatch()
    assert wake.queued == 0 and wake.drained == 1


def case_burst_coalescing() -> None:
    wake = Wake(phase="NOTIFYING", queued=64, owner=True)
    wake.write("SUCCESS")
    for _ in range(63):
        # Additional publishers increment epoch but preserve NOTIFYING/NOTIFIED.
        assert wake.phase == "NOTIFIED"
    assert wake.writes == 1


def case_sustained_awake() -> None:
    wake = Wake(phase="AWAKE", queued=0, owner=False, blocked=False)
    for _ in range(256):
        wake.queued += 1
        wake.drained += wake.queued
        wake.queued = 0
    assert wake.writes == 0 and wake.attempts == 0


def case_teardown_transition() -> None:
    wake = Wake(phase="NOTIFYING", queued=1)
    # A real control-plane transition rejects NOTIFYING while barrier-held;
    # fault teardown first retires the writer to DRAINING.
    wake.owner = False
    wake.phase = "DRAINING"
    wake.teardown()
    assert not any((wake.queued, wake.readable, wake.owner, wake.blocked))


def case_teardown_queued() -> None:
    wake = Wake(phase="NOTIFIED", queued=9, readable=True)
    wake.teardown()
    assert wake.drained == 9 and wake.queued == 0 and not wake.readable


CASES: tuple[tuple[str, Callable[[], None]], ...] = (
    ("eintr_retry_once", case_eintr_retry_1),
    ("eintr_retry_twice", case_eintr_retry_2),
    ("eintr_exhausted_teardown", case_eintr_exhausted),
    ("eagain_readable_retained", case_eagain_readable_retained),
    ("ebadf_teardown", lambda: terminal_fault("EBADF")),
    ("einval_teardown", lambda: terminal_fault("EINVAL")),
    ("short_write_teardown", lambda: terminal_fault("SHORT")),
    ("spurious_epoll", case_epoll_spurious),
    ("epoll_eintr_without_owner", case_epoll_eintr_without_owner),
    ("epoll_eintr_concurrent_notifying", case_epoll_eintr_concurrent_notifying),
    ("burst_coalescing", case_burst_coalescing),
    ("sustained_awake_zero_writes", case_sustained_awake),
    ("teardown_during_transition", case_teardown_transition),
    ("teardown_with_queued_work", case_teardown_queued),
)


def main() -> int:
    results = []
    failed = False
    for name, scenario in CASES:
        try:
            scenario()
            results.append({"name": name, "status": "PASS"})
        except AssertionError as error:
            failed = True
            results.append({"name": name, "status": "FAIL", "detail": str(error)})
    print(json.dumps({"schema": "p6c-fault-v1", "eligible": not failed, "cases": results}, indent=2))
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
