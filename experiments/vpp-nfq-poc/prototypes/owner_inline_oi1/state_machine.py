#!/usr/bin/env python3
"""Throwaway OI-1 scheduler state-machine prototype."""

from dataclasses import dataclass, field
import json
import sys


RUNNABLE = "RUNNABLE"
WAITING = "WAITING"
STOPPED = "STOPPED"
FAULT = "FAULT"


@dataclass
class State:
    status: str = WAITING
    generation: int = 1
    wake_sequence: int = 0
    accepted_wakes: int = 0
    stale_wakes: int = 0
    duplicate_wakes: int = 0
    drive_calls: int = 0
    quanta: int = 0
    cause: str = "initial"
    fault_reason: str = ""
    seen_sequences: set[int] = field(default_factory=set)

    def view(self) -> dict:
        return {
            "status": self.status,
            "generation": self.generation,
            "wake_sequence": self.wake_sequence,
            "accepted_wakes": self.accepted_wakes,
            "stale_wakes": self.stale_wakes,
            "duplicate_wakes": self.duplicate_wakes,
            "drive_calls": self.drive_calls,
            "quanta": self.quanta,
            "cause": self.cause,
            "fault_reason": self.fault_reason,
        }


def wake(state: State, generation: int, sequence: int, cause: str) -> None:
    if state.status in (STOPPED, FAULT):
        state.stale_wakes += 1
        return
    if generation != state.generation:
        state.stale_wakes += 1
        return
    if sequence in state.seen_sequences:
        state.duplicate_wakes += 1
        return
    state.seen_sequences.add(sequence)
    state.wake_sequence = max(state.wake_sequence, sequence)
    state.accepted_wakes += 1
    state.cause = cause
    state.status = RUNNABLE


def drive(state: State) -> None:
    if state.status in (STOPPED, FAULT):
        return
    state.drive_calls += 1
    if state.status != RUNNABLE:
        state.status = FAULT
        state.fault_reason = "drive-without-wake"
        return
    state.quanta += 1
    # The prototype alternates between bounded work and an external wait.
    state.status = WAITING
    state.cause = "drive-complete"


def render(state: State) -> None:
    print("\033[2J\033[H", end="")
    print(json.dumps(state.view(), indent=2, sort_keys=True))
    print("\nCommands: drive | wake <generation> <sequence> <cause> | stop | fault | reset | quit")


def main() -> int:
    state = State()
    render(state)
    for line in sys.stdin:
        words = line.strip().split()
        if not words:
            continue
        command = words[0].lower()
        if command in {"quit", "q"}:
            return 0
        if command == "wake" and len(words) >= 4:
            wake(state, int(words[1]), int(words[2]), words[3])
        elif command == "drive":
            drive(state)
        elif command == "stop":
            state.status = STOPPED
            state.generation += 1
            state.cause = "stop"
        elif command == "fault":
            state.status = FAULT
            state.fault_reason = "manual-fault"
        elif command == "reset":
            state = State(generation=state.generation + 1)
        else:
            state.fault_reason = "invalid-command"
            state.status = FAULT
        render(state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
