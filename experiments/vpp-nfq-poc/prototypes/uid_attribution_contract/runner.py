#!/usr/bin/env python3
"""PROTOTYPE runner for the A1 UID attribution contract.

Default mode executes the bounded Host/model evidence cells and writes the raw
cell ledger to ``artifacts/uid-attribution-contract-host-model.json``.  The
``--interactive`` mode is intentionally tiny: it renders the whole in-memory
state after every action so the contract can be driven by hand.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any, Callable

from model import (
    AttributionModel,
    COMPLETION_ACCEPTED,
    COMPLETION_DUPLICATE,
    COMPLETION_STALE,
    COMPLETION_WRONG_GENERATION,
    COMPLETION_WRONG_OWNER,
    LOOKUP_HIT,
    LOOKUP_MISS,
    LOOKUP_PENDING,
    LOOKUP_QUEUE_FULL,
    LOOKUP_STOPPED,
    LOOKUP_UNAVAILABLE,
    LookupCompletion,
)


ROOT = Path(__file__).resolve().parents[4]
SOURCE = Path(__file__).with_name("model.py")
RUNNER_SOURCE = Path(__file__)
DEFAULT_ARTIFACT = Path(__file__).with_name("artifacts") / (
    "uid-attribution-contract-host-model.json"
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_head() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"


def _flow(model: AttributionModel, suffix: int = 0):
    return model.open_flow(
        "ipv4",
        "tcp",
        "10.0.0.2",
        40000 + suffix,
        "203.0.113.10",
        443,
    )


def _flow6(model: AttributionModel, suffix: int = 0):
    return model.open_flow(
        "ipv6",
        "udp",
        "2001:db8::2",
        41000 + suffix,
        "2001:db8::53",
        53,
    )


def _live_identity(model: AttributionModel, flow_id: int) -> dict[str, Any]:
    """Capture mutable attribution state, excluding expected audit counters."""

    view = model.view()
    return {
        "flow": view["flows"].get(str(flow_id)),
        "pending": view["pending"],
        "cache": view["cache"],
    }


def cell_miss_completion_hit_reverse() -> dict[str, Any]:
    model = AttributionModel(worker_count=2, pending_capacity=4, cache_capacity=4)
    flow = _flow(model)
    first = model.lookup(flow.flow_id)
    assert first.outcome == LOOKUP_MISS
    assert first.token is not None
    assert model.counters["owner_blocking_waits"] == 0
    owner_before = flow.owner
    model.tick(2)
    completion = model.completion(first.token, 10001)
    assert model.complete(completion) == COMPLETION_ACCEPTED
    assert flow.owner == owner_before
    hit = model.lookup(flow.flow_id)
    assert hit.outcome == LOOKUP_HIT and hit.uid == 10001
    reverse = model.open_flow(
        "ipv4",
        "tcp",
        "203.0.113.10",
        443,
        "10.0.0.2",
        40000,
    )
    reverse_hit = model.lookup(reverse.flow_id)
    assert reverse.flow_id == flow.flow_id
    assert reverse_hit.outcome == LOOKUP_HIT and reverse_hit.uid == 10001
    # Explicitly compare the same key under two identities.  The selector has
    # no UID parameter and therefore cannot move a live flow after attribution.
    assert model.owner_for(flow.key) == owner_before
    return {
        "first_lookup": first.as_dict(),
        "completion": completion.identity(),
        "forward_hit": hit.as_dict(),
        "reverse_hit": reverse_hit.as_dict(),
        "owner": owner_before,
        "directions": sorted(flow.directions),
        "state": model.view(include_history=True),
    }


def cell_concurrent_misses() -> dict[str, Any]:
    model = AttributionModel(worker_count=2, pending_capacity=4, cache_capacity=4)
    first_flow = _flow(model, 1)
    second_flow = _flow6(model, 2)
    first = model.lookup(first_flow.flow_id)
    second = model.lookup(second_flow.flow_id)
    coalesced = model.lookup(first_flow.flow_id)
    assert first.outcome == LOOKUP_MISS and first.token is not None
    assert second.outcome == LOOKUP_MISS and second.token is not None
    assert coalesced.outcome == LOOKUP_PENDING and coalesced.token == first.token
    pending_before = model.view()["pending"]
    sentinel_before = model.counters["owner_sentinel_progress"]
    model.tick(3)
    assert model.counters["owner_sentinel_progress"] - sentinel_before >= 3
    assert len(model.pending) == 2
    assert model.complete(model.completion(second.token, 20002)) == COMPLETION_ACCEPTED
    assert model.complete(model.completion(first.token, 10001)) == COMPLETION_ACCEPTED
    first_hit = model.lookup(first_flow.flow_id)
    second_hit = model.lookup(second_flow.flow_id)
    assert first_hit.uid == 10001 and second_hit.uid == 20002
    assert first_flow.owner != second_flow.owner or first_flow.key != second_flow.key
    assert model.counters["owner_sentinel_progress"] >= 3
    return {
        "pending_before_completion": pending_before,
        "first": first.as_dict(),
        "second": second.as_dict(),
        "coalesced": coalesced.as_dict(),
        "first_hit": first_hit.as_dict(),
        "second_hit": second_hit.as_dict(),
        "state": model.view(include_history=True),
    }


def cell_refresh_and_expiry() -> dict[str, Any]:
    model = AttributionModel(
        worker_count=2,
        pending_capacity=4,
        cache_capacity=4,
        cache_ttl=2,
    )
    flow = _flow(model)
    initial = model.lookup(flow.flow_id)
    assert initial.token is not None
    assert model.complete(model.completion(initial.token, 30003)) == COMPLETION_ACCEPTED
    model.tick(2)
    expired = model.lookup(flow.flow_id)
    assert expired.outcome == LOOKUP_MISS and expired.token is not None
    assert model.complete(model.completion(expired.token, 40004)) == COMPLETION_ACCEPTED

    refresh_flow = _flow(model, 9)
    pending = model.lookup(refresh_flow.flow_id)
    assert pending.token is not None
    old_completion = model.completion(pending.token, 50005)
    model.refresh_app()
    refreshed_scope_before_stale = _live_identity(model, refresh_flow.flow_id)
    stale_after_app = model.complete(old_completion)
    assert stale_after_app == COMPLETION_STALE
    assert _live_identity(model, refresh_flow.flow_id) == refreshed_scope_before_stale
    refreshed = model.lookup(refresh_flow.flow_id)
    assert refreshed.outcome == LOOKUP_MISS and refreshed.token is not None
    assert model.complete(model.completion(refreshed.token, 50006)) == COMPLETION_ACCEPTED

    model.refresh_network()
    network_miss = model.lookup(refresh_flow.flow_id)
    assert network_miss.outcome == LOOKUP_MISS and network_miss.token is not None
    wrong_network_scope = model.complete(
        model.completion(
            network_miss.token,
            50008,
            network_epoch=model.network_epoch - 1,
        )
    )
    assert wrong_network_scope == COMPLETION_STALE
    assert _live_identity(model, refresh_flow.flow_id)["flow"]["uid"] is None
    wrong_app_scope = model.complete(
        model.completion(
            network_miss.token,
            50008,
            app_epoch=model.app_epoch - 1,
        )
    )
    assert wrong_app_scope == COMPLETION_STALE
    assert _live_identity(model, refresh_flow.flow_id)["flow"]["uid"] is None
    assert model.complete(model.completion(network_miss.token, 50007)) == COMPLETION_ACCEPTED
    generation_flow = _flow(model, 11)
    generation_pending = model.lookup(generation_flow.flow_id)
    assert generation_pending.outcome == LOOKUP_MISS and generation_pending.token is not None
    old_generation_completion = model.completion(generation_pending.token, 50009)
    generation_before_restart = model.generation
    model.restart_generation()
    assert model.generation == generation_before_restart + 1
    generation_scope_before_stale = _live_identity(model, generation_flow.flow_id)
    stale_after_generation = model.complete(old_generation_completion)
    assert stale_after_generation == COMPLETION_STALE
    assert _live_identity(model, generation_flow.flow_id) == generation_scope_before_stale
    fresh_generation = model.lookup(generation_flow.flow_id)
    assert fresh_generation.outcome == LOOKUP_MISS and fresh_generation.token is not None
    assert model.complete(model.completion(fresh_generation.token, 50010)) == COMPLETION_ACCEPTED
    assert model.counters["cache_expired"] >= 1
    assert model.counters["app_refreshes"] == 1
    assert model.counters["network_refreshes"] == 1
    assert model.counters["generation_restarts"] == 1
    return {
        "initial": initial.as_dict(),
        "expired_miss": expired.as_dict(),
        "stale_after_app_refresh": stale_after_app,
        "post_app_refresh_miss": refreshed.as_dict(),
        "post_network_refresh_miss": network_miss.as_dict(),
        "wrong_network_scope": wrong_network_scope,
        "wrong_app_scope": wrong_app_scope,
        "stale_after_generation_restart": stale_after_generation,
        "post_generation_restart_miss": fresh_generation.as_dict(),
        "state": model.view(include_history=True),
    }


def cell_completion_identity_faults() -> dict[str, Any]:
    model = AttributionModel(worker_count=2, pending_capacity=4, cache_capacity=4)
    flow = _flow(model)
    request = model.lookup(flow.flow_id)
    assert request.token is not None
    identity_before_rejections = _live_identity(model, flow.flow_id)
    wrong_owner = model.complete(
        model.completion(
            request.token,
            61001,
            owner=(flow.owner + 1) % model.worker_count,
        )
    )
    assert wrong_owner == COMPLETION_WRONG_OWNER
    assert request.token in model.pending
    assert _live_identity(model, flow.flow_id) == identity_before_rejections
    wrong_generation = model.complete(
        model.completion(request.token, 61001, generation=model.generation - 1)
    )
    assert wrong_generation == COMPLETION_WRONG_GENERATION
    assert request.token in model.pending
    assert _live_identity(model, flow.flow_id) == identity_before_rejections
    other_flow = _flow6(model, 12)
    other_before_scope_fault = _live_identity(model, other_flow.flow_id)
    wrong_flow_scope = model.complete(
        LookupCompletion(
            replace(
                model.request(request.token),
                flow_id=other_flow.flow_id,
                key=other_flow.key,
            ),
            61003,
        )
    )
    assert wrong_flow_scope == COMPLETION_STALE
    assert _live_identity(model, flow.flow_id) == identity_before_rejections
    assert _live_identity(model, other_flow.flow_id) == other_before_scope_fault
    assert model.complete(model.completion(request.token, 61001)) == COMPLETION_ACCEPTED
    identity_before_duplicate = _live_identity(model, flow.flow_id)
    duplicate = model.complete(model.completion(request.token, 61999))
    assert duplicate == COMPLETION_DUPLICATE
    assert _live_identity(model, flow.flow_id) == identity_before_duplicate

    stale_flow = _flow(model, 10)
    stale_request = model.lookup(stale_flow.flow_id)
    assert stale_request.token is not None
    stale_completion = model.completion(stale_request.token, 61002)
    model.close_flow(stale_flow.flow_id)
    replacement = _flow(model, 10)
    replacement_before_stale = _live_identity(model, replacement.flow_id)
    stale = model.complete(stale_completion)
    assert stale == COMPLETION_STALE
    assert _live_identity(model, replacement.flow_id) == replacement_before_stale
    assert replacement.uid is None and replacement.owner == model.owner_for(replacement.key)
    assert model.counters["completion_wrong_owner"] == 1
    assert model.counters["completion_wrong_generation"] == 1
    assert model.counters["completion_duplicate"] == 1
    assert model.counters["completion_stale"] >= 1
    return {
        "wrong_owner": wrong_owner,
        "wrong_generation": wrong_generation,
        "wrong_flow_scope": wrong_flow_scope,
        "accepted": COMPLETION_ACCEPTED,
        "duplicate": duplicate,
        "stale": stale,
        "state": model.view(include_history=True),
    }


def cell_unavailable_and_queue_full() -> dict[str, Any]:
    unavailable = AttributionModel(worker_count=2, pending_capacity=2, cache_capacity=2)
    unavailable.provider_available = False
    unavailable_flow = _flow(unavailable)
    unavailable_result = unavailable.lookup(unavailable_flow.flow_id)
    assert unavailable_result.outcome == LOOKUP_UNAVAILABLE
    assert unavailable.live_resources()["pending_requests"] == 0

    full = AttributionModel(worker_count=2, pending_capacity=1, cache_capacity=2)
    first_flow = _flow(full, 20)
    second_flow = _flow6(full, 21)
    first = full.lookup(first_flow.flow_id)
    second = full.lookup(second_flow.flow_id)
    assert first.outcome == LOOKUP_MISS and first.token is not None
    assert second.outcome == LOOKUP_QUEUE_FULL and second.token is None
    assert full.live_resources()["pending_requests"] == 1
    assert full.complete(full.completion(first.token, 62001)) == COMPLETION_ACCEPTED
    retry = full.lookup(second_flow.flow_id)
    assert retry.outcome == LOOKUP_MISS and retry.token is not None
    assert full.complete(full.completion(retry.token, 62002)) == COMPLETION_ACCEPTED
    assert full.live_resources()["pending_requests"] == 0
    return {
        "unavailable": unavailable_result.as_dict(),
        "queue_full": second.as_dict(),
        "queue_retry": retry.as_dict(),
        "unavailable_state": unavailable.view(include_history=True),
        "queue_state": full.view(include_history=True),
    }


def cell_bounds_and_zero_residue_teardown() -> dict[str, Any]:
    model = AttributionModel(
        worker_count=2,
        pending_capacity=2,
        cache_capacity=2,
        cache_ttl=20,
    )
    flows = [_flow(model, 30), _flow6(model, 31), _flow(model, 32)]
    requests = [model.lookup(flow.flow_id) for flow in flows]
    assert [result.outcome for result in requests] == [LOOKUP_MISS, LOOKUP_MISS, LOOKUP_QUEUE_FULL]
    assert all(result.token is not None for result in requests[:2])
    model.tick(2)
    assert model.complete(model.completion(requests[0].token, 63001)) == COMPLETION_ACCEPTED
    assert model.complete(model.completion(requests[1].token, 63002)) == COMPLETION_ACCEPTED
    retry = model.lookup(flows[2].flow_id)
    assert retry.outcome == LOOKUP_MISS and retry.token is not None
    assert model.complete(model.completion(retry.token, 63003)) == COMPLETION_ACCEPTED
    assert len(model.cache) == 2
    assert model.counters["cache_evicted"] == 1
    max_pending = max(item["live"]["pending"] for item in model.history)
    max_cache = max(item["live"]["cache"] for item in model.history)
    assert max_pending <= model.pending_capacity
    assert max_cache <= model.cache_capacity
    assert model.counters["owner_sentinel_progress"] >= 2

    late_flow = _flow(model, 33)
    late_request = model.lookup(late_flow.flow_id)
    assert late_request.outcome == LOOKUP_MISS and late_request.token is not None
    late_completion = model.completion(late_request.token, 63004)
    submitted_before_teardown = model.counters["lookup_submitted"]
    model.teardown()
    assert model.live_resources()["residue"] == 0
    assert model.complete(late_completion) == COMPLETION_STALE
    assert model.live_resources()["residue"] == 0
    assert model.lookup(late_flow.flow_id).outcome == LOOKUP_STOPPED
    assert len(model.settled_tokens) == submitted_before_teardown
    return {
        "max_pending": max_pending,
        "max_cache": max_cache,
        "submitted_before_teardown": submitted_before_teardown,
        "late_completion": COMPLETION_STALE,
        "final_state": model.view(include_history=True),
    }


Cell = tuple[str, Callable[[], dict[str, Any]], str]
CELLS: tuple[Cell, ...] = (
    (
        "A1-miss-completion-hit-reverse",
        cell_miss_completion_hit_reverse,
        "blocking lookup, UID in owner key, reverse contamination",
    ),
    (
        "A1-concurrent-misses",
        cell_concurrent_misses,
        "owner stall or cross-flow cache contamination",
    ),
    (
        "A1-refresh-expiry",
        cell_refresh_and_expiry,
        "stale refresh revives identity or cache lacks scope",
    ),
    (
        "A1-completion-identity-faults",
        cell_completion_identity_faults,
        "wrong-owner/generation/stale completion mutates live flow",
    ),
    (
        "A1-unavailable-queue-full",
        cell_unavailable_and_queue_full,
        "lookup failure blocks owner or grows pending queue",
    ),
    (
        "A1-bounds-zero-residue-teardown",
        cell_bounds_and_zero_residue_teardown,
        "unbounded request/cache state or teardown residue",
    ),
)


def run_cells() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for name, function, falsifier in CELLS:
        try:
            facts = function()
            results.append(
                {
                    "id": name,
                    "status": "PASS",
                    "decisive_falsifier": falsifier,
                    "facts": facts,
                }
            )
        except AssertionError as error:
            results.append(
                {
                    "id": name,
                    "status": "FAIL",
                    "decisive_falsifier": falsifier,
                    "error": repr(error),
                }
            )
        except Exception as error:  # A broken harness is not evidence.
            results.append(
                {
                    "id": name,
                    "status": "INVALID",
                    "decisive_falsifier": falsifier,
                    "error": repr(error),
                }
            )
    return results


def build_artifact(cells: list[dict[str, Any]]) -> dict[str, Any]:
    passed = [cell for cell in cells if cell["status"] == "PASS"]
    failed = [cell for cell in cells if cell["status"] == "FAIL"]
    invalid = [cell for cell in cells if cell["status"] == "INVALID"]
    architecture_interruption = bool(failed)
    return {
        "schema": "uid-attribution-contract-evidence/v1",
        "prototype": True,
        "prototype_name": "A1 nonblocking UID attribution contract",
        "question": (
            "Can an asynchronous UID fact provider represent miss, completion, "
            "cache hit, refresh, expiry, and failure without blocking FlowOwner "
            "or changing canonical flow ownership?"
        ),
        "working_assumption": (
            "FlowOwner selects a stable canonical five-tuple owner first; UID "
            "attribution is a bounded asynchronous fact with generation, "
            "network-epoch, app-epoch, and owner identity in every completion."
        ),
        "evidence_refs": {
            "plane_work_item": "SAKAMOTO-138",
            "campaign_spec": "ANDROID_VPN_POC_CAMPAIGN_SPEC.md#poc-a1--nonblocking-uid-attribution-contract",
            "gap_ids": ["EG-08", "EG-09"],
            "finding_ids": ["VPN-F026"],
            "finding_note": (
                "VPN-F026 remains an OPEN_RISK Pixel finding; this Host/model "
                "artifact does not close Android UID correctness or timing."
            ),
        },
        "registered_falsifiers": [cell[2] for cell in CELLS],
        "provenance": {
            "git_head_at_run": _git_head(),
            "model_sha256": _sha256(SOURCE),
            "runner_sha256": _sha256(RUNNER_SOURCE),
            "python": sys.version,
            "platform": platform.platform(),
            "uname": platform.uname()._asdict(),
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        },
        "cells": cells,
        "summary": {
            "pass": len(passed),
            "fail": len(failed),
            "invalid": len(invalid),
            "cell_result": "PASS" if len(passed) == len(cells) else "INCONCLUSIVE",
            "architecture_interruption": architecture_interruption,
            "interruption_reason": (
                "A registered architecture falsifier fired."
                if architecture_interruption
                else "none; owner-inline/nonblocking/FlowOwner invariants held"
            ),
        },
        "supported_claim": [
            "A bounded in-memory contract can represent miss→completion→hit and reverse lookup.",
            "Concurrent misses are isolated and same-flow requests coalesce without owner wait.",
            "Cache entries are scoped to generation/network/app epochs and expire deterministically.",
            "Wrong-owner, wrong-generation, duplicate, and stale completions are rejected without mutation.",
            "Provider unavailable and pending-queue-full are explicit nonblocking outcomes.",
            "Owner sentinel progress continues while requests are pending; live request/cache bounds and teardown residue are observable.",
            "Canonical FlowOwner selection is direction-independent and does not use UID.",
        ],
        "non_claims": [
            "No Android ConnectivityManager timing or real App UID correctness.",
            "No Pixel/arm64, VpnService, TUN, VPP, transport, or policy-path conclusion.",
            "No production queue/cache capacities, TTLs, persistence, multi-user semantics, or OEM compatibility.",
            "The prototype does not prove a particular Android API or wire schema is production-ready.",
        ],
        "poc_corrections": [
            {
                "id": "runner-record-keyword-collision",
                "status": "CORRECTED_AND_RERUN",
                "symptom": "Initial harness run marked all cells INVALID because _record received action twice.",
                "change": "Renamed the owner-turn fact field to operation; no model transition changed.",
                "architecture_impact": "none",
            },
            {
                "id": "completion-scope-and-rejection-invariance",
                "status": "CORRECTED_AND_RERUN",
                "symptom": (
                    "Identity-fault cells did not assert that rejected completions "
                    "left live flow, UID, owner, pending request, and cache state unchanged; "
                    "pending completions also accepted forged app/network scope."
                ),
                "change": (
                    "Snapshot live identity around wrong-owner, wrong-generation, duplicate, "
                    "and stale completions; validate flow/key and network/app scope before "
                    "accepting a pending completion; add wrong-network/app-scope and "
                    "generation-restart cell assertions."
                ),
                "architecture_impact": "none",
            }
        ],
        "artifact_note": (
            "Raw per-cell model histories and final state are embedded in this "
            "JSON artifact; request_archive is audit history, while live_resources "
            "is the bounded runtime accounting used by the cells."
        ),
    }


def write_artifact(path: Path, artifact: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")


def render(model: AttributionModel) -> None:
    print("\033[2J\033[H", end="")
    print(json.dumps(model.view(), indent=2, sort_keys=True))
    print(
        "\nCommands: open <family> <proto> <src> <sport> <dst> <dport> | "
        "lookup [flow_id] | complete <token> <uid> | tick [n] | "
        "refresh-app | refresh-network | restart | stop | quit"
    )


def interactive() -> int:
    model = AttributionModel()
    current_flow: int | None = None
    render(model)
    for line in sys.stdin:
        words = line.strip().split()
        if not words:
            continue
        command = words[0].lower()
        try:
            if command in {"quit", "q"}:
                return 0
            if command == "open" and len(words) == 7:
                flow = model.open_flow(
                    words[1], words[2], words[3], int(words[4]), words[5], int(words[6])
                )
                current_flow = flow.flow_id
            elif command == "lookup":
                flow_id = int(words[1]) if len(words) > 1 else current_flow
                if flow_id is None:
                    raise ValueError("open a flow first")
                print(model.lookup(flow_id).as_dict())
            elif command == "complete" and len(words) == 3:
                print(model.complete(model.completion(int(words[1]), int(words[2]))))
            elif command == "tick":
                model.tick(int(words[1]) if len(words) > 1 else 1)
            elif command == "refresh-app":
                model.refresh_app()
            elif command == "refresh-network":
                model.refresh_network()
            elif command == "restart":
                model.restart_generation()
            elif command == "stop":
                model.teardown()
            else:
                raise ValueError("invalid command")
        except (KeyError, TypeError, ValueError, RuntimeError) as error:
            print(f"command-error: {error}")
        render(model)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument("--output", type=Path, default=DEFAULT_ARTIFACT)
    args = parser.parse_args()
    if args.interactive:
        return interactive()
    cells = run_cells()
    artifact = build_artifact(cells)
    write_artifact(args.output, artifact)
    summary = artifact["summary"]
    print(
        "UID attribution contract PROTOTYPE: "
        f"{summary['cell_result']} "
        f"pass={summary['pass']} fail={summary['fail']} invalid={summary['invalid']}"
    )
    print(f"raw artifact: {args.output}")
    for cell in cells:
        print(f"{cell['status']:>9} {cell['id']}")
    return 0 if summary["cell_result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
