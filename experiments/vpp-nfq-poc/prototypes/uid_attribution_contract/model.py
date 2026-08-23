#!/usr/bin/env python3
"""PROTOTYPE: nonblocking UID attribution state model.

This module deliberately contains no Android, socket, or VPP dependency.  It
models the seam that A1 needs to answer: a FlowOwner can observe an unresolved
UID, keep making progress, and later consume a generation-scoped completion
without putting UID in the canonical flow-owner key.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import asdict, dataclass, field, replace
import hashlib
from typing import Any, Iterable


PROTOTYPE_SCHEMA = "uid-attribution-contract/v1"
LOOKUP_MISS = "MISS_SUBMITTED"
LOOKUP_PENDING = "MISS_COALESCED"
LOOKUP_HIT = "CACHE_HIT"
LOOKUP_UNAVAILABLE = "LOOKUP_UNAVAILABLE"
LOOKUP_QUEUE_FULL = "LOOKUP_QUEUE_FULL"
LOOKUP_STOPPED = "LOOKUP_STOPPED"
COMPLETION_ACCEPTED = "COMPLETION_ACCEPTED"
COMPLETION_WRONG_OWNER = "COMPLETION_WRONG_OWNER"
COMPLETION_WRONG_GENERATION = "COMPLETION_WRONG_GENERATION"
COMPLETION_DUPLICATE = "COMPLETION_DUPLICATE"
COMPLETION_STALE = "COMPLETION_STALE"
FLOW_STALE = "FLOW_STALE"


@dataclass(frozen=True, order=True)
class Endpoint:
    address: str
    port: int

    def text(self) -> str:
        return f"{self.address}:{self.port}"


@dataclass(frozen=True)
class CanonicalFlowKey:
    """Direction-independent key used only by the owner selector."""

    family: str
    protocol: str
    endpoint_a: Endpoint
    endpoint_b: Endpoint

    @classmethod
    def from_packet(
        cls,
        family: str,
        protocol: str,
        source_address: str,
        source_port: int,
        destination_address: str,
        destination_port: int,
    ) -> tuple["CanonicalFlowKey", str]:
        source = Endpoint(source_address, source_port)
        destination = Endpoint(destination_address, destination_port)
        if source <= destination:
            key = cls(family, protocol, source, destination)
        else:
            key = cls(family, protocol, destination, source)
        direction = "ORIG" if source <= destination else "REPLY"
        return key, direction

    def text(self) -> str:
        return (
            f"{self.family}/{self.protocol}/"
            f"{self.endpoint_a.text()}-{self.endpoint_b.text()}"
        )


def owner_for_key(key: CanonicalFlowKey, worker_count: int, seed: str = "a1") -> int:
    """Select a fixed owner from the canonical key; UID is intentionally absent."""

    digest = hashlib.sha256(f"{seed}|{key.text()}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % worker_count


@dataclass(frozen=True)
class LookupRequest:
    token: int
    flow_id: int
    key: CanonicalFlowKey
    owner: int
    generation: int
    network_epoch: int
    app_epoch: int

    def identity(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "flow_id": self.flow_id,
            "key": self.key.text(),
            "owner": self.owner,
            "generation": self.generation,
            "network_epoch": self.network_epoch,
            "app_epoch": self.app_epoch,
        }


@dataclass(frozen=True)
class LookupCompletion:
    request: LookupRequest
    uid: int

    def identity(self) -> dict[str, Any]:
        return {**self.request.identity(), "uid": self.uid}


@dataclass(frozen=True)
class CacheEntry:
    flow_id: int
    key: CanonicalFlowKey
    uid: int
    owner: int
    generation: int
    network_epoch: int
    app_epoch: int
    expires_at: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "key": self.key.text(),
            "uid": self.uid,
            "owner": self.owner,
            "generation": self.generation,
            "network_epoch": self.network_epoch,
            "app_epoch": self.app_epoch,
            "expires_at": self.expires_at,
        }


@dataclass
class Flow:
    flow_id: int
    key: CanonicalFlowKey
    owner: int
    origin: tuple[Endpoint, Endpoint]
    generation: int
    network_epoch: int
    app_epoch: int
    uid: int | None = None
    state: str = "UNRESOLVED"
    directions: set[str] = field(default_factory=set)
    pending_token: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "key": self.key.text(),
            "owner": self.owner,
            "generation": self.generation,
            "network_epoch": self.network_epoch,
            "app_epoch": self.app_epoch,
            "uid": self.uid,
            "state": self.state,
            "directions": sorted(self.directions),
            "pending_token": self.pending_token,
        }


@dataclass(frozen=True)
class LookupResult:
    outcome: str
    flow_id: int
    owner: int | None
    token: int | None = None
    uid: int | None = None
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class AttributionModel:
    """Small in-memory model with explicit live-resource accounting."""

    def __init__(
        self,
        *,
        worker_count: int = 2,
        pending_capacity: int = 4,
        cache_capacity: int = 4,
        cache_ttl: int = 4,
        owner_seed: str = "a1",
    ) -> None:
        if worker_count < 1 or pending_capacity < 1 or cache_capacity < 1:
            raise ValueError("capacities and worker_count must be positive")
        self.worker_count = worker_count
        self.pending_capacity = pending_capacity
        self.cache_capacity = cache_capacity
        self.cache_ttl = cache_ttl
        self.owner_seed = owner_seed
        self.running = True
        self.provider_available = True
        self.clock = 0
        self.generation = 1
        self.network_epoch = 1
        self.app_epoch = 1
        self.next_flow_id = 1
        self.next_token = 1
        self.flows: dict[int, Flow] = {}
        self.active_by_key: dict[str, int] = {}
        self.pending: OrderedDict[int, LookupRequest] = OrderedDict()
        self.pending_by_flow: dict[int, int] = {}
        self.request_archive: dict[int, LookupRequest] = {}
        self.settled_tokens: dict[int, str] = {}
        self.cache: OrderedDict[int, CacheEntry] = OrderedDict()
        self.history: list[dict[str, Any]] = []
        self.counters: dict[str, int] = {
            "owner_turns": 0,
            "owner_sentinel_progress": 0,
            "owner_blocking_waits": 0,
            "lookup_misses": 0,
            "lookup_coalesced": 0,
            "lookup_submitted": 0,
            "lookup_completed": 0,
            "lookup_unavailable": 0,
            "lookup_queue_full": 0,
            "cache_hits": 0,
            "cache_expired": 0,
            "cache_evicted": 0,
            "cache_invalidated": 0,
            "completion_wrong_owner": 0,
            "completion_wrong_generation": 0,
            "completion_duplicate": 0,
            "completion_stale": 0,
            "flow_opened": 0,
            "flow_reused_reverse": 0,
            "flow_closed": 0,
            "app_refreshes": 0,
            "network_refreshes": 0,
            "generation_restarts": 0,
            "teardowns": 0,
        }

    def _inc(self, name: str, amount: int = 1) -> None:
        self.counters[name] += amount

    def _owner_turn(self, action: str) -> None:
        # Every model operation represents a bounded owner turn.  There is no
        # wait on the lookup provider in this path.
        self._inc("owner_turns")
        self._inc("owner_sentinel_progress")
        self._record("owner-turn", operation=action)

    def _record(self, action: str, **facts: Any) -> None:
        self.history.append(
            {
                "clock": self.clock,
                "action": action,
                **facts,
                "live": {
                    "flows": len(self.flows),
                    "pending": len(self.pending),
                    "cache": len(self.cache),
                },
            }
        )

    def owner_for(self, key: CanonicalFlowKey) -> int:
        return owner_for_key(key, self.worker_count, self.owner_seed)

    def open_flow(
        self,
        family: str,
        protocol: str,
        source_address: str,
        source_port: int,
        destination_address: str,
        destination_port: int,
    ) -> Flow:
        key, direction = CanonicalFlowKey.from_packet(
            family,
            protocol,
            source_address,
            source_port,
            destination_address,
            destination_port,
        )
        existing_id = self.active_by_key.get(key.text())
        if existing_id is not None and existing_id in self.flows:
            flow = self.flows[existing_id]
            flow.directions.add(direction)
            self._inc("flow_reused_reverse")
            self._record(
                "open-flow-reuse",
                flow_id=flow.flow_id,
                key=key.text(),
                direction=direction,
                owner=flow.owner,
            )
            return flow
        if not self.running:
            raise RuntimeError("cannot open a flow after teardown")
        flow_id = self.next_flow_id
        self.next_flow_id += 1
        source = Endpoint(source_address, source_port)
        destination = Endpoint(destination_address, destination_port)
        flow = Flow(
            flow_id=flow_id,
            key=key,
            owner=self.owner_for(key),
            origin=(source, destination),
            generation=self.generation,
            network_epoch=self.network_epoch,
            app_epoch=self.app_epoch,
            directions={direction},
        )
        self.flows[flow_id] = flow
        self.active_by_key[key.text()] = flow_id
        self._inc("flow_opened")
        self._record(
            "open-flow",
            flow_id=flow_id,
            key=key.text(),
            direction=direction,
            owner=flow.owner,
        )
        return flow

    def lookup(self, flow_id: int) -> LookupResult:
        self._owner_turn("lookup")
        flow = self.flows.get(flow_id)
        if not self.running:
            result = LookupResult(LOOKUP_STOPPED, flow_id, None, reason="teardown")
            self._record("lookup-stopped", flow_id=flow_id)
            return result
        if flow is None or flow.generation != self.generation:
            result = LookupResult(FLOW_STALE, flow_id, None, reason="flow-generation")
            self._record("lookup-stale-flow", flow_id=flow_id)
            return result

        cached = self.cache.get(flow_id)
        if cached is not None:
            if cached.expires_at <= self.clock:
                del self.cache[flow_id]
                self._inc("cache_expired")
                self._record("cache-expired", flow_id=flow_id, token=None)
            elif (
                cached.generation == self.generation
                and cached.network_epoch == self.network_epoch
                and cached.app_epoch == self.app_epoch
            ):
                self.cache.move_to_end(flow_id)
                flow.uid = cached.uid
                flow.state = "ATTRIBUTED"
                self._inc("cache_hits")
                result = LookupResult(
                    LOOKUP_HIT, flow_id, flow.owner, uid=cached.uid
                )
                self._record("cache-hit", **result.as_dict())
                return result

        pending_token = self.pending_by_flow.get(flow_id)
        if pending_token is not None:
            self._inc("lookup_coalesced")
            result = LookupResult(
                LOOKUP_PENDING,
                flow_id,
                flow.owner,
                token=pending_token,
                reason="same-flow-pending",
            )
            self._record("lookup-coalesced", **result.as_dict())
            return result

        self._inc("lookup_misses")
        if not self.provider_available:
            self._inc("lookup_unavailable")
            flow.state = "UNAVAILABLE"
            result = LookupResult(
                LOOKUP_UNAVAILABLE,
                flow_id,
                flow.owner,
                reason="provider-unavailable",
            )
            self._record("lookup-unavailable", **result.as_dict())
            return result
        if len(self.pending) >= self.pending_capacity:
            self._inc("lookup_queue_full")
            flow.state = "QUEUE_FULL"
            result = LookupResult(
                LOOKUP_QUEUE_FULL,
                flow_id,
                flow.owner,
                reason="pending-capacity",
            )
            self._record("lookup-queue-full", **result.as_dict())
            return result

        token = self.next_token
        self.next_token += 1
        request = LookupRequest(
            token=token,
            flow_id=flow_id,
            key=flow.key,
            owner=flow.owner,
            generation=self.generation,
            network_epoch=self.network_epoch,
            app_epoch=self.app_epoch,
        )
        self.pending[token] = request
        self.pending_by_flow[flow_id] = token
        self.request_archive[token] = request
        flow.pending_token = token
        flow.state = "PENDING"
        self._inc("lookup_submitted")
        result = LookupResult(
            LOOKUP_MISS,
            flow_id,
            flow.owner,
            token=token,
            reason="nonblocking-submit",
        )
        self._record("lookup-miss", request=request.identity(), **result.as_dict())
        return result

    def request(self, token: int) -> LookupRequest:
        return self.request_archive[token]

    def completion(
        self,
        token: int,
        uid: int,
        *,
        owner: int | None = None,
        generation: int | None = None,
        network_epoch: int | None = None,
        app_epoch: int | None = None,
    ) -> LookupCompletion:
        request = self.request(token)
        return LookupCompletion(
            replace(
                request,
                owner=request.owner if owner is None else owner,
                generation=(
                    request.generation if generation is None else generation
                ),
                network_epoch=(
                    request.network_epoch
                    if network_epoch is None
                    else network_epoch
                ),
                app_epoch=request.app_epoch if app_epoch is None else app_epoch,
            ),
            uid,
        )

    def complete(self, completion: LookupCompletion) -> str:
        self._owner_turn("completion")
        token = completion.request.token
        settled = self.settled_tokens.get(token)
        if settled is not None:
            if settled == "COMPLETED":
                self._inc("completion_duplicate")
                self._record(
                    "completion-duplicate",
                    completion=completion.identity(),
                )
                return COMPLETION_DUPLICATE
            self._inc("completion_stale")
            self._record("completion-stale", completion=completion.identity())
            return COMPLETION_STALE

        request = self.pending.get(token)
        if request is None:
            self._inc("completion_stale")
            self._record("completion-stale", completion=completion.identity())
            return COMPLETION_STALE

        if completion.request.owner != request.owner:
            self._inc("completion_wrong_owner")
            self._record(
                "completion-wrong-owner",
                expected=request.identity(),
                received=completion.identity(),
            )
            return COMPLETION_WRONG_OWNER

        # A token is necessary but not sufficient identity. Keep the
        # request's flow/key and lifecycle scope attached to the completion so
        # a forged or misrouted result cannot attribute another live flow or
        # cross an app/network epoch while the token is still pending.
        if (
            completion.request.flow_id != request.flow_id
            or completion.request.key != request.key
            or completion.request.network_epoch != request.network_epoch
            or completion.request.app_epoch != request.app_epoch
            or completion.request.network_epoch != self.network_epoch
            or completion.request.app_epoch != self.app_epoch
        ):
            self._inc("completion_stale")
            self._record(
                "completion-stale-scope",
                expected=request.identity(),
                received=completion.identity(),
            )
            return COMPLETION_STALE

        if (
            completion.request.generation != self.generation
            or completion.request.generation != request.generation
        ):
            self._inc("completion_wrong_generation")
            self._record(
                "completion-wrong-generation",
                expected=request.identity(),
                received=completion.identity(),
            )
            return COMPLETION_WRONG_GENERATION

        flow = self.flows.get(request.flow_id)
        if flow is None or flow.generation != self.generation:
            del self.pending[token]
            self.pending_by_flow.pop(request.flow_id, None)
            self.settled_tokens[token] = "STALE"
            self._inc("completion_stale")
            self._record("completion-stale-flow", completion=completion.identity())
            return COMPLETION_STALE

        del self.pending[token]
        self.pending_by_flow.pop(request.flow_id, None)
        flow.pending_token = None
        flow.uid = completion.uid
        flow.state = "ATTRIBUTED"
        self.settled_tokens[token] = "COMPLETED"
        self._inc("lookup_completed")
        entry = CacheEntry(
            flow_id=flow.flow_id,
            key=flow.key,
            uid=completion.uid,
            owner=flow.owner,
            generation=self.generation,
            network_epoch=self.network_epoch,
            app_epoch=self.app_epoch,
            expires_at=self.clock + self.cache_ttl,
        )
        self.cache[flow.flow_id] = entry
        self.cache.move_to_end(flow.flow_id)
        while len(self.cache) > self.cache_capacity:
            evicted_flow_id, _ = self.cache.popitem(last=False)
            self._inc("cache_evicted")
            self._record("cache-evicted", flow_id=evicted_flow_id)
        self._record(
            "completion-accepted",
            completion=completion.identity(),
            cache=entry.as_dict(),
        )
        return COMPLETION_ACCEPTED

    def tick(self, steps: int = 1) -> None:
        if steps < 0:
            raise ValueError("steps must be non-negative")
        for _ in range(steps):
            self.clock += 1
            self._owner_turn("tick")
            for flow_id, entry in list(self.cache.items()):
                if entry.expires_at <= self.clock:
                    del self.cache[flow_id]
                    self._inc("cache_expired")
                    flow = self.flows.get(flow_id)
                    if flow is not None and flow.state == "ATTRIBUTED":
                        flow.uid = None
                        flow.state = "EXPIRED"
                    self._record("cache-expired", flow_id=flow_id)
            self._record("tick", steps=1)

    def _invalidate_scope(self, reason: str) -> None:
        for token, request in list(self.pending.items()):
            del self.pending[token]
            self.pending_by_flow.pop(request.flow_id, None)
            self.settled_tokens[token] = "INVALIDATED"
            flow = self.flows.get(request.flow_id)
            if flow is not None:
                flow.pending_token = None
                flow.uid = None
                flow.state = "UNRESOLVED"
        self._inc("cache_invalidated", len(self.cache))
        self.cache.clear()
        for flow in self.flows.values():
            flow.generation = self.generation
            flow.network_epoch = self.network_epoch
            flow.app_epoch = self.app_epoch
            flow.uid = None
            flow.state = "UNRESOLVED"
        self._record("scope-invalidated", reason=reason)

    def refresh_app(self) -> None:
        self._owner_turn("app-refresh")
        self.app_epoch += 1
        self._inc("app_refreshes")
        self._invalidate_scope("app-epoch")

    def refresh_network(self) -> None:
        self._owner_turn("network-refresh")
        self.network_epoch += 1
        self._inc("network_refreshes")
        self._invalidate_scope("network-epoch")

    def restart_generation(self) -> None:
        self._owner_turn("generation-restart")
        self.generation += 1
        self._inc("generation_restarts")
        self._invalidate_scope("generation")

    def close_flow(self, flow_id: int) -> None:
        self._owner_turn("close-flow")
        flow = self.flows.pop(flow_id, None)
        if flow is None:
            return
        self.active_by_key.pop(flow.key.text(), None)
        token = self.pending_by_flow.pop(flow_id, None)
        if token is not None:
            self.pending.pop(token, None)
            self.settled_tokens[token] = "INVALIDATED"
        self.cache.pop(flow_id, None)
        self._inc("flow_closed")
        self._record("close-flow", flow_id=flow_id)

    def teardown(self) -> None:
        if not self.running:
            return
        self._owner_turn("teardown")
        self.running = False
        self.generation += 1
        self._invalidate_scope("teardown")
        for flow_id in list(self.flows):
            self.close_flow(flow_id)
        self.pending.clear()
        self.pending_by_flow.clear()
        self.cache.clear()
        self.active_by_key.clear()
        self._inc("teardowns")
        self._record("teardown-complete")

    def live_resources(self) -> dict[str, int]:
        return {
            "active_flows": len(self.flows),
            "pending_requests": len(self.pending),
            "cache_entries": len(self.cache),
            "residue": len(self.flows) + len(self.pending) + len(self.cache),
        }

    def view(self, *, include_history: bool = False) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema": PROTOTYPE_SCHEMA,
            "running": self.running,
            "provider_available": self.provider_available,
            "clock": self.clock,
            "generation": self.generation,
            "network_epoch": self.network_epoch,
            "app_epoch": self.app_epoch,
            "bounds": {
                "worker_count": self.worker_count,
                "pending_capacity": self.pending_capacity,
                "cache_capacity": self.cache_capacity,
                "cache_ttl": self.cache_ttl,
            },
            "counters": dict(self.counters),
            "live_resources": self.live_resources(),
            "flows": {
                str(flow_id): flow.as_dict()
                for flow_id, flow in sorted(self.flows.items())
            },
            "pending": {
                str(token): request.identity()
                for token, request in self.pending.items()
            },
            "cache": {
                str(flow_id): entry.as_dict()
                for flow_id, entry in self.cache.items()
            },
        }
        if include_history:
            result["history"] = list(self.history)
        return result


def completion_variants(
    model: AttributionModel, token: int, uid: int
) -> Iterable[LookupCompletion]:
    """Convenience for a cell that needs all identity variants."""

    request = model.request(token)
    yield model.completion(token, uid, owner=(request.owner + 1) % model.worker_count)
    yield model.completion(token, uid, generation=request.generation - 1)
    yield model.completion(token, uid)
