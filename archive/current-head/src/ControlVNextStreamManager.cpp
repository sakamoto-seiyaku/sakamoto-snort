/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextStreamManager.hpp>

#include <algorithm>
#include <utility>

namespace {

[[nodiscard]] timespec nowUtc() noexcept {
    timespec ts{};
    timespec_get(&ts, TIME_UTC);
    return ts;
}

template <class Event>
[[nodiscard]] bool inHorizon(const Event &event, const timespec now, const std::uint32_t horizonSec) noexcept {
    if (horizonSec == 0) {
        return false;
    }
    const std::time_t delta = now.tv_sec - event.timestamp.tv_sec;
    return delta < static_cast<std::time_t>(horizonSec);
}

} // namespace

ControlVNextStreamManager controlVNextStream(ControlVNextStreamManager::Caps{
    .maxHorizonSec = 300,
    .maxRingEvents = 256,
    .maxPendingEvents = 256,
});

ControlVNextStreamManager::ControlVNextStreamManager(const Caps caps) : _caps(caps) {
    _activity.lastBlockEnabled.store(false, std::memory_order_relaxed);
}

void ControlVNextStreamManager::clampStartParams(const Caps &caps, std::uint32_t &horizonSec,
                                                 std::uint32_t &minSize) {
    horizonSec = std::min(horizonSec, caps.maxHorizonSec);
    minSize = std::min(minSize, caps.maxRingEvents);
}

template <class Event>
void ControlVNextStreamManager::pushRing(std::deque<Event> &ring, const std::uint32_t maxRingEvents,
                                         Event &&event) {
    ring.push_back(std::move(event));
    while (ring.size() > maxRingEvents) {
        ring.pop_front();
    }
}

template <class Event>
void ControlVNextStreamManager::pushPending(std::deque<Event> &pending, const std::uint32_t maxPendingEvents,
                                            std::atomic<std::uint64_t> &droppedEvents, Event &&event) {
    pending.push_back(std::move(event));
    while (pending.size() > maxPendingEvents) {
        pending.pop_front();
        droppedEvents.fetch_add(1, std::memory_order_relaxed);
    }
}

std::uint32_t ControlVNextStreamManager::replayStartIndexForUnion(const std::deque<DnsEvent> &ring,
                                                                  const timespec now,
                                                                  const std::uint32_t horizonSec,
                                                                  const std::uint32_t minSize) {
    const std::uint32_t n = static_cast<std::uint32_t>(ring.size());
    const std::uint32_t minSizeStart = (minSize == 0) ? n : (minSize >= n ? 0u : (n - minSize));

    std::uint32_t horizonStart = n;
    if (horizonSec != 0) {
        for (std::uint32_t i = 0; i < n; ++i) {
            if (inHorizon(ring[i], now, horizonSec)) {
                horizonStart = i;
                break;
            }
        }
    }

    return std::min(minSizeStart, horizonStart);
}

std::uint32_t ControlVNextStreamManager::replayStartIndexForUnion(const std::deque<PktEvent> &ring,
                                                                  const timespec now,
                                                                  const std::uint32_t horizonSec,
                                                                  const std::uint32_t minSize) {
    const std::uint32_t n = static_cast<std::uint32_t>(ring.size());
    const std::uint32_t minSizeStart = (minSize == 0) ? n : (minSize >= n ? 0u : (n - minSize));

    std::uint32_t horizonStart = n;
    if (horizonSec != 0) {
        for (std::uint32_t i = 0; i < n; ++i) {
            if (inHorizon(ring[i], now, horizonSec)) {
                horizonStart = i;
                break;
            }
        }
    }

    return std::min(minSizeStart, horizonStart);
}

bool ControlVNextStreamManager::start(void *sessionKey, const StartParams &params, StartResult &out) {
    if (params.type == Type::Dns) {
        std::uint32_t horizon = params.horizonSec;
        std::uint32_t minSize = params.minSize;
        clampStartParams(_caps, horizon, minSize);
        out.effectiveHorizonSec = horizon;
        out.effectiveMinSize = minSize;

        const timespec now = nowUtc();

        const std::lock_guard lock(_dns.mutex);
        if (_dns.subscriber != nullptr && _dns.subscriber != sessionKey) {
            return false;
        }

        _dns.subscriber = sessionKey;
        _dns.pending.clear();
        _dns.droppedEvents.store(0, std::memory_order_relaxed);
        _dns.suppressedTraffic.reset();
        _dns.subscribed.store(true, std::memory_order_release);

        const std::uint32_t startIdx = replayStartIndexForUnion(_dns.ring, now, horizon, minSize);
        for (std::uint32_t i = startIdx; i < _dns.ring.size(); ++i) {
            pushPending(_dns.pending, _caps.maxPendingEvents, _dns.droppedEvents, DnsEvent(_dns.ring[i]));
        }
        return true;
    }

    if (params.type == Type::Pkt) {
        std::uint32_t horizon = params.horizonSec;
        std::uint32_t minSize = params.minSize;
        clampStartParams(_caps, horizon, minSize);
        out.effectiveHorizonSec = horizon;
        out.effectiveMinSize = minSize;

        const timespec now = nowUtc();

        const std::lock_guard lock(_pkt.mutex);
        if (_pkt.subscriber != nullptr && _pkt.subscriber != sessionKey) {
            return false;
        }

        _pkt.subscriber = sessionKey;
        _pkt.pending.clear();
        _pkt.droppedEvents.store(0, std::memory_order_relaxed);
        _pkt.suppressedTraffic.reset();
        _pkt.subscribed.store(true, std::memory_order_release);

        const std::uint32_t startIdx = replayStartIndexForUnion(_pkt.ring, now, horizon, minSize);
        for (std::uint32_t i = startIdx; i < _pkt.ring.size(); ++i) {
            pushPending(_pkt.pending, _caps.maxPendingEvents, _pkt.droppedEvents, PktEvent(_pkt.ring[i]));
        }
        return true;
    }

    if (params.type == Type::Activity) {
        out.effectiveHorizonSec = 0;
        out.effectiveMinSize = 0;

        const ActivityEvent ev{
            .timestamp = nowUtc(),
            .blockEnabled = params.blockEnabled,
        };

        const std::lock_guard lock(_activity.mutex);
        if (_activity.subscriber != nullptr && _activity.subscriber != sessionKey) {
            return false;
        }
        _activity.subscriber = sessionKey;
        _activity.subscribed.store(true, std::memory_order_release);
        _activity.pending.clear();
        _activity.lastBlockEnabled.store(params.blockEnabled, std::memory_order_relaxed);
        _activity.pending.push_back(ActivityEvent(ev));
        while (_activity.pending.size() > _caps.maxPendingEvents) {
            _activity.pending.pop_front();
        }
        return true;
    }

    return false;
}

void ControlVNextStreamManager::stop(void *sessionKey) {
    {
        const std::lock_guard lock(_dns.mutex);
        if (_dns.subscriber == sessionKey) {
            _dns.subscriber = nullptr;
            _dns.subscribed.store(false, std::memory_order_release);
            _dns.pending.clear();
            _dns.ring.clear();
            _dns.droppedEvents.store(0, std::memory_order_relaxed);
            _dns.suppressedTraffic.reset();
        }
    }
    {
        const std::lock_guard lock(_pkt.mutex);
        if (_pkt.subscriber == sessionKey) {
            _pkt.subscriber = nullptr;
            _pkt.subscribed.store(false, std::memory_order_release);
            _pkt.pending.clear();
            _pkt.ring.clear();
            _pkt.droppedEvents.store(0, std::memory_order_relaxed);
            _pkt.suppressedTraffic.reset();
        }
    }
    {
        const std::lock_guard lock(_activity.mutex);
        if (_activity.subscriber == sessionKey) {
            _activity.subscriber = nullptr;
            _activity.subscribed.store(false, std::memory_order_release);
            _activity.pending.clear();
        }
    }
}

void ControlVNextStreamManager::detach(void *sessionKey) {
    {
        const std::lock_guard lock(_dns.mutex);
        if (_dns.subscriber == sessionKey) {
            _dns.subscriber = nullptr;
            _dns.subscribed.store(false, std::memory_order_release);
            _dns.pending.clear();
            _dns.droppedEvents.store(0, std::memory_order_relaxed);
            _dns.suppressedTraffic.reset();
        }
    }
    {
        const std::lock_guard lock(_pkt.mutex);
        if (_pkt.subscriber == sessionKey) {
            _pkt.subscriber = nullptr;
            _pkt.subscribed.store(false, std::memory_order_release);
            _pkt.pending.clear();
            _pkt.droppedEvents.store(0, std::memory_order_relaxed);
            _pkt.suppressedTraffic.reset();
        }
    }
    {
        const std::lock_guard lock(_activity.mutex);
        if (_activity.subscriber == sessionKey) {
            _activity.subscriber = nullptr;
            _activity.subscribed.store(false, std::memory_order_release);
            _activity.pending.clear();
        }
    }
}

void ControlVNextStreamManager::resetAll() {
    {
        const std::lock_guard lock(_dns.mutex);
        _dns.subscriber = nullptr;
        _dns.subscribed.store(false, std::memory_order_release);
        _dns.pending.clear();
        _dns.ring.clear();
        _dns.droppedEvents.store(0, std::memory_order_relaxed);
        _dns.suppressedTraffic.reset();
    }
    {
        const std::lock_guard lock(_pkt.mutex);
        _pkt.subscriber = nullptr;
        _pkt.subscribed.store(false, std::memory_order_release);
        _pkt.pending.clear();
        _pkt.ring.clear();
        _pkt.droppedEvents.store(0, std::memory_order_relaxed);
        _pkt.suppressedTraffic.reset();
    }
    {
        const std::lock_guard lock(_activity.mutex);
        _activity.subscriber = nullptr;
        _activity.subscribed.store(false, std::memory_order_release);
        _activity.pending.clear();
    }
}

bool ControlVNextStreamManager::ownsSubscription(void *sessionKey, const Type type) {
    if (type == Type::Dns) {
        const std::lock_guard lock(_dns.mutex);
        return _dns.subscriber == sessionKey && _dns.subscribed.load(std::memory_order_acquire);
    }
    if (type == Type::Pkt) {
        const std::lock_guard lock(_pkt.mutex);
        return _pkt.subscriber == sessionKey && _pkt.subscribed.load(std::memory_order_acquire);
    }
    const std::lock_guard lock(_activity.mutex);
    return _activity.subscriber == sessionKey && _activity.subscribed.load(std::memory_order_acquire);
}

std::optional<ControlVNextStreamManager::DnsEvent>
ControlVNextStreamManager::popDnsPending(void *sessionKey) {
    const std::lock_guard lock(_dns.mutex);
    if (_dns.subscriber != sessionKey || _dns.pending.empty()) {
        return std::nullopt;
    }
    DnsEvent ev = std::move(_dns.pending.front());
    _dns.pending.pop_front();
    return ev;
}

std::optional<ControlVNextStreamManager::PktEvent>
ControlVNextStreamManager::popPktPending(void *sessionKey) {
    const std::lock_guard lock(_pkt.mutex);
    if (_pkt.subscriber != sessionKey || _pkt.pending.empty()) {
        return std::nullopt;
    }
    PktEvent ev = std::move(_pkt.pending.front());
    _pkt.pending.pop_front();
    return ev;
}

std::optional<ControlVNextStreamManager::ActivityEvent>
ControlVNextStreamManager::popActivityPending(void *sessionKey) {
    const std::lock_guard lock(_activity.mutex);
    if (_activity.subscriber != sessionKey || _activity.pending.empty()) {
        return std::nullopt;
    }
    ActivityEvent ev = std::move(_activity.pending.front());
    _activity.pending.pop_front();
    return ev;
}

TrafficSnapshot ControlVNextStreamManager::takeSuppressedTraffic(const Type type) {
    if (type == Type::Dns) {
        return _dns.suppressedTraffic.takeAndReset();
    }
    if (type == Type::Pkt) {
        return _pkt.suppressedTraffic.takeAndReset();
    }
    TrafficSnapshot empty{};
    return empty;
}

std::uint64_t ControlVNextStreamManager::takeDroppedEvents(const Type type) {
    if (type == Type::Dns) {
        return _dns.droppedEvents.exchange(0, std::memory_order_relaxed);
    }
    if (type == Type::Pkt) {
        return _pkt.droppedEvents.exchange(0, std::memory_order_relaxed);
    }
    return 0;
}

void ControlVNextStreamManager::observeDnsTracked(DnsEvent event) {
    const std::lock_guard lock(_dns.mutex);
    pushRing(_dns.ring, _caps.maxRingEvents, DnsEvent(event));
    if (_dns.subscribed.load(std::memory_order_acquire)) {
        pushPending(_dns.pending, _caps.maxPendingEvents, _dns.droppedEvents, std::move(event));
    }
}

void ControlVNextStreamManager::observeDnsSuppressed(const bool blocked) noexcept {
    if (!_dns.subscribed.load(std::memory_order_acquire)) {
        return;
    }
    _dns.suppressedTraffic.observeDns(blocked);
}

void ControlVNextStreamManager::observePktTracked(PktEvent event) {
    const std::lock_guard lock(_pkt.mutex);
    pushRing(_pkt.ring, _caps.maxRingEvents, PktEvent(event));
    if (_pkt.subscribed.load(std::memory_order_acquire)) {
        pushPending(_pkt.pending, _caps.maxPendingEvents, _pkt.droppedEvents, std::move(event));
    }
}

void ControlVNextStreamManager::observePktSuppressed(const bool input, const bool accepted,
                                                     const std::uint64_t bytes) noexcept {
    if (!_pkt.subscribed.load(std::memory_order_acquire)) {
        return;
    }
    _pkt.suppressedTraffic.observePacket(input, accepted, bytes);
}

void ControlVNextStreamManager::observeBlockEnabled(const bool enabled) {
    _activity.lastBlockEnabled.store(enabled, std::memory_order_relaxed);
    if (!_activity.subscribed.load(std::memory_order_acquire)) {
        return;
    }

    ActivityEvent ev{.timestamp = nowUtc(), .blockEnabled = enabled};
    const std::lock_guard lock(_activity.mutex);
    if (_activity.subscriber == nullptr) {
        return;
    }
    _activity.pending.push_back(ActivityEvent(ev));
    while (_activity.pending.size() > _caps.maxPendingEvents) {
        _activity.pending.pop_front();
    }
}
