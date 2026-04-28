/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <DomainPolicySources.hpp>
#include <L4ParseResult.hpp>
#include <PacketReasons.hpp>
#include <TrafficCounters.hpp>

#include <atomic>
#include <array>
#include <ctime>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>

class Domain;
class Host;

class ControlVNextStreamManager {
public:
    enum class Type : std::uint8_t {
        Dns,
        Pkt,
        Activity,
    };

    struct Caps {
        std::uint32_t maxHorizonSec = 0;
        std::uint32_t maxRingEvents = 0;
        std::uint32_t maxPendingEvents = 0;
    };

    struct StartParams {
        Type type;
        std::uint32_t horizonSec = 0;
        std::uint32_t minSize = 0;
        bool blockEnabled = false; // used only by activity to emit initial snapshot
    };

    struct StartResult {
        std::uint32_t effectiveHorizonSec = 0;
        std::uint32_t effectiveMinSize = 0;
    };

    struct DnsEvent {
        timespec timestamp{};
        std::uint32_t uid = 0;
        std::uint32_t userId = 0;
        std::shared_ptr<const std::string> app;
        std::shared_ptr<Domain> domain;
        std::uint32_t domMask = 0;
        std::uint32_t appMask = 0;
        bool blocked = false;
        bool getips = false;
        bool useCustomList = false;
        DomainPolicySource policySource = DomainPolicySource::MASK_FALLBACK;
        std::optional<std::uint32_t> ruleId;
    };

    struct PktEvent {
        timespec timestamp{};
        std::uint32_t uid = 0;
        std::uint32_t userId = 0;
        std::shared_ptr<const std::string> app;
        std::shared_ptr<Host> host;
        std::array<std::uint8_t, 16> srcIp{};
        std::array<std::uint8_t, 16> dstIp{};
        std::uint32_t ifindex = 0;
        std::uint16_t proto = 0;
        L4Status l4Status = L4Status::KNOWN_L4;
        std::uint16_t srcPort = 0;
        std::uint16_t dstPort = 0;
        std::uint16_t length = 0;
        std::uint8_t ipVersion = 0;
        std::uint8_t ifaceKindBit = 0;
        bool input = false;
        bool accepted = false;
        PacketReasonId reasonId = PacketReasonId::ALLOW_DEFAULT;
        std::optional<std::uint32_t> ruleId;
        std::optional<std::uint32_t> wouldRuleId;
    };

    struct ActivityEvent {
        timespec timestamp{};
        bool blockEnabled = false;
    };

    explicit ControlVNextStreamManager(Caps caps);

    ControlVNextStreamManager(const ControlVNextStreamManager &) = delete;
    ControlVNextStreamManager &operator=(const ControlVNextStreamManager &) = delete;

    const Caps &caps() const noexcept { return _caps; }

    // Returns false on STATE_CONFLICT (another subscriber already active for the stream type).
    bool start(void *sessionKey, const StartParams &params, StartResult &out);

    // Idempotent: only affects the calling session if it owns the subscription.
    void stop(void *sessionKey);

    // Detach a session (connection closed). Releases any owned subscription but does not clear ring.
    void detach(void *sessionKey);

    // Force-stop all subscriptions and clear all stream state. Owning sessions observe cancellation
    // and close their own sockets.
    void resetAll();

    // Returns true only while the calling session still owns the active subscription.
    bool ownsSubscription(void *sessionKey, Type type);

    // Pop next pending event for a subscribed session.
    std::optional<DnsEvent> popDnsPending(void *sessionKey);
    std::optional<PktEvent> popPktPending(void *sessionKey);
    std::optional<ActivityEvent> popActivityPending(void *sessionKey);

    // Notice aggregation helpers (per-type counters since last snapshot).
    [[nodiscard]] TrafficSnapshot takeSuppressedTraffic(Type type);
    [[nodiscard]] std::uint64_t takeDroppedEvents(Type type);

    // Dataplane hooks (hot-path safe).
    void observeDnsTracked(DnsEvent event);
    void observeDnsSuppressed(const bool blocked) noexcept;

    void observePktTracked(PktEvent event);
    void observePktSuppressed(const bool input, const bool accepted, const std::uint64_t bytes) noexcept;

    void observeBlockEnabled(const bool enabled);

private:
    struct DnsState {
        std::mutex mutex;
        void *subscriber = nullptr;
        std::deque<DnsEvent> ring;
        std::deque<DnsEvent> pending;
        std::atomic_bool subscribed{false};
        TrafficCounters suppressedTraffic;
        std::atomic<std::uint64_t> droppedEvents{0};
    };

    struct PktState {
        std::mutex mutex;
        void *subscriber = nullptr;
        std::deque<PktEvent> ring;
        std::deque<PktEvent> pending;
        std::atomic_bool subscribed{false};
        TrafficCounters suppressedTraffic;
        std::atomic<std::uint64_t> droppedEvents{0};
    };

    struct ActivityState {
        std::mutex mutex;
        void *subscriber = nullptr;
        std::deque<ActivityEvent> pending;
        std::atomic_bool subscribed{false};
        std::atomic_bool lastBlockEnabled{false};
    };

    static void clampStartParams(const Caps &caps, std::uint32_t &horizonSec, std::uint32_t &minSize);

    template <class Event>
    static void pushRing(std::deque<Event> &ring, const std::uint32_t maxRingEvents, Event &&event);

    template <class Event>
    static void pushPending(std::deque<Event> &pending, const std::uint32_t maxPendingEvents,
                            std::atomic<std::uint64_t> &droppedEvents, Event &&event);

    static std::uint32_t replayStartIndexForUnion(const std::deque<DnsEvent> &ring, const timespec now,
                                                  const std::uint32_t horizonSec,
                                                  const std::uint32_t minSize);
    static std::uint32_t replayStartIndexForUnion(const std::deque<PktEvent> &ring, const timespec now,
                                                  const std::uint32_t horizonSec,
                                                  const std::uint32_t minSize);

    Caps _caps;
    DnsState _dns;
    PktState _pkt;
    ActivityState _activity;
};

extern ControlVNextStreamManager controlVNextStream;
