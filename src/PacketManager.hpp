/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <AppManager.hpp>
#include <Conntrack.hpp>
#include <ControlVNextStreamManager.hpp>
#include <HostManager.hpp>
#include <IpRulesEngine.hpp>
#include <Packet.hpp>
#include <ReasonMetrics.hpp>
#include <Streamable.hpp>

#include <atomic>
#include <cstring>
#include <memory>
#include <mutex>
#include <type_traits>
#include <vector>

class PacketManager : public Streamable<Packet<IPv4>>, Streamable<Packet<IPv6>> {
private:
    enum IfaceBit : uint8_t { NONE = 0, WIFI = 1, DATA = 2, VPN = 4, UNMANAGED = 128 };

    // Hot-path data: snapshot of interface bits.
    // Accessed via atomic_load/store_explicit on the pointer value for portability.
    // Readers only load this pointer and perform bounds-check; no locks or writes on hot path.
    std::shared_ptr<std::vector<uint8_t>> _ifaceSnap;
    // Last refresh timestamp (monotonic ns). Relaxed is fine for best-effort rate limiting.
    std::atomic<long long> _ifaceLastRefreshNs{0};
    // Serialize refresh work; never taken on the hot path except via try_lock.
    std::mutex _ifaceRefreshMutex;
    // Cooldown to rate-limit refresh attempts from the hot path.
    static constexpr long long kIfaceRefreshCooldownNs = 200LL * 1000 * 1000; // 200 ms
    // Optional passive (very low frequency) refresh period.
    static constexpr long long kIfacePassiveRefreshNs = 30LL * 1000 * 1000 * 1000; // 30 s

    ReasonMetrics _reasonMetrics;
    IpRulesEngine _ipRules;
    Conntrack _conntrack;

public:
    PacketManager();

    ~PacketManager();

    PacketManager(const PacketManager &) = delete;

    template <class IP>
    bool make(const Address<IP> &srcIp, const Address<IP> &dstIp, const App::Ptr &app,
              const Host::Ptr &host,
              const bool input, const uint32_t iface, const timespec timestamp, const int proto,
              const uint16_t srcPort, const uint16_t dstPort, const uint16_t len,
              const uint8_t ifaceKindBit, const bool ifaceBlockedSnapshot,
              const Conntrack::PacketV4 *ctPktV4 = nullptr,
              ControlVNextStreamManager::PktEvent *streamEventOut = nullptr,
              bool *trackedSnapshotOut = nullptr);

    void reset();

    void save() { _ipRules.save(); }

    void restore() { _ipRules.restore(); }

    IpRulesEngine &ipRules() { return _ipRules; }

    const IpRulesEngine &ipRules() const { return _ipRules; }

    void startStream(const SocketIO::Ptr sockio, const bool pretty, const uint32_t horizon,
                     const std::uint32_t minSize);

    void stopStream(const SocketIO::Ptr sockio);

    ReasonMetrics::Snapshot reasonMetricsSnapshot() const { return _reasonMetrics.snapshot(); }

    void resetReasonMetrics() { _reasonMetrics.reset(); }

    Conntrack::MetricsSnapshot conntrackMetricsSnapshot() const noexcept { return _conntrack.metricsSnapshot(); }

    // Hot-path safe: uses the existing interface kind snapshot and best-effort refresh.
    uint8_t ifaceKindBit(const uint32_t ifindex) { return ifaceBit(ifindex); }

private:
    // Rebuild snapshot from current system state and publish atomically.
    void refreshIfaces();
    // Monotonic clock in nanoseconds.
    static long long monotonicNs();

    uint8_t ifaceBit(const uint32_t iface);

public:
    // Public helpers (not used on hot path) to prime/maintain snapshot.
    // Safe to call from non-critical threads.
    void refreshIfacesPassive();  // low-frequency best-effort refresh
    void refreshIfacesOnce();     // unconditional refresh
};

template <class IP>
bool PacketManager::make(const Address<IP> &srcIp, const Address<IP> &dstIp, const App::Ptr &app,
                         const Host::Ptr &host, const bool input, const uint32_t iface,
                         const timespec timestamp, const int proto, const uint16_t srcPort,
                         const uint16_t dstPort, const uint16_t len, const uint8_t ifaceKindBit,
                         const bool ifaceBlockedSnapshot, const Conntrack::PacketV4 *ctPktV4,
                         ControlVNextStreamManager::PktEvent *streamEventOut,
                         bool *trackedSnapshotOut) {
    const bool trackedSnapshot = app->tracked();
    if (trackedSnapshotOut != nullptr) {
        *trackedSnapshotOut = trackedSnapshot;
    }

    const auto fillStreamEvent = [&](const bool accepted, const PacketReasonId reason,
                                     const std::optional<uint32_t> ruleId,
                                     const std::optional<uint32_t> wouldRuleId) {
        if (!trackedSnapshot || streamEventOut == nullptr) {
            return;
        }
        ControlVNextStreamManager::PktEvent ev{};
        ev.timestamp = timestamp;
        ev.uid = app->uid();
        ev.userId = app->userId();
        ev.app = app->nameSnapshot();
        ev.host = host;
        std::memset(ev.srcIp.data(), 0, ev.srcIp.size());
        std::memset(ev.dstIp.data(), 0, ev.dstIp.size());
        if constexpr (std::is_same_v<IP, IPv4>) {
            std::memcpy(ev.srcIp.data(), srcIp.data(), 4);
            std::memcpy(ev.dstIp.data(), dstIp.data(), 4);
            ev.ipVersion = 4;
        } else {
            std::memcpy(ev.srcIp.data(), srcIp.data(), 16);
            std::memcpy(ev.dstIp.data(), dstIp.data(), 16);
            ev.ipVersion = 6;
        }
        ev.ifindex = iface;
        ev.proto = static_cast<std::uint16_t>(proto);
        ev.srcPort = srcPort;
        ev.dstPort = dstPort;
        ev.length = len;
        ev.ifaceKindBit = ifaceKindBit;
        ev.input = input;
        ev.accepted = accepted;
        ev.reasonId = reason;
        ev.ruleId = ruleId;
        ev.wouldRuleId = wouldRuleId;
        *streamEventOut = std::move(ev);
    };

    const bool ifaceBlockedNow = (app->blockIface() & ifaceKindBit) != 0;
    const bool ifaceBlocked = ifaceBlockedSnapshot || ifaceBlockedNow;
    const uint64_t tsNs =
        static_cast<uint64_t>(timestamp.tv_sec) * 1000000000ULL + static_cast<uint64_t>(timestamp.tv_nsec);

    std::optional<uint32_t> ruleId = std::nullopt;
    std::optional<uint32_t> wouldRuleId = std::nullopt;
    std::optional<Conntrack::PolicyView> ctPolicyView = std::nullopt;
    [[maybe_unused]] bool hasWouldDecision = false;
    [[maybe_unused]] IpRulesEngine::Decision wouldDecision{};

    // 1) Highest priority hard-drop: IFACE_BLOCK.
    if (ifaceBlocked) {
        const bool verdict = false;
        const PacketReasonId reasonId = PacketReasonId::IFACE_BLOCK;
        _reasonMetrics.observe(reasonId, len);
        app->observeTrafficPacket(input, verdict, len);

        if (trackedSnapshot) {
            // IFACE_BLOCK is independent of domain policy; keep stats minimally attributed.
            appManager.updateStats(nullptr, app, true, Stats::GREY, input ? Stats::RXP : Stats::TXP, 1);
            appManager.updateStats(nullptr, app, true, Stats::GREY, input ? Stats::RXB : Stats::TXB, len);
        }

        fillStreamEvent(verdict, reasonId, ruleId, wouldRuleId);
        if (trackedSnapshot) {
            Streamable<Packet<IP>>::stream(std::make_shared<Packet<IP>>(
                srcIp, dstIp, host, app, input, iface, timestamp, proto, srcPort, dstPort, len,
                verdict, reasonId, ruleId, wouldRuleId));
        }
        return verdict;
    }

    // 2) IPv4-only fast path: IPRULES (exact cache -> classifier snapshot).
    if constexpr (std::is_same_v<IP, IPv4>) {
        if (settings.ipRulesEnabled()) {
            auto v4HostFromNetBytes = [](const uint8_t *b) -> uint32_t {
                return (static_cast<uint32_t>(b[0]) << 24) | (static_cast<uint32_t>(b[1]) << 16) |
                       (static_cast<uint32_t>(b[2]) << 8) | static_cast<uint32_t>(b[3]);
            };

            IpRulesEngine::PacketKeyV4 k{};
            k.uid = app->uid();
            k.dir = input ? 0 : 1;
            k.ifaceKind = ifaceKindBit;
            k.proto = static_cast<uint8_t>(proto);
            k.ifindex = iface;
            k.srcIp = v4HostFromNetBytes(srcIp.data());
            k.dstIp = v4HostFromNetBytes(dstIp.data());
            k.srcPort = srcPort;
            k.dstPort = dstPort;

            const auto snap = _ipRules.hotSnapshot();
            if (snap.valid()) {
                const std::uint64_t epoch = snap.rulesEpoch();
                if (epoch != 0) {
                    const auto cached = app->ipRulesUsesCtIfFresh(epoch);
                    const bool usesCt =
                        cached.has_value() ? *cached : snap.uidUsesCt(app->uid());
                    if (!cached.has_value()) {
                        app->setIpRulesUsesCtCache(epoch, usesCt);
                    }
                    if (usesCt) {
                        if (ctPktV4 != nullptr) {
                            ctPolicyView = _conntrack.inspectForPolicy(*ctPktV4);
                            k.ctState = static_cast<std::uint8_t>(ctPolicyView->result.state);
                            k.ctDir = static_cast<std::uint8_t>(ctPolicyView->result.direction);
                        } else {
                            k.ctState = static_cast<std::uint8_t>(IpRulesEngine::CtState::INVALID);
                            k.ctDir = 0;
                        }
                    }
                }
            }

            const auto decision = snap.evaluate(k);

            if (decision.kind == IpRulesEngine::DecisionKind::ALLOW ||
                decision.kind == IpRulesEngine::DecisionKind::BLOCK) {
                const bool verdict = (decision.kind == IpRulesEngine::DecisionKind::ALLOW);
                const PacketReasonId reasonId =
                    verdict ? PacketReasonId::IP_RULE_ALLOW : PacketReasonId::IP_RULE_BLOCK;
                ruleId = decision.ruleId;

                if (verdict && ctPolicyView.has_value() && ctPktV4 != nullptr) {
                    _conntrack.commitAccepted(*ctPktV4, *ctPolicyView);
                }

                IpRulesEngine::observeEnforceHit(decision, static_cast<uint32_t>(len), tsNs);
                _reasonMetrics.observe(reasonId, len);
                app->observeTrafficPacket(input, verdict, len);

                if (trackedSnapshot) {
                    appManager.updateStats(nullptr, app, !verdict, Stats::GREY,
                                           input ? Stats::RXP : Stats::TXP, 1);
                    appManager.updateStats(nullptr, app, !verdict, Stats::GREY,
                                           input ? Stats::RXB : Stats::TXB, len);
                }

                fillStreamEvent(verdict, reasonId, ruleId, std::nullopt);
                if (trackedSnapshot) {
                    Streamable<Packet<IP>>::stream(std::make_shared<Packet<IP>>(
                        srcIp, dstIp, host, app, input, iface, timestamp, proto, srcPort, dstPort, len,
                        verdict, reasonId, ruleId, std::nullopt));
                }
                return verdict;
            }

            if (decision.kind == IpRulesEngine::DecisionKind::WOULD_BLOCK) {
                hasWouldDecision = true;
                wouldDecision = decision;
            }
        }
    }

    // 3) Legacy/domain path (unchanged semantics).
    auto domain = host->domain();
    const auto validIP = domain != nullptr && domain->validIP();
    if (!validIP) {
        domain = nullptr;
    }

    const auto [blocked, cs] = app->blocked(domain);
    const bool ipLeakBlocked = settings.blockIPLeaks() && blocked && validIP;
    const bool verdict = !ipLeakBlocked;
    const PacketReasonId reasonId = ipLeakBlocked ? PacketReasonId::IP_LEAK_BLOCK
                                                  : PacketReasonId::ALLOW_DEFAULT;

    if constexpr (std::is_same_v<IP, IPv4>) {
        if (verdict && ctPolicyView.has_value() && ctPktV4 != nullptr) {
            _conntrack.commitAccepted(*ctPktV4, *ctPolicyView);
        }
    }

    // Would-match overlay: emit only if final verdict is ACCEPT.
    if constexpr (std::is_same_v<IP, IPv4>) {
        if (hasWouldDecision && verdict) {
            wouldRuleId = wouldDecision.ruleId;
            IpRulesEngine::observeWouldHitIfAccepted(wouldDecision, true, static_cast<uint32_t>(len), tsNs);
        }
    }

    _reasonMetrics.observe(reasonId, len);
    app->observeTrafficPacket(input, verdict, len);

    if (trackedSnapshot) {
        appManager.updateStats(domain, app, !verdict, cs, input ? Stats::RXP : Stats::TXP, 1);
        appManager.updateStats(domain, app, !verdict, cs, input ? Stats::RXB : Stats::TXB, len);
    }

    fillStreamEvent(verdict, reasonId, ruleId, wouldRuleId);
    if (trackedSnapshot) {
        Streamable<Packet<IP>>::stream(std::make_shared<Packet<IP>>(
            srcIp, dstIp, host, app, input, iface, timestamp, proto, srcPort, dstPort, len, verdict,
            reasonId, ruleId, wouldRuleId));
    }

    return verdict;
}

extern PacketManager pktManager;
