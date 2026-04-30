/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <AppManager.hpp>
#include <Conntrack.hpp>
#include <ControlVNextStreamManager.hpp>
#include <FlowTelemetry.hpp>
#include <HostManager.hpp>
#include <IpRulesEngine.hpp>
#include <L4ParseResult.hpp>
#include <Packet.hpp>
#include <ReasonMetrics.hpp>
#include <Streamable.hpp>

#include <atomic>
#include <cstring>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace PacketManagerExplainDetail {

[[nodiscard]] inline const char *protocolStr(const std::uint16_t proto) noexcept {
    switch (proto) {
    case IPPROTO_TCP:
        return "tcp";
    case IPPROTO_UDP:
        return "udp";
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        return "icmp";
    default:
        return "other";
    }
}

[[nodiscard]] inline const char *l4StatusStr(const L4Status s) noexcept {
    switch (s) {
    case L4Status::KNOWN_L4:
        return "known-l4";
    case L4Status::OTHER_TERMINAL:
        return "other-terminal";
    case L4Status::FRAGMENT:
        return "fragment";
    case L4Status::INVALID_OR_UNAVAILABLE_L4:
        return "invalid-or-unavailable-l4";
    }
    return "invalid-or-unavailable-l4";
}

[[nodiscard]] inline const char *ifaceKindStr(const std::uint8_t bit) noexcept {
    switch (bit) {
    case 1:
        return "wifi";
    case 2:
        return "data";
    case 4:
        return "vpn";
    case 128:
        return "unmanaged";
    default:
        return "unknown";
    }
}

[[nodiscard]] inline const char *ctStateStr(const std::uint8_t state) noexcept {
    switch (static_cast<IpRulesEngine::CtState>(state)) {
    case IpRulesEngine::CtState::ANY:
        return "any";
    case IpRulesEngine::CtState::NEW:
        return "new";
    case IpRulesEngine::CtState::ESTABLISHED:
        return "established";
    case IpRulesEngine::CtState::INVALID:
        return "invalid";
    }
    return "any";
}

[[nodiscard]] inline const char *ctDirectionStr(const std::uint8_t direction) noexcept {
    switch (static_cast<IpRulesEngine::CtDirection>(direction)) {
    case IpRulesEngine::CtDirection::ANY:
        return "any";
    case IpRulesEngine::CtDirection::ORIG:
        return "orig";
    case IpRulesEngine::CtDirection::REPLY:
        return "reply";
    }
    return "any";
}

} // namespace PacketManagerExplainDetail

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
              const bool input, const uint32_t iface, const timespec timestamp,
              const L4ParseResult &l4, const uint16_t len,
              const uint8_t ifaceKindBit, const uint8_t appIfaceMaskSnapshot,
              const Conntrack::PacketV4 *ctPktV4 = nullptr,
              const Conntrack::PacketV6 *ctPktV6 = nullptr,
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
                         const timespec timestamp, const L4ParseResult &l4, const uint16_t len,
                         const uint8_t ifaceKindBit,
                         const uint8_t appIfaceMaskSnapshot, const Conntrack::PacketV4 *ctPktV4,
                         const Conntrack::PacketV6 *ctPktV6,
                         ControlVNextStreamManager::PktEvent *streamEventOut,
                         bool *trackedSnapshotOut) {
    const bool trackedSnapshot = app->tracked();
    if (trackedSnapshotOut != nullptr) {
        *trackedSnapshotOut = trackedSnapshot;
    }
    const auto teleHot = flowTelemetry.hotPathFlow();
    const bool telemetryActive = teleHot.session != nullptr;
    const bool buildExplain = trackedSnapshot && streamEventOut != nullptr;

    std::optional<ControlVNextStreamExplain::PktStageSnapshot> ifaceStage;
    std::optional<ControlVNextStreamExplain::PktStageSnapshot> enforceStage;
    std::optional<ControlVNextStreamExplain::PktStageSnapshot> domainIpLeakStage;
    std::optional<ControlVNextStreamExplain::PktStageSnapshot> wouldStage;
    if (buildExplain) {
        ifaceStage.emplace(ControlVNextStreamExplain::PktStageSnapshot{
            .name = std::string(ControlVNextStreamExplain::kPktStageIfaceBlock),
            .enabled = settings.blockEnabled(),
            .evaluated = true,
            .matched = false,
            .outcome = "allow",
            .winner = false,
        });
        enforceStage.emplace(ControlVNextStreamExplain::PktStageSnapshot{
            .name = std::string(ControlVNextStreamExplain::kPktStageIpRulesEnforce),
            .enabled = settings.ipRulesEnabled(),
            .evaluated = false,
            .matched = false,
            .outcome = "none",
            .winner = false,
        });
        domainIpLeakStage.emplace(ControlVNextStreamExplain::PktStageSnapshot{
            .name = std::string(ControlVNextStreamExplain::kPktStageDomainIpLeak),
            .enabled = settings.blockEnabled(),
            .evaluated = false,
            .matched = false,
            .outcome = "none",
            .winner = false,
        });
        wouldStage.emplace(ControlVNextStreamExplain::PktStageSnapshot{
            .name = std::string(ControlVNextStreamExplain::kPktStageIpRulesWould),
            .enabled = settings.ipRulesEnabled(),
            .evaluated = false,
            .matched = false,
            .outcome = "none",
            .winner = false,
        });
    }
    bool explainCtEvaluated = false;
    std::optional<std::uint8_t> explainCtState;
    std::optional<std::uint8_t> explainCtDir;

    const auto fillPktRuleIds = [](ControlVNextStreamExplain::PktStageSnapshot &stage) {
        stage.ruleIds.reserve(stage.ruleSnapshots.size());
        for (const auto &snapshot : stage.ruleSnapshots) {
            stage.ruleIds.push_back(snapshot.ruleId);
        }
    };

    const auto markPacketStagesShortCircuitedAfter = [&](const std::string_view winningStageName) {
        if (!buildExplain) {
            return;
        }
        bool afterWinner = false;
        for (auto *stage : {&*ifaceStage, &*enforceStage, &*domainIpLeakStage, &*wouldStage}) {
            if (afterWinner && stage->enabled) {
                stage->evaluated = false;
                stage->matched = false;
                stage->winner = false;
                stage->outcome = "none";
                stage->skipReason = std::string(ControlVNextStreamExplain::kSkipShortCircuited);
                stage->ruleIds.clear();
                stage->ruleSnapshots.clear();
                stage->truncated = false;
                stage->omittedCandidateCount.reset();
            } else if (!stage->enabled) {
                stage->skipReason = std::string(ControlVNextStreamExplain::kSkipDisabled);
            }
            if (stage->name == winningStageName) {
                afterWinner = true;
            }
        }
    };

    const auto fillStreamEvent = [&](const bool accepted, const PacketReasonId reason,
                                     const std::optional<uint32_t> ruleId,
                                     const std::optional<uint32_t> wouldRuleId) {
        if (!buildExplain) {
            return;
        }
        for (auto *stage : {&*ifaceStage, &*enforceStage, &*domainIpLeakStage, &*wouldStage}) {
            if (!stage->enabled && !stage->skipReason.has_value()) {
                stage->skipReason = std::string(ControlVNextStreamExplain::kSkipDisabled);
            }
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
        ev.proto = l4.proto;
        ev.l4Status = l4.l4Status;
        ev.srcPort = l4.srcPort;
        ev.dstPort = l4.dstPort;
        ev.length = len;
        ev.ifaceKindBit = ifaceKindBit;
        ev.input = input;
        ev.accepted = accepted;
        ev.reasonId = reason;
        ev.ruleId = ruleId;
        ev.wouldRuleId = wouldRuleId;
        ev.explain = ControlVNextStreamExplain::PktExplainSnapshot{
            .inputs = ControlVNextStreamExplain::PktInputs{
                .blockEnabled = settings.blockEnabled(),
                .iprulesEnabled = settings.ipRulesEnabled(),
                .direction = input ? "in" : "out",
                .ipVersion = ev.ipVersion,
                .protocol = PacketManagerExplainDetail::protocolStr(ev.proto),
                .l4Status = PacketManagerExplainDetail::l4StatusStr(ev.l4Status),
                .ifindex = ev.ifindex,
                .ifaceKindBit = ev.ifaceKindBit,
                .ifaceKind = PacketManagerExplainDetail::ifaceKindStr(ev.ifaceKindBit),
                .conntrackEvaluated = explainCtEvaluated,
                .conntrackState = explainCtState.has_value()
                                      ? std::optional<std::string>(
                                            PacketManagerExplainDetail::ctStateStr(*explainCtState))
                                      : std::nullopt,
                .conntrackDirection = explainCtDir.has_value()
                                           ? std::optional<std::string>(
                                                 PacketManagerExplainDetail::ctDirectionStr(*explainCtDir))
                                           : std::nullopt,
            },
            .final = ControlVNextStreamExplain::PktFinal{
                .accepted = accepted,
                .reasonId = reason,
                .ruleId = ruleId,
                .wouldRuleId = wouldRuleId,
                .wouldDrop = wouldRuleId.has_value(),
            },
            .stages = {*ifaceStage, *enforceStage, *domainIpLeakStage, *wouldStage},
        };
        *streamEventOut = std::move(ev);
    };

    const bool ifaceBlocked = (appIfaceMaskSnapshot & ifaceKindBit) != 0;
    if (buildExplain) {
        ifaceStage->ifaceBlock = ControlVNextStreamExplain::PktIfaceBlockEvidence{
            .appIfaceMask = static_cast<std::uint32_t>(appIfaceMaskSnapshot),
            .packetIfaceKindBit = static_cast<std::uint32_t>(ifaceKindBit),
            .evaluatedIntersection = static_cast<std::uint32_t>(appIfaceMaskSnapshot & ifaceKindBit),
            .packetIfaceKind = PacketManagerExplainDetail::ifaceKindStr(ifaceKindBit),
            .blocked = ifaceBlocked,
            .shortCircuitReason = std::nullopt,
        };
    }
    const uint64_t tsNs =
        static_cast<uint64_t>(timestamp.tv_sec) * 1000000000ULL + static_cast<uint64_t>(timestamp.tv_nsec);

    std::optional<uint32_t> ruleId = std::nullopt;
    std::optional<uint32_t> wouldRuleId = std::nullopt;
    std::optional<Conntrack::PolicyView> ctPolicyView = std::nullopt;
    [[maybe_unused]] bool hasWouldDecision = false;
    [[maybe_unused]] IpRulesEngine::Decision wouldDecision{};

    const auto observeTelemetryFlow = [&](const PacketReasonId reason,
                                          const std::optional<uint32_t> &rid,
                                          const Conntrack::Result &ctRes) noexcept {
        if (!telemetryActive) {
            return;
        }
        if constexpr (std::is_same_v<IP, IPv4>) {
            if (ctPktV4 == nullptr) {
                return;
            }
            const std::span<const std::byte> srcAddrNet(reinterpret_cast<const std::byte *>(srcIp.data()), 4);
            const std::span<const std::byte> dstAddrNet(reinterpret_cast<const std::byte *>(dstIp.data()), 4);
            _conntrack.observeFlowTelemetry(*ctPktV4, ctRes, teleHot, ifaceKindBit, app->userId(),
                                            iface, reason, rid, srcAddrNet, dstAddrNet, len);
        } else {
            if (ctPktV6 == nullptr) {
                return;
            }
            const std::span<const std::byte> srcAddrNet(reinterpret_cast<const std::byte *>(srcIp.data()), 16);
            const std::span<const std::byte> dstAddrNet(reinterpret_cast<const std::byte *>(dstIp.data()), 16);
            _conntrack.observeFlowTelemetry(*ctPktV6, ctRes, teleHot, ifaceKindBit, app->userId(),
                                            iface, reason, rid, srcAddrNet, dstAddrNet, len);
        }
    };

    // 1) Highest priority hard-drop: IFACE_BLOCK.
    if (ifaceBlocked) {
        const bool verdict = false;
        const PacketReasonId reasonId = PacketReasonId::IFACE_BLOCK;
        if (buildExplain) {
            ifaceStage->matched = true;
            ifaceStage->outcome = "block";
            ifaceStage->winner = true;
            ifaceStage->ifaceBlock = ControlVNextStreamExplain::PktIfaceBlockEvidence{
                .appIfaceMask = static_cast<std::uint32_t>(appIfaceMaskSnapshot),
                .packetIfaceKindBit = static_cast<std::uint32_t>(ifaceKindBit),
                .evaluatedIntersection = static_cast<std::uint32_t>(appIfaceMaskSnapshot & ifaceKindBit),
                .packetIfaceKind = PacketManagerExplainDetail::ifaceKindStr(ifaceKindBit),
                .blocked = true,
                .shortCircuitReason = std::string(ControlVNextStreamExplain::kSkipShortCircuited),
            };
        }
        markPacketStagesShortCircuitedAfter(ControlVNextStreamExplain::kPktStageIfaceBlock);
        _reasonMetrics.observe(reasonId, len);
        app->observeTrafficPacket(input, verdict, len);

        if (trackedSnapshot) {
            // IFACE_BLOCK is independent of domain policy; keep stats minimally attributed.
            appManager.updateStats(nullptr, app, true, Stats::GREY, input ? Stats::RXP : Stats::TXP, 1);
            appManager.updateStats(nullptr, app, true, Stats::GREY, input ? Stats::RXB : Stats::TXB, len);
        }

        observeTelemetryFlow(reasonId, /*rid=*/std::nullopt,
                             Conntrack::Result{.state = Conntrack::CtState::INVALID,
                                               .direction = Conntrack::CtDirection::ANY});

        fillStreamEvent(verdict, reasonId, ruleId, wouldRuleId);
        if (trackedSnapshot) {
            Streamable<Packet<IP>>::stream(std::make_shared<Packet<IP>>(
                srcIp, dstIp, host, app, input, iface, timestamp, static_cast<int>(l4.proto),
                l4.srcPort, l4.dstPort, len,
                verdict, reasonId, ruleId, wouldRuleId));
        }
        return verdict;
    }

    // 2) Fast path: IPRULES (exact cache -> classifier snapshot).
    if (settings.ipRulesEnabled()) {
        const auto snap = _ipRules.hotSnapshot();
        if (snap.valid()) {
            constexpr std::uint8_t kUsesCtV4 = 1u << 0;
            constexpr std::uint8_t kUsesCtV6 = 1u << 1;
            const std::uint8_t maskBit = std::is_same_v<IP, IPv4> ? kUsesCtV4 : kUsesCtV6;

            const std::uint64_t epoch = snap.rulesEpoch();
            bool usesCt = false;
            if (epoch != 0) {
                std::uint8_t mask = 0;
                if (const auto cachedMask = app->ipRulesUsesCtMaskIfFresh(epoch); cachedMask.has_value()) {
                    mask = *cachedMask;
                } else {
                    const bool usesCtV4 = snap.uidUsesCt(app->uid(), IpRulesEngine::Family::IPV4);
                    const bool usesCtV6 = snap.uidUsesCt(app->uid(), IpRulesEngine::Family::IPV6);
                    mask = (usesCtV4 ? kUsesCtV4 : 0u) | (usesCtV6 ? kUsesCtV6 : 0u);
                    app->setIpRulesUsesCtMaskCache(epoch, mask);
                }
                usesCt = (mask & maskBit) != 0;
            }
            // Flow Telemetry (level=flow + consumer active) is a conntrack observation consumer.
            usesCt = usesCt || telemetryActive;

            const auto ipRulesProtoTok = [&]() -> std::uint8_t {
                const std::uint16_t p = l4.proto;
                if (p == IPPROTO_TCP) return static_cast<std::uint8_t>(IpRulesEngine::Proto::TCP);
                if (p == IPPROTO_UDP) return static_cast<std::uint8_t>(IpRulesEngine::Proto::UDP);
                if (p == IPPROTO_ICMP || p == IPPROTO_ICMPV6) {
                    return static_cast<std::uint8_t>(IpRulesEngine::Proto::ICMP);
                }
                if (l4.l4Status == L4Status::INVALID_OR_UNAVAILABLE_L4) {
                    return static_cast<std::uint8_t>(IpRulesEngine::Proto::UNKNOWN);
                }
                return static_cast<std::uint8_t>(IpRulesEngine::Proto::OTHER);
            };

            const bool l4AllowsCt =
                l4.l4Status != L4Status::FRAGMENT &&
                l4.l4Status != L4Status::INVALID_OR_UNAVAILABLE_L4;

            IpRulesEngine::Decision decision{};
            const auto captureIpRulesExplain = [&](const auto &key,
                                                   const IpRulesEngine::Decision &capturedDecision) {
                if (!buildExplain) {
                    return;
                }
                auto &enforce = *enforceStage;
                auto &would = *wouldStage;
                enforce.evaluated = true;
                const std::optional<IpRulesEngine::RuleId> enforceWinner =
                    capturedDecision.isEnforce()
                        ? std::optional<IpRulesEngine::RuleId>(capturedDecision.ruleId)
                        : std::nullopt;
                enforce.ruleSnapshots = snap.explainEnforce(
                    key, enforceWinner, enforce.truncated, enforce.omittedCandidateCount);
                fillPktRuleIds(enforce);
                enforce.matched = !enforce.ruleSnapshots.empty();
                if (capturedDecision.kind == IpRulesEngine::DecisionKind::ALLOW) {
                    enforce.outcome = "allow";
                    enforce.winner = true;
                } else if (capturedDecision.kind == IpRulesEngine::DecisionKind::BLOCK) {
                    enforce.outcome = "block";
                    enforce.winner = true;
                } else {
                    enforce.outcome = enforce.matched ? "shadowed" : "none";
                }

                if (capturedDecision.kind == IpRulesEngine::DecisionKind::WOULD_BLOCK) {
                    would.ruleSnapshots = snap.explainWould(
                        key, capturedDecision.ruleId, would.truncated, would.omittedCandidateCount);
                    fillPktRuleIds(would);
                    would.matched = !would.ruleSnapshots.empty();
                    would.outcome = would.matched ? "wouldBlock" : "none";
                }
            };
            if constexpr (std::is_same_v<IP, IPv4>) {
                auto v4HostFromNetBytes = [](const uint8_t *b) -> uint32_t {
                    return (static_cast<uint32_t>(b[0]) << 24) | (static_cast<uint32_t>(b[1]) << 16) |
                           (static_cast<uint32_t>(b[2]) << 8) | static_cast<uint32_t>(b[3]);
                };

                IpRulesEngine::PacketKeyV4 k{};
                k.uid = app->uid();
                k.dir = input ? 0 : 1;
                k.ifaceKind = ifaceKindBit;
                k.proto = ipRulesProtoTok();
                k.ifindex = iface;
                k.srcIp = v4HostFromNetBytes(srcIp.data());
                k.dstIp = v4HostFromNetBytes(dstIp.data());
                k.srcPort = l4.srcPort;
                k.dstPort = l4.dstPort;
                k.portsAvailable = l4.portsAvailable;

                if (usesCt) {
                    if (l4AllowsCt && ctPktV4 != nullptr) {
                        ctPolicyView = _conntrack.inspectForPolicy(*ctPktV4);
                        k.ctState = static_cast<std::uint8_t>(ctPolicyView->result.state);
                        k.ctDir = static_cast<std::uint8_t>(ctPolicyView->result.direction);
                    } else {
                        k.ctState = static_cast<std::uint8_t>(IpRulesEngine::CtState::INVALID);
                        k.ctDir = 0;
                    }
                    explainCtEvaluated = true;
                    explainCtState = k.ctState;
                    explainCtDir = k.ctDir;
                }

                decision = snap.evaluate(k);
                captureIpRulesExplain(k, decision);
            } else {
                IpRulesEngine::PacketKeyV6 k{};
                k.uid = app->uid();
                k.dir = input ? 0 : 1;
                k.ifaceKind = ifaceKindBit;
                k.proto = ipRulesProtoTok();
                k.ifindex = iface;
                std::memcpy(k.srcIp.data(), srcIp.data(), 16);
                std::memcpy(k.dstIp.data(), dstIp.data(), 16);
                k.srcPort = l4.srcPort;
                k.dstPort = l4.dstPort;
                k.portsAvailable = l4.portsAvailable;

                if (usesCt) {
                    if (l4AllowsCt && ctPktV6 != nullptr) {
                        ctPolicyView = _conntrack.inspectForPolicy(*ctPktV6);
                        k.ctState = static_cast<std::uint8_t>(ctPolicyView->result.state);
                        k.ctDir = static_cast<std::uint8_t>(ctPolicyView->result.direction);
                    } else {
                        k.ctState = static_cast<std::uint8_t>(IpRulesEngine::CtState::INVALID);
                        k.ctDir = 0;
                    }
                    explainCtEvaluated = true;
                    explainCtState = k.ctState;
                    explainCtDir = k.ctDir;
                }

                decision = snap.evaluate(k);
                captureIpRulesExplain(k, decision);
            }

            if (decision.kind == IpRulesEngine::DecisionKind::ALLOW ||
                decision.kind == IpRulesEngine::DecisionKind::BLOCK) {
                const bool verdict = (decision.kind == IpRulesEngine::DecisionKind::ALLOW);
                const PacketReasonId reasonId =
                    verdict ? PacketReasonId::IP_RULE_ALLOW : PacketReasonId::IP_RULE_BLOCK;
                ruleId = decision.ruleId;

                if (verdict && ctPolicyView.has_value()) {
                    if constexpr (std::is_same_v<IP, IPv4>) {
                        if (ctPktV4 != nullptr) {
                            _conntrack.commitAccepted(*ctPktV4, *ctPolicyView);
                        }
                    } else {
                        if (ctPktV6 != nullptr) {
                            _conntrack.commitAccepted(*ctPktV6, *ctPolicyView);
                        }
                    }
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

                observeTelemetryFlow(
                    reasonId, ruleId,
                    ctPolicyView.has_value()
                        ? ctPolicyView->result
                        : Conntrack::Result{.state = Conntrack::CtState::INVALID,
                                            .direction = Conntrack::CtDirection::ANY});

                markPacketStagesShortCircuitedAfter(
                    ControlVNextStreamExplain::kPktStageIpRulesEnforce);
                fillStreamEvent(verdict, reasonId, ruleId, std::nullopt);
                if (trackedSnapshot) {
                    Streamable<Packet<IP>>::stream(std::make_shared<Packet<IP>>(
                        srcIp, dstIp, host, app, input, iface, timestamp, static_cast<int>(l4.proto),
                        l4.srcPort, l4.dstPort, len, verdict, reasonId, ruleId, std::nullopt));
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
    if (buildExplain) {
        domainIpLeakStage->evaluated = true;
        domainIpLeakStage->matched = ipLeakBlocked;
        domainIpLeakStage->outcome = ipLeakBlocked ? "block" : "allow";
        domainIpLeakStage->winner = true;
        if (ipLeakBlocked) {
            markPacketStagesShortCircuitedAfter(ControlVNextStreamExplain::kPktStageDomainIpLeak);
        } else if (hasWouldDecision) {
            wouldStage->evaluated = true;
            wouldStage->matched = true;
            wouldStage->outcome = "wouldBlock";
            wouldStage->winner = false;
        } else if (wouldStage->enabled) {
            wouldStage->evaluated = true;
            wouldStage->matched = false;
            wouldStage->outcome = "none";
        } else {
            wouldStage->skipReason = std::string(ControlVNextStreamExplain::kSkipDisabled);
        }
    }

    if (verdict && ctPolicyView.has_value()) {
        if constexpr (std::is_same_v<IP, IPv4>) {
            if (ctPktV4 != nullptr) {
                _conntrack.commitAccepted(*ctPktV4, *ctPolicyView);
            }
        } else {
            if (ctPktV6 != nullptr) {
                _conntrack.commitAccepted(*ctPktV6, *ctPolicyView);
            }
        }
    }

    observeTelemetryFlow(
        reasonId, ruleId,
        ctPolicyView.has_value()
            ? ctPolicyView->result
            : Conntrack::Result{.state = Conntrack::CtState::INVALID, .direction = Conntrack::CtDirection::ANY});

    // Would-match overlay: emit only if final verdict is ACCEPT.
    if (hasWouldDecision && verdict) {
        wouldRuleId = wouldDecision.ruleId;
        IpRulesEngine::observeWouldHitIfAccepted(wouldDecision, true, static_cast<uint32_t>(len), tsNs);
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
            srcIp, dstIp, host, app, input, iface, timestamp, static_cast<int>(l4.proto),
            l4.srcPort, l4.dstPort, len, verdict,
            reasonId, ruleId, wouldRuleId));
    }

    return verdict;
}

extern PacketManager pktManager;
