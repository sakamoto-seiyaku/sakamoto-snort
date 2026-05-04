/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <Conntrack.hpp>

#include <FlowTelemetryRecords.hpp>
#include <L4ParseResult.hpp>

#include <atomic>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <optional>
#include <utility>
#include <vector>

#include <netinet/in.h>
#include <netinet/tcp.h>

namespace {

inline constexpr std::uint64_t kNsPerMs = 1'000'000ULL;

inline bool isBlockReason(const PacketReasonId reason) noexcept {
    switch (reason) {
    case PacketReasonId::IFACE_BLOCK:
    case PacketReasonId::IP_LEAK_BLOCK:
    case PacketReasonId::IP_RULE_BLOCK:
        return true;
    case PacketReasonId::ALLOW_DEFAULT:
    case PacketReasonId::IP_RULE_ALLOW:
        return false;
    }
    return false;
}

inline bool isL3ObservationStatus(const std::uint8_t l4Status) noexcept {
    return l4Status == static_cast<std::uint8_t>(L4Status::FRAGMENT) ||
        l4Status == static_cast<std::uint8_t>(L4Status::INVALID_OR_UNAVAILABLE_L4);
}

inline bool isPickedUpMidStream(const Conntrack::Result &ctResult) noexcept {
    return ctResult.state == Conntrack::CtState::ESTABLISHED ||
        ctResult.direction == Conntrack::CtDirection::REPLY;
}

inline bool isLooseTcpPickup(const Conntrack::PacketV4 &pkt) noexcept {
    return pkt.proto == IPPROTO_TCP && pkt.hasTcp && (pkt.tcp.flags & TH_SYN) == 0;
}

inline bool isLooseTcpPickup(const Conntrack::PacketV6 &pkt) noexcept {
    return pkt.proto == IPPROTO_TCP && pkt.hasTcp && (pkt.tcp.flags & TH_SYN) == 0;
}

inline std::uint64_t packDecisionKey(const std::uint8_t ctState, const std::uint8_t ctDir,
                                     const FlowTelemetryRecords::FlowVerdict verdict,
                                     const PacketReasonId reason, const std::uint8_t ifaceKindBit,
                                     const std::optional<std::uint32_t> &ruleId) noexcept {
    const std::uint32_t rid = ruleId.value_or(0u);
    return static_cast<std::uint64_t>(ctState) |
        (static_cast<std::uint64_t>(ctDir) << 8) |
        (static_cast<std::uint64_t>(static_cast<std::uint8_t>(verdict)) << 16) |
        (static_cast<std::uint64_t>(static_cast<std::uint8_t>(reason)) << 24) |
        (static_cast<std::uint64_t>(ifaceKindBit) << 32) |
        (static_cast<std::uint64_t>(rid & 0xFFFFFFu) << 40);
}

inline std::uint64_t clampCap(const std::uint64_t a, const std::uint64_t b) noexcept {
    if (a == 0) return b;
    if (b == 0) return a;
    return (a < b) ? a : b;
}

inline std::uint64_t addTimeoutMs(const std::uint64_t nowNs, const std::uint32_t ms) noexcept {
    const std::uint64_t d = static_cast<std::uint64_t>(ms) * kNsPerMs;
    if (nowNs > std::numeric_limits<std::uint64_t>::max() - d) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return nowNs + d;
}

class ScopedAtomicBool {
public:
    explicit ScopedAtomicBool(std::atomic<bool> &flag) noexcept : _flag(flag) {
        bool expected = false;
        _locked = _flag.compare_exchange_strong(expected, true, std::memory_order_acquire,
                                                std::memory_order_relaxed);
    }

    ~ScopedAtomicBool() {
        if (_locked) {
            _flag.store(false, std::memory_order_release);
        }
    }

    ScopedAtomicBool(const ScopedAtomicBool &) = delete;
    ScopedAtomicBool &operator=(const ScopedAtomicBool &) = delete;

    [[nodiscard]] explicit operator bool() const noexcept { return _locked; }

private:
    std::atomic<bool> &_flag;
    bool _locked = false;
};

} // namespace

struct Conntrack::Shared {
    std::atomic<std::uint32_t> totalEntries{0};
    std::atomic<std::uint64_t> nextFlowInstanceId{1};
};

struct Conntrack::ImplV4 {
    Options opt;
    Shared *shared = nullptr;

    struct Endpoint {
        std::uint32_t ip = 0; // host-byte-order

        // TCP/UDP
        std::uint16_t port = 0;

        // ICMP (echo/timestamp/info), see reverseIcmpType().
        std::uint8_t icmpType = 0;
        std::uint8_t icmpCode = 0;
        std::uint16_t icmpId = 0;
    };

    struct KeyV4 {
        std::uint32_t uid = 0;
        std::uint8_t proto = 0;
        Endpoint src{};
        Endpoint dst{};
    };

    enum class OtherState : std::uint8_t {
        FIRST = 0,
        MULTIPLE = 1,
        BIDIR = 2,
    };

    enum class IcmpState : std::uint8_t {
        FIRST = 0,
        REPLY = 1,
    };

    enum class TcpPeerState : std::uint8_t {
        CLOSED = 0,
        SYN_SENT = 1,
        ESTABLISHED = 2,
        CLOSING = 3,
        FIN_WAIT_2 = 4,
        TIME_WAIT = 5,
    };

    struct Entry {
        KeyV4 key{};
        KeyV4 revKey{};
        std::atomic<std::uint64_t> expirationNs{0};
        // Flow Telemetry state (best-effort, bounded; used only when telemetry consumer is active).
        struct TelemetryState {
            std::atomic<std::uint64_t> flowInstanceId{0};
            std::atomic<std::uint64_t> sessionId{0};
            std::atomic<std::uint64_t> recordSeq{0};
            std::atomic<bool> exportInProgress{false};

            std::atomic<std::uint64_t> totalPackets{0};
            std::atomic<std::uint64_t> totalBytes{0};
            std::atomic<std::uint64_t> inPackets{0};
            std::atomic<std::uint64_t> inBytes{0};
            std::atomic<std::uint64_t> outPackets{0};
            std::atomic<std::uint64_t> outBytes{0};
            std::atomic<std::uint64_t> firstSeenNs{0};
            std::atomic<std::uint64_t> lastSeenNs{0};

            // Packed decision fields to detect segment changes. Full rule id is tracked separately.
            std::atomic<std::uint64_t> decisionKey{0};
            std::atomic<std::uint32_t> decisionRuleId{0};
            std::atomic<bool> decisionRuleIdKnown{false};

            // Export throttling snapshots (cumulative totals; consumer derives deltas).
            std::atomic<std::uint64_t> lastExportPackets{0};
            std::atomic<std::uint64_t> lastExportBytes{0};
            std::atomic<std::uint64_t> lastExportTsNs{0};
            std::atomic<std::uint64_t> lastExportDecisionKey{0};
            std::atomic<std::uint32_t> lastExportRuleId{0};
            std::atomic<bool> lastExportRuleIdKnown{false};

            // Last seen raw facts needed for END export on retire.
            std::atomic<std::uint32_t> lastUserId{0};
            std::atomic<std::uint32_t> lastIfindex{0};
            std::atomic<std::uint8_t> observationKind{0};
            std::atomic<std::uint8_t> flowOriginDir{0};
            std::atomic<std::uint8_t> lastPacketDir{0};
            std::atomic<std::uint8_t> lastVerdict{0};
            std::atomic<std::uint8_t> lastCtState{0};
            std::atomic<std::uint8_t> lastCtDir{0};
            std::atomic<std::uint8_t> lastReasonId{0};
            std::atomic<std::uint8_t> lastIfaceKindBit{0};
            std::atomic<std::uint8_t> lastL4Status{0};
            std::atomic<bool> lastUidKnown{false};
            std::atomic<bool> lastIfindexKnown{false};
            std::atomic<bool> lastPortsAvailable{false};
            std::atomic<bool> pickedUpMidStream{false};
            std::atomic<std::uint8_t> lastIcmpType{0};
            std::atomic<std::uint8_t> lastIcmpCode{0};
            std::atomic<std::uint16_t> lastIcmpId{0};
        } tele{};
        // Tracker state:
        // - TCP: state0/state1 are peer[0]/peer[1] TcpPeerState values.
        // - other(UDP+other): state0 is OtherState.
        // - ICMP: state0 is IcmpState.
        std::atomic<std::uint8_t> state0{0};
        std::atomic<std::uint8_t> state1{0};
        std::atomic<Entry *> next{nullptr};
        Entry *retiredNext = nullptr;
    };

    struct Shard {
        std::mutex mutex;
        std::uint32_t bucketCount = 0;
        std::unique_ptr<std::atomic<Entry *>[]> buckets;
        std::atomic<std::uint32_t> size{0};
        std::uint32_t cursorBucket = 0;
        std::atomic<std::uint64_t> lastHotSweepTsNs{0};
        std::array<Entry *, 3> retired{nullptr, nullptr, nullptr};

        explicit Shard(const std::uint32_t n)
            : bucketCount(n), buckets(std::make_unique<std::atomic<Entry *>[]>(n)) {
            for (std::uint32_t i = 0; i < bucketCount; ++i) {
                buckets[i].store(nullptr, std::memory_order_relaxed);
            }
        }
    };

    struct TimeoutPolicySec {
        // Default timeout policy in seconds (OVS userspace conntrack, netdev).
        std::uint32_t tcpSynSent = 30;
        std::uint32_t tcpSynRecv = 30;
        std::uint32_t tcpEstablished = 24u * 60u * 60u; // 1 day
        std::uint32_t tcpFinWait = 15u * 60u;
        std::uint32_t tcpTimeWait = 45;
        std::uint32_t tcpClose = 30;
        std::uint32_t udpFirst = 60;
        std::uint32_t udpSingle = 60;
        std::uint32_t udpMultiple = 30;
        std::uint32_t icmpFirst = 60;
        std::uint32_t icmpReply = 30;
    };

    struct Epoch {
        static constexpr std::uint8_t kQuiescent = 0xFF;
        static constexpr std::uint32_t kMaxSlots = 1024;

        struct Slot {
            std::atomic<std::uint8_t> epoch{kQuiescent};
        };

        struct ThreadCache {
            std::uint64_t ownerInstanceId = 0;
            Slot *slot = nullptr;
        };

        std::array<Slot, kMaxSlots> slots{};
        std::atomic<std::uint32_t> used{0};
        std::atomic<std::uint8_t> global{0};
        std::atomic<bool> exhausted{false};
        std::atomic<bool> reclaiming{false};
        const std::uint64_t instanceId = allocateInstanceId();

        static std::uint64_t allocateInstanceId() noexcept {
            static std::atomic<std::uint64_t> nextInstanceId{1};
            return nextInstanceId.fetch_add(1, std::memory_order_relaxed);
        }

        Slot *slotForThread() noexcept {
            thread_local ThreadCache tls{};
            if (tls.ownerInstanceId == instanceId) {
                return tls.slot;
            }
            const std::uint32_t idx = used.fetch_add(1, std::memory_order_relaxed);
            if (idx >= kMaxSlots) {
                exhausted.store(true, std::memory_order_relaxed);
                tls.ownerInstanceId = instanceId;
                tls.slot = nullptr;
                return nullptr;
            }
            tls.ownerInstanceId = instanceId;
            tls.slot = &slots[idx];
            return tls.slot;
        }

        std::uint8_t current() const noexcept { return global.load(std::memory_order_acquire); }

        void enter(Slot *s) noexcept {
            if (!s) {
                return;
            }
            for (;;) {
                while (reclaiming.load(std::memory_order_acquire)) {
                }
                const std::uint8_t observed = current();
                s->epoch.store(observed, std::memory_order_release);
                if (!reclaiming.load(std::memory_order_acquire) &&
                    global.load(std::memory_order_acquire) == observed) {
                    return;
                }
                s->epoch.store(kQuiescent, std::memory_order_release);
            }
        }

        void exit(Slot *s) noexcept {
            if (!s) {
                return;
            }
            s->epoch.store(kQuiescent, std::memory_order_release);
        }

        std::optional<std::uint8_t> beginAdvanceForReclaim() noexcept {
            if (exhausted.load(std::memory_order_relaxed)) {
                return std::nullopt;
            }
            bool expected = false;
            if (!reclaiming.compare_exchange_strong(expected, true, std::memory_order_acq_rel,
                                                    std::memory_order_relaxed)) {
                return std::nullopt;
            }
            const std::uint8_t cur = global.load(std::memory_order_relaxed);
            const std::uint32_t n = used.load(std::memory_order_acquire);
            for (std::uint32_t i = 0; i < n && i < kMaxSlots; ++i) {
                const std::uint8_t e = slots[i].epoch.load(std::memory_order_acquire);
                if (e != kQuiescent) {
                    reclaiming.store(false, std::memory_order_release);
                    return std::nullopt;
                }
            }
            const std::uint8_t next = static_cast<std::uint8_t>((cur + 1u) % 3u);
            global.store(next, std::memory_order_release);
            const std::uint8_t reclaim = static_cast<std::uint8_t>((next + 1u) % 3u);
            return reclaim;
        }

        void endReclaim() noexcept { reclaiming.store(false, std::memory_order_release); }
    };

    static constexpr std::uint64_t kNsPerSec = 1'000'000'000ULL;

    std::uint32_t bucketMask = 0;
    std::vector<std::unique_ptr<Shard>> shards;
    TimeoutPolicySec tp{};
    Epoch epoch{};

    std::atomic<std::uint32_t> totalEntries{0};
    std::atomic<std::uint64_t> creates{0};
    std::atomic<std::uint64_t> expiredRetires{0};
    std::atomic<std::uint64_t> overflowDrops{0};
    std::atomic<std::uint64_t> lastEpochAdvanceTsNs{0};
    static inline bool isPow2(const std::uint32_t v) noexcept {
        return v != 0 && ((v & (v - 1u)) == 0u);
    }

    static inline std::uint32_t clampU32(const std::uint32_t v, const std::uint32_t lo,
                                         const std::uint32_t hi) noexcept {
        return (v < lo) ? lo : (v > hi) ? hi : v;
    }

    static inline std::uint8_t reverseIcmpType(const std::uint8_t type) noexcept {
        // OVS supports a small set of ICMP "connection-like" request/reply types.
        // For everything else (incl. error types), phase-1 treats as invalid.
        switch (type) {
        case 8:  // Echo request
            return 0; // Echo reply
        case 0:  // Echo reply
            return 8; // Echo request
        case 13: // Timestamp
            return 14;
        case 14: // Timestamp reply
            return 13;
        case 15: // Info request
            return 16;
        case 16: // Info reply
            return 15;
        default:
            return 0xFF;
        }
    }

    static inline KeyV4 reverseKey(const KeyV4 &k) noexcept {
        KeyV4 r = k;
        std::swap(r.src, r.dst);
        return r;
    }

    static inline bool tcpInvalidFlags(std::uint8_t flags) noexcept {
        // OVS-grade loose TCP flag validation (derived from OVS conntrack-tcp.c).
        // We ignore ECE/CWR for state validation purposes.
#ifdef TH_ECE
        flags &= static_cast<std::uint8_t>(~TH_ECE);
#endif
#ifdef TH_CWR
        flags &= static_cast<std::uint8_t>(~TH_CWR);
#endif
        if ((flags & TH_SYN) != 0) {
            if ((flags & (TH_RST | TH_FIN)) != 0) {
                return true;
            }
        } else if ((flags & TH_ACK) == 0 && (flags & TH_RST) == 0) {
            return true;
        }
        if ((flags & TH_ACK) == 0 && (flags & (TH_FIN | TH_PUSH | TH_URG)) != 0) {
            return true;
        }
        return false;
    }

    static inline bool tcpValidNew(const PacketV4 &pkt) noexcept {
        if (!pkt.hasTcp) {
            return false;
        }
        std::uint16_t tcpPayloadLen = 0;
        if (!Conntrack::computeTcpPayloadLen(pkt, tcpPayloadLen)) {
            return false;
        }
        (void)tcpPayloadLen;
        const std::uint8_t flags = pkt.tcp.flags;
        if (tcpInvalidFlags(flags)) {
            return false;
        }
        if ((flags & TH_SYN) != 0 && (flags & TH_ACK) != 0) {
            // OVS: don't create a conn from SYN-ACK (partially open).
            return false;
        }
        return true;
    }

    static inline bool tcpValidUpdate(const PacketV4 &pkt) noexcept {
        if (!pkt.hasTcp) {
            return false;
        }
        std::uint16_t tcpPayloadLen = 0;
        if (!Conntrack::computeTcpPayloadLen(pkt, tcpPayloadLen)) {
            return false;
        }
        (void)tcpPayloadLen;
        return !tcpInvalidFlags(pkt.tcp.flags);
    }

    static inline bool icmp4ValidNew(const PacketV4 &pkt) noexcept {
        if (!pkt.hasIcmp) {
            return false;
        }
        // OVS: only treat request types as valid-new (reply/error cannot create a conn).
        if (pkt.icmp.code != 0) {
            return false;
        }
        return pkt.icmp.type == 8 || pkt.icmp.type == 13 || pkt.icmp.type == 15;
    }

    static inline bool keyEq(const KeyV4 &a, const KeyV4 &b) noexcept {
        return a.uid == b.uid && a.proto == b.proto && a.src.ip == b.src.ip && a.dst.ip == b.dst.ip &&
            a.src.port == b.src.port && a.dst.port == b.dst.port && a.src.icmpType == b.src.icmpType &&
            a.dst.icmpType == b.dst.icmpType && a.src.icmpCode == b.src.icmpCode &&
            a.dst.icmpCode == b.dst.icmpCode && a.src.icmpId == b.src.icmpId && a.dst.icmpId == b.dst.icmpId;
    }

    static inline std::uint64_t mix(std::uint64_t x) noexcept {
        // SplitMix64 finalizer.
        x ^= x >> 30;
        x *= 0xbf58476d1ce4e5b9ULL;
        x ^= x >> 27;
        x *= 0x94d049bb133111ebULL;
        x ^= x >> 31;
        return x;
    }

    static inline std::uint64_t hashEndpoint(const Endpoint &ep) noexcept {
        std::uint64_t h = 0;
        h ^= mix(static_cast<std::uint64_t>(ep.ip));
        h ^= mix(static_cast<std::uint64_t>(ep.port) << 16 |
                 static_cast<std::uint64_t>(ep.icmpType) << 8 |
                 static_cast<std::uint64_t>(ep.icmpCode));
        h ^= mix(static_cast<std::uint64_t>(ep.icmpId));
        return h;
    }

    static inline std::uint64_t hashKey(const KeyV4 &k) noexcept {
        // Symmetric hashing: swapping src/dst yields the same hash.
        const std::uint64_t hsrc = hashEndpoint(k.src);
        const std::uint64_t hdst = hashEndpoint(k.dst);
        std::uint64_t h = hsrc ^ hdst;
        h ^= mix(static_cast<std::uint64_t>(k.uid));
        h ^= mix(static_cast<std::uint64_t>(k.proto));
        return h;
    }

    static inline std::uint64_t addTimeoutNs(const std::uint64_t nowNs, const std::uint32_t sec) noexcept {
        const std::uint64_t d = static_cast<std::uint64_t>(sec) * kNsPerSec;
        if (nowNs > std::numeric_limits<std::uint64_t>::max() - d) {
            return std::numeric_limits<std::uint64_t>::max();
        }
        return nowNs + d;
    }

    explicit ImplV4(const Options &o, Shared *shared_) : opt(o), shared(shared_) {
        opt.shards = static_cast<std::uint16_t>(clampU32(opt.shards, 1, 4096));
        if (!isPow2(opt.bucketsPerShard)) {
            opt.bucketsPerShard = 4096;
        }
        if (opt.maxEntries == 0) {
            opt.maxEntries = 1;
        }
        if (opt.sweepMaxBuckets == 0) {
            opt.sweepMaxBuckets = 1;
        }
        if (opt.sweepMaxEntries == 0) {
            opt.sweepMaxEntries = 1;
        }

        bucketMask = opt.bucketsPerShard - 1u;
        shards.reserve(opt.shards);
        for (std::uint16_t i = 0; i < opt.shards; ++i) {
            shards.emplace_back(std::make_unique<Shard>(opt.bucketsPerShard));
        }
    }

    ~ImplV4() {
        for (auto &sp : shards) {
            if (!sp) {
                continue;
            }
            Shard &shard = *sp;
            const std::lock_guard<std::mutex> g(shard.mutex);

            for (std::uint32_t bi = 0; bi < shard.bucketCount; ++bi) {
                Entry *cur = shard.buckets[bi].load(std::memory_order_relaxed);
                shard.buckets[bi].store(nullptr, std::memory_order_relaxed);
                while (cur) {
                    Entry *next = cur->next.load(std::memory_order_relaxed);
                    delete cur;
                    cur = next;
                }
            }

            for (auto &head : shard.retired) {
                Entry *cur = head;
                head = nullptr;
                while (cur) {
                    Entry *next = cur->retiredNext;
                    delete cur;
                    cur = next;
                }
            }
        }
    }

    static inline bool expired(const Entry &e, const std::uint64_t nowNs) noexcept {
        const std::uint64_t exp = e.expirationNs.load(std::memory_order_relaxed);
        return exp != 0 && nowNs >= exp;
    }

    FlowTelemetryRecords::FlowEndReason endReasonForRetire(
        const Entry &e, const FlowTelemetryRecords::FlowEndReason requested) const noexcept {
        if (requested != FlowTelemetryRecords::FlowEndReason::IdleTimeout ||
            e.key.proto != IPPROTO_TCP) {
            return requested;
        }
        const auto s0 = static_cast<TcpPeerState>(e.state0.load(std::memory_order_relaxed));
        const auto s1 = static_cast<TcpPeerState>(e.state1.load(std::memory_order_relaxed));
        if (s0 >= TcpPeerState::CLOSING || s1 >= TcpPeerState::CLOSING) {
            return FlowTelemetryRecords::FlowEndReason::TcpEndDetected;
        }
        return requested;
    }

    bool exportTelemetryEndLocked(Entry &e, const std::uint64_t nowNs,
                                  const FlowTelemetry::HotPath &teleHot,
                                  const FlowTelemetryRecords::FlowEndReason requested) noexcept {
        if (!teleHot.session || !teleHot.cfg || teleHot.sessionId == 0) {
            return false;
        }
        if (e.tele.sessionId.load(std::memory_order_relaxed) != teleHot.sessionId) {
            return false;
        }
        const std::uint64_t flowId = e.tele.flowInstanceId.load(std::memory_order_relaxed);
        const std::uint64_t lastExportTs = e.tele.lastExportTsNs.load(std::memory_order_relaxed);
        if (flowId == 0 || lastExportTs == 0) {
            return false;
        }

        ScopedAtomicBool exportGuard(e.tele.exportInProgress);
        if (!exportGuard) {
            return false;
        }

        const std::uint64_t recordSeq = e.tele.recordSeq.load(std::memory_order_relaxed) + 1;
        const std::uint64_t packedKey = e.tele.decisionKey.load(std::memory_order_relaxed);
        const bool ridKnown = e.tele.decisionRuleIdKnown.load(std::memory_order_relaxed);
        const std::uint32_t ridValue = e.tele.decisionRuleId.load(std::memory_order_relaxed);
        const std::optional<std::uint32_t> rid =
            ridKnown ? std::optional<std::uint32_t>(ridValue) : std::nullopt;
        const std::uint64_t totalPk = e.tele.totalPackets.load(std::memory_order_relaxed);
        const std::uint64_t totalBy = e.tele.totalBytes.load(std::memory_order_relaxed);
        const std::uint64_t inPk = e.tele.inPackets.load(std::memory_order_relaxed);
        const std::uint64_t inBy = e.tele.inBytes.load(std::memory_order_relaxed);
        const std::uint64_t outPk = e.tele.outPackets.load(std::memory_order_relaxed);
        const std::uint64_t outBy = e.tele.outBytes.load(std::memory_order_relaxed);

        const auto toV4 = [](const std::uint32_t ip) noexcept {
            std::array<std::byte, 4> out{};
            out[0] = static_cast<std::byte>((ip >> 24) & 0xFFu);
            out[1] = static_cast<std::byte>((ip >> 16) & 0xFFu);
            out[2] = static_cast<std::byte>((ip >> 8) & 0xFFu);
            out[3] = static_cast<std::byte>(ip & 0xFFu);
            return out;
        };
        const auto src = toV4(e.key.src.ip);
        const auto dst = toV4(e.key.dst.ip);

        FlowTelemetryRecords::FlowV1Fields fields{};
        fields.kind = FlowTelemetryRecords::FlowRecordKind::End;
        fields.observationKind = static_cast<FlowTelemetryRecords::FlowObservationKind>(
            e.tele.observationKind.load(std::memory_order_relaxed));
        fields.ctState = e.tele.lastCtState.load(std::memory_order_relaxed);
        fields.ctDir = e.tele.lastCtDir.load(std::memory_order_relaxed);
        fields.packetDir = static_cast<FlowTelemetryRecords::FlowPacketDirection>(
            e.tele.lastPacketDir.load(std::memory_order_relaxed));
        fields.flowOriginDir = static_cast<FlowTelemetryRecords::FlowPacketDirection>(
            e.tele.flowOriginDir.load(std::memory_order_relaxed));
        fields.verdict = static_cast<FlowTelemetryRecords::FlowVerdict>(
            e.tele.lastVerdict.load(std::memory_order_relaxed));
        fields.reasonId = e.tele.lastReasonId.load(std::memory_order_relaxed);
        fields.ifaceKindBit = e.tele.lastIfaceKindBit.load(std::memory_order_relaxed);
        fields.l4Status = e.tele.lastL4Status.load(std::memory_order_relaxed);
        fields.endReason = endReasonForRetire(e, requested);
        fields.proto = e.key.proto;
        fields.isIpv6 = false;
        fields.pickedUpMidStream = e.tele.pickedUpMidStream.load(std::memory_order_relaxed);
        fields.uidKnown = e.tele.lastUidKnown.load(std::memory_order_relaxed);
        fields.ifindexKnown = e.tele.lastIfindexKnown.load(std::memory_order_relaxed);
        fields.portsAvailable = e.tele.lastPortsAvailable.load(std::memory_order_relaxed);
        fields.srcPort = e.key.src.port;
        fields.dstPort = e.key.dst.port;
        fields.icmpType = e.tele.lastIcmpType.load(std::memory_order_relaxed);
        fields.icmpCode = e.tele.lastIcmpCode.load(std::memory_order_relaxed);
        fields.icmpId = e.tele.lastIcmpId.load(std::memory_order_relaxed);
        fields.timestampNs = nowNs;
        fields.firstSeenNs = e.tele.firstSeenNs.load(std::memory_order_relaxed);
        fields.lastSeenNs = e.tele.lastSeenNs.load(std::memory_order_relaxed);
        fields.flowInstanceId = flowId;
        fields.recordSeq = recordSeq;
        fields.uid = e.key.uid;
        fields.userId = e.tele.lastUserId.load(std::memory_order_relaxed);
        fields.ifindex = e.tele.lastIfindex.load(std::memory_order_relaxed);
        fields.srcAddr = std::span<const std::byte>(src.data(), src.size());
        fields.dstAddr = std::span<const std::byte>(dst.data(), dst.size());
        fields.totalPackets = totalPk;
        fields.totalBytes = totalBy;
        fields.inPackets = inPk;
        fields.inBytes = inBy;
        fields.outPackets = outPk;
        fields.outBytes = outBy;
        fields.ruleId = rid;

        FlowTelemetryRecords::EncodedPayload payload{};
        if (!FlowTelemetryRecords::encodeFlowV1(payload, fields)) {
            return false;
        }
        if (!flowTelemetry.exportRecordHot(teleHot, FlowTelemetryAbi::RecordType::Flow, payload.span())) {
            return false;
        }

        e.tele.recordSeq.store(recordSeq, std::memory_order_relaxed);
        e.tele.lastExportPackets.store(totalPk, std::memory_order_relaxed);
        e.tele.lastExportBytes.store(totalBy, std::memory_order_relaxed);
        e.tele.lastExportTsNs.store(nowNs, std::memory_order_relaxed);
        e.tele.lastExportDecisionKey.store(packedKey, std::memory_order_relaxed);
        e.tele.lastExportRuleId.store(ridValue, std::memory_order_relaxed);
        e.tele.lastExportRuleIdKnown.store(ridKnown, std::memory_order_relaxed);
        return true;
    }

    void retireUnlinkedLocked(Shard &shard, Entry *e, const std::uint8_t retireEpoch) noexcept {
        e->retiredNext = shard.retired[retireEpoch];
        shard.retired[retireEpoch] = e;
        shard.size.fetch_sub(1, std::memory_order_relaxed);
        totalEntries.fetch_sub(1, std::memory_order_relaxed);
        if (shared) {
            shared->totalEntries.fetch_sub(1, std::memory_order_relaxed);
        }
    }

    bool evictOneLocked(Shard &shard, const std::uint64_t nowNs, const std::uint8_t retireEpoch,
                        const FlowTelemetry::HotPath &teleHot) noexcept {
        std::uint32_t scannedBuckets = 0;
        std::uint32_t scannedEntries = 0;
        while (scannedBuckets < opt.sweepMaxBuckets && scannedEntries < opt.sweepMaxEntries) {
            const std::uint32_t bi = shard.cursorBucket & bucketMask;
            shard.cursorBucket = (shard.cursorBucket + 1u) & bucketMask;
            scannedBuckets++;

            Entry *head = shard.buckets[bi].load(std::memory_order_relaxed);
            Entry *prev = nullptr;
            Entry *cur = head;
            while (cur && scannedEntries < opt.sweepMaxEntries) {
                scannedEntries++;
                Entry *next = cur->next.load(std::memory_order_relaxed);
                const bool canEvict =
                    cur->tele.sessionId.load(std::memory_order_relaxed) == teleHot.sessionId &&
                    cur->tele.lastExportTsNs.load(std::memory_order_relaxed) != 0;
                if (!canEvict) {
                    prev = cur;
                    cur = next;
                    continue;
                }

                if (prev) {
                    prev->next.store(next, std::memory_order_relaxed);
                } else {
                    head = next;
                }
                shard.buckets[bi].store(head, std::memory_order_release);
                (void)exportTelemetryEndLocked(
                    *cur, nowNs, teleHot, FlowTelemetryRecords::FlowEndReason::ResourceEvicted);
                retireUnlinkedLocked(shard, cur, retireEpoch);
                return true;
            }
        }
        return false;
    }

    std::uint32_t emitTelemetryDisabledEnds(const std::uint64_t nowNs,
                                            const FlowTelemetry::HotPath &teleHot) noexcept {
        if (!teleHot.session || !teleHot.cfg || teleHot.sessionId == 0) {
            return 0;
        }

        std::uint32_t emitted = 0;
        std::uint32_t scannedBuckets = 0;
        std::uint32_t scannedEntries = 0;
        const std::uint32_t bucketBudget = opt.sweepMaxBuckets;
        const std::uint32_t entryBudget = opt.sweepMaxEntries;
        for (auto &sp : shards) {
            if (!sp || scannedBuckets >= bucketBudget || scannedEntries >= entryBudget) {
                break;
            }
            const std::lock_guard<std::mutex> g(sp->mutex);
            std::uint32_t bi = sp->cursorBucket & bucketMask;
            for (std::uint32_t bucketScans = 0;
                 bucketScans < sp->bucketCount &&
                 scannedBuckets < bucketBudget &&
                 scannedEntries < entryBudget;
                 ++bucketScans, ++scannedBuckets, bi = (bi + 1u) & bucketMask) {
                Entry *cur = sp->buckets[bi].load(std::memory_order_relaxed);
                while (cur && scannedEntries < entryBudget) {
                    scannedEntries++;
                    if (cur->tele.sessionId.load(std::memory_order_relaxed) == teleHot.sessionId &&
                        cur->tele.lastExportTsNs.load(std::memory_order_relaxed) != 0) {
                        if (exportTelemetryEndLocked(
                                *cur, nowNs, teleHot,
                                FlowTelemetryRecords::FlowEndReason::TelemetryDisabled)) {
                            emitted++;
                        }
                    }
                    cur = cur->next.load(std::memory_order_relaxed);
                }
            }
            sp->cursorBucket = bi;
        }
        return emitted;
    }

    void resetTelemetryForSessionLocked(Entry &e, const FlowTelemetry::HotPath &teleHot,
                                        const std::uint64_t pktTsNs,
                                        const FlowTelemetryRecords::FlowPacketDirection packetDir,
                                        const FlowTelemetryRecords::FlowObservationKind observationKind,
                                        const bool inheritFirstSeen,
                                        const bool pickedUpMidStream) noexcept {
        std::uint64_t firstSeenNs = inheritFirstSeen
            ? e.tele.firstSeenNs.load(std::memory_order_relaxed)
            : 0;
        if (firstSeenNs == 0) {
            firstSeenNs = pktTsNs;
        }

        e.tele.flowInstanceId.store(shared->nextFlowInstanceId.fetch_add(1, std::memory_order_relaxed),
                                    std::memory_order_relaxed);
        e.tele.recordSeq.store(0, std::memory_order_relaxed);
        e.tele.totalPackets.store(0, std::memory_order_relaxed);
        e.tele.totalBytes.store(0, std::memory_order_relaxed);
        e.tele.inPackets.store(0, std::memory_order_relaxed);
        e.tele.inBytes.store(0, std::memory_order_relaxed);
        e.tele.outPackets.store(0, std::memory_order_relaxed);
        e.tele.outBytes.store(0, std::memory_order_relaxed);
        e.tele.firstSeenNs.store(firstSeenNs, std::memory_order_relaxed);
        e.tele.lastSeenNs.store(firstSeenNs, std::memory_order_relaxed);
        e.tele.decisionKey.store(0, std::memory_order_relaxed);
        e.tele.decisionRuleId.store(0, std::memory_order_relaxed);
        e.tele.decisionRuleIdKnown.store(false, std::memory_order_relaxed);
        e.tele.lastExportPackets.store(0, std::memory_order_relaxed);
        e.tele.lastExportBytes.store(0, std::memory_order_relaxed);
        e.tele.lastExportTsNs.store(0, std::memory_order_relaxed);
        e.tele.lastExportDecisionKey.store(0, std::memory_order_relaxed);
        e.tele.lastExportRuleId.store(0, std::memory_order_relaxed);
        e.tele.lastExportRuleIdKnown.store(false, std::memory_order_relaxed);
        e.tele.lastUserId.store(0, std::memory_order_relaxed);
        e.tele.lastIfindex.store(0, std::memory_order_relaxed);
        e.tele.observationKind.store(static_cast<std::uint8_t>(observationKind),
                                     std::memory_order_relaxed);
        e.tele.flowOriginDir.store(static_cast<std::uint8_t>(packetDir), std::memory_order_relaxed);
        e.tele.lastPacketDir.store(0, std::memory_order_relaxed);
        e.tele.lastVerdict.store(0, std::memory_order_relaxed);
        e.tele.lastCtState.store(0, std::memory_order_relaxed);
        e.tele.lastCtDir.store(0, std::memory_order_relaxed);
        e.tele.lastReasonId.store(0, std::memory_order_relaxed);
        e.tele.lastIfaceKindBit.store(0, std::memory_order_relaxed);
        e.tele.lastL4Status.store(0, std::memory_order_relaxed);
        e.tele.lastUidKnown.store(false, std::memory_order_relaxed);
        e.tele.lastIfindexKnown.store(false, std::memory_order_relaxed);
        e.tele.lastPortsAvailable.store(false, std::memory_order_relaxed);
        e.tele.pickedUpMidStream.store(pickedUpMidStream, std::memory_order_relaxed);
        e.tele.lastIcmpType.store(0, std::memory_order_relaxed);
        e.tele.lastIcmpCode.store(0, std::memory_order_relaxed);
        e.tele.lastIcmpId.store(0, std::memory_order_relaxed);
        e.tele.sessionId.store(teleHot.sessionId, std::memory_order_release);
    }

    bool ensureTelemetrySession(Entry &e, const FlowTelemetry::HotPath &teleHot,
                                const std::uint64_t pktTsNs,
                                const FlowTelemetryRecords::FlowPacketDirection packetDir,
                                const FlowTelemetryRecords::FlowObservationKind observationKind,
                                const bool l3Observation,
                                const Conntrack::Result &ctResult) noexcept {
        const std::uint64_t currentSession = e.tele.sessionId.load(std::memory_order_acquire);
        if (currentSession == teleHot.sessionId) {
            return true;
        }

        ScopedAtomicBool sessionGuard(e.tele.exportInProgress);
        if (!sessionGuard) {
            return false;
        }
        const std::uint64_t checkedSession = e.tele.sessionId.load(std::memory_order_acquire);
        if (checkedSession == teleHot.sessionId) {
            return true;
        }

        const bool inheritFirstSeen = checkedSession == 0;
        const std::uint64_t priorFirstSeen = e.tele.firstSeenNs.load(std::memory_order_relaxed);
        const bool pickedUp = !l3Observation &&
            (isPickedUpMidStream(ctResult) ||
             (inheritFirstSeen && priorFirstSeen != 0 && priorFirstSeen != pktTsNs));
        resetTelemetryForSessionLocked(e, teleHot, pktTsNs, packetDir, observationKind,
                                       inheritFirstSeen, pickedUp);
        return true;
    }

    std::uint32_t sweepLocked(Shard &shard, const std::uint64_t nowNs, const std::uint8_t retireEpoch) noexcept {
        const FlowTelemetry::HotPath teleHot = flowTelemetry.hotPathFlow();
        const bool telemetryActive = teleHot.session != nullptr && teleHot.cfg != nullptr;

        std::uint32_t removed = 0;
        std::uint32_t scannedBuckets = 0;
        std::uint32_t scannedEntries = 0;

        while (scannedBuckets < opt.sweepMaxBuckets && removed < opt.sweepMaxEntries) {
            const std::uint32_t bi = shard.cursorBucket & bucketMask;
            shard.cursorBucket = (shard.cursorBucket + 1u) & bucketMask;
            scannedBuckets++;

            Entry *head = shard.buckets[bi].load(std::memory_order_relaxed);
            Entry *prev = nullptr;
            Entry *cur = head;

            while (cur && removed < opt.sweepMaxEntries && scannedEntries < opt.sweepMaxEntries) {
                scannedEntries++;
                Entry *next = cur->next.load(std::memory_order_relaxed);
                if (expired(*cur, nowNs)) {
                    if (telemetryActive) {
                        const std::uint64_t flowId =
                            cur->tele.flowInstanceId.load(std::memory_order_relaxed);
                        const std::uint64_t sessionId =
                            cur->tele.sessionId.load(std::memory_order_relaxed);
                        const std::uint64_t packedKey =
                            cur->tele.decisionKey.load(std::memory_order_relaxed);
                        const std::uint64_t lastExportTs =
                            cur->tele.lastExportTsNs.load(std::memory_order_relaxed);
                        if (flowId != 0 && lastExportTs != 0 &&
                            sessionId == teleHot.sessionId) {
                            const std::uint64_t totalPk =
                                cur->tele.totalPackets.load(std::memory_order_relaxed);
                            const std::uint64_t totalBy =
                                cur->tele.totalBytes.load(std::memory_order_relaxed);
                            const std::uint64_t inPk =
                                cur->tele.inPackets.load(std::memory_order_relaxed);
                            const std::uint64_t inBy =
                                cur->tele.inBytes.load(std::memory_order_relaxed);
                            const std::uint64_t outPk =
                                cur->tele.outPackets.load(std::memory_order_relaxed);
                            const std::uint64_t outBy =
                                cur->tele.outBytes.load(std::memory_order_relaxed);
                            const std::uint32_t userId =
                                cur->tele.lastUserId.load(std::memory_order_relaxed);
                            const std::uint32_t ifindex =
                                cur->tele.lastIfindex.load(std::memory_order_relaxed);
                            const bool ridKnown =
                                cur->tele.decisionRuleIdKnown.load(std::memory_order_relaxed);
                            const std::uint32_t ridValue =
                                cur->tele.decisionRuleId.load(std::memory_order_relaxed);
                            const std::optional<std::uint32_t> rid =
                                ridKnown ? std::optional<std::uint32_t>(ridValue) : std::nullopt;

                            const auto toV4 = [](const std::uint32_t ip) noexcept {
                                std::array<std::byte, 4> out{};
                                out[0] = static_cast<std::byte>((ip >> 24) & 0xFFu);
                                out[1] = static_cast<std::byte>((ip >> 16) & 0xFFu);
                                out[2] = static_cast<std::byte>((ip >> 8) & 0xFFu);
                                out[3] = static_cast<std::byte>(ip & 0xFFu);
                                return out;
                            };
                            const auto src = toV4(cur->key.src.ip);
                            const auto dst = toV4(cur->key.dst.ip);

                            ScopedAtomicBool exportGuard(cur->tele.exportInProgress);
                            if (exportGuard) {
                                const std::uint64_t recordSeq =
                                    cur->tele.recordSeq.load(std::memory_order_relaxed) + 1;

                                auto endReason = FlowTelemetryRecords::FlowEndReason::IdleTimeout;
                                if (cur->key.proto == IPPROTO_TCP) {
                                    const auto s0 = static_cast<TcpPeerState>(
                                        cur->state0.load(std::memory_order_relaxed));
                                    const auto s1 = static_cast<TcpPeerState>(
                                        cur->state1.load(std::memory_order_relaxed));
                                    if (s0 >= TcpPeerState::CLOSING || s1 >= TcpPeerState::CLOSING) {
                                        endReason = FlowTelemetryRecords::FlowEndReason::TcpEndDetected;
                                    }
                                }

                                FlowTelemetryRecords::FlowV1Fields fields{};
                                fields.kind = FlowTelemetryRecords::FlowRecordKind::End;
                                fields.observationKind = static_cast<FlowTelemetryRecords::FlowObservationKind>(
                                    cur->tele.observationKind.load(std::memory_order_relaxed));
                                fields.ctState = cur->tele.lastCtState.load(std::memory_order_relaxed);
                                fields.ctDir = cur->tele.lastCtDir.load(std::memory_order_relaxed);
                                fields.packetDir = static_cast<FlowTelemetryRecords::FlowPacketDirection>(
                                    cur->tele.lastPacketDir.load(std::memory_order_relaxed));
                                fields.flowOriginDir = static_cast<FlowTelemetryRecords::FlowPacketDirection>(
                                    cur->tele.flowOriginDir.load(std::memory_order_relaxed));
                                fields.verdict = static_cast<FlowTelemetryRecords::FlowVerdict>(
                                    cur->tele.lastVerdict.load(std::memory_order_relaxed));
                                fields.reasonId = cur->tele.lastReasonId.load(std::memory_order_relaxed);
                                fields.ifaceKindBit = cur->tele.lastIfaceKindBit.load(std::memory_order_relaxed);
                                fields.l4Status = cur->tele.lastL4Status.load(std::memory_order_relaxed);
                                fields.endReason = endReason;
                                fields.proto = cur->key.proto;
                                fields.isIpv6 = false;
                                fields.pickedUpMidStream =
                                    cur->tele.pickedUpMidStream.load(std::memory_order_relaxed);
                                fields.uidKnown = cur->tele.lastUidKnown.load(std::memory_order_relaxed);
                                fields.ifindexKnown = cur->tele.lastIfindexKnown.load(std::memory_order_relaxed);
                                fields.portsAvailable =
                                    cur->tele.lastPortsAvailable.load(std::memory_order_relaxed);
                                fields.srcPort = cur->key.src.port;
                                fields.dstPort = cur->key.dst.port;
                                fields.icmpType = cur->tele.lastIcmpType.load(std::memory_order_relaxed);
                                fields.icmpCode = cur->tele.lastIcmpCode.load(std::memory_order_relaxed);
                                fields.icmpId = cur->tele.lastIcmpId.load(std::memory_order_relaxed);
                                fields.timestampNs = nowNs;
                                fields.firstSeenNs = cur->tele.firstSeenNs.load(std::memory_order_relaxed);
                                fields.lastSeenNs = cur->tele.lastSeenNs.load(std::memory_order_relaxed);
                                fields.flowInstanceId = flowId;
                                fields.recordSeq = recordSeq;
                                fields.uid = cur->key.uid;
                                fields.userId = userId;
                                fields.ifindex = ifindex;
                                fields.srcAddr = std::span<const std::byte>(src.data(), src.size());
                                fields.dstAddr = std::span<const std::byte>(dst.data(), dst.size());
                                fields.totalPackets = totalPk;
                                fields.totalBytes = totalBy;
                                fields.inPackets = inPk;
                                fields.inBytes = inBy;
                                fields.outPackets = outPk;
                                fields.outBytes = outBy;
                                fields.ruleId = rid;

                                FlowTelemetryRecords::EncodedPayload payload{};
                                if (FlowTelemetryRecords::encodeFlowV1(payload, fields)) {
                                    if (flowTelemetry.exportRecordHot(
                                            teleHot, FlowTelemetryAbi::RecordType::Flow, payload.span())) {
                                        cur->tele.recordSeq.store(recordSeq, std::memory_order_relaxed);
                                        cur->tele.lastExportPackets.store(totalPk, std::memory_order_relaxed);
                                        cur->tele.lastExportBytes.store(totalBy, std::memory_order_relaxed);
                                        cur->tele.lastExportTsNs.store(nowNs, std::memory_order_relaxed);
                                        cur->tele.lastExportDecisionKey.store(packedKey, std::memory_order_relaxed);
                                        cur->tele.lastExportRuleId.store(ridValue, std::memory_order_relaxed);
                                        cur->tele.lastExportRuleIdKnown.store(
                                            ridKnown, std::memory_order_relaxed);
                                    }
                                }
                            }
                        }
                    }

                    // Unlink.
                    if (prev) {
                        prev->next.store(next, std::memory_order_relaxed);
                    } else {
                        head = next;
                    }

                    // Retire (no free in hot path).
                    cur->retiredNext = shard.retired[retireEpoch];
                    shard.retired[retireEpoch] = cur;
                    shard.size.fetch_sub(1, std::memory_order_relaxed);
                    totalEntries.fetch_sub(1, std::memory_order_relaxed);
                    if (shared) {
                        shared->totalEntries.fetch_sub(1, std::memory_order_relaxed);
                    }
                    expiredRetires.fetch_add(1, std::memory_order_relaxed);
                    removed++;
                } else {
                    prev = cur;
                }
                cur = next;
            }

            shard.buckets[bi].store(head, std::memory_order_release);
        }

        return removed;
    }

    void reclaimEpochAllShards(const std::uint8_t epochToReclaim) noexcept {
        for (auto &sp : shards) {
            if (!sp) {
                continue;
            }

            Entry *toFree = nullptr;
            {
                const std::lock_guard<std::mutex> g(sp->mutex);
                toFree = sp->retired[epochToReclaim];
                sp->retired[epochToReclaim] = nullptr;
            }

            while (toFree) {
                Entry *next = toFree->retiredNext;
                delete toFree;
                toFree = next;
            }
        }
    }

    void maybeAdvanceAndReclaim(const std::uint64_t nowNs) noexcept {
        const std::uint64_t minIntervalNs = static_cast<std::uint64_t>(opt.sweepMinIntervalMs) * 1'000'000ULL;
        const std::uint64_t last = lastEpochAdvanceTsNs.load(std::memory_order_relaxed);
        if (minIntervalNs != 0 && nowNs > last && nowNs - last < minIntervalNs) {
            return;
        }
        const auto reclaimEpoch = epoch.beginAdvanceForReclaim();
        if (!reclaimEpoch.has_value()) {
            return;
        }
        lastEpochAdvanceTsNs.store(nowNs, std::memory_order_relaxed);
        reclaimEpochAllShards(*reclaimEpoch);
        epoch.endReclaim();
    }

    bool maybeHotSweep(Shard &shard, const std::uint64_t nowNs) noexcept {
        const std::uint64_t intervalNs = static_cast<std::uint64_t>(opt.sweepMinIntervalMs) * 1'000'000ULL;
        if (intervalNs == 0) {
            return false;
        }
        const std::uint64_t last = shard.lastHotSweepTsNs.load(std::memory_order_relaxed);
        if (nowNs > last && nowNs - last < intervalNs) {
            return false;
        }
        if (!shard.mutex.try_lock()) {
            return false;
        }

        bool retiredAny = false;
        shard.lastHotSweepTsNs.store(nowNs, std::memory_order_relaxed);
        const std::uint8_t retireEpoch = epoch.current();
        const std::uint32_t removed = sweepLocked(shard, nowNs, retireEpoch);
        retiredAny = removed != 0;
        shard.mutex.unlock();

        if (retiredAny) {
            maybeAdvanceAndReclaim(nowNs);
        }
        return retiredAny;
    }

    bool makeKey(const PacketV4 &pkt, KeyV4 &out) noexcept {
        out = KeyV4{};
        out.uid = pkt.uid;
        out.proto = pkt.proto;
        out.src.ip = pkt.srcIp;
        out.dst.ip = pkt.dstIp;

        if (pkt.proto == IPPROTO_TCP) {
            if (!pkt.hasTcp) {
                return false;
            }
            if (pkt.srcPort == 0 || pkt.dstPort == 0) {
                return false;
            }
            out.src.port = pkt.srcPort;
            out.dst.port = pkt.dstPort;
            return true;
        }

        if (pkt.proto == IPPROTO_UDP) {
            if (pkt.srcPort == 0 || pkt.dstPort == 0) {
                return false;
            }
            out.src.port = pkt.srcPort;
            out.dst.port = pkt.dstPort;
            return true;
        }

        if (pkt.proto == IPPROTO_ICMP) {
            if (!pkt.hasIcmp) {
                return false;
            }
            const std::uint8_t rtype = reverseIcmpType(pkt.icmp.type);
            if (rtype == 0xFF) {
                return false;
            }
            if (pkt.icmp.code != 0) {
                return false;
            }
            out.src.icmpId = pkt.icmp.id;
            out.dst.icmpId = pkt.icmp.id;
            out.src.icmpType = pkt.icmp.type;
            out.dst.icmpType = rtype;
            out.src.icmpCode = pkt.icmp.code;
            out.dst.icmpCode = pkt.icmp.code;
            return true;
        }

        // other: only L3 identity + proto.
        return true;
    }

    bool makeObservationKey(const PacketV4 &pkt, KeyV4 &out) noexcept {
        out = KeyV4{};
        out.uid = pkt.uid;
        out.proto = pkt.proto;
        out.src.ip = pkt.srcIp;
        out.dst.ip = pkt.dstIp;
        // Keep telemetry-only L3 observations disjoint from normal CT keys in the shared table.
        out.src.icmpCode = 0xFE;
        out.dst.icmpCode = 0xFE;
        if (pkt.hasIcmp) {
            out.src.icmpType = pkt.icmp.type;
            out.dst.icmpType = pkt.icmp.type;
            out.src.icmpId = pkt.icmp.id;
            out.dst.icmpId = pkt.icmp.id;
        }
        return true;
    }

    std::uint32_t timeoutForOtherState(const OtherState s) const noexcept {
        switch (s) {
        case OtherState::FIRST:
            return tp.udpFirst;
        case OtherState::MULTIPLE:
            return tp.udpMultiple;
        case OtherState::BIDIR:
            return tp.udpSingle;
        }
        return tp.udpFirst;
    }

    std::uint32_t timeoutForIcmpState(const IcmpState s) const noexcept {
        switch (s) {
        case IcmpState::FIRST:
            return tp.icmpFirst;
        case IcmpState::REPLY:
            return tp.icmpReply;
        }
        return tp.icmpFirst;
    }

    std::uint32_t timeoutForTcpPeers(const TcpPeerState a, const TcpPeerState b) const noexcept {
        // Minimal mapping aligned with OVS's "opening/established/closing/fin_wait/closed" buckets.
        if (a >= TcpPeerState::FIN_WAIT_2 && b >= TcpPeerState::FIN_WAIT_2) {
            return tp.tcpClose;
        }
        if (a >= TcpPeerState::CLOSING && b >= TcpPeerState::CLOSING) {
            return tp.tcpFinWait;
        }
        if (a < TcpPeerState::ESTABLISHED || b < TcpPeerState::ESTABLISHED) {
            return tp.tcpSynRecv;
        }
        if (a >= TcpPeerState::CLOSING || b >= TcpPeerState::CLOSING) {
            return tp.tcpTimeWait;
        }
        return tp.tcpEstablished;
    }
};

struct Conntrack::ImplV6 {
    Options opt;
    Shared *shared = nullptr;

    struct Endpoint {
        std::array<std::uint8_t, 16> ip{}; // network-byte-order

        // TCP/UDP
        std::uint16_t port = 0;

        // ICMPv6 (echo), see reverseIcmp6Type().
        std::uint8_t icmpType = 0;
        std::uint8_t icmpCode = 0;
        std::uint16_t icmpId = 0;
    };

    struct KeyV6 {
        std::uint32_t uid = 0;
        std::uint8_t proto = 0;
        Endpoint src{};
        Endpoint dst{};
    };

    enum class OtherState : std::uint8_t {
        FIRST = 0,
        MULTIPLE = 1,
        BIDIR = 2,
    };

    enum class IcmpState : std::uint8_t {
        FIRST = 0,
        REPLY = 1,
    };

    enum class TcpPeerState : std::uint8_t {
        CLOSED = 0,
        SYN_SENT = 1,
        ESTABLISHED = 2,
        CLOSING = 3,
        FIN_WAIT_2 = 4,
        TIME_WAIT = 5,
    };

    struct Entry {
        KeyV6 key{};
        KeyV6 revKey{};
        std::atomic<std::uint64_t> expirationNs{0};
        // Flow Telemetry state (best-effort, bounded; used only when telemetry consumer is active).
        struct TelemetryState {
            std::atomic<std::uint64_t> flowInstanceId{0};
            std::atomic<std::uint64_t> sessionId{0};
            std::atomic<std::uint64_t> recordSeq{0};
            std::atomic<bool> exportInProgress{false};

            std::atomic<std::uint64_t> totalPackets{0};
            std::atomic<std::uint64_t> totalBytes{0};
            std::atomic<std::uint64_t> inPackets{0};
            std::atomic<std::uint64_t> inBytes{0};
            std::atomic<std::uint64_t> outPackets{0};
            std::atomic<std::uint64_t> outBytes{0};
            std::atomic<std::uint64_t> firstSeenNs{0};
            std::atomic<std::uint64_t> lastSeenNs{0};

            std::atomic<std::uint64_t> decisionKey{0};
            std::atomic<std::uint32_t> decisionRuleId{0};
            std::atomic<bool> decisionRuleIdKnown{false};

            std::atomic<std::uint64_t> lastExportPackets{0};
            std::atomic<std::uint64_t> lastExportBytes{0};
            std::atomic<std::uint64_t> lastExportTsNs{0};
            std::atomic<std::uint64_t> lastExportDecisionKey{0};
            std::atomic<std::uint32_t> lastExportRuleId{0};
            std::atomic<bool> lastExportRuleIdKnown{false};

            std::atomic<std::uint32_t> lastUserId{0};
            std::atomic<std::uint32_t> lastIfindex{0};
            std::atomic<std::uint8_t> observationKind{0};
            std::atomic<std::uint8_t> flowOriginDir{0};
            std::atomic<std::uint8_t> lastPacketDir{0};
            std::atomic<std::uint8_t> lastVerdict{0};
            std::atomic<std::uint8_t> lastCtState{0};
            std::atomic<std::uint8_t> lastCtDir{0};
            std::atomic<std::uint8_t> lastReasonId{0};
            std::atomic<std::uint8_t> lastIfaceKindBit{0};
            std::atomic<std::uint8_t> lastL4Status{0};
            std::atomic<bool> lastUidKnown{false};
            std::atomic<bool> lastIfindexKnown{false};
            std::atomic<bool> lastPortsAvailable{false};
            std::atomic<bool> pickedUpMidStream{false};
            std::atomic<std::uint8_t> lastIcmpType{0};
            std::atomic<std::uint8_t> lastIcmpCode{0};
            std::atomic<std::uint16_t> lastIcmpId{0};
        } tele{};
        std::atomic<std::uint8_t> state0{0};
        std::atomic<std::uint8_t> state1{0};
        std::atomic<Entry *> next{nullptr};
        Entry *retiredNext = nullptr;
    };

    struct Shard {
        std::mutex mutex;
        std::uint32_t bucketCount = 0;
        std::unique_ptr<std::atomic<Entry *>[]> buckets;
        std::atomic<std::uint32_t> size{0};
        std::uint32_t cursorBucket = 0;
        std::atomic<std::uint64_t> lastHotSweepTsNs{0};
        std::array<Entry *, 3> retired{nullptr, nullptr, nullptr};

        explicit Shard(const std::uint32_t n)
            : bucketCount(n), buckets(std::make_unique<std::atomic<Entry *>[]>(n)) {
            for (std::uint32_t i = 0; i < bucketCount; ++i) {
                buckets[i].store(nullptr, std::memory_order_relaxed);
            }
        }
    };

    struct TimeoutPolicySec {
        std::uint32_t tcpSynSent = 30;
        std::uint32_t tcpSynRecv = 30;
        std::uint32_t tcpEstablished = 24u * 60u * 60u;
        std::uint32_t tcpFinWait = 15u * 60u;
        std::uint32_t tcpTimeWait = 45;
        std::uint32_t tcpClose = 30;
        std::uint32_t udpFirst = 60;
        std::uint32_t udpSingle = 60;
        std::uint32_t udpMultiple = 30;
        std::uint32_t icmpFirst = 60;
        std::uint32_t icmpReply = 30;
    };

    struct Epoch {
        static constexpr std::uint8_t kQuiescent = 0xFF;
        static constexpr std::uint32_t kMaxSlots = 1024;

        struct Slot {
            std::atomic<std::uint8_t> epoch{kQuiescent};
        };

        struct ThreadCache {
            std::uint64_t ownerInstanceId = 0;
            Slot *slot = nullptr;
        };

        std::array<Slot, kMaxSlots> slots{};
        std::atomic<std::uint32_t> used{0};
        std::atomic<std::uint8_t> global{0};
        std::atomic<bool> exhausted{false};
        std::atomic<bool> reclaiming{false};
        const std::uint64_t instanceId = allocateInstanceId();

        static std::uint64_t allocateInstanceId() noexcept {
            static std::atomic<std::uint64_t> nextInstanceId{1};
            return nextInstanceId.fetch_add(1, std::memory_order_relaxed);
        }

        Slot *slotForThread() noexcept {
            thread_local ThreadCache tls{};
            if (tls.ownerInstanceId == instanceId) {
                return tls.slot;
            }
            const std::uint32_t idx = used.fetch_add(1, std::memory_order_relaxed);
            if (idx >= kMaxSlots) {
                exhausted.store(true, std::memory_order_relaxed);
                tls.ownerInstanceId = instanceId;
                tls.slot = nullptr;
                return nullptr;
            }
            tls.ownerInstanceId = instanceId;
            tls.slot = &slots[idx];
            return tls.slot;
        }

        std::uint8_t current() const noexcept { return global.load(std::memory_order_acquire); }

        void enter(Slot *s) noexcept {
            if (!s) {
                return;
            }
            for (;;) {
                while (reclaiming.load(std::memory_order_acquire)) {
                }
                const std::uint8_t observed = current();
                s->epoch.store(observed, std::memory_order_release);
                if (!reclaiming.load(std::memory_order_acquire) &&
                    global.load(std::memory_order_acquire) == observed) {
                    return;
                }
                s->epoch.store(kQuiescent, std::memory_order_release);
            }
        }

        void exit(Slot *s) noexcept {
            if (!s) {
                return;
            }
            s->epoch.store(kQuiescent, std::memory_order_release);
        }

        std::optional<std::uint8_t> beginAdvanceForReclaim() noexcept {
            if (exhausted.load(std::memory_order_relaxed)) {
                return std::nullopt;
            }
            bool expected = false;
            if (!reclaiming.compare_exchange_strong(expected, true, std::memory_order_acq_rel,
                                                    std::memory_order_relaxed)) {
                return std::nullopt;
            }
            const std::uint8_t cur = global.load(std::memory_order_relaxed);
            const std::uint32_t n = used.load(std::memory_order_acquire);
            for (std::uint32_t i = 0; i < n && i < kMaxSlots; ++i) {
                const std::uint8_t e = slots[i].epoch.load(std::memory_order_acquire);
                if (e != kQuiescent) {
                    reclaiming.store(false, std::memory_order_release);
                    return std::nullopt;
                }
            }
            const std::uint8_t next = static_cast<std::uint8_t>((cur + 1u) % 3u);
            global.store(next, std::memory_order_release);
            const std::uint8_t reclaim = static_cast<std::uint8_t>((next + 1u) % 3u);
            return reclaim;
        }

        void endReclaim() noexcept { reclaiming.store(false, std::memory_order_release); }
    };

    static constexpr std::uint64_t kNsPerSec = 1'000'000'000ULL;

    std::uint32_t bucketMask = 0;
    std::vector<std::unique_ptr<Shard>> shards;
    TimeoutPolicySec tp{};
    Epoch epoch{};

    std::atomic<std::uint32_t> totalEntries{0};
    std::atomic<std::uint64_t> creates{0};
    std::atomic<std::uint64_t> expiredRetires{0};
    std::atomic<std::uint64_t> overflowDrops{0};
    std::atomic<std::uint64_t> lastEpochAdvanceTsNs{0};
    static inline bool isPow2(const std::uint32_t v) noexcept {
        return v != 0 && ((v & (v - 1u)) == 0u);
    }

    static inline std::uint32_t clampU32(const std::uint32_t v, const std::uint32_t lo,
                                         const std::uint32_t hi) noexcept {
        return (v < lo) ? lo : (v > hi) ? hi : v;
    }

    static inline std::uint8_t reverseIcmp6Type(const std::uint8_t type) noexcept {
        switch (type) {
        case 128: // Echo request
            return 129;
        case 129: // Echo reply
            return 128;
        default:
            return 0xFF;
        }
    }

    static inline KeyV6 reverseKey(const KeyV6 &k) noexcept {
        KeyV6 r = k;
        std::swap(r.src, r.dst);
        return r;
    }

    static inline bool tcpInvalidFlags(std::uint8_t flags) noexcept {
        // Same loose validation as IPv4 variant.
#ifdef TH_ECE
        flags &= static_cast<std::uint8_t>(~TH_ECE);
#endif
#ifdef TH_CWR
        flags &= static_cast<std::uint8_t>(~TH_CWR);
#endif
        if ((flags & TH_SYN) != 0) {
            if ((flags & (TH_RST | TH_FIN)) != 0) {
                return true;
            }
        } else if ((flags & TH_ACK) == 0 && (flags & TH_RST) == 0) {
            return true;
        }
        if ((flags & TH_ACK) == 0 && (flags & (TH_FIN | TH_PUSH | TH_URG)) != 0) {
            return true;
        }
        return false;
    }

    static inline bool tcpValidNew(const PacketV6 &pkt) noexcept {
        if (!pkt.hasTcp) {
            return false;
        }
        std::uint16_t tcpPayloadLen = 0;
        if (!Conntrack::computeTcpPayloadLen(pkt, tcpPayloadLen)) {
            return false;
        }
        (void)tcpPayloadLen;
        const std::uint8_t flags = pkt.tcp.flags;
        if (tcpInvalidFlags(flags)) {
            return false;
        }
        if ((flags & TH_SYN) != 0 && (flags & TH_ACK) != 0) {
            return false;
        }
        return true;
    }

    static inline bool tcpValidUpdate(const PacketV6 &pkt) noexcept {
        if (!pkt.hasTcp) {
            return false;
        }
        std::uint16_t tcpPayloadLen = 0;
        if (!Conntrack::computeTcpPayloadLen(pkt, tcpPayloadLen)) {
            return false;
        }
        (void)tcpPayloadLen;
        return !tcpInvalidFlags(pkt.tcp.flags);
    }

    static inline bool icmp6ValidNew(const PacketV6 &pkt) noexcept {
        if (!pkt.hasIcmp) {
            return false;
        }
        if (pkt.icmp.code != 0) {
            return false;
        }
        return pkt.icmp.type == 128; // echo request
    }

    static inline bool keyEq(const KeyV6 &a, const KeyV6 &b) noexcept {
        return a.uid == b.uid && a.proto == b.proto && a.src.ip == b.src.ip && a.dst.ip == b.dst.ip &&
            a.src.port == b.src.port && a.dst.port == b.dst.port && a.src.icmpType == b.src.icmpType &&
            a.dst.icmpType == b.dst.icmpType && a.src.icmpCode == b.src.icmpCode &&
            a.dst.icmpCode == b.dst.icmpCode && a.src.icmpId == b.src.icmpId && a.dst.icmpId == b.dst.icmpId;
    }

    static inline std::uint64_t mix(std::uint64_t x) noexcept {
        x ^= x >> 30;
        x *= 0xbf58476d1ce4e5b9ULL;
        x ^= x >> 27;
        x *= 0x94d049bb133111ebULL;
        x ^= x >> 31;
        return x;
    }

    static inline std::uint64_t hashEndpoint(const Endpoint &ep) noexcept {
        std::uint64_t h = 0;
        std::uint64_t a = 0;
        std::uint64_t b = 0;
        std::memcpy(&a, ep.ip.data(), 8);
        std::memcpy(&b, ep.ip.data() + 8, 8);
        h ^= mix(a);
        h ^= mix(b);
        h ^= mix(static_cast<std::uint64_t>(ep.port) << 16 |
                 static_cast<std::uint64_t>(ep.icmpType) << 8 |
                 static_cast<std::uint64_t>(ep.icmpCode));
        h ^= mix(static_cast<std::uint64_t>(ep.icmpId));
        return h;
    }

    static inline std::uint64_t hashKey(const KeyV6 &k) noexcept {
        const std::uint64_t hsrc = hashEndpoint(k.src);
        const std::uint64_t hdst = hashEndpoint(k.dst);
        std::uint64_t h = hsrc ^ hdst;
        h ^= mix(static_cast<std::uint64_t>(k.uid));
        h ^= mix(static_cast<std::uint64_t>(k.proto));
        return h;
    }

    static inline std::uint64_t addTimeoutNs(const std::uint64_t nowNs, const std::uint32_t sec) noexcept {
        const std::uint64_t d = static_cast<std::uint64_t>(sec) * kNsPerSec;
        if (nowNs > std::numeric_limits<std::uint64_t>::max() - d) {
            return std::numeric_limits<std::uint64_t>::max();
        }
        return nowNs + d;
    }

    explicit ImplV6(const Options &o, Shared *shared_) : opt(o), shared(shared_) {
        opt.shards = static_cast<std::uint16_t>(clampU32(opt.shards, 1, 4096));
        if (!isPow2(opt.bucketsPerShard)) {
            opt.bucketsPerShard = 4096;
        }
        if (opt.maxEntries == 0) {
            opt.maxEntries = 1;
        }
        if (opt.sweepMaxBuckets == 0) {
            opt.sweepMaxBuckets = 1;
        }
        if (opt.sweepMaxEntries == 0) {
            opt.sweepMaxEntries = 1;
        }

        bucketMask = opt.bucketsPerShard - 1u;
        shards.reserve(opt.shards);
        for (std::uint16_t i = 0; i < opt.shards; ++i) {
            shards.emplace_back(std::make_unique<Shard>(opt.bucketsPerShard));
        }
    }

    ~ImplV6() {
        for (auto &sp : shards) {
            if (!sp) {
                continue;
            }
            Shard &shard = *sp;
            const std::lock_guard<std::mutex> g(shard.mutex);

            for (std::uint32_t bi = 0; bi < shard.bucketCount; ++bi) {
                Entry *cur = shard.buckets[bi].load(std::memory_order_relaxed);
                shard.buckets[bi].store(nullptr, std::memory_order_relaxed);
                while (cur) {
                    Entry *next = cur->next.load(std::memory_order_relaxed);
                    delete cur;
                    cur = next;
                }
            }

            for (auto &head : shard.retired) {
                Entry *cur = head;
                head = nullptr;
                while (cur) {
                    Entry *next = cur->retiredNext;
                    delete cur;
                    cur = next;
                }
            }
        }
    }

    static inline bool expired(const Entry &e, const std::uint64_t nowNs) noexcept {
        const std::uint64_t exp = e.expirationNs.load(std::memory_order_relaxed);
        return exp != 0 && nowNs >= exp;
    }

    FlowTelemetryRecords::FlowEndReason endReasonForRetire(
        const Entry &e, const FlowTelemetryRecords::FlowEndReason requested) const noexcept {
        if (requested != FlowTelemetryRecords::FlowEndReason::IdleTimeout ||
            e.key.proto != IPPROTO_TCP) {
            return requested;
        }
        const auto s0 = static_cast<TcpPeerState>(e.state0.load(std::memory_order_relaxed));
        const auto s1 = static_cast<TcpPeerState>(e.state1.load(std::memory_order_relaxed));
        if (s0 >= TcpPeerState::CLOSING || s1 >= TcpPeerState::CLOSING) {
            return FlowTelemetryRecords::FlowEndReason::TcpEndDetected;
        }
        return requested;
    }

    bool exportTelemetryEndLocked(Entry &e, const std::uint64_t nowNs,
                                  const FlowTelemetry::HotPath &teleHot,
                                  const FlowTelemetryRecords::FlowEndReason requested) noexcept {
        if (!teleHot.session || !teleHot.cfg || teleHot.sessionId == 0) {
            return false;
        }
        if (e.tele.sessionId.load(std::memory_order_relaxed) != teleHot.sessionId) {
            return false;
        }
        const std::uint64_t flowId = e.tele.flowInstanceId.load(std::memory_order_relaxed);
        const std::uint64_t lastExportTs = e.tele.lastExportTsNs.load(std::memory_order_relaxed);
        if (flowId == 0 || lastExportTs == 0) {
            return false;
        }

        ScopedAtomicBool exportGuard(e.tele.exportInProgress);
        if (!exportGuard) {
            return false;
        }

        const std::uint64_t recordSeq = e.tele.recordSeq.load(std::memory_order_relaxed) + 1;
        const std::uint64_t packedKey = e.tele.decisionKey.load(std::memory_order_relaxed);
        const bool ridKnown = e.tele.decisionRuleIdKnown.load(std::memory_order_relaxed);
        const std::uint32_t ridValue = e.tele.decisionRuleId.load(std::memory_order_relaxed);
        const std::optional<std::uint32_t> rid =
            ridKnown ? std::optional<std::uint32_t>(ridValue) : std::nullopt;
        const std::uint64_t totalPk = e.tele.totalPackets.load(std::memory_order_relaxed);
        const std::uint64_t totalBy = e.tele.totalBytes.load(std::memory_order_relaxed);
        const std::uint64_t inPk = e.tele.inPackets.load(std::memory_order_relaxed);
        const std::uint64_t inBy = e.tele.inBytes.load(std::memory_order_relaxed);
        const std::uint64_t outPk = e.tele.outPackets.load(std::memory_order_relaxed);
        const std::uint64_t outBy = e.tele.outBytes.load(std::memory_order_relaxed);

        std::array<std::byte, 16> src{};
        std::array<std::byte, 16> dst{};
        for (std::size_t i = 0; i < src.size(); ++i) {
            src[i] = static_cast<std::byte>(e.key.src.ip[i]);
            dst[i] = static_cast<std::byte>(e.key.dst.ip[i]);
        }

        FlowTelemetryRecords::FlowV1Fields fields{};
        fields.kind = FlowTelemetryRecords::FlowRecordKind::End;
        fields.observationKind = static_cast<FlowTelemetryRecords::FlowObservationKind>(
            e.tele.observationKind.load(std::memory_order_relaxed));
        fields.ctState = e.tele.lastCtState.load(std::memory_order_relaxed);
        fields.ctDir = e.tele.lastCtDir.load(std::memory_order_relaxed);
        fields.packetDir = static_cast<FlowTelemetryRecords::FlowPacketDirection>(
            e.tele.lastPacketDir.load(std::memory_order_relaxed));
        fields.flowOriginDir = static_cast<FlowTelemetryRecords::FlowPacketDirection>(
            e.tele.flowOriginDir.load(std::memory_order_relaxed));
        fields.verdict = static_cast<FlowTelemetryRecords::FlowVerdict>(
            e.tele.lastVerdict.load(std::memory_order_relaxed));
        fields.reasonId = e.tele.lastReasonId.load(std::memory_order_relaxed);
        fields.ifaceKindBit = e.tele.lastIfaceKindBit.load(std::memory_order_relaxed);
        fields.l4Status = e.tele.lastL4Status.load(std::memory_order_relaxed);
        fields.endReason = endReasonForRetire(e, requested);
        fields.proto = e.key.proto;
        fields.isIpv6 = true;
        fields.pickedUpMidStream = e.tele.pickedUpMidStream.load(std::memory_order_relaxed);
        fields.uidKnown = e.tele.lastUidKnown.load(std::memory_order_relaxed);
        fields.ifindexKnown = e.tele.lastIfindexKnown.load(std::memory_order_relaxed);
        fields.portsAvailable = e.tele.lastPortsAvailable.load(std::memory_order_relaxed);
        fields.srcPort = e.key.src.port;
        fields.dstPort = e.key.dst.port;
        fields.icmpType = e.tele.lastIcmpType.load(std::memory_order_relaxed);
        fields.icmpCode = e.tele.lastIcmpCode.load(std::memory_order_relaxed);
        fields.icmpId = e.tele.lastIcmpId.load(std::memory_order_relaxed);
        fields.timestampNs = nowNs;
        fields.firstSeenNs = e.tele.firstSeenNs.load(std::memory_order_relaxed);
        fields.lastSeenNs = e.tele.lastSeenNs.load(std::memory_order_relaxed);
        fields.flowInstanceId = flowId;
        fields.recordSeq = recordSeq;
        fields.uid = e.key.uid;
        fields.userId = e.tele.lastUserId.load(std::memory_order_relaxed);
        fields.ifindex = e.tele.lastIfindex.load(std::memory_order_relaxed);
        fields.srcAddr = std::span<const std::byte>(src.data(), src.size());
        fields.dstAddr = std::span<const std::byte>(dst.data(), dst.size());
        fields.totalPackets = totalPk;
        fields.totalBytes = totalBy;
        fields.inPackets = inPk;
        fields.inBytes = inBy;
        fields.outPackets = outPk;
        fields.outBytes = outBy;
        fields.ruleId = rid;

        FlowTelemetryRecords::EncodedPayload payload{};
        if (!FlowTelemetryRecords::encodeFlowV1(payload, fields)) {
            return false;
        }
        if (!flowTelemetry.exportRecordHot(teleHot, FlowTelemetryAbi::RecordType::Flow, payload.span())) {
            return false;
        }

        e.tele.recordSeq.store(recordSeq, std::memory_order_relaxed);
        e.tele.lastExportPackets.store(totalPk, std::memory_order_relaxed);
        e.tele.lastExportBytes.store(totalBy, std::memory_order_relaxed);
        e.tele.lastExportTsNs.store(nowNs, std::memory_order_relaxed);
        e.tele.lastExportDecisionKey.store(packedKey, std::memory_order_relaxed);
        e.tele.lastExportRuleId.store(ridValue, std::memory_order_relaxed);
        e.tele.lastExportRuleIdKnown.store(ridKnown, std::memory_order_relaxed);
        return true;
    }

    void retireUnlinkedLocked(Shard &shard, Entry *e, const std::uint8_t retireEpoch) noexcept {
        e->retiredNext = shard.retired[retireEpoch];
        shard.retired[retireEpoch] = e;
        shard.size.fetch_sub(1, std::memory_order_relaxed);
        totalEntries.fetch_sub(1, std::memory_order_relaxed);
        if (shared) {
            shared->totalEntries.fetch_sub(1, std::memory_order_relaxed);
        }
    }

    bool evictOneLocked(Shard &shard, const std::uint64_t nowNs, const std::uint8_t retireEpoch,
                        const FlowTelemetry::HotPath &teleHot) noexcept {
        std::uint32_t scannedBuckets = 0;
        std::uint32_t scannedEntries = 0;
        while (scannedBuckets < opt.sweepMaxBuckets && scannedEntries < opt.sweepMaxEntries) {
            const std::uint32_t bi = shard.cursorBucket & bucketMask;
            shard.cursorBucket = (shard.cursorBucket + 1u) & bucketMask;
            scannedBuckets++;

            Entry *head = shard.buckets[bi].load(std::memory_order_relaxed);
            Entry *prev = nullptr;
            Entry *cur = head;
            while (cur && scannedEntries < opt.sweepMaxEntries) {
                scannedEntries++;
                Entry *next = cur->next.load(std::memory_order_relaxed);
                const bool canEvict =
                    cur->tele.sessionId.load(std::memory_order_relaxed) == teleHot.sessionId &&
                    cur->tele.lastExportTsNs.load(std::memory_order_relaxed) != 0;
                if (!canEvict) {
                    prev = cur;
                    cur = next;
                    continue;
                }

                if (prev) {
                    prev->next.store(next, std::memory_order_relaxed);
                } else {
                    head = next;
                }
                shard.buckets[bi].store(head, std::memory_order_release);
                (void)exportTelemetryEndLocked(
                    *cur, nowNs, teleHot, FlowTelemetryRecords::FlowEndReason::ResourceEvicted);
                retireUnlinkedLocked(shard, cur, retireEpoch);
                return true;
            }
        }
        return false;
    }

    std::uint32_t emitTelemetryDisabledEnds(const std::uint64_t nowNs,
                                            const FlowTelemetry::HotPath &teleHot) noexcept {
        if (!teleHot.session || !teleHot.cfg || teleHot.sessionId == 0) {
            return 0;
        }

        std::uint32_t emitted = 0;
        std::uint32_t scannedBuckets = 0;
        std::uint32_t scannedEntries = 0;
        const std::uint32_t bucketBudget = opt.sweepMaxBuckets;
        const std::uint32_t entryBudget = opt.sweepMaxEntries;
        for (auto &sp : shards) {
            if (!sp || scannedBuckets >= bucketBudget || scannedEntries >= entryBudget) {
                break;
            }
            const std::lock_guard<std::mutex> g(sp->mutex);
            std::uint32_t bi = sp->cursorBucket & bucketMask;
            for (std::uint32_t bucketScans = 0;
                 bucketScans < sp->bucketCount &&
                 scannedBuckets < bucketBudget &&
                 scannedEntries < entryBudget;
                 ++bucketScans, ++scannedBuckets, bi = (bi + 1u) & bucketMask) {
                Entry *cur = sp->buckets[bi].load(std::memory_order_relaxed);
                while (cur && scannedEntries < entryBudget) {
                    scannedEntries++;
                    if (cur->tele.sessionId.load(std::memory_order_relaxed) == teleHot.sessionId &&
                        cur->tele.lastExportTsNs.load(std::memory_order_relaxed) != 0) {
                        if (exportTelemetryEndLocked(
                                *cur, nowNs, teleHot,
                                FlowTelemetryRecords::FlowEndReason::TelemetryDisabled)) {
                            emitted++;
                        }
                    }
                    cur = cur->next.load(std::memory_order_relaxed);
                }
            }
            sp->cursorBucket = bi;
        }
        return emitted;
    }

    void resetTelemetryForSessionLocked(Entry &e, const FlowTelemetry::HotPath &teleHot,
                                        const std::uint64_t pktTsNs,
                                        const FlowTelemetryRecords::FlowPacketDirection packetDir,
                                        const FlowTelemetryRecords::FlowObservationKind observationKind,
                                        const bool inheritFirstSeen,
                                        const bool pickedUpMidStream) noexcept {
        std::uint64_t firstSeenNs = inheritFirstSeen
            ? e.tele.firstSeenNs.load(std::memory_order_relaxed)
            : 0;
        if (firstSeenNs == 0) {
            firstSeenNs = pktTsNs;
        }

        e.tele.flowInstanceId.store(shared->nextFlowInstanceId.fetch_add(1, std::memory_order_relaxed),
                                    std::memory_order_relaxed);
        e.tele.recordSeq.store(0, std::memory_order_relaxed);
        e.tele.totalPackets.store(0, std::memory_order_relaxed);
        e.tele.totalBytes.store(0, std::memory_order_relaxed);
        e.tele.inPackets.store(0, std::memory_order_relaxed);
        e.tele.inBytes.store(0, std::memory_order_relaxed);
        e.tele.outPackets.store(0, std::memory_order_relaxed);
        e.tele.outBytes.store(0, std::memory_order_relaxed);
        e.tele.firstSeenNs.store(firstSeenNs, std::memory_order_relaxed);
        e.tele.lastSeenNs.store(firstSeenNs, std::memory_order_relaxed);
        e.tele.decisionKey.store(0, std::memory_order_relaxed);
        e.tele.decisionRuleId.store(0, std::memory_order_relaxed);
        e.tele.decisionRuleIdKnown.store(false, std::memory_order_relaxed);
        e.tele.lastExportPackets.store(0, std::memory_order_relaxed);
        e.tele.lastExportBytes.store(0, std::memory_order_relaxed);
        e.tele.lastExportTsNs.store(0, std::memory_order_relaxed);
        e.tele.lastExportDecisionKey.store(0, std::memory_order_relaxed);
        e.tele.lastExportRuleId.store(0, std::memory_order_relaxed);
        e.tele.lastExportRuleIdKnown.store(false, std::memory_order_relaxed);
        e.tele.lastUserId.store(0, std::memory_order_relaxed);
        e.tele.lastIfindex.store(0, std::memory_order_relaxed);
        e.tele.observationKind.store(static_cast<std::uint8_t>(observationKind),
                                     std::memory_order_relaxed);
        e.tele.flowOriginDir.store(static_cast<std::uint8_t>(packetDir), std::memory_order_relaxed);
        e.tele.lastPacketDir.store(0, std::memory_order_relaxed);
        e.tele.lastVerdict.store(0, std::memory_order_relaxed);
        e.tele.lastCtState.store(0, std::memory_order_relaxed);
        e.tele.lastCtDir.store(0, std::memory_order_relaxed);
        e.tele.lastReasonId.store(0, std::memory_order_relaxed);
        e.tele.lastIfaceKindBit.store(0, std::memory_order_relaxed);
        e.tele.lastL4Status.store(0, std::memory_order_relaxed);
        e.tele.lastUidKnown.store(false, std::memory_order_relaxed);
        e.tele.lastIfindexKnown.store(false, std::memory_order_relaxed);
        e.tele.lastPortsAvailable.store(false, std::memory_order_relaxed);
        e.tele.pickedUpMidStream.store(pickedUpMidStream, std::memory_order_relaxed);
        e.tele.lastIcmpType.store(0, std::memory_order_relaxed);
        e.tele.lastIcmpCode.store(0, std::memory_order_relaxed);
        e.tele.lastIcmpId.store(0, std::memory_order_relaxed);
        e.tele.sessionId.store(teleHot.sessionId, std::memory_order_release);
    }

    bool ensureTelemetrySession(Entry &e, const FlowTelemetry::HotPath &teleHot,
                                const std::uint64_t pktTsNs,
                                const FlowTelemetryRecords::FlowPacketDirection packetDir,
                                const FlowTelemetryRecords::FlowObservationKind observationKind,
                                const bool l3Observation,
                                const Conntrack::Result &ctResult) noexcept {
        const std::uint64_t currentSession = e.tele.sessionId.load(std::memory_order_acquire);
        if (currentSession == teleHot.sessionId) {
            return true;
        }

        ScopedAtomicBool sessionGuard(e.tele.exportInProgress);
        if (!sessionGuard) {
            return false;
        }
        const std::uint64_t checkedSession = e.tele.sessionId.load(std::memory_order_acquire);
        if (checkedSession == teleHot.sessionId) {
            return true;
        }

        const bool inheritFirstSeen = checkedSession == 0;
        const std::uint64_t priorFirstSeen = e.tele.firstSeenNs.load(std::memory_order_relaxed);
        const bool pickedUp = !l3Observation &&
            (isPickedUpMidStream(ctResult) ||
             (inheritFirstSeen && priorFirstSeen != 0 && priorFirstSeen != pktTsNs));
        resetTelemetryForSessionLocked(e, teleHot, pktTsNs, packetDir, observationKind,
                                       inheritFirstSeen, pickedUp);
        return true;
    }

    std::uint32_t sweepLocked(Shard &shard, const std::uint64_t nowNs, const std::uint8_t retireEpoch) noexcept {
        const FlowTelemetry::HotPath teleHot = flowTelemetry.hotPathFlow();
        const bool telemetryActive = teleHot.session != nullptr && teleHot.cfg != nullptr;

        std::uint32_t removed = 0;
        std::uint32_t scannedBuckets = 0;
        std::uint32_t scannedEntries = 0;

        while (scannedBuckets < opt.sweepMaxBuckets && removed < opt.sweepMaxEntries) {
            const std::uint32_t bi = shard.cursorBucket & bucketMask;
            shard.cursorBucket = (shard.cursorBucket + 1u) & bucketMask;
            scannedBuckets++;

            Entry *head = shard.buckets[bi].load(std::memory_order_relaxed);
            Entry *prev = nullptr;
            Entry *cur = head;

            while (cur && removed < opt.sweepMaxEntries && scannedEntries < opt.sweepMaxEntries) {
                scannedEntries++;
                Entry *next = cur->next.load(std::memory_order_relaxed);
                if (expired(*cur, nowNs)) {
                    if (telemetryActive) {
                        const std::uint64_t flowId =
                            cur->tele.flowInstanceId.load(std::memory_order_relaxed);
                        const std::uint64_t sessionId =
                            cur->tele.sessionId.load(std::memory_order_relaxed);
                        const std::uint64_t packedKey =
                            cur->tele.decisionKey.load(std::memory_order_relaxed);
                        const std::uint64_t lastExportTs =
                            cur->tele.lastExportTsNs.load(std::memory_order_relaxed);
                        if (flowId != 0 && lastExportTs != 0 &&
                            sessionId == teleHot.sessionId) {
                            const std::uint64_t totalPk =
                                cur->tele.totalPackets.load(std::memory_order_relaxed);
                            const std::uint64_t totalBy =
                                cur->tele.totalBytes.load(std::memory_order_relaxed);
                            const std::uint64_t inPk =
                                cur->tele.inPackets.load(std::memory_order_relaxed);
                            const std::uint64_t inBy =
                                cur->tele.inBytes.load(std::memory_order_relaxed);
                            const std::uint64_t outPk =
                                cur->tele.outPackets.load(std::memory_order_relaxed);
                            const std::uint64_t outBy =
                                cur->tele.outBytes.load(std::memory_order_relaxed);
                            const std::uint32_t userId =
                                cur->tele.lastUserId.load(std::memory_order_relaxed);
                            const std::uint32_t ifindex =
                                cur->tele.lastIfindex.load(std::memory_order_relaxed);
                            const bool ridKnown =
                                cur->tele.decisionRuleIdKnown.load(std::memory_order_relaxed);
                            const std::uint32_t ridValue =
                                cur->tele.decisionRuleId.load(std::memory_order_relaxed);
                            const std::optional<std::uint32_t> rid =
                                ridKnown ? std::optional<std::uint32_t>(ridValue) : std::nullopt;

                            ScopedAtomicBool exportGuard(cur->tele.exportInProgress);
                            if (exportGuard) {
                                const std::uint64_t recordSeq =
                                    cur->tele.recordSeq.load(std::memory_order_relaxed) + 1;

                                auto endReason = FlowTelemetryRecords::FlowEndReason::IdleTimeout;
                                if (cur->key.proto == IPPROTO_TCP) {
                                    const auto s0 = static_cast<TcpPeerState>(
                                        cur->state0.load(std::memory_order_relaxed));
                                    const auto s1 = static_cast<TcpPeerState>(
                                        cur->state1.load(std::memory_order_relaxed));
                                    if (s0 >= TcpPeerState::CLOSING || s1 >= TcpPeerState::CLOSING) {
                                        endReason = FlowTelemetryRecords::FlowEndReason::TcpEndDetected;
                                    }
                                }

                                FlowTelemetryRecords::FlowV1Fields fields{};
                                fields.kind = FlowTelemetryRecords::FlowRecordKind::End;
                                fields.observationKind = static_cast<FlowTelemetryRecords::FlowObservationKind>(
                                    cur->tele.observationKind.load(std::memory_order_relaxed));
                                fields.ctState = cur->tele.lastCtState.load(std::memory_order_relaxed);
                                fields.ctDir = cur->tele.lastCtDir.load(std::memory_order_relaxed);
                                fields.packetDir = static_cast<FlowTelemetryRecords::FlowPacketDirection>(
                                    cur->tele.lastPacketDir.load(std::memory_order_relaxed));
                                fields.flowOriginDir = static_cast<FlowTelemetryRecords::FlowPacketDirection>(
                                    cur->tele.flowOriginDir.load(std::memory_order_relaxed));
                                fields.verdict = static_cast<FlowTelemetryRecords::FlowVerdict>(
                                    cur->tele.lastVerdict.load(std::memory_order_relaxed));
                                fields.reasonId = cur->tele.lastReasonId.load(std::memory_order_relaxed);
                                fields.ifaceKindBit = cur->tele.lastIfaceKindBit.load(std::memory_order_relaxed);
                                fields.l4Status = cur->tele.lastL4Status.load(std::memory_order_relaxed);
                                fields.endReason = endReason;
                                fields.proto = cur->key.proto;
                                fields.isIpv6 = true;
                                fields.pickedUpMidStream =
                                    cur->tele.pickedUpMidStream.load(std::memory_order_relaxed);
                                fields.uidKnown = cur->tele.lastUidKnown.load(std::memory_order_relaxed);
                                fields.ifindexKnown = cur->tele.lastIfindexKnown.load(std::memory_order_relaxed);
                                fields.portsAvailable =
                                    cur->tele.lastPortsAvailable.load(std::memory_order_relaxed);
                                fields.srcPort = cur->key.src.port;
                                fields.dstPort = cur->key.dst.port;
                                fields.icmpType = cur->tele.lastIcmpType.load(std::memory_order_relaxed);
                                fields.icmpCode = cur->tele.lastIcmpCode.load(std::memory_order_relaxed);
                                fields.icmpId = cur->tele.lastIcmpId.load(std::memory_order_relaxed);
                                fields.timestampNs = nowNs;
                                fields.firstSeenNs = cur->tele.firstSeenNs.load(std::memory_order_relaxed);
                                fields.lastSeenNs = cur->tele.lastSeenNs.load(std::memory_order_relaxed);
                                fields.flowInstanceId = flowId;
                                fields.recordSeq = recordSeq;
                                fields.uid = cur->key.uid;
                                fields.userId = userId;
                                fields.ifindex = ifindex;
                                fields.srcAddr = std::span<const std::byte>(
                                    reinterpret_cast<const std::byte *>(cur->key.src.ip.data()), 16);
                                fields.dstAddr = std::span<const std::byte>(
                                    reinterpret_cast<const std::byte *>(cur->key.dst.ip.data()), 16);
                                fields.totalPackets = totalPk;
                                fields.totalBytes = totalBy;
                                fields.inPackets = inPk;
                                fields.inBytes = inBy;
                                fields.outPackets = outPk;
                                fields.outBytes = outBy;
                                fields.ruleId = rid;

                                FlowTelemetryRecords::EncodedPayload payload{};
                                if (FlowTelemetryRecords::encodeFlowV1(payload, fields)) {
                                    if (flowTelemetry.exportRecordHot(
                                            teleHot, FlowTelemetryAbi::RecordType::Flow, payload.span())) {
                                        cur->tele.recordSeq.store(recordSeq, std::memory_order_relaxed);
                                        cur->tele.lastExportPackets.store(totalPk, std::memory_order_relaxed);
                                        cur->tele.lastExportBytes.store(totalBy, std::memory_order_relaxed);
                                        cur->tele.lastExportTsNs.store(nowNs, std::memory_order_relaxed);
                                        cur->tele.lastExportDecisionKey.store(packedKey, std::memory_order_relaxed);
                                        cur->tele.lastExportRuleId.store(ridValue, std::memory_order_relaxed);
                                        cur->tele.lastExportRuleIdKnown.store(
                                            ridKnown, std::memory_order_relaxed);
                                    }
                                }
                            }
                        }
                    }

                    if (prev) {
                        prev->next.store(next, std::memory_order_relaxed);
                    } else {
                        head = next;
                    }

                    cur->retiredNext = shard.retired[retireEpoch];
                    shard.retired[retireEpoch] = cur;
                    shard.size.fetch_sub(1, std::memory_order_relaxed);
                    totalEntries.fetch_sub(1, std::memory_order_relaxed);
                    if (shared) {
                        shared->totalEntries.fetch_sub(1, std::memory_order_relaxed);
                    }
                    expiredRetires.fetch_add(1, std::memory_order_relaxed);
                    removed++;
                } else {
                    prev = cur;
                }
                cur = next;
            }

            shard.buckets[bi].store(head, std::memory_order_release);
        }

        return removed;
    }

    void reclaimEpochAllShards(const std::uint8_t epochToReclaim) noexcept {
        for (auto &sp : shards) {
            if (!sp) {
                continue;
            }

            Entry *toFree = nullptr;
            {
                const std::lock_guard<std::mutex> g(sp->mutex);
                toFree = sp->retired[epochToReclaim];
                sp->retired[epochToReclaim] = nullptr;
            }

            while (toFree) {
                Entry *next = toFree->retiredNext;
                delete toFree;
                toFree = next;
            }
        }
    }

    void maybeAdvanceAndReclaim(const std::uint64_t nowNs) noexcept {
        const std::uint64_t minIntervalNs = static_cast<std::uint64_t>(opt.sweepMinIntervalMs) * 1'000'000ULL;
        const std::uint64_t last = lastEpochAdvanceTsNs.load(std::memory_order_relaxed);
        if (minIntervalNs != 0 && nowNs > last && nowNs - last < minIntervalNs) {
            return;
        }
        const auto reclaimEpoch = epoch.beginAdvanceForReclaim();
        if (!reclaimEpoch.has_value()) {
            return;
        }
        lastEpochAdvanceTsNs.store(nowNs, std::memory_order_relaxed);
        reclaimEpochAllShards(*reclaimEpoch);
        epoch.endReclaim();
    }

    bool maybeHotSweep(Shard &shard, const std::uint64_t nowNs) noexcept {
        const std::uint64_t intervalNs = static_cast<std::uint64_t>(opt.sweepMinIntervalMs) * 1'000'000ULL;
        if (intervalNs == 0) {
            return false;
        }
        const std::uint64_t last = shard.lastHotSweepTsNs.load(std::memory_order_relaxed);
        if (nowNs > last && nowNs - last < intervalNs) {
            return false;
        }
        if (!shard.mutex.try_lock()) {
            return false;
        }

        bool retiredAny = false;
        shard.lastHotSweepTsNs.store(nowNs, std::memory_order_relaxed);
        const std::uint8_t retireEpoch = epoch.current();
        const std::uint32_t removed = sweepLocked(shard, nowNs, retireEpoch);
        retiredAny = removed != 0;
        shard.mutex.unlock();

        if (retiredAny) {
            maybeAdvanceAndReclaim(nowNs);
        }
        return retiredAny;
    }

    bool makeKey(const PacketV6 &pkt, KeyV6 &out) noexcept {
        out = KeyV6{};
        out.uid = pkt.uid;
        out.proto = pkt.proto;
        out.src.ip = pkt.srcIp;
        out.dst.ip = pkt.dstIp;

        if (pkt.proto == IPPROTO_TCP) {
            if (!pkt.hasTcp) {
                return false;
            }
            if (pkt.srcPort == 0 || pkt.dstPort == 0) {
                return false;
            }
            out.src.port = pkt.srcPort;
            out.dst.port = pkt.dstPort;
            return true;
        }

        if (pkt.proto == IPPROTO_UDP) {
            if (pkt.srcPort == 0 || pkt.dstPort == 0) {
                return false;
            }
            out.src.port = pkt.srcPort;
            out.dst.port = pkt.dstPort;
            return true;
        }

        if (pkt.proto == IPPROTO_ICMPV6) {
            if (!pkt.hasIcmp) {
                return false;
            }
            const std::uint8_t rtype = reverseIcmp6Type(pkt.icmp.type);
            if (rtype == 0xFF) {
                return false;
            }
            if (pkt.icmp.code != 0) {
                return false;
            }
            out.src.icmpId = pkt.icmp.id;
            out.dst.icmpId = pkt.icmp.id;
            out.src.icmpType = pkt.icmp.type;
            out.dst.icmpType = rtype;
            out.src.icmpCode = pkt.icmp.code;
            out.dst.icmpCode = pkt.icmp.code;
            return true;
        }

        return true;
    }

    bool makeObservationKey(const PacketV6 &pkt, KeyV6 &out) noexcept {
        out = KeyV6{};
        out.uid = pkt.uid;
        out.proto = pkt.proto;
        out.src.ip = pkt.srcIp;
        out.dst.ip = pkt.dstIp;
        out.src.icmpCode = 0xFE;
        out.dst.icmpCode = 0xFE;
        if (pkt.hasIcmp) {
            out.src.icmpType = pkt.icmp.type;
            out.dst.icmpType = pkt.icmp.type;
            out.src.icmpId = pkt.icmp.id;
            out.dst.icmpId = pkt.icmp.id;
        }
        return true;
    }

    std::uint32_t timeoutForOtherState(const OtherState s) const noexcept {
        switch (s) {
        case OtherState::FIRST:
            return tp.udpFirst;
        case OtherState::MULTIPLE:
            return tp.udpMultiple;
        case OtherState::BIDIR:
            return tp.udpSingle;
        }
        return tp.udpFirst;
    }

    std::uint32_t timeoutForIcmpState(const IcmpState s) const noexcept {
        switch (s) {
        case IcmpState::FIRST:
            return tp.icmpFirst;
        case IcmpState::REPLY:
            return tp.icmpReply;
        }
        return tp.icmpFirst;
    }

    std::uint32_t timeoutForTcpPeers(const TcpPeerState a, const TcpPeerState b) const noexcept {
        if (a >= TcpPeerState::FIN_WAIT_2 && b >= TcpPeerState::FIN_WAIT_2) {
            return tp.tcpClose;
        }
        if (a >= TcpPeerState::CLOSING && b >= TcpPeerState::CLOSING) {
            return tp.tcpFinWait;
        }
        if (a < TcpPeerState::ESTABLISHED || b < TcpPeerState::ESTABLISHED) {
            return tp.tcpSynRecv;
        }
        if (a >= TcpPeerState::CLOSING || b >= TcpPeerState::CLOSING) {
            return tp.tcpTimeWait;
        }
        return tp.tcpEstablished;
    }
};

Conntrack::Conntrack() : Conntrack(Options{}) {}

Conntrack::Conntrack(const Options &opt)
    : _shared(std::make_unique<Shared>())
    , _impl4(std::make_unique<ImplV4>(opt, _shared.get()))
    , _impl6(std::make_unique<ImplV6>(opt, _shared.get())) {}

Conntrack::~Conntrack() = default;

bool Conntrack::computeTcpPayloadLen(const PacketV4 &pkt, std::uint16_t &outPayloadLen) noexcept {
    if (!pkt.hasTcp) {
        return false;
    }
    if (pkt.tcp.dataOffsetWords < 5) {
        return false;
    }
    const std::uint16_t tcpHdrLen = static_cast<std::uint16_t>(pkt.tcp.dataOffsetWords) * 4u;
    if (tcpHdrLen > pkt.ipPayloadLen) {
        return false;
    }
    outPayloadLen = static_cast<std::uint16_t>(pkt.ipPayloadLen - tcpHdrLen);
    return true;
}

bool Conntrack::computeTcpPayloadLen(const PacketV6 &pkt, std::uint16_t &outPayloadLen) noexcept {
    if (!pkt.hasTcp) {
        return false;
    }
    if (pkt.tcp.dataOffsetWords < 5) {
        return false;
    }
    const std::uint16_t tcpHdrLen = static_cast<std::uint16_t>(pkt.tcp.dataOffsetWords) * 4u;
    if (tcpHdrLen > pkt.ipPayloadLen) {
        return false;
    }
    outPayloadLen = static_cast<std::uint16_t>(pkt.ipPayloadLen - tcpHdrLen);
    return true;
}

Conntrack::PolicyView Conntrack::inspectForPolicy(const PacketV4 &pkt) noexcept {
    PolicyView view{};
    Result &r = view.result;
    if (!_impl4) {
        r.state = CtState::INVALID;
        r.direction = CtDirection::ANY;
        return view;
    }
    if (pkt.isFragment) {
        r.state = CtState::INVALID;
        r.direction = CtDirection::ANY;
        return view;
    }

    ImplV4::KeyV4 key{};
    if (!_impl4->makeKey(pkt, key)) {
        r.state = CtState::INVALID;
        r.direction = CtDirection::ANY;
        return view;
    }

    const std::uint64_t h = ImplV4::hashKey(key);
    const std::uint32_t shardIndex = static_cast<std::uint32_t>(h % _impl4->shards.size());
    const std::uint32_t bucketIndex = static_cast<std::uint32_t>(h) & _impl4->bucketMask;
    ImplV4::Shard &shard = *_impl4->shards[shardIndex];

    const auto epochSlot = _impl4->epoch.slotForThread();
    struct EpochGuard {
        ImplV4::Epoch &epoch;
        ImplV4::Epoch::Slot *slot = nullptr;
        EpochGuard(ImplV4::Epoch &e, ImplV4::Epoch::Slot *s) noexcept : epoch(e), slot(s) {
            epoch.enter(slot);
        }
        ~EpochGuard() { epoch.exit(slot); }
    } epochGuard(_impl4->epoch, epochSlot);

    // Optional best-effort sweep on hot path (interval + try_lock; never blocks verdict).
    (void)_impl4->maybeHotSweep(shard, pkt.tsNs);

    const auto isExpired = [&](const ImplV4::Entry &e) noexcept -> bool {
        const std::uint64_t exp = e.expirationNs.load(std::memory_order_relaxed);
        return exp != 0 && pkt.tsNs >= exp;
    };

    const auto updateExisting = [&](ImplV4::Entry &e, const bool isReply) noexcept -> CtState {
        if (pkt.proto == IPPROTO_TCP) {
            if (!ImplV4::tcpValidUpdate(pkt)) {
                return CtState::INVALID;
            }

            const std::uint8_t flags = pkt.tcp.flags;
            const int srcIdx = isReply ? 1 : 0;
            const int dstIdx = isReply ? 0 : 1;
            std::atomic<std::uint8_t> &srcState = (srcIdx == 0) ? e.state0 : e.state1;
            std::atomic<std::uint8_t> &dstState = (dstIdx == 0) ? e.state0 : e.state1;

            const auto bumpAtLeast = [&](std::atomic<std::uint8_t> &st,
                                         const ImplV4::TcpPeerState target) noexcept {
                std::uint8_t cur = st.load(std::memory_order_relaxed);
                const auto want = static_cast<std::uint8_t>(target);
                while (cur < want && !st.compare_exchange_weak(cur, want, std::memory_order_relaxed)) {
                }
            };

            if ((flags & TH_SYN) != 0) {
                bumpAtLeast(srcState, ImplV4::TcpPeerState::SYN_SENT);
            }
            if ((flags & TH_FIN) != 0) {
                bumpAtLeast(srcState, ImplV4::TcpPeerState::CLOSING);
            }
            if ((flags & TH_ACK) != 0) {
                const std::uint8_t dstCur = dstState.load(std::memory_order_relaxed);
                if (dstCur == static_cast<std::uint8_t>(ImplV4::TcpPeerState::SYN_SENT)) {
                    bumpAtLeast(dstState, ImplV4::TcpPeerState::ESTABLISHED);
                } else if (dstCur == static_cast<std::uint8_t>(ImplV4::TcpPeerState::CLOSING)) {
                    bumpAtLeast(dstState, ImplV4::TcpPeerState::FIN_WAIT_2);
                }
            }
            if ((flags & TH_RST) != 0) {
                e.state0.store(static_cast<std::uint8_t>(ImplV4::TcpPeerState::TIME_WAIT),
                               std::memory_order_relaxed);
                e.state1.store(static_cast<std::uint8_t>(ImplV4::TcpPeerState::TIME_WAIT),
                               std::memory_order_relaxed);
            }

            const auto p0 = static_cast<ImplV4::TcpPeerState>(e.state0.load(std::memory_order_relaxed));
            const auto p1 = static_cast<ImplV4::TcpPeerState>(e.state1.load(std::memory_order_relaxed));
            e.expirationNs.store(ImplV4::addTimeoutNs(pkt.tsNs, _impl4->timeoutForTcpPeers(p0, p1)),
                                 std::memory_order_relaxed);

            // OVS: once a TCP conn entry exists, all subsequent packets are +est (not +new).
            return CtState::ESTABLISHED;
        }

        if (pkt.proto == IPPROTO_ICMP) {
            auto st = static_cast<ImplV4::IcmpState>(e.state0.load(std::memory_order_relaxed));
            if (isReply && st == ImplV4::IcmpState::FIRST) {
                std::uint8_t expected = static_cast<std::uint8_t>(ImplV4::IcmpState::FIRST);
                (void)e.state0.compare_exchange_strong(expected,
                                                      static_cast<std::uint8_t>(ImplV4::IcmpState::REPLY),
                                                      std::memory_order_relaxed);
                st = static_cast<ImplV4::IcmpState>(e.state0.load(std::memory_order_relaxed));
            }
            e.expirationNs.store(ImplV4::addTimeoutNs(pkt.tsNs, _impl4->timeoutForIcmpState(st)),
                                 std::memory_order_relaxed);
            return st == ImplV4::IcmpState::REPLY ? CtState::ESTABLISHED : CtState::NEW;
        }

        // other (includes UDP)
        auto st = static_cast<ImplV4::OtherState>(e.state0.load(std::memory_order_relaxed));
        if (isReply && st != ImplV4::OtherState::BIDIR) {
            e.state0.store(static_cast<std::uint8_t>(ImplV4::OtherState::BIDIR),
                           std::memory_order_relaxed);
            st = ImplV4::OtherState::BIDIR;
        } else if (!isReply && st == ImplV4::OtherState::FIRST) {
            std::uint8_t expected = static_cast<std::uint8_t>(ImplV4::OtherState::FIRST);
            (void)e.state0.compare_exchange_strong(expected,
                                                  static_cast<std::uint8_t>(ImplV4::OtherState::MULTIPLE),
                                                  std::memory_order_relaxed);
            st = static_cast<ImplV4::OtherState>(e.state0.load(std::memory_order_relaxed));
        }
        e.expirationNs.store(ImplV4::addTimeoutNs(pkt.tsNs, _impl4->timeoutForOtherState(st)),
                             std::memory_order_relaxed);
        return st == ImplV4::OtherState::BIDIR ? CtState::ESTABLISHED : CtState::NEW;
    };

    // Fast path: lockless bucket traversal (safe while we don't unlink/free yet).
    {
        ImplV4::Entry *cur = shard.buckets[bucketIndex].load(std::memory_order_acquire);
        while (cur) {
            if (ImplV4::keyEq(cur->key, key) || ImplV4::keyEq(cur->revKey, key)) {
                if (isExpired(*cur)) {
                    break;
                }

                const bool isReply = ImplV4::keyEq(cur->revKey, key);
                const CtState st = updateExisting(*cur, isReply);
                if (st == CtState::INVALID) {
                    r.state = CtState::INVALID;
                    r.direction = CtDirection::ANY;
                } else {
                    r.state = st;
                    r.direction = isReply ? CtDirection::REPLY : CtDirection::ORIG;
                }
                return view;
            }
            cur = cur->next.load(std::memory_order_relaxed);
        }
    }

    // Create path: shard structure lock + double-check.
    bool didRetire = false;
    {
        const std::lock_guard<std::mutex> g(shard.mutex);
        ImplV4::Entry *cur = shard.buckets[bucketIndex].load(std::memory_order_acquire);
        while (cur) {
            if (ImplV4::keyEq(cur->key, key) || ImplV4::keyEq(cur->revKey, key)) {
                if (!isExpired(*cur)) {
                    const bool isReply = ImplV4::keyEq(cur->revKey, key);
                    const CtState st = updateExisting(*cur, isReply);
                    if (st == CtState::INVALID) {
                        r.state = CtState::INVALID;
                        r.direction = CtDirection::ANY;
                    } else {
                        r.state = st;
                        r.direction = isReply ? CtDirection::REPLY : CtDirection::ORIG;
                    }
                    return view;
                }
                break;
            }
            cur = cur->next.load(std::memory_order_relaxed);
        }

        // Miss: run a small budgeted sweep under shard lock before attempting insert.
        const std::uint8_t retireEpoch = _impl4->epoch.current();
        const std::uint32_t swept = _impl4->sweepLocked(shard, pkt.tsNs, retireEpoch);
        didRetire = didRetire || swept != 0;

        const std::uint32_t n = _impl4->shared ? _impl4->shared->totalEntries.load(std::memory_order_relaxed)
                                               : _impl4->totalEntries.load(std::memory_order_relaxed);
        if (n >= _impl4->opt.maxEntries) {
            _impl4->overflowDrops.fetch_add(1, std::memory_order_relaxed);
            r.state = CtState::INVALID;
            r.direction = CtDirection::ANY;
            return view;
        }

        if (pkt.proto == IPPROTO_TCP && !ImplV4::tcpValidNew(pkt)) {
            r.state = CtState::INVALID;
            r.direction = CtDirection::ANY;
            return view;
        }
        if (pkt.proto == IPPROTO_ICMP && !ImplV4::icmp4ValidNew(pkt)) {
            r.state = CtState::INVALID;
            r.direction = CtDirection::ANY;
            return view;
        }
        r.state = CtState::NEW;
        r.direction = CtDirection::ORIG;
        view.createOnAccept = true;
    }

    if (didRetire) {
        _impl4->maybeAdvanceAndReclaim(pkt.tsNs);
    }
    return view;
}

void Conntrack::commitAccepted(const PacketV4 &pkt, const PolicyView &view) noexcept {
    if (!_impl4 || !view.createOnAccept || view.result.state != CtState::NEW ||
        view.result.direction != CtDirection::ORIG) {
        return;
    }

    ImplV4::KeyV4 key{};
    if (!_impl4->makeKey(pkt, key)) {
        return;
    }

    const std::uint64_t h = ImplV4::hashKey(key);
    const std::uint32_t shardIndex = static_cast<std::uint32_t>(h % _impl4->shards.size());
    const std::uint32_t bucketIndex = static_cast<std::uint32_t>(h) & _impl4->bucketMask;
    ImplV4::Shard &shard = *_impl4->shards[shardIndex];

    const auto isExpired = [&](const ImplV4::Entry &e) noexcept -> bool {
        const std::uint64_t exp = e.expirationNs.load(std::memory_order_relaxed);
        return exp != 0 && pkt.tsNs >= exp;
    };

    bool didRetire = false;
    {
        const std::lock_guard<std::mutex> g(shard.mutex);
        ImplV4::Entry *cur = shard.buckets[bucketIndex].load(std::memory_order_acquire);
        while (cur) {
            if (ImplV4::keyEq(cur->key, key) || ImplV4::keyEq(cur->revKey, key)) {
                if (!isExpired(*cur)) {
                    return;
                }
                break;
            }
            cur = cur->next.load(std::memory_order_relaxed);
        }

        const std::uint8_t retireEpoch = _impl4->epoch.current();
        const std::uint32_t swept = _impl4->sweepLocked(shard, pkt.tsNs, retireEpoch);
        didRetire = swept != 0;

        if (pkt.proto == IPPROTO_TCP && !ImplV4::tcpValidNew(pkt)) {
            return;
        }
        if (pkt.proto == IPPROTO_ICMP && !ImplV4::icmp4ValidNew(pkt)) {
            return;
        }

        auto *e = new (std::nothrow) ImplV4::Entry();
        if (!e) {
            return;
        }

        if (_impl4->shared) {
            const std::uint32_t prev =
                _impl4->shared->totalEntries.fetch_add(1, std::memory_order_relaxed);
            if (prev >= _impl4->opt.maxEntries) {
                _impl4->shared->totalEntries.fetch_sub(1, std::memory_order_relaxed);
                _impl4->overflowDrops.fetch_add(1, std::memory_order_relaxed);
                delete e;
                return;
            }
        }

        e->key = key;
        e->revKey = ImplV4::reverseKey(key);
        e->tele.flowInstanceId.store(_impl4->shared->nextFlowInstanceId.fetch_add(1, std::memory_order_relaxed),
                                     std::memory_order_relaxed);
        e->tele.firstSeenNs.store(pkt.tsNs, std::memory_order_relaxed);
        e->tele.lastSeenNs.store(pkt.tsNs, std::memory_order_relaxed);
        if (pkt.proto == IPPROTO_TCP) {
            e->state0.store(static_cast<std::uint8_t>(ImplV4::TcpPeerState::SYN_SENT),
                            std::memory_order_relaxed);
            e->state1.store(static_cast<std::uint8_t>(ImplV4::TcpPeerState::CLOSED),
                            std::memory_order_relaxed);
            e->expirationNs.store(ImplV4::addTimeoutNs(pkt.tsNs, _impl4->tp.tcpSynSent),
                                  std::memory_order_relaxed);
        } else if (pkt.proto == IPPROTO_ICMP) {
            e->state0.store(static_cast<std::uint8_t>(ImplV4::IcmpState::FIRST),
                            std::memory_order_relaxed);
            e->expirationNs.store(ImplV4::addTimeoutNs(pkt.tsNs, _impl4->tp.icmpFirst),
                                  std::memory_order_relaxed);
        } else {
            e->state0.store(static_cast<std::uint8_t>(ImplV4::OtherState::FIRST),
                            std::memory_order_relaxed);
            e->expirationNs.store(ImplV4::addTimeoutNs(pkt.tsNs, _impl4->tp.udpFirst),
                                  std::memory_order_relaxed);
        }

        e->next.store(shard.buckets[bucketIndex].load(std::memory_order_relaxed),
                      std::memory_order_relaxed);
        shard.buckets[bucketIndex].store(e, std::memory_order_release);
        shard.size.fetch_add(1, std::memory_order_relaxed);
        _impl4->totalEntries.fetch_add(1, std::memory_order_relaxed);
        _impl4->creates.fetch_add(1, std::memory_order_relaxed);
    }

    if (didRetire) {
        _impl4->maybeAdvanceAndReclaim(pkt.tsNs);
    }
}

Conntrack::Result Conntrack::update(const PacketV4 &pkt) noexcept {
    const auto view = inspectForPolicy(pkt);
    commitAccepted(pkt, view);
    return view.result;
}

Conntrack::PolicyView Conntrack::inspectForPolicy(const PacketV6 &pkt) noexcept {
    PolicyView view{};
    Result &r = view.result;
    if (!_impl6) {
        r.state = CtState::INVALID;
        r.direction = CtDirection::ANY;
        return view;
    }
    if (pkt.isFragment) {
        r.state = CtState::INVALID;
        r.direction = CtDirection::ANY;
        return view;
    }

    ImplV6::KeyV6 key{};
    if (!_impl6->makeKey(pkt, key)) {
        r.state = CtState::INVALID;
        r.direction = CtDirection::ANY;
        return view;
    }

    const std::uint64_t h = ImplV6::hashKey(key);
    const std::uint32_t shardIndex = static_cast<std::uint32_t>(h % _impl6->shards.size());
    const std::uint32_t bucketIndex = static_cast<std::uint32_t>(h) & _impl6->bucketMask;
    ImplV6::Shard &shard = *_impl6->shards[shardIndex];

    const auto epochSlot = _impl6->epoch.slotForThread();
    struct EpochGuard {
        ImplV6::Epoch &epoch;
        ImplV6::Epoch::Slot *slot = nullptr;
        EpochGuard(ImplV6::Epoch &e, ImplV6::Epoch::Slot *s) noexcept : epoch(e), slot(s) {
            epoch.enter(slot);
        }
        ~EpochGuard() { epoch.exit(slot); }
    } epochGuard(_impl6->epoch, epochSlot);

    (void)_impl6->maybeHotSweep(shard, pkt.tsNs);

    const auto isExpired = [&](const ImplV6::Entry &e) noexcept -> bool {
        const std::uint64_t exp = e.expirationNs.load(std::memory_order_relaxed);
        return exp != 0 && pkt.tsNs >= exp;
    };

    const auto updateExisting = [&](ImplV6::Entry &e, const bool isReply) noexcept -> CtState {
        if (pkt.proto == IPPROTO_TCP) {
            if (!ImplV6::tcpValidUpdate(pkt)) {
                return CtState::INVALID;
            }

            const std::uint8_t flags = pkt.tcp.flags;
            const int srcIdx = isReply ? 1 : 0;
            const int dstIdx = isReply ? 0 : 1;
            std::atomic<std::uint8_t> &srcState = (srcIdx == 0) ? e.state0 : e.state1;
            std::atomic<std::uint8_t> &dstState = (dstIdx == 0) ? e.state0 : e.state1;

            const auto bumpAtLeast = [&](std::atomic<std::uint8_t> &st,
                                         const ImplV6::TcpPeerState target) noexcept {
                std::uint8_t cur = st.load(std::memory_order_relaxed);
                const auto want = static_cast<std::uint8_t>(target);
                while (cur < want && !st.compare_exchange_weak(cur, want, std::memory_order_relaxed)) {
                }
            };

            if ((flags & TH_SYN) != 0) {
                bumpAtLeast(srcState, ImplV6::TcpPeerState::SYN_SENT);
            }
            if ((flags & TH_FIN) != 0) {
                bumpAtLeast(srcState, ImplV6::TcpPeerState::CLOSING);
            }
            if ((flags & TH_ACK) != 0) {
                const std::uint8_t dstCur = dstState.load(std::memory_order_relaxed);
                if (dstCur == static_cast<std::uint8_t>(ImplV6::TcpPeerState::SYN_SENT)) {
                    bumpAtLeast(dstState, ImplV6::TcpPeerState::ESTABLISHED);
                } else if (dstCur == static_cast<std::uint8_t>(ImplV6::TcpPeerState::CLOSING)) {
                    bumpAtLeast(dstState, ImplV6::TcpPeerState::FIN_WAIT_2);
                }
            }
            if ((flags & TH_RST) != 0) {
                e.state0.store(static_cast<std::uint8_t>(ImplV6::TcpPeerState::TIME_WAIT),
                               std::memory_order_relaxed);
                e.state1.store(static_cast<std::uint8_t>(ImplV6::TcpPeerState::TIME_WAIT),
                               std::memory_order_relaxed);
            }

            const auto p0 = static_cast<ImplV6::TcpPeerState>(e.state0.load(std::memory_order_relaxed));
            const auto p1 = static_cast<ImplV6::TcpPeerState>(e.state1.load(std::memory_order_relaxed));
            e.expirationNs.store(ImplV6::addTimeoutNs(pkt.tsNs, _impl6->timeoutForTcpPeers(p0, p1)),
                                 std::memory_order_relaxed);
            return CtState::ESTABLISHED;
        }

        if (pkt.proto == IPPROTO_ICMPV6) {
            auto st = static_cast<ImplV6::IcmpState>(e.state0.load(std::memory_order_relaxed));
            if (isReply && st == ImplV6::IcmpState::FIRST) {
                std::uint8_t expected = static_cast<std::uint8_t>(ImplV6::IcmpState::FIRST);
                (void)e.state0.compare_exchange_strong(expected,
                                                      static_cast<std::uint8_t>(ImplV6::IcmpState::REPLY),
                                                      std::memory_order_relaxed);
                st = static_cast<ImplV6::IcmpState>(e.state0.load(std::memory_order_relaxed));
            }
            e.expirationNs.store(ImplV6::addTimeoutNs(pkt.tsNs, _impl6->timeoutForIcmpState(st)),
                                 std::memory_order_relaxed);
            return st == ImplV6::IcmpState::REPLY ? CtState::ESTABLISHED : CtState::NEW;
        }

        auto st = static_cast<ImplV6::OtherState>(e.state0.load(std::memory_order_relaxed));
        if (isReply && st != ImplV6::OtherState::BIDIR) {
            e.state0.store(static_cast<std::uint8_t>(ImplV6::OtherState::BIDIR),
                           std::memory_order_relaxed);
            st = ImplV6::OtherState::BIDIR;
        } else if (!isReply && st == ImplV6::OtherState::FIRST) {
            std::uint8_t expected = static_cast<std::uint8_t>(ImplV6::OtherState::FIRST);
            (void)e.state0.compare_exchange_strong(expected,
                                                  static_cast<std::uint8_t>(ImplV6::OtherState::MULTIPLE),
                                                  std::memory_order_relaxed);
            st = static_cast<ImplV6::OtherState>(e.state0.load(std::memory_order_relaxed));
        }
        e.expirationNs.store(ImplV6::addTimeoutNs(pkt.tsNs, _impl6->timeoutForOtherState(st)),
                             std::memory_order_relaxed);
        return st == ImplV6::OtherState::BIDIR ? CtState::ESTABLISHED : CtState::NEW;
    };

    {
        ImplV6::Entry *cur = shard.buckets[bucketIndex].load(std::memory_order_acquire);
        while (cur) {
            if (ImplV6::keyEq(cur->key, key) || ImplV6::keyEq(cur->revKey, key)) {
                if (isExpired(*cur)) {
                    break;
                }

                const bool isReply = ImplV6::keyEq(cur->revKey, key);
                const CtState st = updateExisting(*cur, isReply);
                if (st == CtState::INVALID) {
                    r.state = CtState::INVALID;
                    r.direction = CtDirection::ANY;
                } else {
                    r.state = st;
                    r.direction = isReply ? CtDirection::REPLY : CtDirection::ORIG;
                }
                return view;
            }
            cur = cur->next.load(std::memory_order_relaxed);
        }
    }

    bool didRetire = false;
    {
        const std::lock_guard<std::mutex> g(shard.mutex);
        ImplV6::Entry *cur = shard.buckets[bucketIndex].load(std::memory_order_acquire);
        while (cur) {
            if (ImplV6::keyEq(cur->key, key) || ImplV6::keyEq(cur->revKey, key)) {
                if (!isExpired(*cur)) {
                    const bool isReply = ImplV6::keyEq(cur->revKey, key);
                    const CtState st = updateExisting(*cur, isReply);
                    if (st == CtState::INVALID) {
                        r.state = CtState::INVALID;
                        r.direction = CtDirection::ANY;
                    } else {
                        r.state = st;
                        r.direction = isReply ? CtDirection::REPLY : CtDirection::ORIG;
                    }
                    return view;
                }
                break;
            }
            cur = cur->next.load(std::memory_order_relaxed);
        }

        const std::uint8_t retireEpoch = _impl6->epoch.current();
        const std::uint32_t swept = _impl6->sweepLocked(shard, pkt.tsNs, retireEpoch);
        didRetire = didRetire || swept != 0;

        const std::uint32_t n = _impl6->shared ? _impl6->shared->totalEntries.load(std::memory_order_relaxed)
                                               : _impl6->totalEntries.load(std::memory_order_relaxed);
        if (n >= _impl6->opt.maxEntries) {
            _impl6->overflowDrops.fetch_add(1, std::memory_order_relaxed);
            r.state = CtState::INVALID;
            r.direction = CtDirection::ANY;
            return view;
        }

        if (pkt.proto == IPPROTO_TCP && !ImplV6::tcpValidNew(pkt)) {
            r.state = CtState::INVALID;
            r.direction = CtDirection::ANY;
            return view;
        }
        if (pkt.proto == IPPROTO_ICMPV6 && !ImplV6::icmp6ValidNew(pkt)) {
            r.state = CtState::INVALID;
            r.direction = CtDirection::ANY;
            return view;
        }
        r.state = CtState::NEW;
        r.direction = CtDirection::ORIG;
        view.createOnAccept = true;
    }

    if (didRetire) {
        _impl6->maybeAdvanceAndReclaim(pkt.tsNs);
    }
    return view;
}

void Conntrack::commitAccepted(const PacketV6 &pkt, const PolicyView &view) noexcept {
    if (!_impl6 || !view.createOnAccept || view.result.state != CtState::NEW ||
        view.result.direction != CtDirection::ORIG) {
        return;
    }

    ImplV6::KeyV6 key{};
    if (!_impl6->makeKey(pkt, key)) {
        return;
    }

    const std::uint64_t h = ImplV6::hashKey(key);
    const std::uint32_t shardIndex = static_cast<std::uint32_t>(h % _impl6->shards.size());
    const std::uint32_t bucketIndex = static_cast<std::uint32_t>(h) & _impl6->bucketMask;
    ImplV6::Shard &shard = *_impl6->shards[shardIndex];

    const auto isExpired = [&](const ImplV6::Entry &e) noexcept -> bool {
        const std::uint64_t exp = e.expirationNs.load(std::memory_order_relaxed);
        return exp != 0 && pkt.tsNs >= exp;
    };

    bool didRetire = false;
    {
        const std::lock_guard<std::mutex> g(shard.mutex);
        ImplV6::Entry *cur = shard.buckets[bucketIndex].load(std::memory_order_acquire);
        while (cur) {
            if (ImplV6::keyEq(cur->key, key) || ImplV6::keyEq(cur->revKey, key)) {
                if (!isExpired(*cur)) {
                    return;
                }
                break;
            }
            cur = cur->next.load(std::memory_order_relaxed);
        }

        const std::uint8_t retireEpoch = _impl6->epoch.current();
        const std::uint32_t swept = _impl6->sweepLocked(shard, pkt.tsNs, retireEpoch);
        didRetire = swept != 0;

        if (pkt.proto == IPPROTO_TCP && !ImplV6::tcpValidNew(pkt)) {
            return;
        }
        if (pkt.proto == IPPROTO_ICMPV6 && !ImplV6::icmp6ValidNew(pkt)) {
            return;
        }

        auto *e = new (std::nothrow) ImplV6::Entry();
        if (!e) {
            return;
        }

        if (_impl6->shared) {
            const std::uint32_t prev =
                _impl6->shared->totalEntries.fetch_add(1, std::memory_order_relaxed);
            if (prev >= _impl6->opt.maxEntries) {
                _impl6->shared->totalEntries.fetch_sub(1, std::memory_order_relaxed);
                _impl6->overflowDrops.fetch_add(1, std::memory_order_relaxed);
                delete e;
                return;
            }
        }

        e->key = key;
        e->revKey = ImplV6::reverseKey(key);
        e->tele.flowInstanceId.store(_impl6->shared->nextFlowInstanceId.fetch_add(1, std::memory_order_relaxed),
                                     std::memory_order_relaxed);
        e->tele.firstSeenNs.store(pkt.tsNs, std::memory_order_relaxed);
        e->tele.lastSeenNs.store(pkt.tsNs, std::memory_order_relaxed);
        if (pkt.proto == IPPROTO_TCP) {
            e->state0.store(static_cast<std::uint8_t>(ImplV6::TcpPeerState::SYN_SENT),
                            std::memory_order_relaxed);
            e->state1.store(static_cast<std::uint8_t>(ImplV6::TcpPeerState::CLOSED),
                            std::memory_order_relaxed);
            e->expirationNs.store(ImplV6::addTimeoutNs(pkt.tsNs, _impl6->tp.tcpSynSent),
                                  std::memory_order_relaxed);
        } else if (pkt.proto == IPPROTO_ICMPV6) {
            e->state0.store(static_cast<std::uint8_t>(ImplV6::IcmpState::FIRST),
                            std::memory_order_relaxed);
            e->expirationNs.store(ImplV6::addTimeoutNs(pkt.tsNs, _impl6->tp.icmpFirst),
                                  std::memory_order_relaxed);
        } else {
            e->state0.store(static_cast<std::uint8_t>(ImplV6::OtherState::FIRST),
                            std::memory_order_relaxed);
            e->expirationNs.store(ImplV6::addTimeoutNs(pkt.tsNs, _impl6->tp.udpFirst),
                                  std::memory_order_relaxed);
        }

        e->next.store(shard.buckets[bucketIndex].load(std::memory_order_relaxed),
                      std::memory_order_relaxed);
        shard.buckets[bucketIndex].store(e, std::memory_order_release);
        shard.size.fetch_add(1, std::memory_order_relaxed);
        _impl6->totalEntries.fetch_add(1, std::memory_order_relaxed);
        _impl6->creates.fetch_add(1, std::memory_order_relaxed);
    }

    if (didRetire) {
        _impl6->maybeAdvanceAndReclaim(pkt.tsNs);
    }
}

Conntrack::Result Conntrack::update(const PacketV6 &pkt) noexcept {
    const auto view = inspectForPolicy(pkt);
    commitAccepted(pkt, view);
    return view.result;
}

void Conntrack::observeFlowTelemetry(const PacketV4 &pkt, const Result &ctResult,
                                     const FlowTelemetry::HotPath &teleHot,
                                     const TelemetryPacketFacts &facts) noexcept {
    if (!_impl4) {
        return;
    }
    if (!teleHot.session || !teleHot.cfg) {
        return;
    }

    if (facts.srcAddrNet.size() != 4 || facts.dstAddrNet.size() != 4) {
        return;
    }

    const bool l3Observation = isL3ObservationStatus(facts.l4Status);
    ImplV4::KeyV4 key{};
    if (!_impl4->makeKey(pkt, key)) {
        if (!l3Observation || !_impl4->makeObservationKey(pkt, key)) {
            return;
        }
    }

    const std::uint64_t h = ImplV4::hashKey(key);
    const std::uint32_t shardIndex = static_cast<std::uint32_t>(h % _impl4->shards.size());
    const std::uint32_t bucketIndex = static_cast<std::uint32_t>(h) & _impl4->bucketMask;
    ImplV4::Shard &shard = *_impl4->shards[shardIndex];

    const auto epochSlot = _impl4->epoch.slotForThread();
    struct EpochGuard {
        ImplV4::Epoch &epoch;
        ImplV4::Epoch::Slot *slot = nullptr;
        EpochGuard(ImplV4::Epoch &e, ImplV4::Epoch::Slot *s) noexcept : epoch(e), slot(s) {
            epoch.enter(slot);
        }
        ~EpochGuard() { epoch.exit(slot); }
    } epochGuard(_impl4->epoch, epochSlot);

    const auto isExpired = [&](const ImplV4::Entry &e) noexcept -> bool {
        const std::uint64_t exp = e.expirationNs.load(std::memory_order_relaxed);
        return exp != 0 && pkt.tsNs >= exp;
    };

    ImplV4::Entry *e = nullptr;
    // Lock-free search first.
    {
        ImplV4::Entry *cur = shard.buckets[bucketIndex].load(std::memory_order_acquire);
        while (cur) {
            if (ImplV4::keyEq(cur->key, key) || ImplV4::keyEq(cur->revKey, key)) {
                if (isExpired(*cur)) {
                    break;
                }
                e = cur;
                break;
            }
            cur = cur->next.load(std::memory_order_relaxed);
        }
    }

    bool didRetire = false;
    if (!e) {
        // Miss: create an entry (telemetry tracks both allow and block attempts).
        const std::lock_guard<std::mutex> g(shard.mutex);

        ImplV4::Entry *cur = shard.buckets[bucketIndex].load(std::memory_order_acquire);
        while (cur) {
            if (ImplV4::keyEq(cur->key, key) || ImplV4::keyEq(cur->revKey, key)) {
                if (!isExpired(*cur)) {
                    e = cur;
                }
                break;
            }
            cur = cur->next.load(std::memory_order_relaxed);
        }

        if (!e) {
            // Budgeted sweep before insert to free expired entries.
            const std::uint8_t retireEpoch = _impl4->epoch.current();
            const std::uint32_t swept = _impl4->sweepLocked(shard, pkt.tsNs, retireEpoch);
            didRetire = swept != 0;

            const std::uint64_t cap = clampCap(static_cast<std::uint64_t>(_impl4->opt.maxEntries),
                                               static_cast<std::uint64_t>(teleHot.cfg->maxFlowEntries));
            const std::uint64_t n =
                _impl4->shared ? _impl4->shared->totalEntries.load(std::memory_order_relaxed)
                               : _impl4->totalEntries.load(std::memory_order_relaxed);
            if (cap != 0 && n >= cap) {
                _impl4->overflowDrops.fetch_add(1, std::memory_order_relaxed);
                const bool evicted = _impl4->evictOneLocked(shard, pkt.tsNs, retireEpoch, teleHot);
                didRetire = didRetire || evicted;
                if (!evicted) {
                    flowTelemetry.accountResourcePressureDrop();
                    return;
                }
            }

            if (!l3Observation && pkt.proto == IPPROTO_TCP && !ImplV4::tcpValidNew(pkt)) {
                return;
            }
            if (!l3Observation && pkt.proto == IPPROTO_ICMP && !ImplV4::icmp4ValidNew(pkt)) {
                return;
            }

            auto *ne = new (std::nothrow) ImplV4::Entry();
            if (!ne) {
                flowTelemetry.accountResourcePressureDrop();
                return;
            }

            if (_impl4->shared) {
                const std::uint32_t prev =
                    _impl4->shared->totalEntries.fetch_add(1, std::memory_order_relaxed);
                if (cap != 0 && static_cast<std::uint64_t>(prev) >= cap) {
                    _impl4->shared->totalEntries.fetch_sub(1, std::memory_order_relaxed);
                    _impl4->overflowDrops.fetch_add(1, std::memory_order_relaxed);
                    flowTelemetry.accountResourcePressureDrop();
                    delete ne;
                    return;
                }
            }

            ne->key = key;
            ne->revKey = ImplV4::reverseKey(key);
            ne->tele.flowInstanceId.store(
                _impl4->shared->nextFlowInstanceId.fetch_add(1, std::memory_order_relaxed),
                std::memory_order_relaxed);
            ne->tele.sessionId.store(teleHot.sessionId, std::memory_order_relaxed);
            ne->tele.firstSeenNs.store(pkt.tsNs, std::memory_order_relaxed);
            ne->tele.lastSeenNs.store(pkt.tsNs, std::memory_order_relaxed);
            ne->tele.flowOriginDir.store(static_cast<std::uint8_t>(facts.packetDir),
                                         std::memory_order_relaxed);
            ne->tele.observationKind.store(
                static_cast<std::uint8_t>(l3Observation ? FlowTelemetryRecords::FlowObservationKind::L3Observation
                                                        : FlowTelemetryRecords::FlowObservationKind::Normal),
                std::memory_order_relaxed);
            const bool pickedUp = !l3Observation &&
                (isLooseTcpPickup(pkt) || isPickedUpMidStream(ctResult));
            ne->tele.pickedUpMidStream.store(pickedUp, std::memory_order_relaxed);

            if (l3Observation) {
                ne->state0.store(static_cast<std::uint8_t>(ImplV4::OtherState::FIRST),
                                 std::memory_order_relaxed);
                ne->expirationNs.store(addTimeoutMs(pkt.tsNs, teleHot.cfg->invalidTtlMs),
                                       std::memory_order_relaxed);
            } else if (pkt.proto == IPPROTO_TCP) {
                ne->state0.store(static_cast<std::uint8_t>(ImplV4::TcpPeerState::SYN_SENT),
                                 std::memory_order_relaxed);
                ne->state1.store(static_cast<std::uint8_t>(ImplV4::TcpPeerState::CLOSED),
                                 std::memory_order_relaxed);
                const std::uint64_t exp = pickedUp
                    ? addTimeoutMs(pkt.tsNs, teleHot.cfg->pickupTtlMs)
                    : ImplV4::addTimeoutNs(pkt.tsNs, _impl4->tp.tcpSynSent);
                ne->expirationNs.store(exp, std::memory_order_relaxed);
            } else if (pkt.proto == IPPROTO_ICMP) {
                ne->state0.store(static_cast<std::uint8_t>(ImplV4::IcmpState::FIRST),
                                 std::memory_order_relaxed);
                ne->expirationNs.store(ImplV4::addTimeoutNs(pkt.tsNs, _impl4->tp.icmpFirst),
                                       std::memory_order_relaxed);
            } else {
                ne->state0.store(static_cast<std::uint8_t>(ImplV4::OtherState::FIRST),
                                 std::memory_order_relaxed);
                ne->expirationNs.store(ImplV4::addTimeoutNs(pkt.tsNs, _impl4->tp.udpFirst),
                                       std::memory_order_relaxed);
            }

            ne->next.store(shard.buckets[bucketIndex].load(std::memory_order_relaxed),
                           std::memory_order_relaxed);
            shard.buckets[bucketIndex].store(ne, std::memory_order_release);
            shard.size.fetch_add(1, std::memory_order_relaxed);
            _impl4->totalEntries.fetch_add(1, std::memory_order_relaxed);
            _impl4->creates.fetch_add(1, std::memory_order_relaxed);
            e = ne;
        }
    }

    if (!e) {
        return;
    }

    const auto observationKind = l3Observation ? FlowTelemetryRecords::FlowObservationKind::L3Observation
                                               : FlowTelemetryRecords::FlowObservationKind::Normal;
    if (!_impl4->ensureTelemetrySession(*e, teleHot, pkt.tsNs, facts.packetDir, observationKind,
                                        l3Observation, ctResult)) {
        if (didRetire) {
            _impl4->maybeAdvanceAndReclaim(pkt.tsNs);
        }
        return;
    }

    std::uint64_t firstSeenNs = e->tele.firstSeenNs.load(std::memory_order_relaxed);
    if (firstSeenNs == 0) {
        e->tele.firstSeenNs.store(pkt.tsNs, std::memory_order_relaxed);
        firstSeenNs = pkt.tsNs;
    } else if (firstSeenNs != pkt.tsNs &&
               e->tele.lastExportTsNs.load(std::memory_order_relaxed) == 0 &&
               !l3Observation) {
        e->tele.pickedUpMidStream.store(true, std::memory_order_relaxed);
    }

    const auto unknownDir =
        static_cast<std::uint8_t>(FlowTelemetryRecords::FlowPacketDirection::Unknown);
    const auto packetDir = static_cast<std::uint8_t>(facts.packetDir);
    if (packetDir != unknownDir) {
        std::uint8_t expected = unknownDir;
        (void)e->tele.flowOriginDir.compare_exchange_strong(expected,
                                                            packetDir,
                                                            std::memory_order_relaxed,
                                                            std::memory_order_relaxed);
    }

    // Update cumulative counters (count blocked attempts too).
    const std::uint64_t totalPackets =
        e->tele.totalPackets.fetch_add(1, std::memory_order_relaxed) + 1;
    const std::uint64_t totalBytes =
        e->tele.totalBytes.fetch_add(facts.packetBytes, std::memory_order_relaxed) + facts.packetBytes;

    std::uint64_t inPackets = e->tele.inPackets.load(std::memory_order_relaxed);
    std::uint64_t inBytes = e->tele.inBytes.load(std::memory_order_relaxed);
    std::uint64_t outPackets = e->tele.outPackets.load(std::memory_order_relaxed);
    std::uint64_t outBytes = e->tele.outBytes.load(std::memory_order_relaxed);
    if (facts.packetDir == FlowTelemetryRecords::FlowPacketDirection::In) {
        inPackets = e->tele.inPackets.fetch_add(1, std::memory_order_relaxed) + 1;
        inBytes = e->tele.inBytes.fetch_add(facts.packetBytes, std::memory_order_relaxed) + facts.packetBytes;
    } else if (facts.packetDir == FlowTelemetryRecords::FlowPacketDirection::Out) {
        outPackets = e->tele.outPackets.fetch_add(1, std::memory_order_relaxed) + 1;
        outBytes = e->tele.outBytes.fetch_add(facts.packetBytes, std::memory_order_relaxed) + facts.packetBytes;
    }

    e->tele.lastSeenNs.store(pkt.tsNs, std::memory_order_relaxed);
    e->tele.lastUserId.store(facts.userId, std::memory_order_relaxed);
    e->tele.lastIfindex.store(facts.ifindex, std::memory_order_relaxed);
    e->tele.lastPacketDir.store(static_cast<std::uint8_t>(facts.packetDir), std::memory_order_relaxed);
    e->tele.lastVerdict.store(static_cast<std::uint8_t>(facts.verdict), std::memory_order_relaxed);
    e->tele.lastCtState.store(static_cast<std::uint8_t>(ctResult.state), std::memory_order_relaxed);
    e->tele.lastCtDir.store(static_cast<std::uint8_t>(ctResult.direction), std::memory_order_relaxed);
    e->tele.lastReasonId.store(static_cast<std::uint8_t>(facts.reasonId), std::memory_order_relaxed);
    e->tele.lastIfaceKindBit.store(facts.ifaceKindBit, std::memory_order_relaxed);
    e->tele.lastL4Status.store(facts.l4Status, std::memory_order_relaxed);
    e->tele.lastUidKnown.store(facts.uidKnown, std::memory_order_relaxed);
    e->tele.lastIfindexKnown.store(facts.ifindexKnown, std::memory_order_relaxed);
    e->tele.lastPortsAvailable.store(facts.portsAvailable, std::memory_order_relaxed);
    e->tele.lastIcmpType.store(facts.icmpType, std::memory_order_relaxed);
    e->tele.lastIcmpCode.store(facts.icmpCode, std::memory_order_relaxed);
    e->tele.lastIcmpId.store(facts.icmpId, std::memory_order_relaxed);

    if (l3Observation) {
        e->expirationNs.store(addTimeoutMs(pkt.tsNs, teleHot.cfg->invalidTtlMs),
                              std::memory_order_relaxed);
    } else if (isBlockReason(facts.reasonId)) {
        // Clamp expiration for blocked segments (IFACE_BLOCK / IP_RULE_BLOCK / IP_LEAK_BLOCK).
        const std::uint64_t blockExp = pkt.tsNs + static_cast<std::uint64_t>(teleHot.cfg->blockTtlMs) * kNsPerMs;
        const std::uint64_t curExp = e->expirationNs.load(std::memory_order_relaxed);
        if (curExp == 0 || curExp > blockExp) {
            e->expirationNs.store(blockExp, std::memory_order_relaxed);
        }
    }

    const std::uint8_t ctStateU8 = static_cast<std::uint8_t>(ctResult.state);
    const std::uint8_t ctDirU8 = static_cast<std::uint8_t>(ctResult.direction);
    const std::uint64_t decisionKey =
        packDecisionKey(ctStateU8, ctDirU8, facts.verdict, facts.reasonId, facts.ifaceKindBit, facts.ruleId);
    const bool ruleIdKnown = facts.ruleId.has_value();
    const std::uint32_t ruleIdValue = facts.ruleId.value_or(0u);
    (void)e->tele.decisionKey.exchange(decisionKey, std::memory_order_relaxed);
    e->tele.decisionRuleId.store(ruleIdValue, std::memory_order_relaxed);
    e->tele.decisionRuleIdKnown.store(ruleIdKnown, std::memory_order_relaxed);

    const std::uint64_t lastPk = e->tele.lastExportPackets.load(std::memory_order_relaxed);
    const std::uint64_t lastBy = e->tele.lastExportBytes.load(std::memory_order_relaxed);
    const std::uint64_t lastTs = e->tele.lastExportTsNs.load(std::memory_order_relaxed);
    const std::uint64_t lastKey = e->tele.lastExportDecisionKey.load(std::memory_order_relaxed);
    const std::uint32_t lastRuleId = e->tele.lastExportRuleId.load(std::memory_order_relaxed);
    const bool lastRuleIdKnown = e->tele.lastExportRuleIdKnown.load(std::memory_order_relaxed);

    const bool decisionChanged =
        (decisionKey != lastKey || ruleIdValue != lastRuleId || ruleIdKnown != lastRuleIdKnown) &&
        (lastTs != 0);
    const bool countersDue =
        (teleHot.cfg->packetsThreshold != 0 && totalPackets - lastPk >= teleHot.cfg->packetsThreshold) ||
        (teleHot.cfg->bytesThreshold != 0 && totalBytes - lastBy >= teleHot.cfg->bytesThreshold);
    const bool timeDue =
        (lastTs == 0) ||
        (teleHot.cfg->maxExportIntervalMs != 0 &&
         pkt.tsNs > lastTs &&
         (pkt.tsNs - lastTs) >= static_cast<std::uint64_t>(teleHot.cfg->maxExportIntervalMs) * kNsPerMs);

    // Export policy:
    // - First export is BEGIN (even if decisionKey packed is 0).
    // - Subsequent exports are UPDATE when decisionKey changes or thresholds/interval are hit.
    if (!decisionChanged && !countersDue && !timeDue) {
        if (didRetire) {
            _impl4->maybeAdvanceAndReclaim(pkt.tsNs);
        }
        return;
    }

    const FlowTelemetryRecords::FlowRecordKind kind =
        (lastTs == 0) ? FlowTelemetryRecords::FlowRecordKind::Begin
                      : FlowTelemetryRecords::FlowRecordKind::Update;

    ScopedAtomicBool exportGuard(e->tele.exportInProgress);
    if (!exportGuard) {
        if (didRetire) {
            _impl4->maybeAdvanceAndReclaim(pkt.tsNs);
        }
        return;
    }

    const std::uint64_t recordSeq = e->tele.recordSeq.load(std::memory_order_relaxed) + 1;

    FlowTelemetryRecords::FlowV1Fields fields{};
    fields.kind = kind;
    fields.observationKind = static_cast<FlowTelemetryRecords::FlowObservationKind>(
        e->tele.observationKind.load(std::memory_order_relaxed));
    fields.ctState = ctStateU8;
    fields.ctDir = ctDirU8;
    fields.packetDir = facts.packetDir;
    fields.flowOriginDir = static_cast<FlowTelemetryRecords::FlowPacketDirection>(
        e->tele.flowOriginDir.load(std::memory_order_relaxed));
    fields.verdict = facts.verdict;
    fields.reasonId = static_cast<std::uint8_t>(facts.reasonId);
    fields.ifaceKindBit = facts.ifaceKindBit;
    fields.l4Status = facts.l4Status;
    fields.proto = pkt.proto;
    fields.isIpv6 = false;
    fields.pickedUpMidStream = e->tele.pickedUpMidStream.load(std::memory_order_relaxed);
    fields.uidKnown = facts.uidKnown;
    fields.ifindexKnown = facts.ifindexKnown;
    fields.portsAvailable = facts.portsAvailable;
    fields.srcPort = pkt.srcPort;
    fields.dstPort = pkt.dstPort;
    fields.icmpType = facts.icmpType;
    fields.icmpCode = facts.icmpCode;
    fields.icmpId = facts.icmpId;
    fields.timestampNs = pkt.tsNs;
    fields.firstSeenNs = firstSeenNs;
    fields.lastSeenNs = pkt.tsNs;
    fields.flowInstanceId = e->tele.flowInstanceId.load(std::memory_order_relaxed);
    fields.recordSeq = recordSeq;
    fields.uid = pkt.uid;
    fields.userId = facts.userId;
    fields.ifindex = facts.ifindex;
    fields.srcAddr = facts.srcAddrNet;
    fields.dstAddr = facts.dstAddrNet;
    fields.totalPackets = totalPackets;
    fields.totalBytes = totalBytes;
    fields.inPackets = inPackets;
    fields.inBytes = inBytes;
    fields.outPackets = outPackets;
    fields.outBytes = outBytes;
    fields.ruleId = facts.ruleId;

    FlowTelemetryRecords::EncodedPayload payload{};
    if (!FlowTelemetryRecords::encodeFlowV1(payload, fields)) {
        if (didRetire) {
            _impl4->maybeAdvanceAndReclaim(pkt.tsNs);
        }
        return;
    }

    if (flowTelemetry.exportRecordHot(teleHot, FlowTelemetryAbi::RecordType::Flow, payload.span())) {
        e->tele.recordSeq.store(recordSeq, std::memory_order_relaxed);
        e->tele.lastExportPackets.store(totalPackets, std::memory_order_relaxed);
        e->tele.lastExportBytes.store(totalBytes, std::memory_order_relaxed);
        e->tele.lastExportTsNs.store(pkt.tsNs, std::memory_order_relaxed);
        e->tele.lastExportDecisionKey.store(decisionKey, std::memory_order_relaxed);
        e->tele.lastExportRuleId.store(ruleIdValue, std::memory_order_relaxed);
        e->tele.lastExportRuleIdKnown.store(ruleIdKnown, std::memory_order_relaxed);
    }

    if (didRetire) {
        _impl4->maybeAdvanceAndReclaim(pkt.tsNs);
    }
}

void Conntrack::observeFlowTelemetry(const PacketV6 &pkt, const Result &ctResult,
                                     const FlowTelemetry::HotPath &teleHot,
                                     const TelemetryPacketFacts &facts) noexcept {
    if (!_impl6) {
        return;
    }
    if (!teleHot.session || !teleHot.cfg) {
        return;
    }

    if (facts.srcAddrNet.size() != 16 || facts.dstAddrNet.size() != 16) {
        return;
    }

    const bool l3Observation = isL3ObservationStatus(facts.l4Status);
    ImplV6::KeyV6 key{};
    if (!_impl6->makeKey(pkt, key)) {
        if (!l3Observation || !_impl6->makeObservationKey(pkt, key)) {
            return;
        }
    }

    const std::uint64_t h = ImplV6::hashKey(key);
    const std::uint32_t shardIndex = static_cast<std::uint32_t>(h % _impl6->shards.size());
    const std::uint32_t bucketIndex = static_cast<std::uint32_t>(h) & _impl6->bucketMask;
    ImplV6::Shard &shard = *_impl6->shards[shardIndex];

    const auto epochSlot = _impl6->epoch.slotForThread();
    struct EpochGuard {
        ImplV6::Epoch &epoch;
        ImplV6::Epoch::Slot *slot = nullptr;
        EpochGuard(ImplV6::Epoch &e, ImplV6::Epoch::Slot *s) noexcept : epoch(e), slot(s) {
            epoch.enter(slot);
        }
        ~EpochGuard() { epoch.exit(slot); }
    } epochGuard(_impl6->epoch, epochSlot);

    const auto isExpired = [&](const ImplV6::Entry &e) noexcept -> bool {
        const std::uint64_t exp = e.expirationNs.load(std::memory_order_relaxed);
        return exp != 0 && pkt.tsNs >= exp;
    };

    ImplV6::Entry *e = nullptr;
    {
        ImplV6::Entry *cur = shard.buckets[bucketIndex].load(std::memory_order_acquire);
        while (cur) {
            if (ImplV6::keyEq(cur->key, key) || ImplV6::keyEq(cur->revKey, key)) {
                if (isExpired(*cur)) {
                    break;
                }
                e = cur;
                break;
            }
            cur = cur->next.load(std::memory_order_relaxed);
        }
    }

    bool didRetire = false;
    if (!e) {
        const std::lock_guard<std::mutex> g(shard.mutex);
        ImplV6::Entry *cur = shard.buckets[bucketIndex].load(std::memory_order_acquire);
        while (cur) {
            if (ImplV6::keyEq(cur->key, key) || ImplV6::keyEq(cur->revKey, key)) {
                if (!isExpired(*cur)) {
                    e = cur;
                }
                break;
            }
            cur = cur->next.load(std::memory_order_relaxed);
        }

        if (!e) {
            const std::uint8_t retireEpoch = _impl6->epoch.current();
            const std::uint32_t swept = _impl6->sweepLocked(shard, pkt.tsNs, retireEpoch);
            didRetire = swept != 0;

            const std::uint64_t cap = clampCap(static_cast<std::uint64_t>(_impl6->opt.maxEntries),
                                               static_cast<std::uint64_t>(teleHot.cfg->maxFlowEntries));
            const std::uint64_t n =
                _impl6->shared ? _impl6->shared->totalEntries.load(std::memory_order_relaxed)
                               : _impl6->totalEntries.load(std::memory_order_relaxed);
            if (cap != 0 && n >= cap) {
                _impl6->overflowDrops.fetch_add(1, std::memory_order_relaxed);
                const bool evicted = _impl6->evictOneLocked(shard, pkt.tsNs, retireEpoch, teleHot);
                didRetire = didRetire || evicted;
                if (!evicted) {
                    flowTelemetry.accountResourcePressureDrop();
                    return;
                }
            }

            if (!l3Observation && pkt.proto == IPPROTO_TCP && !ImplV6::tcpValidNew(pkt)) {
                return;
            }
            if (!l3Observation && pkt.proto == IPPROTO_ICMPV6 && !ImplV6::icmp6ValidNew(pkt)) {
                return;
            }

            auto *ne = new (std::nothrow) ImplV6::Entry();
            if (!ne) {
                flowTelemetry.accountResourcePressureDrop();
                return;
            }

            if (_impl6->shared) {
                const std::uint32_t prev =
                    _impl6->shared->totalEntries.fetch_add(1, std::memory_order_relaxed);
                if (cap != 0 && static_cast<std::uint64_t>(prev) >= cap) {
                    _impl6->shared->totalEntries.fetch_sub(1, std::memory_order_relaxed);
                    _impl6->overflowDrops.fetch_add(1, std::memory_order_relaxed);
                    flowTelemetry.accountResourcePressureDrop();
                    delete ne;
                    return;
                }
            }

            ne->key = key;
            ne->revKey = ImplV6::reverseKey(key);
            ne->tele.flowInstanceId.store(
                _impl6->shared->nextFlowInstanceId.fetch_add(1, std::memory_order_relaxed),
                std::memory_order_relaxed);
            ne->tele.sessionId.store(teleHot.sessionId, std::memory_order_relaxed);
            ne->tele.firstSeenNs.store(pkt.tsNs, std::memory_order_relaxed);
            ne->tele.lastSeenNs.store(pkt.tsNs, std::memory_order_relaxed);
            ne->tele.flowOriginDir.store(static_cast<std::uint8_t>(facts.packetDir),
                                         std::memory_order_relaxed);
            ne->tele.observationKind.store(
                static_cast<std::uint8_t>(l3Observation ? FlowTelemetryRecords::FlowObservationKind::L3Observation
                                                        : FlowTelemetryRecords::FlowObservationKind::Normal),
                std::memory_order_relaxed);
            const bool pickedUp = !l3Observation &&
                (isLooseTcpPickup(pkt) || isPickedUpMidStream(ctResult));
            ne->tele.pickedUpMidStream.store(pickedUp, std::memory_order_relaxed);

            if (l3Observation) {
                ne->state0.store(static_cast<std::uint8_t>(ImplV6::OtherState::FIRST),
                                 std::memory_order_relaxed);
                ne->expirationNs.store(addTimeoutMs(pkt.tsNs, teleHot.cfg->invalidTtlMs),
                                       std::memory_order_relaxed);
            } else if (pkt.proto == IPPROTO_TCP) {
                ne->state0.store(static_cast<std::uint8_t>(ImplV6::TcpPeerState::SYN_SENT),
                                 std::memory_order_relaxed);
                ne->state1.store(static_cast<std::uint8_t>(ImplV6::TcpPeerState::CLOSED),
                                 std::memory_order_relaxed);
                const std::uint64_t exp = pickedUp
                    ? addTimeoutMs(pkt.tsNs, teleHot.cfg->pickupTtlMs)
                    : ImplV6::addTimeoutNs(pkt.tsNs, _impl6->tp.tcpSynSent);
                ne->expirationNs.store(exp, std::memory_order_relaxed);
            } else if (pkt.proto == IPPROTO_ICMPV6) {
                ne->state0.store(static_cast<std::uint8_t>(ImplV6::IcmpState::FIRST),
                                 std::memory_order_relaxed);
                ne->expirationNs.store(ImplV6::addTimeoutNs(pkt.tsNs, _impl6->tp.icmpFirst),
                                       std::memory_order_relaxed);
            } else {
                ne->state0.store(static_cast<std::uint8_t>(ImplV6::OtherState::FIRST),
                                 std::memory_order_relaxed);
                ne->expirationNs.store(ImplV6::addTimeoutNs(pkt.tsNs, _impl6->tp.udpFirst),
                                       std::memory_order_relaxed);
            }

            ne->next.store(shard.buckets[bucketIndex].load(std::memory_order_relaxed),
                           std::memory_order_relaxed);
            shard.buckets[bucketIndex].store(ne, std::memory_order_release);
            shard.size.fetch_add(1, std::memory_order_relaxed);
            _impl6->totalEntries.fetch_add(1, std::memory_order_relaxed);
            _impl6->creates.fetch_add(1, std::memory_order_relaxed);
            e = ne;
        }
    }

    if (!e) {
        return;
    }

    const auto observationKind = l3Observation ? FlowTelemetryRecords::FlowObservationKind::L3Observation
                                               : FlowTelemetryRecords::FlowObservationKind::Normal;
    if (!_impl6->ensureTelemetrySession(*e, teleHot, pkt.tsNs, facts.packetDir, observationKind,
                                        l3Observation, ctResult)) {
        if (didRetire) {
            _impl6->maybeAdvanceAndReclaim(pkt.tsNs);
        }
        return;
    }

    std::uint64_t firstSeenNs = e->tele.firstSeenNs.load(std::memory_order_relaxed);
    if (firstSeenNs == 0) {
        e->tele.firstSeenNs.store(pkt.tsNs, std::memory_order_relaxed);
        firstSeenNs = pkt.tsNs;
    } else if (firstSeenNs != pkt.tsNs &&
               e->tele.lastExportTsNs.load(std::memory_order_relaxed) == 0 &&
               !l3Observation) {
        e->tele.pickedUpMidStream.store(true, std::memory_order_relaxed);
    }

    const auto unknownDir =
        static_cast<std::uint8_t>(FlowTelemetryRecords::FlowPacketDirection::Unknown);
    const auto packetDir = static_cast<std::uint8_t>(facts.packetDir);
    if (packetDir != unknownDir) {
        std::uint8_t expected = unknownDir;
        (void)e->tele.flowOriginDir.compare_exchange_strong(expected,
                                                            packetDir,
                                                            std::memory_order_relaxed,
                                                            std::memory_order_relaxed);
    }

    const std::uint64_t totalPackets =
        e->tele.totalPackets.fetch_add(1, std::memory_order_relaxed) + 1;
    const std::uint64_t totalBytes =
        e->tele.totalBytes.fetch_add(facts.packetBytes, std::memory_order_relaxed) + facts.packetBytes;

    std::uint64_t inPackets = e->tele.inPackets.load(std::memory_order_relaxed);
    std::uint64_t inBytes = e->tele.inBytes.load(std::memory_order_relaxed);
    std::uint64_t outPackets = e->tele.outPackets.load(std::memory_order_relaxed);
    std::uint64_t outBytes = e->tele.outBytes.load(std::memory_order_relaxed);
    if (facts.packetDir == FlowTelemetryRecords::FlowPacketDirection::In) {
        inPackets = e->tele.inPackets.fetch_add(1, std::memory_order_relaxed) + 1;
        inBytes = e->tele.inBytes.fetch_add(facts.packetBytes, std::memory_order_relaxed) + facts.packetBytes;
    } else if (facts.packetDir == FlowTelemetryRecords::FlowPacketDirection::Out) {
        outPackets = e->tele.outPackets.fetch_add(1, std::memory_order_relaxed) + 1;
        outBytes = e->tele.outBytes.fetch_add(facts.packetBytes, std::memory_order_relaxed) + facts.packetBytes;
    }

    e->tele.lastSeenNs.store(pkt.tsNs, std::memory_order_relaxed);
    e->tele.lastUserId.store(facts.userId, std::memory_order_relaxed);
    e->tele.lastIfindex.store(facts.ifindex, std::memory_order_relaxed);
    e->tele.lastPacketDir.store(static_cast<std::uint8_t>(facts.packetDir), std::memory_order_relaxed);
    e->tele.lastVerdict.store(static_cast<std::uint8_t>(facts.verdict), std::memory_order_relaxed);
    e->tele.lastCtState.store(static_cast<std::uint8_t>(ctResult.state), std::memory_order_relaxed);
    e->tele.lastCtDir.store(static_cast<std::uint8_t>(ctResult.direction), std::memory_order_relaxed);
    e->tele.lastReasonId.store(static_cast<std::uint8_t>(facts.reasonId), std::memory_order_relaxed);
    e->tele.lastIfaceKindBit.store(facts.ifaceKindBit, std::memory_order_relaxed);
    e->tele.lastL4Status.store(facts.l4Status, std::memory_order_relaxed);
    e->tele.lastUidKnown.store(facts.uidKnown, std::memory_order_relaxed);
    e->tele.lastIfindexKnown.store(facts.ifindexKnown, std::memory_order_relaxed);
    e->tele.lastPortsAvailable.store(facts.portsAvailable, std::memory_order_relaxed);
    e->tele.lastIcmpType.store(facts.icmpType, std::memory_order_relaxed);
    e->tele.lastIcmpCode.store(facts.icmpCode, std::memory_order_relaxed);
    e->tele.lastIcmpId.store(facts.icmpId, std::memory_order_relaxed);

    if (l3Observation) {
        e->expirationNs.store(addTimeoutMs(pkt.tsNs, teleHot.cfg->invalidTtlMs),
                              std::memory_order_relaxed);
    } else if (isBlockReason(facts.reasonId)) {
        const std::uint64_t blockExp = pkt.tsNs + static_cast<std::uint64_t>(teleHot.cfg->blockTtlMs) * kNsPerMs;
        const std::uint64_t curExp = e->expirationNs.load(std::memory_order_relaxed);
        if (curExp == 0 || curExp > blockExp) {
            e->expirationNs.store(blockExp, std::memory_order_relaxed);
        }
    }

    const std::uint8_t ctStateU8 = static_cast<std::uint8_t>(ctResult.state);
    const std::uint8_t ctDirU8 = static_cast<std::uint8_t>(ctResult.direction);
    const std::uint64_t decisionKey =
        packDecisionKey(ctStateU8, ctDirU8, facts.verdict, facts.reasonId, facts.ifaceKindBit, facts.ruleId);
    const bool ruleIdKnown = facts.ruleId.has_value();
    const std::uint32_t ruleIdValue = facts.ruleId.value_or(0u);
    (void)e->tele.decisionKey.exchange(decisionKey, std::memory_order_relaxed);
    e->tele.decisionRuleId.store(ruleIdValue, std::memory_order_relaxed);
    e->tele.decisionRuleIdKnown.store(ruleIdKnown, std::memory_order_relaxed);

    const std::uint64_t lastPk = e->tele.lastExportPackets.load(std::memory_order_relaxed);
    const std::uint64_t lastBy = e->tele.lastExportBytes.load(std::memory_order_relaxed);
    const std::uint64_t lastTs = e->tele.lastExportTsNs.load(std::memory_order_relaxed);
    const std::uint64_t lastKey = e->tele.lastExportDecisionKey.load(std::memory_order_relaxed);
    const std::uint32_t lastRuleId = e->tele.lastExportRuleId.load(std::memory_order_relaxed);
    const bool lastRuleIdKnown = e->tele.lastExportRuleIdKnown.load(std::memory_order_relaxed);

    const bool decisionChanged =
        (decisionKey != lastKey || ruleIdValue != lastRuleId || ruleIdKnown != lastRuleIdKnown) &&
        (lastTs != 0);
    const bool countersDue =
        (teleHot.cfg->packetsThreshold != 0 && totalPackets - lastPk >= teleHot.cfg->packetsThreshold) ||
        (teleHot.cfg->bytesThreshold != 0 && totalBytes - lastBy >= teleHot.cfg->bytesThreshold);
    const bool timeDue =
        (lastTs == 0) ||
        (teleHot.cfg->maxExportIntervalMs != 0 &&
         pkt.tsNs > lastTs &&
         (pkt.tsNs - lastTs) >= static_cast<std::uint64_t>(teleHot.cfg->maxExportIntervalMs) * kNsPerMs);

    if (!decisionChanged && !countersDue && !timeDue) {
        if (didRetire) {
            _impl6->maybeAdvanceAndReclaim(pkt.tsNs);
        }
        return;
    }

    const FlowTelemetryRecords::FlowRecordKind kind =
        (lastTs == 0) ? FlowTelemetryRecords::FlowRecordKind::Begin
                      : FlowTelemetryRecords::FlowRecordKind::Update;

    ScopedAtomicBool exportGuard(e->tele.exportInProgress);
    if (!exportGuard) {
        if (didRetire) {
            _impl6->maybeAdvanceAndReclaim(pkt.tsNs);
        }
        return;
    }

    const std::uint64_t recordSeq = e->tele.recordSeq.load(std::memory_order_relaxed) + 1;

    FlowTelemetryRecords::FlowV1Fields fields{};
    fields.kind = kind;
    fields.observationKind = static_cast<FlowTelemetryRecords::FlowObservationKind>(
        e->tele.observationKind.load(std::memory_order_relaxed));
    fields.ctState = ctStateU8;
    fields.ctDir = ctDirU8;
    fields.packetDir = facts.packetDir;
    fields.flowOriginDir = static_cast<FlowTelemetryRecords::FlowPacketDirection>(
        e->tele.flowOriginDir.load(std::memory_order_relaxed));
    fields.verdict = facts.verdict;
    fields.reasonId = static_cast<std::uint8_t>(facts.reasonId);
    fields.ifaceKindBit = facts.ifaceKindBit;
    fields.l4Status = facts.l4Status;
    fields.proto = pkt.proto;
    fields.isIpv6 = true;
    fields.pickedUpMidStream = e->tele.pickedUpMidStream.load(std::memory_order_relaxed);
    fields.uidKnown = facts.uidKnown;
    fields.ifindexKnown = facts.ifindexKnown;
    fields.portsAvailable = facts.portsAvailable;
    fields.srcPort = pkt.srcPort;
    fields.dstPort = pkt.dstPort;
    fields.icmpType = facts.icmpType;
    fields.icmpCode = facts.icmpCode;
    fields.icmpId = facts.icmpId;
    fields.timestampNs = pkt.tsNs;
    fields.firstSeenNs = firstSeenNs;
    fields.lastSeenNs = pkt.tsNs;
    fields.flowInstanceId = e->tele.flowInstanceId.load(std::memory_order_relaxed);
    fields.recordSeq = recordSeq;
    fields.uid = pkt.uid;
    fields.userId = facts.userId;
    fields.ifindex = facts.ifindex;
    fields.srcAddr = facts.srcAddrNet;
    fields.dstAddr = facts.dstAddrNet;
    fields.totalPackets = totalPackets;
    fields.totalBytes = totalBytes;
    fields.inPackets = inPackets;
    fields.inBytes = inBytes;
    fields.outPackets = outPackets;
    fields.outBytes = outBytes;
    fields.ruleId = facts.ruleId;

    FlowTelemetryRecords::EncodedPayload payload{};
    if (!FlowTelemetryRecords::encodeFlowV1(payload, fields)) {
        if (didRetire) {
            _impl6->maybeAdvanceAndReclaim(pkt.tsNs);
        }
        return;
    }

    if (flowTelemetry.exportRecordHot(teleHot, FlowTelemetryAbi::RecordType::Flow, payload.span())) {
        e->tele.recordSeq.store(recordSeq, std::memory_order_relaxed);
        e->tele.lastExportPackets.store(totalPackets, std::memory_order_relaxed);
        e->tele.lastExportBytes.store(totalBytes, std::memory_order_relaxed);
        e->tele.lastExportTsNs.store(pkt.tsNs, std::memory_order_relaxed);
        e->tele.lastExportDecisionKey.store(decisionKey, std::memory_order_relaxed);
        e->tele.lastExportRuleId.store(ruleIdValue, std::memory_order_relaxed);
        e->tele.lastExportRuleIdKnown.store(ruleIdKnown, std::memory_order_relaxed);
    }

    if (didRetire) {
        _impl6->maybeAdvanceAndReclaim(pkt.tsNs);
    }
}

std::uint32_t Conntrack::exportTelemetryDisabledEnds(const std::uint64_t nowNs) noexcept {
    const FlowTelemetry::HotPath teleHot = flowTelemetry.hotPathFlow();
    if (!teleHot.session || !teleHot.cfg || teleHot.sessionId == 0) {
        return 0;
    }

    std::uint32_t emitted = 0;
    if (_impl4) {
        emitted += _impl4->emitTelemetryDisabledEnds(nowNs, teleHot);
    }
    if (_impl6) {
        emitted += _impl6->emitTelemetryDisabledEnds(nowNs, teleHot);
    }
    return emitted;
}

Conntrack::MetricsSnapshot Conntrack::metricsSnapshot() const noexcept {
    MetricsSnapshot m{};
    if (!_impl4 || !_impl6) {
        return m;
    }

    m.byFamily.ipv4.totalEntries = _impl4->totalEntries.load(std::memory_order_relaxed);
    m.byFamily.ipv4.creates = _impl4->creates.load(std::memory_order_relaxed);
    m.byFamily.ipv4.expiredRetires = _impl4->expiredRetires.load(std::memory_order_relaxed);
    m.byFamily.ipv4.overflowDrops = _impl4->overflowDrops.load(std::memory_order_relaxed);

    m.byFamily.ipv6.totalEntries = _impl6->totalEntries.load(std::memory_order_relaxed);
    m.byFamily.ipv6.creates = _impl6->creates.load(std::memory_order_relaxed);
    m.byFamily.ipv6.expiredRetires = _impl6->expiredRetires.load(std::memory_order_relaxed);
    m.byFamily.ipv6.overflowDrops = _impl6->overflowDrops.load(std::memory_order_relaxed);

    m.totalEntries = m.byFamily.ipv4.totalEntries + m.byFamily.ipv6.totalEntries;
    m.creates = m.byFamily.ipv4.creates + m.byFamily.ipv6.creates;
    m.expiredRetires = m.byFamily.ipv4.expiredRetires + m.byFamily.ipv6.expiredRetires;
    m.overflowDrops = m.byFamily.ipv4.overflowDrops + m.byFamily.ipv6.overflowDrops;
    return m;
}

void Conntrack::reset() noexcept {
    if (!_impl4) {
        return;
    }
    const Options opt = _impl4->opt;
    _shared = std::make_unique<Shared>();
    _impl4 = std::make_unique<ImplV4>(opt, _shared.get());
    _impl6 = std::make_unique<ImplV6>(opt, _shared.get());
}

#ifdef SUCRE_SNORT_TESTING
std::uint32_t Conntrack::debugEpochUsedSlots() const noexcept {
    if (!_impl4) {
        return 0;
    }
    return _impl4->epoch.used.load(std::memory_order_relaxed);
}

std::uint64_t Conntrack::debugEpochInstanceId() const noexcept {
    if (!_impl4) {
        return 0;
    }
    return _impl4->epoch.instanceId;
}
#endif
