/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <Conntrack.hpp>

#include <atomic>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <mutex>
#include <new>
#include <optional>
#include <utility>
#include <vector>

#include <netinet/in.h>
#include <netinet/tcp.h>

struct Conntrack::Impl {
    Options opt;

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
            s->epoch.store(current(), std::memory_order_release);
        }

        void exit(Slot *s) noexcept {
            if (!s) {
                return;
            }
            s->epoch.store(kQuiescent, std::memory_order_release);
        }

        std::optional<std::uint8_t> tryAdvance() noexcept {
            if (exhausted.load(std::memory_order_relaxed)) {
                return std::nullopt;
            }
            const std::uint8_t cur = global.load(std::memory_order_relaxed);
            const std::uint32_t n = used.load(std::memory_order_acquire);
            for (std::uint32_t i = 0; i < n && i < kMaxSlots; ++i) {
                const std::uint8_t e = slots[i].epoch.load(std::memory_order_acquire);
                if (e != kQuiescent && e != cur) {
                    return std::nullopt;
                }
            }
            const std::uint8_t next = static_cast<std::uint8_t>((cur + 1u) % 3u);
            global.store(next, std::memory_order_release);
            const std::uint8_t reclaim = static_cast<std::uint8_t>((next + 1u) % 3u);
            return reclaim;
        }
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

    explicit Impl(const Options &o) : opt(o) {
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

    ~Impl() {
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

    std::uint32_t sweepLocked(Shard &shard, const std::uint64_t nowNs, const std::uint8_t retireEpoch) noexcept {
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
        const auto reclaimEpoch = epoch.tryAdvance();
        if (!reclaimEpoch.has_value()) {
            return;
        }
        lastEpochAdvanceTsNs.store(nowNs, std::memory_order_relaxed);
        reclaimEpochAllShards(*reclaimEpoch);
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

Conntrack::Conntrack() : Conntrack(Options{}) {}

Conntrack::Conntrack(const Options &opt) : _impl(std::make_unique<Impl>(opt)) {}

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

Conntrack::PolicyView Conntrack::inspectForPolicy(const PacketV4 &pkt) noexcept {
    PolicyView view{};
    Result &r = view.result;
    if (pkt.isFragment) {
        r.state = CtState::INVALID;
        r.direction = CtDirection::ANY;
        return view;
    }

    Impl::KeyV4 key{};
    if (!_impl->makeKey(pkt, key)) {
        r.state = CtState::INVALID;
        r.direction = CtDirection::ANY;
        return view;
    }

    const std::uint64_t h = Impl::hashKey(key);
    const std::uint32_t shardIndex = static_cast<std::uint32_t>(h % _impl->shards.size());
    const std::uint32_t bucketIndex = static_cast<std::uint32_t>(h) & _impl->bucketMask;
    Impl::Shard &shard = *_impl->shards[shardIndex];

    const auto epochSlot = _impl->epoch.slotForThread();
    struct EpochGuard {
        Impl::Epoch &epoch;
        Impl::Epoch::Slot *slot = nullptr;
        EpochGuard(Impl::Epoch &e, Impl::Epoch::Slot *s) noexcept : epoch(e), slot(s) { epoch.enter(slot); }
        ~EpochGuard() { epoch.exit(slot); }
    } epochGuard(_impl->epoch, epochSlot);

    // Optional best-effort sweep on hot path (interval + try_lock; never blocks verdict).
    (void)_impl->maybeHotSweep(shard, pkt.tsNs);

    const auto isExpired = [&](const Impl::Entry &e) noexcept -> bool {
        const std::uint64_t exp = e.expirationNs.load(std::memory_order_relaxed);
        return exp != 0 && pkt.tsNs >= exp;
    };

    const auto updateExisting = [&](Impl::Entry &e, const bool isReply) noexcept -> CtState {
        if (pkt.proto == IPPROTO_TCP) {
            if (!Impl::tcpValidUpdate(pkt)) {
                return CtState::INVALID;
            }

            const std::uint8_t flags = pkt.tcp.flags;
            const int srcIdx = isReply ? 1 : 0;
            const int dstIdx = isReply ? 0 : 1;
            std::atomic<std::uint8_t> &srcState = (srcIdx == 0) ? e.state0 : e.state1;
            std::atomic<std::uint8_t> &dstState = (dstIdx == 0) ? e.state0 : e.state1;

            const auto bumpAtLeast = [&](std::atomic<std::uint8_t> &st,
                                         const Impl::TcpPeerState target) noexcept {
                std::uint8_t cur = st.load(std::memory_order_relaxed);
                const auto want = static_cast<std::uint8_t>(target);
                while (cur < want && !st.compare_exchange_weak(cur, want, std::memory_order_relaxed)) {
                }
            };

            if ((flags & TH_SYN) != 0) {
                bumpAtLeast(srcState, Impl::TcpPeerState::SYN_SENT);
            }
            if ((flags & TH_FIN) != 0) {
                bumpAtLeast(srcState, Impl::TcpPeerState::CLOSING);
            }
            if ((flags & TH_ACK) != 0) {
                const std::uint8_t dstCur = dstState.load(std::memory_order_relaxed);
                if (dstCur == static_cast<std::uint8_t>(Impl::TcpPeerState::SYN_SENT)) {
                    bumpAtLeast(dstState, Impl::TcpPeerState::ESTABLISHED);
                } else if (dstCur == static_cast<std::uint8_t>(Impl::TcpPeerState::CLOSING)) {
                    bumpAtLeast(dstState, Impl::TcpPeerState::FIN_WAIT_2);
                }
            }
            if ((flags & TH_RST) != 0) {
                e.state0.store(static_cast<std::uint8_t>(Impl::TcpPeerState::TIME_WAIT),
                               std::memory_order_relaxed);
                e.state1.store(static_cast<std::uint8_t>(Impl::TcpPeerState::TIME_WAIT),
                               std::memory_order_relaxed);
            }

            const auto p0 = static_cast<Impl::TcpPeerState>(e.state0.load(std::memory_order_relaxed));
            const auto p1 = static_cast<Impl::TcpPeerState>(e.state1.load(std::memory_order_relaxed));
            e.expirationNs.store(Impl::addTimeoutNs(pkt.tsNs, _impl->timeoutForTcpPeers(p0, p1)),
                                 std::memory_order_relaxed);

            // OVS: once a TCP conn entry exists, all subsequent packets are +est (not +new).
            return CtState::ESTABLISHED;
        }

        if (pkt.proto == IPPROTO_ICMP) {
            auto st = static_cast<Impl::IcmpState>(e.state0.load(std::memory_order_relaxed));
            if (isReply && st == Impl::IcmpState::FIRST) {
                std::uint8_t expected = static_cast<std::uint8_t>(Impl::IcmpState::FIRST);
                (void)e.state0.compare_exchange_strong(expected,
                                                      static_cast<std::uint8_t>(Impl::IcmpState::REPLY),
                                                      std::memory_order_relaxed);
                st = static_cast<Impl::IcmpState>(e.state0.load(std::memory_order_relaxed));
            }
            e.expirationNs.store(Impl::addTimeoutNs(pkt.tsNs, _impl->timeoutForIcmpState(st)),
                                 std::memory_order_relaxed);
            return st == Impl::IcmpState::REPLY ? CtState::ESTABLISHED : CtState::NEW;
        }

        // other (includes UDP)
        auto st = static_cast<Impl::OtherState>(e.state0.load(std::memory_order_relaxed));
        if (isReply && st != Impl::OtherState::BIDIR) {
            e.state0.store(static_cast<std::uint8_t>(Impl::OtherState::BIDIR), std::memory_order_relaxed);
            st = Impl::OtherState::BIDIR;
        } else if (!isReply && st == Impl::OtherState::FIRST) {
            std::uint8_t expected = static_cast<std::uint8_t>(Impl::OtherState::FIRST);
            (void)e.state0.compare_exchange_strong(expected,
                                                  static_cast<std::uint8_t>(Impl::OtherState::MULTIPLE),
                                                  std::memory_order_relaxed);
            st = static_cast<Impl::OtherState>(e.state0.load(std::memory_order_relaxed));
        }
        e.expirationNs.store(Impl::addTimeoutNs(pkt.tsNs, _impl->timeoutForOtherState(st)),
                             std::memory_order_relaxed);
        return st == Impl::OtherState::BIDIR ? CtState::ESTABLISHED : CtState::NEW;
    };

    // Fast path: lockless bucket traversal (safe while we don't unlink/free yet).
    {
        Impl::Entry *cur = shard.buckets[bucketIndex].load(std::memory_order_acquire);
        while (cur) {
            if (Impl::keyEq(cur->key, key) || Impl::keyEq(cur->revKey, key)) {
                if (isExpired(*cur)) {
                    break;
                }

                const bool isReply = Impl::keyEq(cur->revKey, key);
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
        Impl::Entry *cur = shard.buckets[bucketIndex].load(std::memory_order_acquire);
        while (cur) {
            if (Impl::keyEq(cur->key, key) || Impl::keyEq(cur->revKey, key)) {
                if (!isExpired(*cur)) {
                    const bool isReply = Impl::keyEq(cur->revKey, key);
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
        const std::uint8_t retireEpoch = _impl->epoch.current();
        const std::uint32_t swept = _impl->sweepLocked(shard, pkt.tsNs, retireEpoch);
        didRetire = didRetire || swept != 0;

        const std::uint32_t n = _impl->totalEntries.load(std::memory_order_relaxed);
        if (n >= _impl->opt.maxEntries) {
            _impl->overflowDrops.fetch_add(1, std::memory_order_relaxed);
            r.state = CtState::INVALID;
            r.direction = CtDirection::ANY;
            return view;
        }

        if (pkt.proto == IPPROTO_TCP && !Impl::tcpValidNew(pkt)) {
            r.state = CtState::INVALID;
            r.direction = CtDirection::ANY;
            return view;
        }
        if (pkt.proto == IPPROTO_ICMP && !Impl::icmp4ValidNew(pkt)) {
            r.state = CtState::INVALID;
            r.direction = CtDirection::ANY;
            return view;
        }
        r.state = CtState::NEW;
        r.direction = CtDirection::ORIG;
        view.createOnAccept = true;
    }

    if (didRetire) {
        _impl->maybeAdvanceAndReclaim(pkt.tsNs);
    }
    return view;
}

void Conntrack::commitAccepted(const PacketV4 &pkt, const PolicyView &view) noexcept {
    if (!_impl || !view.createOnAccept || view.result.state != CtState::NEW ||
        view.result.direction != CtDirection::ORIG) {
        return;
    }

    Impl::KeyV4 key{};
    if (!_impl->makeKey(pkt, key)) {
        return;
    }

    const std::uint64_t h = Impl::hashKey(key);
    const std::uint32_t shardIndex = static_cast<std::uint32_t>(h % _impl->shards.size());
    const std::uint32_t bucketIndex = static_cast<std::uint32_t>(h) & _impl->bucketMask;
    Impl::Shard &shard = *_impl->shards[shardIndex];

    const auto isExpired = [&](const Impl::Entry &e) noexcept -> bool {
        const std::uint64_t exp = e.expirationNs.load(std::memory_order_relaxed);
        return exp != 0 && pkt.tsNs >= exp;
    };

    bool didRetire = false;
    {
        const std::lock_guard<std::mutex> g(shard.mutex);
        Impl::Entry *cur = shard.buckets[bucketIndex].load(std::memory_order_acquire);
        while (cur) {
            if (Impl::keyEq(cur->key, key) || Impl::keyEq(cur->revKey, key)) {
                if (!isExpired(*cur)) {
                    return;
                }
                break;
            }
            cur = cur->next.load(std::memory_order_relaxed);
        }

        const std::uint8_t retireEpoch = _impl->epoch.current();
        const std::uint32_t swept = _impl->sweepLocked(shard, pkt.tsNs, retireEpoch);
        didRetire = swept != 0;

        const std::uint32_t n = _impl->totalEntries.load(std::memory_order_relaxed);
        if (n >= _impl->opt.maxEntries) {
            _impl->overflowDrops.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        if (pkt.proto == IPPROTO_TCP && !Impl::tcpValidNew(pkt)) {
            return;
        }
        if (pkt.proto == IPPROTO_ICMP && !Impl::icmp4ValidNew(pkt)) {
            return;
        }

        auto *e = new (std::nothrow) Impl::Entry();
        if (!e) {
            return;
        }

        e->key = key;
        e->revKey = Impl::reverseKey(key);
        if (pkt.proto == IPPROTO_TCP) {
            e->state0.store(static_cast<std::uint8_t>(Impl::TcpPeerState::SYN_SENT),
                            std::memory_order_relaxed);
            e->state1.store(static_cast<std::uint8_t>(Impl::TcpPeerState::CLOSED),
                            std::memory_order_relaxed);
            e->expirationNs.store(Impl::addTimeoutNs(pkt.tsNs, _impl->tp.tcpSynSent),
                                  std::memory_order_relaxed);
        } else if (pkt.proto == IPPROTO_ICMP) {
            e->state0.store(static_cast<std::uint8_t>(Impl::IcmpState::FIRST),
                            std::memory_order_relaxed);
            e->expirationNs.store(Impl::addTimeoutNs(pkt.tsNs, _impl->tp.icmpFirst),
                                  std::memory_order_relaxed);
        } else {
            e->state0.store(static_cast<std::uint8_t>(Impl::OtherState::FIRST),
                            std::memory_order_relaxed);
            e->expirationNs.store(Impl::addTimeoutNs(pkt.tsNs, _impl->tp.udpFirst),
                                  std::memory_order_relaxed);
        }

        e->next.store(shard.buckets[bucketIndex].load(std::memory_order_relaxed),
                      std::memory_order_relaxed);
        shard.buckets[bucketIndex].store(e, std::memory_order_release);
        shard.size.fetch_add(1, std::memory_order_relaxed);
        _impl->totalEntries.fetch_add(1, std::memory_order_relaxed);
        _impl->creates.fetch_add(1, std::memory_order_relaxed);
    }

    if (didRetire) {
        _impl->maybeAdvanceAndReclaim(pkt.tsNs);
    }
}

Conntrack::Result Conntrack::update(const PacketV4 &pkt) noexcept {
    const auto view = inspectForPolicy(pkt);
    commitAccepted(pkt, view);
    return view.result;
}

Conntrack::MetricsSnapshot Conntrack::metricsSnapshot() const noexcept {
    MetricsSnapshot m{};
    if (!_impl) {
        return m;
    }
    m.totalEntries = _impl->totalEntries.load(std::memory_order_relaxed);
    m.creates = _impl->creates.load(std::memory_order_relaxed);
    m.expiredRetires = _impl->expiredRetires.load(std::memory_order_relaxed);
    m.overflowDrops = _impl->overflowDrops.load(std::memory_order_relaxed);
    return m;
}

void Conntrack::reset() noexcept {
    if (!_impl) {
        return;
    }
    const Options opt = _impl->opt;
    _impl = std::make_unique<Impl>(opt);
}

#ifdef SUCRE_SNORT_TESTING
std::uint32_t Conntrack::debugEpochUsedSlots() const noexcept {
    if (!_impl) {
        return 0;
    }
    return _impl->epoch.used.load(std::memory_order_relaxed);
}

std::uint64_t Conntrack::debugEpochInstanceId() const noexcept {
    if (!_impl) {
        return 0;
    }
    return _impl->epoch.instanceId;
}
#endif
