/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>

// Telemetry plane hot-path wiring.
#include <FlowTelemetry.hpp>
#include <PacketReasons.hpp>

// Userspace conntrack core (IPv4 first).
//
// This header defines the minimal packet input model and output dimensions needed to support
// IPRULES `ct.*` match semantics (state + direction), aligned with OVS conntrack.

class Conntrack {
public:
    enum class CtState : std::uint8_t {
        ANY = 0,
        NEW = 1,
        ESTABLISHED = 2, // Includes OVS +rel folded into established.
        INVALID = 3,
    };

    enum class CtDirection : std::uint8_t {
        ANY = 0,
        ORIG = 1,
        REPLY = 2,
    };

    struct TcpMeta {
        std::uint8_t flags = 0;
        std::uint8_t dataOffsetWords = 0; // TCP doff field (header length in 4-byte words).
        bool hasWscale = false;
        std::uint8_t wscale = 0;
        std::uint16_t window = 0;
        std::uint32_t seq = 0;
        std::uint32_t ack = 0;
    };

    struct IcmpMeta {
        std::uint8_t type = 0;
        std::uint8_t code = 0;
        std::uint16_t id = 0;
    };

    struct PacketV4 {
        std::uint64_t tsNs = 0;
        std::uint32_t uid = 0;
        std::uint32_t srcIp = 0; // host-byte-order
        std::uint32_t dstIp = 0; // host-byte-order
        std::uint8_t proto = 0;  // IPPROTO_*
        bool isFragment = false;

        // Bytes available starting at the L4 header (i.e. IPv4 payload length).
        std::uint16_t ipPayloadLen = 0;

        // L4 identifiers. For TCP/UDP: ports. For ICMP: id is provided in icmp meta, ports are 0.
        std::uint16_t srcPort = 0;
        std::uint16_t dstPort = 0;

        bool hasTcp = false;
        TcpMeta tcp{};

        bool hasIcmp = false;
        IcmpMeta icmp{};
    };

    struct PacketV6 {
        std::uint64_t tsNs = 0;
        std::uint32_t uid = 0;
        std::array<std::uint8_t, 16> srcIp{}; // network-byte-order
        std::array<std::uint8_t, 16> dstIp{}; // network-byte-order
        std::uint8_t proto = 0;               // IPPROTO_* (terminal/declared after ext-header walking)
        bool isFragment = false;

        // Bytes available starting at the L4 header (i.e. IPv6 payload length after ext headers).
        std::uint16_t ipPayloadLen = 0;

        // L4 identifiers. For TCP/UDP: ports. For ICMPv6: id is provided in icmp meta, ports are 0.
        std::uint16_t srcPort = 0;
        std::uint16_t dstPort = 0;

        bool hasTcp = false;
        TcpMeta tcp{};

        bool hasIcmp = false;
        IcmpMeta icmp{};
    };

    struct Result {
        CtState state = CtState::ANY;
        CtDirection direction = CtDirection::ANY;
    };

    struct PolicyView {
        Result result{};
        bool createOnAccept = false;
    };

    struct Options {
        // Hard cap on number of entries (must not be unbounded).
        std::uint32_t maxEntries = 1'000'000;

        // Hash table layout.
        std::uint16_t shards = 64;
        std::uint32_t bucketsPerShard = 4096; // Must be power-of-two.

        // Budgeted sweep knobs (baseline): bounds per sweep invocation.
        std::uint16_t sweepMaxBuckets = 8;
        std::uint16_t sweepMaxEntries = 64;
        std::uint32_t sweepMinIntervalMs = 50;
    };

    Conntrack();
    explicit Conntrack(const Options &opt);
    ~Conntrack();

    Conntrack(const Conntrack &) = delete;
    Conntrack &operator=(const Conntrack &) = delete;

    static bool computeTcpPayloadLen(const PacketV4 &pkt, std::uint16_t &outPayloadLen) noexcept;
    static bool computeTcpPayloadLen(const PacketV6 &pkt, std::uint16_t &outPayloadLen) noexcept;

    // Pre-verdict conntrack view for policy matching:
    // - existing entries may still be advanced in-place
    // - misses never create an entry until commitAccepted() is called
    PolicyView inspectForPolicy(const PacketV4 &pkt) noexcept;
    PolicyView inspectForPolicy(const PacketV6 &pkt) noexcept;

    // Commits a previously previewed miss once the packet is accepted.
    void commitAccepted(const PacketV4 &pkt, const PolicyView &view) noexcept;
    void commitAccepted(const PacketV6 &pkt, const PolicyView &view) noexcept;

    Result update(const PacketV4 &pkt) noexcept;
    Result update(const PacketV6 &pkt) noexcept;

    struct MetricsSnapshot {
        struct Family {
            std::uint64_t totalEntries = 0;
            std::uint64_t creates = 0;
            std::uint64_t expiredRetires = 0;
            std::uint64_t overflowDrops = 0;
        };

        std::uint64_t totalEntries = 0;
        std::uint64_t creates = 0;
        std::uint64_t expiredRetires = 0;
        std::uint64_t overflowDrops = 0;

        struct {
            Family ipv4;
            Family ipv6;
        } byFamily;
    };

    MetricsSnapshot metricsSnapshot() const noexcept;

    // Clears the conntrack table and counters. Caller MUST exclude concurrent public method calls.
    void reset() noexcept;

    // ---- Telemetry plane ----------------------------------------------------
    //
    // Best-effort per-packet observation for Flow Telemetry (records written to the telemetry ring).
    // Caller must sample `FlowTelemetry::HotPath` once per packet and pass it down.
    //
    // Notes:
    // - Telemetry failures must never change packet verdict.
    // - This path is allowed to drop records under backpressure; drops are accounted by FlowTelemetry.
    void observeFlowTelemetry(const PacketV4 &pkt, const Result &ctResult,
                              const FlowTelemetry::HotPath &teleHot,
                              std::uint8_t ifaceKindBit, std::uint32_t userId,
                              std::uint32_t ifindex, PacketReasonId reasonId,
                              const std::optional<std::uint32_t> &ruleId,
                              std::span<const std::byte> srcAddrNet,
                              std::span<const std::byte> dstAddrNet,
                              std::uint32_t packetBytes) noexcept;
    void observeFlowTelemetry(const PacketV6 &pkt, const Result &ctResult,
                              const FlowTelemetry::HotPath &teleHot,
                              std::uint8_t ifaceKindBit, std::uint32_t userId,
                              std::uint32_t ifindex, PacketReasonId reasonId,
                              const std::optional<std::uint32_t> &ruleId,
                              std::span<const std::byte> srcAddrNet,
                              std::span<const std::byte> dstAddrNet,
                              std::uint32_t packetBytes) noexcept;

#ifdef SUCRE_SNORT_TESTING
    std::uint32_t debugEpochUsedSlots() const noexcept;
    std::uint64_t debugEpochInstanceId() const noexcept;
#endif

private:
    struct Shared;
    struct ImplV4;
    struct ImplV6;
    std::unique_ptr<Shared> _shared;
    std::unique_ptr<ImplV4> _impl4;
    std::unique_ptr<ImplV6> _impl6;
};
