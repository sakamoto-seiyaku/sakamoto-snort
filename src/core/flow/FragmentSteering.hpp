/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <FlowSteering.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <vector>

namespace SnortDatapath::Flow {

/** Key used only while an IP datagram is being reassembled. */
struct FragmentKey final {
    AddressFamily family = AddressFamily::Ipv4;
    IpAddress source;
    IpAddress destination;
    std::uint8_t ipProtocol = 0;
    std::uint32_t identification = 0;

    friend bool operator==(const FragmentKey &, const FragmentKey &) = default;
};

/** Final flow ownership captured from the initial fragment, when available. */
struct FragmentOwnerMetadata final {
    CanonicalFlowKey flowKey;
    std::uint32_t finalOwner = std::numeric_limits<std::uint32_t>::max();

    friend bool operator==(const FragmentOwnerMetadata &,
                           const FragmentOwnerMetadata &) = default;
};

enum class FragmentSubmitStatus : std::uint8_t {
    NotFragment,
    Buffered,
    Duplicate,
    Reassembled,
    Malformed,
    Conflict,
    Timeout,
    Capacity,
};

struct FragmentReassemblyResult final {
    FragmentSubmitStatus status = FragmentSubmitStatus::Malformed;
    std::vector<std::byte> packet;
    std::optional<FragmentOwnerMetadata> owner;

    [[nodiscard]] bool hasPacket() const noexcept {
        return status == FragmentSubmitStatus::Reassembled && !packet.empty();
    }

    /** Fragment-stage owner transition is not a corrective owner handoff. */
    [[nodiscard]] bool correctiveHandoffConsumed() const noexcept { return false; }
};

/** Runtime-fixed bounds for one FragmentSteering instance. */
struct FragmentSteeringConfig final {
    std::size_t maxDatagrams = 64;
    std::size_t maxFragmentsPerDatagram = 32;
    std::uint32_t maxPacketBytes = 65535;
    std::uint64_t timeoutTicks = 1000;
};

struct FragmentSteeringCounters final {
    std::uint64_t packetsSeen = 0;
    std::uint64_t bufferedPackets = 0;
    std::uint64_t duplicatePackets = 0;
    std::uint64_t reassembledPackets = 0;
    std::uint64_t malformedPackets = 0;
    std::uint64_t conflictPackets = 0;
    std::uint64_t timeoutDatagrams = 0;
    std::uint64_t capacityDrops = 0;
};

/**
 * Fixed-capacity IPv4/IPv6 fragment co-location and bounded reassembly.
 *
 * The input span is a complete captured L3 fragment prefix. `originalLength`
 * is the wire length for that fragment; bytes outside the span are treated as
 * unavailable. IPv4 options and the IPv6 base header are retained only from
 * the offset-zero fragment. The IPv6 Fragment header is removed from the
 * reconstructed packet.
 *
 * This class owns all bytes copied into an active datagram and into a
 * successful result. It never fabricates ports: final owner metadata is set
 * only if a complete TCP/UDP header is present in the initial fragment.
 */
class FragmentSteering final {
public:
    explicit FragmentSteering(
        WorkerLayout layout = {}, FragmentSteeringConfig config = {});
    explicit FragmentSteering(
        OwnerSelector selector, FragmentSteeringConfig config = {});

    [[nodiscard]] FragmentReassemblyResult submit(
        std::span<const std::byte> packet, std::uint32_t originalLength,
        std::uint64_t now);

    /** Expire all datagrams whose last activity reached the timeout. */
    [[nodiscard]] std::size_t expire(std::uint64_t now) noexcept;

    [[nodiscard]] std::size_t activeDatagrams() const noexcept {
        return activeDatagrams_;
    }
    [[nodiscard]] const FragmentSteeringConfig &config() const noexcept {
        return config_;
    }
    [[nodiscard]] const OwnerSelector &selector() const noexcept { return selector_; }
    [[nodiscard]] const FragmentSteeringCounters &counters() const noexcept {
        return counters_;
    }

private:
    struct FragmentPiece final {
        std::uint32_t offset = 0;
        std::vector<std::byte> payload;
    };

    struct ReassemblyState final {
        bool active = false;
        FragmentKey key;
        std::uint64_t lastSeen = 0;
        std::vector<std::byte> firstHeader;
        std::vector<FragmentPiece> pieces;
        std::optional<std::uint32_t> finalPayloadLength;
        std::optional<FragmentOwnerMetadata> owner;
    };

    static FragmentSteeringConfig validateConfig(FragmentSteeringConfig config);

    OwnerSelector selector_;
    FragmentSteeringConfig config_;
    std::vector<ReassemblyState> states_;
    std::size_t activeDatagrams_ = 0;
    FragmentSteeringCounters counters_;

    [[nodiscard]] std::size_t findState(const FragmentKey &key) const noexcept;
    [[nodiscard]] std::size_t findFreeState() const noexcept;
    [[nodiscard]] static bool existingByteAt(
        const ReassemblyState &state, std::uint32_t offset,
        std::byte &value) noexcept;
    [[nodiscard]] static bool completeCoverage(
        const ReassemblyState &state) noexcept;
    [[nodiscard]] static std::vector<std::byte> buildPacket(
        const ReassemblyState &state);
    void resetState(ReassemblyState &state) noexcept;
};

} // namespace SnortDatapath::Flow
