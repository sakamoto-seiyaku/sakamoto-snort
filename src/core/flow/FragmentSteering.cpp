/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <FragmentSteering.hpp>

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <utility>

namespace SnortDatapath::Flow {
namespace {

constexpr std::uint8_t kIpv4Version = 4;
constexpr std::uint8_t kIpv6Version = 6;
constexpr std::uint8_t kIpv6FragmentHeader = 44;
constexpr std::uint8_t kTcpProtocol = 6;
constexpr std::uint8_t kUdpProtocol = 17;
constexpr std::size_t kIpv4MinimumHeaderLength = 20;
constexpr std::size_t kIpv6HeaderLength = 40;
constexpr std::size_t kIpv6FragmentHeaderLength = 8;
constexpr std::size_t kTcpMinimumHeaderLength = 20;
constexpr std::size_t kUdpHeaderLength = 8;
constexpr std::size_t kNoState = std::numeric_limits<std::size_t>::max();

enum class FragmentParseKind : std::uint8_t {
    NotFragment,
    Fragment,
    Malformed,
    Capacity,
};

struct ParsedFragment final {
    FragmentKey key;
    std::size_t headerLength = 0;
    std::size_t payloadOffset = 0;
    std::size_t payloadLength = 0;
    std::uint32_t fragmentOffset = 0;
    bool moreFragments = false;
    std::uint32_t packetLength = 0;
    std::optional<CanonicalFlowKey> ownerKey;
};

struct FragmentParseResult final {
    FragmentParseKind kind = FragmentParseKind::Malformed;
    ParsedFragment fragment;
};

[[nodiscard]] std::uint8_t byteAt(
    const std::span<const std::byte> bytes, const std::size_t offset) noexcept {
    return std::to_integer<std::uint8_t>(bytes[offset]);
}

[[nodiscard]] std::uint16_t readNetworkU16(
    const std::span<const std::byte> bytes, const std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(byteAt(bytes, offset)) << 8U)
        | static_cast<std::uint16_t>(byteAt(bytes, offset + 1)));
}

[[nodiscard]] std::uint32_t readNetworkU32(
    const std::span<const std::byte> bytes, const std::size_t offset) noexcept {
    return (static_cast<std::uint32_t>(byteAt(bytes, offset)) << 24U)
        | (static_cast<std::uint32_t>(byteAt(bytes, offset + 1)) << 16U)
        | (static_cast<std::uint32_t>(byteAt(bytes, offset + 2)) << 8U)
        | static_cast<std::uint32_t>(byteAt(bytes, offset + 3));
}

void writeNetworkU16(std::vector<std::byte> &bytes, const std::size_t offset,
                     const std::uint16_t value) noexcept {
    bytes[offset] = static_cast<std::byte>(value >> 8U);
    bytes[offset + 1] = static_cast<std::byte>(value & 0xffU);
}

void recomputeIpv4HeaderChecksum(std::vector<std::byte> &packet,
                                 const std::size_t headerLength) noexcept {
    packet[10] = std::byte{0};
    packet[11] = std::byte{0};
    std::uint32_t sum = 0;
    for (std::size_t offset = 0; offset < headerLength; offset += 2) {
        sum += readNetworkU16(packet, offset);
    }
    while ((sum >> 16U) != 0) {
        sum = (sum & 0xffffU) + (sum >> 16U);
    }
    writeNetworkU16(packet, 10, static_cast<std::uint16_t>(~sum));
}

[[nodiscard]] bool hasBytes(
    const std::span<const std::byte> bytes, const std::size_t offset,
    const std::size_t count) noexcept {
    return offset <= bytes.size() && count <= bytes.size() - offset;
}

void setIpv4Address(IpAddress &address, const std::span<const std::byte> bytes,
                    const std::size_t offset) noexcept {
    std::array<std::uint8_t, 4> value{};
    for (std::size_t index = 0; index < value.size(); ++index) {
        value[index] = byteAt(bytes, offset + index);
    }
    address = IpAddress::v4(value);
}

void setIpv6Address(IpAddress &address, const std::span<const std::byte> bytes,
                    const std::size_t offset) noexcept {
    std::array<std::uint8_t, 16> value{};
    for (std::size_t index = 0; index < value.size(); ++index) {
        value[index] = byteAt(bytes, offset + index);
    }
    address = IpAddress::v6(value);
}

[[nodiscard]] std::optional<CanonicalFlowKey> extractOwnerKey(
    const ParsedFragment &fragment, const std::span<const std::byte> bytes,
    const std::uint32_t originalLength) noexcept {
    if (fragment.fragmentOffset != 0
        || (fragment.key.ipProtocol != kTcpProtocol
            && fragment.key.ipProtocol != kUdpProtocol)) {
        return std::nullopt;
    }

    PacketFacts facts{};
    facts.source = fragment.key.source;
    facts.destination = fragment.key.destination;
    facts.ipProtocol = fragment.key.ipProtocol;
    facts.fragmented = false;
    facts.parseStatus = ParseStatus::Ready;
    facts.originalLength = originalLength;
    facts.boundedPrefixLength = fragment.packetLength;

    if (fragment.key.ipProtocol == kTcpProtocol) {
        if (fragment.payloadLength < kTcpMinimumHeaderLength
            || !hasBytes(bytes, fragment.payloadOffset, kTcpMinimumHeaderLength)) {
            return std::nullopt;
        }

        const auto tcpHeaderLength = static_cast<std::size_t>(
            (byteAt(bytes, fragment.payloadOffset + 12) >> 4U) * 4U);
        if (tcpHeaderLength < kTcpMinimumHeaderLength
            || tcpHeaderLength > fragment.payloadLength) {
            return std::nullopt;
        }
    } else {
        if (fragment.payloadLength < kUdpHeaderLength
            || !hasBytes(bytes, fragment.payloadOffset, kUdpHeaderLength)
            || readNetworkU16(bytes, fragment.payloadOffset + 4) < kUdpHeaderLength) {
            return std::nullopt;
        }
    }

    facts.sourcePort = readNetworkU16(bytes, fragment.payloadOffset);
    facts.destinationPort = readNetworkU16(bytes, fragment.payloadOffset + 2);
    facts.portsAvailable = true;
    return CanonicalFlowKey::from(facts);
}

[[nodiscard]] FragmentParseResult parseFragment(
    const std::span<const std::byte> packet, const std::uint32_t originalLength,
    const std::uint32_t maxPacketBytes) noexcept {
    FragmentParseResult result{};
    if (packet.empty() || originalLength == 0) {
        return result;
    }

    const auto boundedLength = std::min(
        packet.size(), static_cast<std::size_t>(originalLength));
    const auto bytes = packet.first(boundedLength);
    if (!hasBytes(bytes, 0, 1)) {
        return result;
    }

    const auto version = byteAt(bytes, 0) >> 4U;
    if (version == kIpv4Version) {
        if (!hasBytes(bytes, 0, kIpv4MinimumHeaderLength)) {
            return result;
        }

        const auto ihl = static_cast<std::size_t>(byteAt(bytes, 0) & 0x0fU);
        const auto headerLength = ihl * 4U;
        if (ihl < 5 || !hasBytes(bytes, 0, headerLength)) {
            return result;
        }

        const auto totalLength = static_cast<std::size_t>(readNetworkU16(bytes, 2));
        if (totalLength < headerLength || totalLength < kIpv4MinimumHeaderLength
            || totalLength > bytes.size()) {
            return result;
        }

        const auto fragmentField = readNetworkU16(bytes, 6);
        if ((fragmentField & 0x8000U) != 0) {
            return result;
        }
        const auto moreFragments = (fragmentField & 0x2000U) != 0;
        const auto fragmentOffset = static_cast<std::uint32_t>(
            fragmentField & 0x1fffU) * 8U;
        if (!moreFragments && fragmentOffset == 0) {
            result.kind = FragmentParseKind::NotFragment;
            return result;
        }

        const auto payloadLength = totalLength - headerLength;
        if (payloadLength == 0) {
            return result;
        }
        if (moreFragments && payloadLength % 8U != 0) {
            return result;
        }

        if (headerLength > maxPacketBytes) {
            result.kind = FragmentParseKind::Capacity;
            return result;
        }
        const auto maxPayloadBytes = static_cast<std::size_t>(maxPacketBytes)
            - headerLength;
        if (fragmentOffset > maxPayloadBytes
            || payloadLength > maxPayloadBytes - fragmentOffset) {
            result.kind = FragmentParseKind::Capacity;
            return result;
        }

        ParsedFragment fragment{};
        fragment.key.family = AddressFamily::Ipv4;
        setIpv4Address(fragment.key.source, bytes, 12);
        setIpv4Address(fragment.key.destination, bytes, 16);
        fragment.key.ipProtocol = byteAt(bytes, 9);
        fragment.key.identification = readNetworkU16(bytes, 4);
        fragment.headerLength = headerLength;
        fragment.payloadOffset = headerLength;
        fragment.payloadLength = payloadLength;
        fragment.fragmentOffset = fragmentOffset;
        fragment.moreFragments = moreFragments;
        fragment.packetLength = static_cast<std::uint32_t>(totalLength);
        fragment.ownerKey = extractOwnerKey(fragment, bytes, originalLength);
        result.fragment = std::move(fragment);
        result.kind = FragmentParseKind::Fragment;
        return result;
    }

    if (version != kIpv6Version || !hasBytes(bytes, 0, kIpv6HeaderLength)) {
        return result;
    }

    const auto payloadLength = static_cast<std::size_t>(readNetworkU16(bytes, 4));
    const auto totalLength = kIpv6HeaderLength + payloadLength;
    if (totalLength < kIpv6HeaderLength || totalLength > bytes.size()) {
        return result;
    }
    if (byteAt(bytes, 6) != kIpv6FragmentHeader) {
        result.kind = FragmentParseKind::NotFragment;
        return result;
    }
    if (payloadLength < kIpv6FragmentHeaderLength
        || !hasBytes(bytes, kIpv6HeaderLength, kIpv6FragmentHeaderLength)) {
        return result;
    }

    const auto fragmentField = readNetworkU16(bytes, kIpv6HeaderLength + 2);
    if (byteAt(bytes, kIpv6HeaderLength + 1) != 0
        || (fragmentField & 0x0006U) != 0) {
        return result;
    }

    const auto fragmentOffset = static_cast<std::uint32_t>(
        (fragmentField >> 3U) & 0x1fffU) * 8U;
    const auto moreFragments = (fragmentField & 0x0001U) != 0;
    const auto fragmentPayloadLength = payloadLength - kIpv6FragmentHeaderLength;
    if (fragmentPayloadLength == 0) {
        return result;
    }
    if (moreFragments && fragmentPayloadLength % 8U != 0) {
        return result;
    }

    const auto maxPayloadBytes = static_cast<std::size_t>(maxPacketBytes)
        - kIpv6HeaderLength;
    if (fragmentOffset > maxPayloadBytes
        || fragmentPayloadLength > maxPayloadBytes - fragmentOffset) {
        result.kind = FragmentParseKind::Capacity;
        return result;
    }

    ParsedFragment fragment{};
    fragment.key.family = AddressFamily::Ipv6;
    setIpv6Address(fragment.key.source, bytes, 8);
    setIpv6Address(fragment.key.destination, bytes, 24);
    fragment.key.ipProtocol = byteAt(bytes, kIpv6HeaderLength);
    fragment.key.identification = readNetworkU32(bytes, kIpv6HeaderLength + 4);
    fragment.headerLength = kIpv6HeaderLength;
    fragment.payloadOffset = kIpv6HeaderLength + kIpv6FragmentHeaderLength;
    fragment.payloadLength = fragmentPayloadLength;
    fragment.fragmentOffset = fragmentOffset;
    fragment.moreFragments = moreFragments;
    fragment.packetLength = static_cast<std::uint32_t>(totalLength);
    fragment.ownerKey = extractOwnerKey(fragment, bytes, originalLength);
    result.fragment = std::move(fragment);
    result.kind = FragmentParseKind::Fragment;
    return result;
}

[[nodiscard]] bool timedOut(const std::uint64_t now, const std::uint64_t lastSeen,
                            const std::uint64_t timeoutTicks) noexcept {
    return now >= lastSeen && now - lastSeen >= timeoutTicks;
}

} // namespace

FragmentSteeringConfig FragmentSteering::validateConfig(
    const FragmentSteeringConfig config) {
    if (config.maxDatagrams == 0 || config.maxFragmentsPerDatagram == 0
        || config.timeoutTicks == 0) {
        throw std::invalid_argument(
            "FragmentSteering bounds and timeout must be non-zero");
    }
    if (config.maxPacketBytes < kIpv6HeaderLength + kIpv6FragmentHeaderLength
        || config.maxPacketBytes > std::numeric_limits<std::uint16_t>::max()) {
        throw std::invalid_argument(
            "FragmentSteering maxPacketBytes is outside the IP length range");
    }
    return config;
}

FragmentSteering::FragmentSteering(
    const WorkerLayout layout, const FragmentSteeringConfig config)
    : FragmentSteering(OwnerSelector(layout), config) {}

FragmentSteering::FragmentSteering(
    OwnerSelector selector, const FragmentSteeringConfig config)
    : selector_(std::move(selector)), config_(validateConfig(config)),
      states_(config_.maxDatagrams) {
    for (auto &state : states_) {
        state.pieces.reserve(config_.maxFragmentsPerDatagram);
    }
}

std::size_t FragmentSteering::findState(const FragmentKey &key) const noexcept {
    for (std::size_t index = 0; index < states_.size(); ++index) {
        if (states_[index].active && states_[index].key == key) {
            return index;
        }
    }
    return kNoState;
}

std::size_t FragmentSteering::findFreeState() const noexcept {
    for (std::size_t index = 0; index < states_.size(); ++index) {
        if (!states_[index].active) {
            return index;
        }
    }
    return kNoState;
}

bool FragmentSteering::existingByteAt(
    const ReassemblyState &state, const std::uint32_t offset,
    std::byte &value) noexcept {
    for (const auto &piece : state.pieces) {
        if (offset < piece.offset
            || offset - piece.offset >= piece.payload.size()) {
            continue;
        }
        value = piece.payload[offset - piece.offset];
        return true;
    }
    return false;
}

bool FragmentSteering::completeCoverage(const ReassemblyState &state) noexcept {
    if (!state.finalPayloadLength.has_value() || state.firstHeader.empty()) {
        return false;
    }

    const auto finalLength = *state.finalPayloadLength;
    for (std::uint32_t offset = 0; offset < finalLength; ++offset) {
        std::byte value{};
        if (!existingByteAt(state, offset, value)) {
            return false;
        }
    }
    return true;
}

std::vector<std::byte> FragmentSteering::buildPacket(
    const ReassemblyState &state) {
    const auto finalLength = *state.finalPayloadLength;
    std::vector<std::byte> packet(
        state.firstHeader.size() + static_cast<std::size_t>(finalLength));
    std::copy(state.firstHeader.begin(), state.firstHeader.end(), packet.begin());

    for (std::uint32_t offset = 0; offset < finalLength; ++offset) {
        std::byte value{};
        const bool found = existingByteAt(state, offset, value);
        if (!found) {
            return {};
        }
        packet[state.firstHeader.size() + offset] = value;
    }

    if (state.key.family == AddressFamily::Ipv4) {
        writeNetworkU16(packet, 2, static_cast<std::uint16_t>(packet.size()));
        writeNetworkU16(packet, 6, 0);
        recomputeIpv4HeaderChecksum(packet, state.firstHeader.size());
    } else {
        packet[6] = static_cast<std::byte>(state.key.ipProtocol);
        writeNetworkU16(
            packet, 4, static_cast<std::uint16_t>(finalLength));
    }
    return packet;
}

void FragmentSteering::resetState(ReassemblyState &state) noexcept {
    if (state.active) {
        state.active = false;
        if (activeDatagrams_ > 0) {
            --activeDatagrams_;
        }
    }
    state.firstHeader.clear();
    state.pieces.clear();
    state.finalPayloadLength.reset();
    state.owner.reset();
    state.lastSeen = 0;
}

std::size_t FragmentSteering::expire(const std::uint64_t now) noexcept {
    std::size_t expired = 0;
    for (auto &state : states_) {
        if (!state.active
            || !timedOut(now, state.lastSeen, config_.timeoutTicks)) {
            continue;
        }
        resetState(state);
        ++expired;
        ++counters_.timeoutDatagrams;
    }
    return expired;
}

FragmentReassemblyResult FragmentSteering::submit(
    const std::span<const std::byte> packet, const std::uint32_t originalLength,
    const std::uint64_t now) {
    ++counters_.packetsSeen;

    const auto parsed = parseFragment(packet, originalLength, config_.maxPacketBytes);
    if (parsed.kind == FragmentParseKind::NotFragment) {
        return {.status = FragmentSubmitStatus::NotFragment};
    }
    if (parsed.kind == FragmentParseKind::Capacity) {
        ++counters_.capacityDrops;
        return {.status = FragmentSubmitStatus::Capacity};
    }
    if (parsed.kind != FragmentParseKind::Fragment) {
        ++counters_.malformedPackets;
        return {.status = FragmentSubmitStatus::Malformed};
    }

    const auto boundedLength = std::min(
        packet.size(), static_cast<std::size_t>(originalLength));
    const auto bytes = packet.first(boundedLength);
    const auto &fragment = parsed.fragment;

    auto stateIndex = findState(fragment.key);
    if (stateIndex != kNoState
        && timedOut(now, states_[stateIndex].lastSeen, config_.timeoutTicks)) {
        resetState(states_[stateIndex]);
        ++counters_.timeoutDatagrams;
        return {.status = FragmentSubmitStatus::Timeout};
    }
    static_cast<void>(expire(now));
    stateIndex = findState(fragment.key);

    if (stateIndex == kNoState) {
        stateIndex = findFreeState();
        if (stateIndex == kNoState) {
            ++counters_.capacityDrops;
            return {.status = FragmentSubmitStatus::Capacity};
        }

        auto &state = states_[stateIndex];
        state.active = true;
        state.key = fragment.key;
        state.lastSeen = now;
        state.finalPayloadLength.reset();
        state.owner.reset();
        state.firstHeader.clear();
        state.pieces.clear();
        ++activeDatagrams_;
    }

    auto &state = states_[stateIndex];
    const auto fragmentEnd = fragment.fragmentOffset
        + static_cast<std::uint32_t>(fragment.payloadLength);

    if (fragment.fragmentOffset == 0) {
        const auto incomingHeader = bytes.first(fragment.headerLength);
        if (!state.firstHeader.empty()
            && (state.firstHeader.size() != incomingHeader.size()
                || !std::equal(state.firstHeader.begin(), state.firstHeader.end(),
                               incomingHeader.begin()))) {
            resetState(state);
            ++counters_.conflictPackets;
            return {.status = FragmentSubmitStatus::Conflict};
        }
        if (state.firstHeader.empty()) {
            state.firstHeader.assign(incomingHeader.begin(), incomingHeader.end());
        }

        if (state.owner.has_value() && fragment.ownerKey.has_value()
            && (state.owner->flowKey != *fragment.ownerKey
                || state.owner->finalOwner != selector_.ownerFor(*fragment.ownerKey))) {
            resetState(state);
            ++counters_.conflictPackets;
            return {.status = FragmentSubmitStatus::Conflict};
        }
        if (!state.owner.has_value() && fragment.ownerKey.has_value()) {
            state.owner = FragmentOwnerMetadata{
                .flowKey = *fragment.ownerKey,
                .finalOwner = selector_.ownerFor(*fragment.ownerKey),
            };
        }
    }

    if (state.finalPayloadLength.has_value()) {
        if (fragment.moreFragments
            ? fragmentEnd >= *state.finalPayloadLength
            : fragmentEnd != *state.finalPayloadLength) {
            resetState(state);
            ++counters_.conflictPackets;
            return {.status = FragmentSubmitStatus::Conflict};
        }
    } else if (!fragment.moreFragments) {
        state.finalPayloadLength = fragmentEnd;
        for (const auto &piece : state.pieces) {
            const auto pieceEnd = piece.offset
                + static_cast<std::uint32_t>(piece.payload.size());
            if (pieceEnd > fragmentEnd) {
                resetState(state);
                ++counters_.conflictPackets;
                return {.status = FragmentSubmitStatus::Conflict};
            }
        }
    }

    bool fullyCovered = true;
    for (std::size_t index = 0; index < fragment.payloadLength; ++index) {
        const auto offset = fragment.fragmentOffset + static_cast<std::uint32_t>(index);
        std::byte existing{};
        if (!existingByteAt(state, offset, existing)) {
            fullyCovered = false;
            continue;
        }
        if (existing != bytes[fragment.payloadOffset + index]) {
            resetState(state);
            ++counters_.conflictPackets;
            return {.status = FragmentSubmitStatus::Conflict};
        }
    }

    state.lastSeen = now;
    if (!fullyCovered) {
        if (state.pieces.size() >= config_.maxFragmentsPerDatagram) {
            resetState(state);
            ++counters_.capacityDrops;
            return {.status = FragmentSubmitStatus::Capacity};
        }

        FragmentPiece piece{};
        piece.offset = fragment.fragmentOffset;
        piece.payload.assign(
            bytes.begin() + static_cast<std::ptrdiff_t>(fragment.payloadOffset),
            bytes.begin() + static_cast<std::ptrdiff_t>(
                fragment.payloadOffset + fragment.payloadLength));
        state.pieces.push_back(std::move(piece));
    }

    if (completeCoverage(state)) {
        FragmentReassemblyResult result{};
        result.status = FragmentSubmitStatus::Reassembled;
        result.packet = buildPacket(state);
        if (result.packet.empty()) {
            resetState(state);
            ++counters_.malformedPackets;
            return {.status = FragmentSubmitStatus::Malformed};
        }
        result.owner = state.owner;
        resetState(state);
        ++counters_.reassembledPackets;
        return result;
    }

    if (fullyCovered) {
        ++counters_.duplicatePackets;
        return {.status = FragmentSubmitStatus::Duplicate};
    }

    ++counters_.bufferedPackets;
    return {.status = FragmentSubmitStatus::Buffered};
}

} // namespace SnortDatapath::Flow
