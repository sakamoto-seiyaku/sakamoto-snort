/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <NfqueueTopology.hpp>

#include <cstdint>
#include <optional>

namespace SnortDatapath::Nfqueue {

inline constexpr std::uint32_t kNfAcceptVerdict = 1;

struct SentVerdict {
    std::uint32_t packetId = 0;
    std::uint32_t verdict = 0;

    friend bool operator==(const SentVerdict &, const SentVerdict &) = default;
};

struct QueueEvent {
    std::uint32_t packetId = 0;
    NfqueuePacketDirection direction = NfqueuePacketDirection::Input;
};

struct PassThroughMetadata {
    std::uint32_t packetId = 0;
    std::uint8_t hook = 0;
};

struct PassThroughPacketHeader {
    std::optional<std::uint32_t> packetId;
    std::uint8_t hook = 0;
};

enum class PassThroughResult : std::uint8_t {
    VerdictAccepted,
    VerdictSendFailed,
    NoPacketId,
};

class VerdictSink {
public:
    virtual ~VerdictSink() = default;

    virtual bool sendVerdict(std::uint32_t packetId, std::uint32_t verdict) = 0;
};

[[nodiscard]] std::optional<QueueEvent> makeQueueEventFromHook(std::uint32_t packetId,
                                                               std::uint8_t hook) noexcept;
[[nodiscard]] PassThroughResult acceptPassThroughEvent(const QueueEvent &event, VerdictSink &sink);
[[nodiscard]] PassThroughResult acceptPassThroughMetadata(const PassThroughMetadata &metadata,
                                                          VerdictSink &sink);
[[nodiscard]] PassThroughResult acceptPassThroughPacketHeader(
    const PassThroughPacketHeader &header, VerdictSink &sink);

} // namespace SnortDatapath::Nfqueue
