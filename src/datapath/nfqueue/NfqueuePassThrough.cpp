/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueuePassThrough.hpp>

namespace SnortDatapath::Nfqueue {

std::optional<QueueEvent> makeQueueEventFromHook(const std::uint32_t packetId,
                                                 const std::uint8_t hook) noexcept {
    const auto direction = nfqueueHookToDirection(hook);
    if (!direction.has_value()) {
        return std::nullopt;
    }
    return QueueEvent{
        .packetId = packetId,
        .direction = *direction,
    };
}

PassThroughResult acceptPassThroughEvent(const QueueEvent &event, VerdictSink &sink) {
    if (!sink.sendVerdict(event.packetId, kNfAcceptVerdict)) {
        return PassThroughResult::VerdictSendFailed;
    }
    return PassThroughResult::VerdictAccepted;
}

PassThroughResult acceptPassThroughMetadata(const PassThroughMetadata &metadata,
                                            VerdictSink &sink) {
    const auto event = makeQueueEventFromHook(metadata.packetId, metadata.hook);
    if (event.has_value()) {
        return acceptPassThroughEvent(*event, sink);
    }
    if (!sink.sendVerdict(metadata.packetId, kNfAcceptVerdict)) {
        return PassThroughResult::VerdictSendFailed;
    }
    return PassThroughResult::VerdictAccepted;
}

PassThroughResult acceptPassThroughPacketHeader(const PassThroughPacketHeader &header,
                                                VerdictSink &sink) {
    if (!header.packetId.has_value()) {
        return PassThroughResult::NoPacketId;
    }
    return acceptPassThroughMetadata(PassThroughMetadata{
                                         .packetId = *header.packetId,
                                         .hook = header.hook,
                                     },
                                     sink);
}

} // namespace SnortDatapath::Nfqueue
