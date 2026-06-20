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

} // namespace SnortDatapath::Nfqueue
