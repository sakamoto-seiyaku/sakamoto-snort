/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueuePassThrough.hpp>

namespace SnortDatapath::Nfqueue {

PassThroughResult acceptPassThroughEvent(const QueueEvent &event, VerdictSink &sink) {
    if (!sink.sendVerdict(event.packetId, kNfAcceptVerdict)) {
        return PassThroughResult::VerdictSendFailed;
    }
    return PassThroughResult::VerdictAccepted;
}

} // namespace SnortDatapath::Nfqueue
