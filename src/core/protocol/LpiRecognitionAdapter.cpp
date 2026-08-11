/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <core/protocol/LpiRecognitionAdapter.hpp>

#include <core/protocol/ApplicationProtocolCatalog.hpp>

namespace SnortDatapath::Protocol {

LpiAdapterOutcome LpiRecognitionAdapter::submitProviderFact(
    const Flow::PacketFacts &facts,
    const LpiProviderFact fact) noexcept {
    const auto mapped = fact.providerAlias.empty()
        ? std::optional<sucre::protocol::ApplicationProtocolId>{}
        : sucre::protocol::applicationProtocolIdForProviderAlias(fact.providerAlias);
    const auto payloadBearing = facts.hasTransportPayload();
    const auto update = flowTable_.recordLpiRecognition(
        facts,
        payloadBearing,
        mapped,
        !fact.providerAlias.empty(),
        fact.detectorDone,
        fact.budgetExhausted);
    return LpiAdapterOutcome{
        .flowUpdate = update,
        .cutoff = fact.producedBeforeAdapterCompletion
            ? RecognitionDecisionCutoff::CurrentPacket
            : RecognitionDecisionCutoff::FuturePacketsOnly,
        .mappedProviderResult = mapped.has_value(),
        .unmappedProviderResult = payloadBearing
            && !fact.providerAlias.empty()
            && !mapped.has_value(),
    };
}

} // namespace SnortDatapath::Protocol
