/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <core/protocol/LpiRecognitionProvider.hpp>

#include <algorithm>

namespace SnortDatapath::Protocol {
namespace {

[[nodiscard]] std::span<const std::byte> transportPayloadFor(
    const std::span<const std::byte> l3Packet,
    const Flow::PacketFacts &facts) noexcept {
    if (!facts.hasTransportPayload()) {
        return {};
    }
    const auto offset = static_cast<std::size_t>(facts.transportPayloadOffset);
    if (offset >= l3Packet.size()) {
        return {};
    }
    const auto available = l3Packet.size() - offset;
    const auto length = std::min<std::size_t>(
        available, static_cast<std::size_t>(facts.transportPayloadLength));
    return l3Packet.subspan(offset, length);
}

} // namespace

LpiRecognitionPipeline::LpiRecognitionPipeline(
    Flow::BoundedFlowTable &flowTable,
    LpiRecognitionProvider *provider) noexcept
    : flowTable_(flowTable),
      adapter_(flowTable),
      provider_(provider == nullptr ? &disabledProvider_ : provider) {}

LpiPipelineOutcome LpiRecognitionPipeline::submitBeforeAdapterCompletion(
    const std::span<const std::byte> l3Packet,
    const Flow::PacketFacts &facts) noexcept {
    ++counters_.packetsObserved;
    const auto payload = transportPayloadFor(l3Packet, facts);
    if (payload.empty()) {
        return LpiPipelineOutcome{
            .observed = true,
            .payloadEligible = false,
            .providerAvailable = provider_->available(),
        };
    }
    ++counters_.payloadEligiblePackets;

    const auto currentState = flowTable_.lpiRecognitionStateFor(facts);
    if (currentState.has_value() && currentState->terminal()) {
        ++counters_.terminalSkippedPackets;
        return LpiPipelineOutcome{
            .observed = true,
            .payloadEligible = true,
            .providerAvailable = provider_->available(),
            .terminalSkipped = true,
            .stateAfterSubmit = currentState,
        };
    }

    if (!provider_->available()) {
        ++counters_.providerUnavailablePackets;
        return LpiPipelineOutcome{
            .observed = true,
            .payloadEligible = true,
            .providerAvailable = false,
            .stateAfterSubmit = currentState,
        };
    }

    ++counters_.packetsSubmittedToProvider;
    auto providerFact = provider_->recognize(LpiPacketSubmission{
        .facts = facts,
        .l3Packet = l3Packet,
        .transportPayload = payload,
    });
    if (!providerFact.has_value()) {
        ++counters_.providerNoResultPackets;
        providerFact = LpiProviderFact{
            .providerAlias = {},
            .detectorDone = false,
            .budgetExhausted = false,
            .producedBeforeAdapterCompletion = true,
        };
    } else {
        ++counters_.providerFactPackets;
        providerFact->producedBeforeAdapterCompletion = true;
    }

    auto adapterOutcome = adapter_.submitProviderFact(facts, *providerFact);
    return LpiPipelineOutcome{
        .observed = true,
        .payloadEligible = true,
        .providerAvailable = true,
        .submittedToProvider = true,
        .providerProducedFact = !providerFact->providerAlias.empty(),
        .adapterOutcome = adapterOutcome,
        .stateAfterSubmit = flowTable_.lpiRecognitionStateFor(facts),
    };
}

LpiProviderStatus LpiRecognitionPipeline::status() const noexcept {
    return LpiProviderStatus{
        .available = provider_->available(),
        .providerName = provider_->providerName(),
        .counters = counters_,
    };
}

} // namespace SnortDatapath::Protocol
