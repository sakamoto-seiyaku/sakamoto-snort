/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <core/protocol/LpiRecognitionProvider.hpp>

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
    const auto length = static_cast<std::size_t>(facts.transportPayloadLength);
    if (length > l3Packet.size() - offset) {
        return {};
    }
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

    auto slot = flowTable_.lpiRecognitionFlowSlotFor(facts);
    if (slot.has_value() && slot->recognition != nullptr
        && slot->recognition->terminal()) {
        if (slot->providerContext != nullptr) {
            slot->providerContext->reset();
        }
        ++counters_.terminalSkippedPackets;
        return LpiPipelineOutcome{
            .observed = true,
            .payloadEligible = true,
            .providerAvailable = provider_->available(),
            .terminalSkipped = true,
            .stateAfterSubmit = *slot->recognition,
        };
    }

    if (!provider_->available()) {
        if (slot.has_value() && slot->providerContext != nullptr) {
            slot->providerContext->reset();
        }
        ++counters_.providerUnavailablePackets;
        return LpiPipelineOutcome{
            .observed = true,
            .payloadEligible = true,
            .providerAvailable = false,
            .stateAfterSubmit = slot.has_value() && slot->recognition != nullptr
                ? std::optional<Flow::LpiRecognitionState>{*slot->recognition}
                : std::nullopt,
        };
    }

    if (!slot.has_value() || slot->recognition == nullptr
        || slot->providerContext == nullptr) {
        ++counters_.flowSlotUnavailablePackets;
        return LpiPipelineOutcome{
            .observed = true,
            .payloadEligible = true,
            .providerAvailable = true,
        };
    }

    if (!slot->providerContext->get()) {
        *slot->providerContext = provider_->createFlowContext(LpiProviderFlowInit{
            .packetDirection = slot->packetDirection,
            .ipProtocol = slot->ipProtocol,
            .originSourcePort = slot->originSourcePort,
            .originDestinationPort = slot->originDestinationPort,
        });
    }
    if (!slot->providerContext->get()) {
        ++counters_.providerContextUnavailablePackets;
        return LpiPipelineOutcome{
            .observed = true,
            .payloadEligible = true,
            .providerAvailable = true,
            .stateAfterSubmit = *slot->recognition,
        };
    }

    ++counters_.packetsSubmittedToProvider;
    auto providerFact = provider_->recognize(LpiPacketSubmission{
        .facts = facts,
        .l3Packet = l3Packet,
        .transportPayload = payload,
        .packetDirection = slot->packetDirection,
        .flowContext = **slot->providerContext,
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
    if (adapterOutcome.flowUpdate.has_value()) {
        if (adapterOutcome.flowUpdate->terminalState
            == Flow::LpiRecognitionTerminalState::Done) {
            ++counters_.detectorDonePackets;
            slot->providerContext->reset();
        } else if (adapterOutcome.flowUpdate->terminalState
                   == Flow::LpiRecognitionTerminalState::Exhausted) {
            ++counters_.budgetExhaustedPackets;
            slot->providerContext->reset();
        }
    }
    return LpiPipelineOutcome{
        .observed = true,
        .payloadEligible = true,
        .providerAvailable = true,
        .submittedToProvider = true,
        .providerProducedFact = !providerFact->providerAlias.empty(),
        .adapterOutcome = adapterOutcome,
        .stateAfterSubmit = *slot->recognition,
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
