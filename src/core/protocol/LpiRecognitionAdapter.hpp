/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <core/flow/FlowSteering.hpp>

#include <cstdint>
#include <optional>
#include <string_view>

namespace SnortDatapath::Protocol {

enum class RecognitionDecisionCutoff : std::uint8_t {
    CurrentPacket,
    FuturePacketsOnly,
};

struct LpiProviderFact {
    bool payloadBearing = false;
    std::string_view providerAlias;
    bool detectorDone = false;
    bool budgetExhausted = false;
    bool producedBeforeAdapterCompletion = true;
};

struct LpiAdapterOutcome {
    std::optional<Flow::LpiRecognitionUpdate> flowUpdate;
    RecognitionDecisionCutoff cutoff = RecognitionDecisionCutoff::CurrentPacket;
    bool mappedProviderResult = false;
    bool unmappedProviderResult = false;
};

/**
 * Adapter-neutral seam between libprotoident provider facts and the
 * worker-owned FlowEntry recognition state. It never owns a second flow table;
 * missing flows are reported through BoundedFlowTable::recordLpiRecognition.
 */
class LpiRecognitionAdapter final {
public:
    explicit LpiRecognitionAdapter(Flow::BoundedFlowTable &flowTable) noexcept
        : flowTable_(flowTable) {}

    [[nodiscard]] LpiAdapterOutcome submitProviderFact(
        const Flow::PacketFacts &facts,
        LpiProviderFact fact) noexcept;

private:
    Flow::BoundedFlowTable &flowTable_;
};

} // namespace SnortDatapath::Protocol
