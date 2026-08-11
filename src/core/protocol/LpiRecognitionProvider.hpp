/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <core/flow/FlowSteering.hpp>
#include <core/protocol/LpiRecognitionAdapter.hpp>

#include <cstdint>
#include <cstddef>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <string_view>

namespace SnortDatapath::Protocol {

inline constexpr std::string_view kDisabledLpiProviderName = "disabled";
inline constexpr bool kRealLpiProviderEnabledByDefault = false;

struct LpiProviderFlowInit {
    Flow::FlowRelativeDirection packetDirection = Flow::FlowRelativeDirection::Orig;
    std::uint8_t ipProtocol = 0;
    std::uint16_t originSourcePort = 0;
    std::uint16_t originDestinationPort = 0;
};

struct LpiPacketSubmission {
    const Flow::PacketFacts &facts;
    std::span<const std::byte> l3Packet;
    std::span<const std::byte> transportPayload;
    Flow::FlowRelativeDirection packetDirection = Flow::FlowRelativeDirection::Orig;
    Flow::LpiProviderFlowContext &flowContext;
};

struct LpiProviderCounters {
    std::uint64_t packetsObserved = 0;
    std::uint64_t payloadEligiblePackets = 0;
    std::uint64_t terminalSkippedPackets = 0;
    std::uint64_t providerUnavailablePackets = 0;
    std::uint64_t flowSlotUnavailablePackets = 0;
    std::uint64_t providerContextUnavailablePackets = 0;
    std::uint64_t packetsSubmittedToProvider = 0;
    std::uint64_t providerNoResultPackets = 0;
    std::uint64_t providerFactPackets = 0;
    std::uint64_t detectorDonePackets = 0;
    std::uint64_t budgetExhaustedPackets = 0;
};

struct LpiProviderStatus {
    bool available = false;
    std::string_view providerName;
    std::uint32_t payloadBudgetPackets =
        Flow::LpiRecognitionState::kMaxPayloadPackets;
    std::uint32_t mappedResultCapacity =
        Flow::LpiRecognitionState::kMaxMappedResults;
    LpiProviderCounters counters;
};

class LpiRecognitionProvider {
public:
    virtual ~LpiRecognitionProvider() = default;

    [[nodiscard]] virtual bool available() const noexcept = 0;
    [[nodiscard]] virtual std::string_view providerName() const noexcept = 0;
    [[nodiscard]] virtual std::unique_ptr<Flow::LpiProviderFlowContext> createFlowContext(
        const LpiProviderFlowInit &) noexcept {
        return std::unique_ptr<Flow::LpiProviderFlowContext>{
            new (std::nothrow) Flow::LpiProviderFlowContext()};
    }
    [[nodiscard]] virtual std::optional<LpiProviderFact> recognize(
        const LpiPacketSubmission &submission) noexcept = 0;
};

class DisabledLpiRecognitionProvider final : public LpiRecognitionProvider {
public:
    [[nodiscard]] bool available() const noexcept override { return false; }
    [[nodiscard]] std::string_view providerName() const noexcept override {
        return kDisabledLpiProviderName;
    }
    [[nodiscard]] std::optional<LpiProviderFact> recognize(
        const LpiPacketSubmission &) noexcept override {
        return std::nullopt;
    }
};

struct LpiPipelineOutcome {
    bool observed = false;
    bool payloadEligible = false;
    bool providerAvailable = false;
    bool terminalSkipped = false;
    bool submittedToProvider = false;
    bool providerProducedFact = false;
    std::optional<LpiAdapterOutcome> adapterOutcome;
    std::optional<Flow::LpiRecognitionState> stateAfterSubmit;
};

/**
 * Bounded packet-submission seam for libprotoident-like recognizers.
 *
 * This class owns no flow/session table. It only submits payload-bearing
 * packets from an existing FlowEntry to a provider, then maps provider facts
 * back through LpiRecognitionAdapter. When no provider is wired, eligible
 * packets are counted as unavailable instead of producing synthetic results.
 */
class LpiRecognitionPipeline final {
public:
    explicit LpiRecognitionPipeline(
        Flow::BoundedFlowTable &flowTable,
        LpiRecognitionProvider *provider = nullptr) noexcept;

    [[nodiscard]] LpiPipelineOutcome submitBeforeAdapterCompletion(
        std::span<const std::byte> l3Packet,
        const Flow::PacketFacts &facts) noexcept;

    [[nodiscard]] LpiProviderStatus status() const noexcept;

private:
    Flow::BoundedFlowTable &flowTable_;
    LpiRecognitionAdapter adapter_;
    DisabledLpiRecognitionProvider disabledProvider_;
    LpiRecognitionProvider *provider_ = nullptr;
    LpiProviderCounters counters_;
};

} // namespace SnortDatapath::Protocol
