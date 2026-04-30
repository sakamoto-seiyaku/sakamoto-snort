/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <FlowTelemetryAbi.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

// Fixed-slot overwrite ring for Flow Telemetry export channel.
//
// This is a view over a byte buffer with explicit offsets. It can be backed by shared memory
// (memfd+mmap) or by an in-memory buffer in host tests.
class FlowTelemetryRing {
public:
    struct Config {
        std::uint32_t slotBytes = FlowTelemetryAbi::kSlotBytes;
        std::uint32_t slotCount = FlowTelemetryAbi::kSlotCount;
    };

    enum class DropReason : std::uint8_t {
        None = 0,
        ConsumerAbsent = 1,
        SlotBusy = 2,
        RecordTooLarge = 3,
        Disabled = 4,
        ResourcePressure = 5,
    };

    struct WriteResult {
        bool wrote = false;
        DropReason dropReason = DropReason::None;
        std::uint64_t ticket = 0;
    };

    FlowTelemetryRing() = default;

    FlowTelemetryRing(const FlowTelemetryRing &) = delete;
    FlowTelemetryRing &operator=(const FlowTelemetryRing &) = delete;

    FlowTelemetryRing(FlowTelemetryRing &&) = delete;
    FlowTelemetryRing &operator=(FlowTelemetryRing &&) = delete;

    // Initialize ring view over `storage`. The storage must be at least slotBytes*slotCount bytes.
    bool init(std::span<std::byte> storage, const Config &cfg);

    [[nodiscard]] const Config &config() const noexcept { return _cfg; }
    [[nodiscard]] std::uint32_t slotHeaderBytes() const noexcept { return FlowTelemetryAbi::kSlotHeaderBytes; }
    [[nodiscard]] std::uint32_t maxPayloadBytes() const noexcept { return _cfg.slotBytes - slotHeaderBytes(); }

    // Producer write attempt: reserves a ticket, then attempts to write a single record into the
    // corresponding slot.
    WriteResult tryWrite(FlowTelemetryAbi::RecordType type, std::span<const std::byte> payload) noexcept;

    // Test/support helpers.
    [[nodiscard]] std::uint64_t writeTicketSnapshot() const noexcept {
        return _writeTicket.load(std::memory_order_relaxed);
    }

    // Read-only access to raw slot bytes (for tests / debug).
    [[nodiscard]] std::span<const std::byte> slotBytesForTicket(const std::uint64_t ticket) const noexcept;
    [[nodiscard]] std::span<std::byte> slotBytesForTicket(const std::uint64_t ticket) noexcept;

private:
    struct SlotPtr {
        std::byte *base = nullptr;
    };

    [[nodiscard]] SlotPtr slotForTicket(const std::uint64_t ticket) const noexcept;
    [[nodiscard]] std::atomic_ref<std::uint32_t> slotStateRef(SlotPtr slot) const noexcept;

    Config _cfg{};
    std::span<std::byte> _storage{};
    std::atomic<std::uint64_t> _writeTicket{0};
    bool _inited = false;
};

inline constexpr std::string_view flowTelemetryDropReasonStr(const FlowTelemetryRing::DropReason r) noexcept {
    switch (r) {
    case FlowTelemetryRing::DropReason::None:
        return "none";
    case FlowTelemetryRing::DropReason::ConsumerAbsent:
        return "consumerAbsent";
    case FlowTelemetryRing::DropReason::SlotBusy:
        return "slotBusy";
    case FlowTelemetryRing::DropReason::RecordTooLarge:
        return "recordTooLarge";
    case FlowTelemetryRing::DropReason::Disabled:
        return "disabled";
    case FlowTelemetryRing::DropReason::ResourcePressure:
        return "resourcePressure";
    }
    return "unknown";
}
