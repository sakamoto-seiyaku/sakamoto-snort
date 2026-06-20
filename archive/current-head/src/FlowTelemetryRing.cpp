/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <FlowTelemetryRing.hpp>

#include <algorithm>
#include <cstring>
#include <new>

bool FlowTelemetryRing::init(std::span<std::byte> storage, const Config &cfg) {
    if (cfg.slotBytes == 0 || cfg.slotCount == 0) {
        return false;
    }
    if (cfg.slotBytes < FlowTelemetryAbi::kSlotHeaderBytes) {
        return false;
    }
    const std::size_t need = static_cast<std::size_t>(cfg.slotBytes) * static_cast<std::size_t>(cfg.slotCount);
    if (storage.size() < need) {
        return false;
    }

    _cfg = cfg;
    _storage = storage.first(need);
    _writeTicket.store(0, std::memory_order_relaxed);
    _inited = true;

    // Initialize slot state to Empty.
    for (std::uint32_t i = 0; i < _cfg.slotCount; ++i) {
        std::byte *slot = _storage.data() + static_cast<std::size_t>(i) * _cfg.slotBytes;
        // Ensure the state field has an object lifetime for atomic_ref.
        auto *statePtr = std::launder(reinterpret_cast<std::uint32_t *>(slot + FlowTelemetryAbi::kSlotOffsetState));
        new (statePtr) std::uint32_t(static_cast<std::uint32_t>(FlowTelemetryAbi::SlotState::Empty));
    }

    return true;
}

FlowTelemetryRing::SlotPtr FlowTelemetryRing::slotForTicket(const std::uint64_t ticket) const noexcept {
    const std::uint32_t idx = static_cast<std::uint32_t>(ticket % _cfg.slotCount);
    return SlotPtr{.base = _storage.data() + static_cast<std::size_t>(idx) * _cfg.slotBytes};
}

std::atomic_ref<std::uint32_t> FlowTelemetryRing::slotStateRef(const SlotPtr slot) const noexcept {
    auto *p = std::launder(reinterpret_cast<std::uint32_t *>(slot.base + FlowTelemetryAbi::kSlotOffsetState));
    return std::atomic_ref<std::uint32_t>(*p);
}

FlowTelemetryRing::WriteResult
FlowTelemetryRing::tryWrite(const FlowTelemetryAbi::RecordType type,
                            const std::span<const std::byte> payload) noexcept {
    WriteResult out{};
    if (!_inited) {
        out.wrote = false;
        out.dropReason = DropReason::Disabled;
        return out;
    }

    const std::uint64_t ticket = _writeTicket.fetch_add(1, std::memory_order_relaxed);
    out.ticket = ticket;

    const std::uint32_t maxPayload = maxPayloadBytes();
    if (payload.size() > maxPayload) {
        out.wrote = false;
        out.dropReason = DropReason::RecordTooLarge;
        return out;
    }

    const SlotPtr slot = slotForTicket(ticket);
    auto state = slotStateRef(slot);

    std::uint32_t expected = static_cast<std::uint32_t>(FlowTelemetryAbi::SlotState::Empty);
    if (!state.compare_exchange_strong(expected, static_cast<std::uint32_t>(FlowTelemetryAbi::SlotState::Writing),
                                       std::memory_order_acq_rel, std::memory_order_acquire)) {
        if (expected == static_cast<std::uint32_t>(FlowTelemetryAbi::SlotState::Committed)) {
            // Allowed overwrite of a committed slot, but must atomically win the WRITING transition.
            expected = static_cast<std::uint32_t>(FlowTelemetryAbi::SlotState::Committed);
            if (!state.compare_exchange_strong(
                    expected, static_cast<std::uint32_t>(FlowTelemetryAbi::SlotState::Writing),
                    std::memory_order_acq_rel, std::memory_order_acquire)) {
                out.wrote = false;
                out.dropReason = DropReason::SlotBusy;
                return out;
            }
        } else {
            out.wrote = false;
            out.dropReason = DropReason::SlotBusy;
            return out;
        }
    }

    // Write non-atomic header fields using the explicit shared-memory ABI byte order.
    std::span<std::byte> slotBytes(slot.base, _cfg.slotBytes);
    FlowTelemetryAbi::writeU16Le(slotBytes, FlowTelemetryAbi::kSlotOffsetRecordType,
                                 static_cast<std::uint16_t>(type));
    FlowTelemetryAbi::writeU64Le(slotBytes, FlowTelemetryAbi::kSlotOffsetTicket, ticket);
    FlowTelemetryAbi::writeU32Le(slotBytes, FlowTelemetryAbi::kSlotOffsetPayloadSize,
                                 static_cast<std::uint32_t>(payload.size()));

    // Copy payload bytes.
    if (!payload.empty()) {
        std::byte *dst = slot.base + FlowTelemetryAbi::kSlotHeaderBytes;
        std::memcpy(dst, payload.data(), payload.size());
    }

    // Commit (release: publishes header+payload).
    state.store(static_cast<std::uint32_t>(FlowTelemetryAbi::SlotState::Committed), std::memory_order_release);

    out.wrote = true;
    out.dropReason = DropReason::None;
    return out;
}

std::span<const std::byte>
FlowTelemetryRing::slotBytesForTicket(const std::uint64_t ticket) const noexcept {
    const SlotPtr slot = slotForTicket(ticket);
    return std::span<const std::byte>(slot.base, _cfg.slotBytes);
}

std::span<std::byte> FlowTelemetryRing::slotBytesForTicket(const std::uint64_t ticket) noexcept {
    const SlotPtr slot = slotForTicket(ticket);
    return std::span<std::byte>(slot.base, _cfg.slotBytes);
}
