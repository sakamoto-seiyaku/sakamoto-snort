/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <span>

namespace FlowTelemetryAbi {

static_assert(std::endian::native == std::endian::little,
              "FlowTelemetry ABI requires a little-endian platform");

// Shared-memory ring sizing defaults (ABI baseline).
inline constexpr std::uint32_t kSlotBytes = 1024;
inline constexpr std::uint64_t kRingDataBytes = 16ull * 1024ull * 1024ull;
inline constexpr std::uint32_t kSlotCount = 16384;

// Fixed-slot header layout (explicit ABI, independent of C++ struct padding).
//
// Offsets are from the start of a slot.
inline constexpr std::uint32_t kSlotHeaderBytes = 24;
inline constexpr std::uint32_t kSlotOffsetState = 0;       // u32 (atomic semantics)
inline constexpr std::uint32_t kSlotOffsetRecordType = 4;  // u16
inline constexpr std::uint32_t kSlotOffsetTicket = 8;      // u64
inline constexpr std::uint32_t kSlotOffsetPayloadSize = 16; // u32

inline constexpr std::uint32_t kMaxPayloadBytes = kSlotBytes - kSlotHeaderBytes;

enum class SlotState : std::uint32_t {
    Empty = 0,
    Writing = 1,
    Committed = 2,
};

// Top-level record types (MVP).
enum class RecordType : std::uint16_t {
    Flow = 1,
    DnsDecision = 2,
};

// Little-endian serialization helpers for ABI payloads.
//
// These are intentionally explicit and do not rely on host struct layout. Callers are responsible
// for bounds checks.
inline void writeU16Le(std::span<std::byte> out, const std::size_t off, const std::uint16_t v) {
    out[off + 0] = static_cast<std::byte>(v & 0xFFu);
    out[off + 1] = static_cast<std::byte>((v >> 8) & 0xFFu);
}

inline void writeU32Le(std::span<std::byte> out, const std::size_t off, const std::uint32_t v) {
    out[off + 0] = static_cast<std::byte>(v & 0xFFu);
    out[off + 1] = static_cast<std::byte>((v >> 8) & 0xFFu);
    out[off + 2] = static_cast<std::byte>((v >> 16) & 0xFFu);
    out[off + 3] = static_cast<std::byte>((v >> 24) & 0xFFu);
}

inline void writeU64Le(std::span<std::byte> out, const std::size_t off, const std::uint64_t v) {
    writeU32Le(out, off + 0, static_cast<std::uint32_t>(v & 0xFFFFFFFFull));
    writeU32Le(out, off + 4, static_cast<std::uint32_t>((v >> 32) & 0xFFFFFFFFull));
}

inline std::uint16_t readU16Le(std::span<const std::byte> in, const std::size_t off) {
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(in[off + 0]) |
                                      (static_cast<std::uint16_t>(in[off + 1]) << 8));
}

inline std::uint32_t readU32Le(std::span<const std::byte> in, const std::size_t off) {
    return static_cast<std::uint32_t>(static_cast<std::uint32_t>(in[off + 0]) |
                                      (static_cast<std::uint32_t>(in[off + 1]) << 8) |
                                      (static_cast<std::uint32_t>(in[off + 2]) << 16) |
                                      (static_cast<std::uint32_t>(in[off + 3]) << 24));
}

inline std::uint64_t readU64Le(std::span<const std::byte> in, const std::size_t off) {
    const std::uint64_t lo = readU32Le(in, off);
    const std::uint64_t hi = readU32Le(in, off + 4);
    return lo | (hi << 32);
}

} // namespace FlowTelemetryAbi
