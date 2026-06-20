/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <FlowTelemetryAbi.hpp>
#include <FlowTelemetryRing.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

class FlowTelemetry {
public:
    enum class Level : std::uint8_t {
        Off = 0,
        Flow = 1,
    };

    struct Config {
        std::uint32_t slotBytes = FlowTelemetryAbi::kSlotBytes;
        std::uint64_t ringDataBytes = FlowTelemetryAbi::kRingDataBytes;

        std::uint32_t pollIntervalMs = 1000;
        std::uint64_t bytesThreshold = 128ull * 1024ull;
        std::uint64_t packetsThreshold = 128;
        std::uint32_t maxExportIntervalMs = 5000;

        std::uint32_t blockTtlMs = 10000;
        std::uint32_t pickupTtlMs = 30000;
        std::uint32_t invalidTtlMs = 3000;

        std::uint32_t maxFlowEntries = 1'000'000;
        std::uint32_t maxEntriesPerUid = 10'000;
    };

    // Opaque session handle for hot-path callers. Definition is private to FlowTelemetry.cpp.
    struct Session;

    // Hot-path view for dataplane: a single pointer read (session) plus a borrowed config pointer.
    // When `session==nullptr`, telemetry is considered disabled/absent for this packet.
    struct HotPath {
        Session *session = nullptr;
        const Config *cfg = nullptr;
        std::uint64_t sessionId = 0;
    };

    struct OpenResult {
        Level actualLevel = Level::Off;
        std::uint64_t sessionId = 0;
        std::uint32_t abiVersion = 1;
        std::uint32_t slotBytes = 0;
        std::uint32_t slotCount = 0;
        std::uint64_t ringDataBytes = 0;
        std::uint32_t maxPayloadBytes = 0;
        std::uint64_t writeTicketSnapshot = 0;
        int sharedMemoryFd = -1; // only for Unix-domain OPEN(level=flow)
    };

    struct HealthSnapshot {
        bool enabled = false;
        bool consumerPresent = false;
        std::uint64_t sessionId = 0;
        std::uint32_t slotBytes = 0;
        std::uint32_t slotCount = 0;
        std::uint64_t recordsWritten = 0;
        std::uint64_t recordsDropped = 0;
        FlowTelemetryRing::DropReason lastDropReason = FlowTelemetryRing::DropReason::None;
        std::optional<std::string> lastError;
    };

    FlowTelemetry();
    ~FlowTelemetry();

    FlowTelemetry(const FlowTelemetry &) = delete;
    FlowTelemetry &operator=(const FlowTelemetry &) = delete;

    // vNext control-plane entrypoints. Caller must hold mutexControlMutations, and must take
    // mutexListeners unique lock when replacing/destroying sessions (to avoid use-after-free vs
    // packet shared locks).
    bool open(void *ownerKey, bool canPassFd, Level level, const std::optional<Config> &overrideCfg,
              OpenResult &out, std::string &outError);
    void close(void *ownerKey) noexcept;
    [[nodiscard]] bool isOwner(void *ownerKey) const noexcept;

    // Called under snortResetAll() critical section.
    void resetAll() noexcept;

    [[nodiscard]] HealthSnapshot healthSnapshot() const;

    // Datapath helper: true only when a level=flow consumer session is active.
    [[nodiscard]] bool hasActiveFlowConsumer() const noexcept;

    // Datapath helper: single atomic load to obtain an active flow session + config snapshot.
    [[nodiscard]] HotPath hotPathFlow() const noexcept;

    // Dataplane export (best-effort). When no active consumer session is present, this returns
    // false and accounts a consumerAbsent drop.
    bool exportRecord(FlowTelemetryAbi::RecordType type, std::span<const std::byte> payload) noexcept;

    // Dataplane export using a previously sampled hotPath (avoids repeated session/config loads).
    bool exportRecordHot(const HotPath &hot, FlowTelemetryAbi::RecordType type,
                         std::span<const std::byte> payload) noexcept;

    // Dataplane accounting for telemetry flow-table pressure when no record can be formed.
    void accountResourcePressureDrop() noexcept;

    // Test-only hook to validate OPEN+mmap reader without connecting real packet/DNS hot paths.
    bool exportSyntheticTestRecord() noexcept;

private:
    [[nodiscard]] static std::uint64_t allocateSessionId() noexcept;

    void accountDrop(FlowTelemetryRing::DropReason reason) noexcept;
    void setLastError(std::string message) noexcept;

    std::atomic<Session *> _session{nullptr}; // hot-path view (non-owning)
    std::unique_ptr<Session> _sessionOwner;   // owning pointer; mutated under control lock
    void *_ownerKey = nullptr; // only mutated under control lock

    std::atomic<std::uint64_t> _recordsWritten{0};
    std::atomic<std::uint64_t> _recordsDropped{0};
    std::atomic<FlowTelemetryRing::DropReason> _lastDropReason{FlowTelemetryRing::DropReason::None};

    // Slow-path error text. Written under control lock; read under metrics GET only.
    std::string _lastError;
};

inline constexpr const char *flowTelemetryLevelStr(const FlowTelemetry::Level level) noexcept {
    switch (level) {
    case FlowTelemetry::Level::Off:
        return "off";
    case FlowTelemetry::Level::Flow:
        return "flow";
    }
    return "off";
}

extern FlowTelemetry flowTelemetry;
