/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <PacketReasons.hpp>

#include <array>
#include <atomic>
#include <cstdint>

class ReasonMetrics {
public:
    struct Counters {
        uint64_t packets = 0;
        uint64_t bytes = 0;
    };

    struct Snapshot {
        std::array<Counters, kPacketReasonIds.size()> reasons;
    };

    ReasonMetrics() { reset(); }

    ReasonMetrics(const ReasonMetrics &) = delete;
    ReasonMetrics &operator=(const ReasonMetrics &) = delete;

    void observe(const PacketReasonId reasonId, const uint64_t bytes) noexcept {
        const size_t idx = static_cast<size_t>(reasonId);
        const uint32_t shardIdx = shardIndexForThread();
        Shard &shard = _shards[shardIdx];
        shard.packets[idx].fetch_add(1, std::memory_order_relaxed);
        shard.bytes[idx].fetch_add(bytes, std::memory_order_relaxed);
    }

    void reset() noexcept {
        for (auto &shard : _shards) {
            for (size_t i = 0; i < kPacketReasonIds.size(); ++i) {
                shard.packets[i].store(0, std::memory_order_relaxed);
                shard.bytes[i].store(0, std::memory_order_relaxed);
            }
        }
    }

    Snapshot snapshot() const noexcept {
        Snapshot snap{};
        for (auto &c : snap.reasons) {
            c = Counters{};
        }

        for (const auto &shard : _shards) {
            for (size_t i = 0; i < kPacketReasonIds.size(); ++i) {
                snap.reasons[i].packets += shard.packets[i].load(std::memory_order_relaxed);
                snap.reasons[i].bytes += shard.bytes[i].load(std::memory_order_relaxed);
            }
        }
        return snap;
    }

private:
    static constexpr uint32_t kShardCount = 16;

    struct alignas(64) Shard {
        std::array<std::atomic<uint64_t>, kPacketReasonIds.size()> packets;
        std::array<std::atomic<uint64_t>, kPacketReasonIds.size()> bytes;

        Shard() noexcept {
            for (size_t i = 0; i < kPacketReasonIds.size(); ++i) {
                packets[i].store(0, std::memory_order_relaxed);
                bytes[i].store(0, std::memory_order_relaxed);
            }
        }
    };

    std::array<Shard, kShardCount> _shards;
    std::atomic<uint32_t> _nextShard{0};

    uint32_t shardIndexForThread() noexcept {
        struct Cache {
            const ReasonMetrics *owner = nullptr;
            uint32_t idx = 0;
        };
        thread_local Cache cache;
        if (cache.owner != this) {
            cache.owner = this;
            cache.idx = _nextShard.fetch_add(1, std::memory_order_relaxed) % kShardCount;
        }
        return cache.idx;
    }
};

