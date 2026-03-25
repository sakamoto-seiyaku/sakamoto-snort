/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <DomainPolicySources.hpp>

#include <array>
#include <atomic>
#include <cstdint>

struct DomainPolicySourceCounts {
    uint64_t allow = 0;
    uint64_t block = 0;
};

struct DomainPolicySourcesSnapshot {
    std::array<DomainPolicySourceCounts, kDomainPolicySources.size()> sources;
};

// Device-wide metrics with per-thread sharding to reduce contention.
class DomainPolicySourcesMetrics {
public:
    DomainPolicySourcesMetrics() { reset(); }

    DomainPolicySourcesMetrics(const DomainPolicySourcesMetrics &) = delete;
    DomainPolicySourcesMetrics &operator=(const DomainPolicySourcesMetrics &) = delete;

    void observe(const DomainPolicySource source, const bool blocked) noexcept {
        const size_t idx = static_cast<size_t>(source);
        const uint32_t shardIdx = shardIndexForThread();
        Shard &shard = _shards[shardIdx];
        if (blocked) {
            shard.block[idx].fetch_add(1, std::memory_order_relaxed);
        } else {
            shard.allow[idx].fetch_add(1, std::memory_order_relaxed);
        }
    }

    void reset() noexcept {
        for (auto &shard : _shards) {
            for (size_t i = 0; i < kDomainPolicySources.size(); ++i) {
                shard.allow[i].store(0, std::memory_order_relaxed);
                shard.block[i].store(0, std::memory_order_relaxed);
            }
        }
    }

    DomainPolicySourcesSnapshot snapshot() const noexcept {
        DomainPolicySourcesSnapshot snap{};
        for (auto &c : snap.sources) {
            c = DomainPolicySourceCounts{};
        }

        for (const auto &shard : _shards) {
            for (size_t i = 0; i < kDomainPolicySources.size(); ++i) {
                snap.sources[i].allow += shard.allow[i].load(std::memory_order_relaxed);
                snap.sources[i].block += shard.block[i].load(std::memory_order_relaxed);
            }
        }
        return snap;
    }

private:
    static constexpr uint32_t kShardCount = 16;

    struct alignas(64) Shard {
        std::array<std::atomic<uint64_t>, kDomainPolicySources.size()> allow;
        std::array<std::atomic<uint64_t>, kDomainPolicySources.size()> block;

        Shard() noexcept {
            for (size_t i = 0; i < kDomainPolicySources.size(); ++i) {
                allow[i].store(0, std::memory_order_relaxed);
                block[i].store(0, std::memory_order_relaxed);
            }
        }
    };

    std::array<Shard, kShardCount> _shards;
    std::atomic<uint32_t> _nextShard{0};

    uint32_t shardIndexForThread() noexcept {
        struct Cache {
            const DomainPolicySourcesMetrics *owner = nullptr;
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

// Per-app counters (fixed-dimension, no sharding to keep memory bounded).
class DomainPolicySourcesCounters {
public:
    DomainPolicySourcesCounters() { reset(); }

    DomainPolicySourcesCounters(const DomainPolicySourcesCounters &) = delete;
    DomainPolicySourcesCounters &operator=(const DomainPolicySourcesCounters &) = delete;

    void observe(const DomainPolicySource source, const bool blocked) noexcept {
        const size_t idx = static_cast<size_t>(source);
        if (blocked) {
            _block[idx].fetch_add(1, std::memory_order_relaxed);
        } else {
            _allow[idx].fetch_add(1, std::memory_order_relaxed);
        }
    }

    void reset() noexcept {
        for (size_t i = 0; i < kDomainPolicySources.size(); ++i) {
            _allow[i].store(0, std::memory_order_relaxed);
            _block[i].store(0, std::memory_order_relaxed);
        }
    }

    DomainPolicySourcesSnapshot snapshot() const noexcept {
        DomainPolicySourcesSnapshot snap{};
        for (size_t i = 0; i < kDomainPolicySources.size(); ++i) {
            snap.sources[i].allow = _allow[i].load(std::memory_order_relaxed);
            snap.sources[i].block = _block[i].load(std::memory_order_relaxed);
        }
        return snap;
    }

private:
    std::array<std::atomic<uint64_t>, kDomainPolicySources.size()> _allow{};
    std::array<std::atomic<uint64_t>, kDomainPolicySources.size()> _block{};
};

