/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <limits>
#include <mutex>
#include <time.h>

class PerfMetrics {
public:
    struct Summary {
        uint64_t samples = 0;
        uint64_t min = 0;
        uint64_t avg = 0;
        uint64_t p50 = 0;
        uint64_t p95 = 0;
        uint64_t p99 = 0;
        uint64_t max = 0;
    };

    struct Snapshot {
        Summary nfq_total_us;
        Summary dns_decision_us;
    };

    PerfMetrics();

    PerfMetrics(const PerfMetrics &) = delete;
    PerfMetrics &operator=(const PerfMetrics &) = delete;

    bool enabled() const noexcept { return _enabled.load(std::memory_order_relaxed); }

    // Control semantics:
    // - default disabled (0)
    // - enable transition 0->1 clears aggregates
    // - idempotent for 1->1 and 0->0 (no clearing)
    // - disable transition 1->0 does NOT clear aggregates (METRICS.PERF returns zeros when disabled)
    void setEnabled(bool enabled);

    // Clears aggregates without changing enabled state.
    void reset();

    // Clears aggregates and forces disabled state.
    void resetAll();

    Snapshot snapshotForControl() const;

    static uint64_t nowUs() noexcept;

    void observeNfqTotalUs(const uint64_t us) noexcept { observe(Metric::NfqTotalUs, us); }

    void observeDnsDecisionUs(const uint64_t us) noexcept { observe(Metric::DnsDecisionUs, us); }

private:
    static constexpr uint32_t kShardCount = 16;
    static constexpr uint32_t kSubBuckets = 8;
    static constexpr uint32_t kMaxLog2 = 23;
    static constexpr uint32_t kBucketCount = 8 + (kMaxLog2 - 3 + 1) * kSubBuckets; // 176
    static constexpr uint64_t kBucketClampMaxUs = (1ULL << 24) - 1;

    enum class Metric : uint32_t { NfqTotalUs = 0, DnsDecisionUs = 1 };

    struct MetricShard {
        std::atomic<uint64_t> samples;
        std::atomic<uint64_t> sum_us;
        std::atomic<uint64_t> min_us;
        std::atomic<uint64_t> max_us;
        std::array<std::atomic<uint64_t>, kBucketCount> buckets;

        MetricShard() noexcept { reset(); }

        void reset() noexcept {
            samples.store(0, std::memory_order_relaxed);
            sum_us.store(0, std::memory_order_relaxed);
            min_us.store(std::numeric_limits<uint64_t>::max(), std::memory_order_relaxed);
            max_us.store(0, std::memory_order_relaxed);
            for (auto &b : buckets) {
                b.store(0, std::memory_order_relaxed);
            }
        }
    };

    struct alignas(64) Shard {
        MetricShard metrics[2];
    };

    std::array<Shard, kShardCount> _shards;
    std::atomic<bool> _enabled{false};
    mutable std::mutex _controlMutex;
    std::atomic<uint32_t> _nextShard{0};

    uint32_t shardIndexForThread() noexcept;

    static constexpr uint32_t bucketUpperBoundFromIndex(const uint32_t idx) noexcept {
        if (idx <= 7) {
            return idx;
        }
        const uint32_t level = (idx - 8) / kSubBuckets;
        const uint32_t sub = (idx - 8) % kSubBuckets;
        const uint32_t k = level + 3;
        const uint32_t shift = k - 3;
        const uint32_t base = 1U << k;
        const uint32_t ub = base + ((sub + 1U) << shift) - 1U;
        return ub;
    }

    static uint64_t percentileFromHistogram(const std::array<uint64_t, kBucketCount> &hist,
                                            uint64_t samples, uint32_t pct) noexcept;

    static inline uint32_t bucketIndexClamped(uint64_t us) noexcept {
        if (us <= 7) {
            return static_cast<uint32_t>(us);
        }

        if (us > kBucketClampMaxUs) {
            us = kBucketClampMaxUs;
        }

        const uint32_t k = static_cast<uint32_t>(63 - __builtin_clzll(static_cast<unsigned long long>(us)));
        const uint32_t kClamped = (k > kMaxLog2) ? kMaxLog2 : k;
        const uint64_t base = 1ULL << kClamped;
        const uint32_t shift = kClamped - 3;
        uint32_t sub = static_cast<uint32_t>((us - base) >> shift);
        if (sub >= kSubBuckets) {
            sub = kSubBuckets - 1;
        }
        return 8 + (kClamped - 3) * kSubBuckets + sub;
    }

    static inline void atomicMin(std::atomic<uint64_t> &dst, const uint64_t value) noexcept {
        uint64_t current = dst.load(std::memory_order_relaxed);
        while (value < current &&
               !dst.compare_exchange_weak(current, value, std::memory_order_relaxed,
                                         std::memory_order_relaxed)) {
        }
    }

    static inline void atomicMax(std::atomic<uint64_t> &dst, const uint64_t value) noexcept {
        uint64_t current = dst.load(std::memory_order_relaxed);
        while (value > current &&
               !dst.compare_exchange_weak(current, value, std::memory_order_relaxed,
                                         std::memory_order_relaxed)) {
        }
    }

    inline void observe(const Metric metric, const uint64_t us) noexcept {
        const uint32_t shardIdx = shardIndexForThread();
        MetricShard &m = _shards[shardIdx].metrics[static_cast<size_t>(metric)];

        // Maintain min/avg/max on the true sample value (no clamp).
        m.sum_us.fetch_add(us, std::memory_order_relaxed);
        atomicMin(m.min_us, us);
        atomicMax(m.max_us, us);

        // Clamp only for percentile buckets.
        const uint32_t idx = bucketIndexClamped(us);
        m.buckets[idx].fetch_add(1, std::memory_order_relaxed);

        // Increment samples last so histogram counts are never observed smaller than samples.
        m.samples.fetch_add(1, std::memory_order_relaxed);
    }

    void resetAggregatesLocked();

    Summary computeSummaryLocked(const Metric metric) const;
};

extern PerfMetrics perfMetrics;

inline PerfMetrics::PerfMetrics() {}

inline uint32_t PerfMetrics::shardIndexForThread() noexcept {
    struct Cache {
        const PerfMetrics *owner = nullptr;
        uint32_t idx = 0;
    };
    thread_local Cache cache;
    if (cache.owner != this) {
        cache.owner = this;
        cache.idx = _nextShard.fetch_add(1, std::memory_order_relaxed) % kShardCount;
    }
    return cache.idx;
}

inline uint64_t PerfMetrics::nowUs() noexcept {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000ULL +
           static_cast<uint64_t>(ts.tv_nsec) / 1000ULL;
}

inline uint64_t PerfMetrics::percentileFromHistogram(
    const std::array<uint64_t, kBucketCount> &hist,
    const uint64_t samples,
    const uint32_t pct) noexcept {
    if (samples == 0) {
        return 0;
    }

    const uint64_t rank = (static_cast<uint64_t>(pct) * samples + 100 - 1) / 100; // nearest-rank
    uint64_t cumulative = 0;
    for (uint32_t i = 0; i < kBucketCount; ++i) {
        cumulative += hist[i];
        if (cumulative >= rank) {
            return bucketUpperBoundFromIndex(i);
        }
    }
    return bucketUpperBoundFromIndex(kBucketCount - 1);
}

inline void PerfMetrics::resetAggregatesLocked() {
    for (auto &shard : _shards) {
        for (auto &metric : shard.metrics) {
            metric.reset();
        }
    }
}

inline void PerfMetrics::setEnabled(const bool enabled) {
    const std::lock_guard<std::mutex> g(_controlMutex);
    const bool current = _enabled.load(std::memory_order_relaxed);

    if (enabled) {
        if (!current) {
            resetAggregatesLocked();
            _enabled.store(true, std::memory_order_relaxed);
        }
        return;
    }

    if (current) {
        _enabled.store(false, std::memory_order_relaxed);
    }
}

inline void PerfMetrics::reset() {
    const std::lock_guard<std::mutex> g(_controlMutex);
    resetAggregatesLocked();
}

inline void PerfMetrics::resetAll() {
    const std::lock_guard<std::mutex> g(_controlMutex);
    _enabled.store(false, std::memory_order_relaxed);
    resetAggregatesLocked();
}

inline PerfMetrics::Summary PerfMetrics::computeSummaryLocked(const Metric metric) const {
    uint64_t samples = 0;
    uint64_t sum = 0;
    uint64_t min = std::numeric_limits<uint64_t>::max();
    uint64_t max = 0;
    std::array<uint64_t, kBucketCount> hist{};

    for (const auto &shard : _shards) {
        const MetricShard &m = shard.metrics[static_cast<size_t>(metric)];
        const uint64_t shardSamples = m.samples.load(std::memory_order_relaxed);
        if (shardSamples == 0) {
            continue;
        }

        samples += shardSamples;
        sum += m.sum_us.load(std::memory_order_relaxed);

        min = std::min(min, m.min_us.load(std::memory_order_relaxed));
        max = std::max(max, m.max_us.load(std::memory_order_relaxed));

        for (uint32_t i = 0; i < kBucketCount; ++i) {
            hist[i] += m.buckets[i].load(std::memory_order_relaxed);
        }
    }

    if (samples == 0) {
        return Summary{};
    }

    Summary out{};
    out.samples = samples;
    out.min = (min == std::numeric_limits<uint64_t>::max()) ? 0 : min;
    out.max = max;
    out.avg = sum / samples;
    out.p50 = percentileFromHistogram(hist, samples, 50);
    out.p95 = percentileFromHistogram(hist, samples, 95);
    out.p99 = percentileFromHistogram(hist, samples, 99);
    return out;
}

inline PerfMetrics::Snapshot PerfMetrics::snapshotForControl() const {
    const std::lock_guard<std::mutex> g(_controlMutex);
    if (!_enabled.load(std::memory_order_relaxed)) {
        return Snapshot{};
    }

    Snapshot out{};
    out.nfq_total_us = computeSummaryLocked(Metric::NfqTotalUs);
    out.dns_decision_us = computeSummaryLocked(Metric::DnsDecisionUs);
    return out;
}
