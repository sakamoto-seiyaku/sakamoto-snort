#include <PerfMetrics.hpp>

#include <gtest/gtest.h>

namespace {

TEST(PerfMetricsTest, DisabledSnapshotReturnsAllZeros) {
    PerfMetrics pm;
    const auto snap = pm.snapshotForControl();

    EXPECT_EQ(snap.nfq_total_us.samples, 0u);
    EXPECT_EQ(snap.nfq_total_us.min, 0u);
    EXPECT_EQ(snap.nfq_total_us.avg, 0u);
    EXPECT_EQ(snap.nfq_total_us.p50, 0u);
    EXPECT_EQ(snap.nfq_total_us.p95, 0u);
    EXPECT_EQ(snap.nfq_total_us.p99, 0u);
    EXPECT_EQ(snap.nfq_total_us.max, 0u);

    EXPECT_EQ(snap.dns_decision_us.samples, 0u);
    EXPECT_EQ(snap.dns_decision_us.min, 0u);
    EXPECT_EQ(snap.dns_decision_us.avg, 0u);
    EXPECT_EQ(snap.dns_decision_us.p50, 0u);
    EXPECT_EQ(snap.dns_decision_us.p95, 0u);
    EXPECT_EQ(snap.dns_decision_us.p99, 0u);
    EXPECT_EQ(snap.dns_decision_us.max, 0u);
}

TEST(PerfMetricsTest, EnableTransitionResetsAggregates) {
    PerfMetrics pm;
    pm.setEnabled(true);
    pm.observeNfqTotalUs(1);
    ASSERT_EQ(pm.snapshotForControl().nfq_total_us.samples, 1u);

    pm.setEnabled(false);
    pm.setEnabled(true); // 0->1 MUST clear aggregates

    const auto snap = pm.snapshotForControl();
    EXPECT_EQ(snap.nfq_total_us.samples, 0u);
}

TEST(PerfMetricsTest, IdempotentEnableDoesNotResetAggregates) {
    PerfMetrics pm;
    pm.setEnabled(true);
    pm.observeNfqTotalUs(1);
    ASSERT_EQ(pm.snapshotForControl().nfq_total_us.samples, 1u);

    pm.setEnabled(true); // 1->1 MUST NOT clear aggregates
    const auto snap = pm.snapshotForControl();
    EXPECT_EQ(snap.nfq_total_us.samples, 1u);
}

TEST(PerfMetricsTest, PercentilesUseBucketUpperBound) {
    PerfMetrics pm;
    pm.setEnabled(true);

    pm.observeNfqTotalUs(16);
    const auto snap = pm.snapshotForControl().nfq_total_us;

    EXPECT_EQ(snap.samples, 1u);
    EXPECT_EQ(snap.min, 16u);
    EXPECT_EQ(snap.max, 16u);
    EXPECT_EQ(snap.avg, 16u);
    EXPECT_EQ(snap.p50, 17u);
    EXPECT_EQ(snap.p95, 17u);
    EXPECT_EQ(snap.p99, 17u);
}

TEST(PerfMetricsTest, ClampAffectsPercentilesOnly) {
    constexpr uint64_t kMaxUs = (1ULL << 24) - 1;

    PerfMetrics pm;
    pm.setEnabled(true);

    const uint64_t value = 20000000ULL; // > 2^24, MUST clamp to last bucket for pXX
    pm.observeNfqTotalUs(value);

    const auto snap = pm.snapshotForControl().nfq_total_us;
    EXPECT_EQ(snap.samples, 1u);

    // Real values
    EXPECT_EQ(snap.min, value);
    EXPECT_EQ(snap.max, value);
    EXPECT_EQ(snap.avg, value);

    // Percentiles are histogram upper bounds (clamped by buckets range)
    EXPECT_EQ(snap.p50, kMaxUs);
    EXPECT_EQ(snap.p95, kMaxUs);
    EXPECT_EQ(snap.p99, kMaxUs);
}

TEST(PerfMetricsTest, NearestRankPercentilesMatchDefinitionForExactBuckets) {
    PerfMetrics pm;
    pm.setEnabled(true);

    pm.observeNfqTotalUs(1);
    pm.observeNfqTotalUs(2);
    pm.observeNfqTotalUs(3);
    pm.observeNfqTotalUs(4);

    const auto snap = pm.snapshotForControl().nfq_total_us;
    EXPECT_EQ(snap.samples, 4u);
    EXPECT_EQ(snap.min, 1u);
    EXPECT_EQ(snap.max, 4u);
    EXPECT_EQ(snap.avg, 2u); // floor(10/4)
    EXPECT_EQ(snap.p50, 2u); // rank=ceil(0.5*4)=2 -> x[2]=2
    EXPECT_EQ(snap.p95, 4u); // rank=ceil(0.95*4)=4 -> x[4]=4
    EXPECT_EQ(snap.p99, 4u);
}

TEST(PerfMetricsTest, ResetClearsSamplesWithoutChangingEnabledState) {
    PerfMetrics pm;
    pm.setEnabled(true);
    pm.observeDnsDecisionUs(5);
    ASSERT_EQ(pm.snapshotForControl().dns_decision_us.samples, 1u);

    pm.reset();
    const auto snap = pm.snapshotForControl();
    EXPECT_EQ(snap.nfq_total_us.samples, 0u);
    EXPECT_EQ(snap.dns_decision_us.samples, 0u);
}

} // namespace

