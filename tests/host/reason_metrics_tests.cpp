#include <gtest/gtest.h>

#include <PacketReasons.hpp>
#include <ReasonMetrics.hpp>

TEST(ReasonMetricsTest, StartsZero) {
    ReasonMetrics metrics;
    const auto snap = metrics.snapshot();
    for (const auto reasonId : kPacketReasonIds) {
        const size_t idx = static_cast<size_t>(reasonId);
        EXPECT_EQ(snap.reasons[idx].packets, 0U);
        EXPECT_EQ(snap.reasons[idx].bytes, 0U);
        EXPECT_NE(packetReasonIdStr(reasonId), nullptr);
    }
}

TEST(ReasonMetricsTest, ObserveAndReset) {
    ReasonMetrics metrics;

    metrics.observe(PacketReasonId::ALLOW_DEFAULT, 100);
    metrics.observe(PacketReasonId::ALLOW_DEFAULT, 50);
    metrics.observe(PacketReasonId::IFACE_BLOCK, 7);

    auto snap = metrics.snapshot();
    EXPECT_EQ(snap.reasons[static_cast<size_t>(PacketReasonId::ALLOW_DEFAULT)].packets, 2U);
    EXPECT_EQ(snap.reasons[static_cast<size_t>(PacketReasonId::ALLOW_DEFAULT)].bytes, 150U);
    EXPECT_EQ(snap.reasons[static_cast<size_t>(PacketReasonId::IFACE_BLOCK)].packets, 1U);
    EXPECT_EQ(snap.reasons[static_cast<size_t>(PacketReasonId::IFACE_BLOCK)].bytes, 7U);

    metrics.reset();
    snap = metrics.snapshot();
    for (const auto reasonId : kPacketReasonIds) {
        const size_t idx = static_cast<size_t>(reasonId);
        EXPECT_EQ(snap.reasons[idx].packets, 0U);
        EXPECT_EQ(snap.reasons[idx].bytes, 0U);
    }
}

