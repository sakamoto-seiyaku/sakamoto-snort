/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueueTopology.hpp>

#include <gtest/gtest.h>

TEST(NfqueueTopologyTest, ParseAndFormatSupportedModes) {
    EXPECT_EQ(defaultNfqueueTopology(), NfqueueTopology::SplitInOut);

    ASSERT_TRUE(parseNfqueueTopology("split-in-out").has_value());
    EXPECT_EQ(*parseNfqueueTopology("split-in-out"), NfqueueTopology::SplitInOut);
    EXPECT_EQ(nfqueueTopologyToString(NfqueueTopology::SplitInOut), "split-in-out");

    ASSERT_TRUE(parseNfqueueTopology("shared-flow-pool").has_value());
    EXPECT_EQ(*parseNfqueueTopology("shared-flow-pool"), NfqueueTopology::SharedFlowPool);
    EXPECT_EQ(nfqueueTopologyToString(NfqueueTopology::SharedFlowPool), "shared-flow-pool");

    EXPECT_FALSE(parseNfqueueTopology("").has_value());
    EXPECT_FALSE(parseNfqueueTopology("shared").has_value());
}

TEST(NfqueueTopologyTest, SplitInOutUsesDisjointHalfRangesForIpv4AndIpv6) {
    const auto ipv4Plan = makeNfqueueQueuePlan(NfqueueTopology::SplitInOut, 0, 8);
    EXPECT_EQ(ipv4Plan.input, (NfqueueRange{.first = 0, .count = 4}));
    EXPECT_EQ(ipv4Plan.output, (NfqueueRange{.first = 4, .count = 4}));
    EXPECT_EQ(ipv4Plan.listeners, (NfqueueRange{.first = 0, .count = 8}));

    const auto ipv6Plan = makeNfqueueQueuePlan(NfqueueTopology::SplitInOut, 8, 8);
    EXPECT_EQ(ipv6Plan.input, (NfqueueRange{.first = 8, .count = 4}));
    EXPECT_EQ(ipv6Plan.output, (NfqueueRange{.first = 12, .count = 4}));
    EXPECT_EQ(ipv6Plan.listeners, (NfqueueRange{.first = 8, .count = 8}));
}

TEST(NfqueueTopologyTest, SharedFlowPoolUsesFullRangeForBothDirectionsForIpv4AndIpv6) {
    const auto ipv4Plan = makeNfqueueQueuePlan(NfqueueTopology::SharedFlowPool, 0, 8);
    EXPECT_EQ(ipv4Plan.input, (NfqueueRange{.first = 0, .count = 8}));
    EXPECT_EQ(ipv4Plan.output, (NfqueueRange{.first = 0, .count = 8}));
    EXPECT_EQ(ipv4Plan.listeners, (NfqueueRange{.first = 0, .count = 8}));

    const auto ipv6Plan = makeNfqueueQueuePlan(NfqueueTopology::SharedFlowPool, 8, 8);
    EXPECT_EQ(ipv6Plan.input, (NfqueueRange{.first = 8, .count = 8}));
    EXPECT_EQ(ipv6Plan.output, (NfqueueRange{.first = 8, .count = 8}));
    EXPECT_EQ(ipv6Plan.listeners, (NfqueueRange{.first = 8, .count = 8}));
}

TEST(NfqueueTopologyTest, HookToDirectionUsesLocalInAndLocalOut) {
    ASSERT_TRUE(nfqueueHookToDirection(kNfqueueHookLocalIn).has_value());
    EXPECT_EQ(*nfqueueHookToDirection(kNfqueueHookLocalIn), NfqueuePacketDirection::Input);
    EXPECT_TRUE(nfqueueDirectionIsInput(*nfqueueHookToDirection(kNfqueueHookLocalIn)));

    ASSERT_TRUE(nfqueueHookToDirection(kNfqueueHookLocalOut).has_value());
    EXPECT_EQ(*nfqueueHookToDirection(kNfqueueHookLocalOut), NfqueuePacketDirection::Output);
    EXPECT_FALSE(nfqueueDirectionIsInput(*nfqueueHookToDirection(kNfqueueHookLocalOut)));

    EXPECT_FALSE(nfqueueHookToDirection(kNfqueueHookPreRouting).has_value());
    EXPECT_FALSE(nfqueueHookToDirection(kNfqueueHookForward).has_value());
    EXPECT_FALSE(nfqueueHookToDirection(kNfqueueHookPostRouting).has_value());
}
