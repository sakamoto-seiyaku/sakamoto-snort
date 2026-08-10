/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <PacketPolicy.hpp>

#include <gtest/gtest.h>

#include <utility>
#include <vector>

namespace {

using namespace SnortDatapath::Flow;

namespace Policy = SnortDatapath::Policy;

constexpr std::uint8_t kTcp = 6;
constexpr std::uint8_t kUdp = 17;
constexpr std::uint32_t kUid = 10001;
constexpr std::uint64_t kRevision = 7;

PacketFacts ipv4TcpFacts() {
    return PacketFacts{
        .source = IpAddress::v4({10, 0, 0, 1}),
        .destination = IpAddress::v4({192, 0, 2, 1}),
        .ipProtocol = kTcp,
        .sourcePort = 40000,
        .destinationPort = 443,
        .portsAvailable = true,
        .fragmented = false,
        .parseStatus = ParseStatus::Ready,
        .deviceDirection = DevicePacketDirection::Input,
        .originalLength = 128,
        .boundedPrefixLength = 128,
        .domain = FlowDomain{
            .adapter = AdapterKind::RootNfqueue,
            .linuxUid = kUid,
            .captureQueue = 7,
            .networkContext = 2,
            .runtimeProfile = 3,
        },
    };
}

PacketFacts ipv6UdpFacts() {
    return PacketFacts{
        .source = IpAddress::v6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 1}),
        .destination = IpAddress::v6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 2}),
        .ipProtocol = kUdp,
        .sourcePort = 49152,
        .destinationPort = 5353,
        .portsAvailable = true,
        .fragmented = false,
        .parseStatus = ParseStatus::Ready,
        .deviceDirection = DevicePacketDirection::Output,
        .originalLength = 256,
        .boundedPrefixLength = 256,
        .domain = FlowDomain{
            .adapter = AdapterKind::VpnTun,
            .linuxUid = kUid,
            .captureQueue = 11,
            .networkContext = 65,
            .runtimeProfile = 4,
        },
    };
}

Policy::L4Rule dropTcpDst443(
    const std::int32_t priority = 0,
    const std::uint32_t order = 0,
    const std::uint64_t ruleId = 443) {
    return Policy::L4Rule{
        .ruleId = ruleId,
        .reasonId = 44,
        .priority = priority,
        .order = order,
        .action = Policy::L4RuleAction::Drop,
        .match = Policy::L4RuleMatch{
            .family = AddressFamily::Ipv4,
            .direction = DevicePacketDirection::Input,
            .ipProtocol = kTcp,
            .destinationPorts = Policy::PortRange::exact(443),
        },
    };
}

Policy::L4Rule allowTcpDst443(
    const std::int32_t priority = 0,
    const std::uint32_t order = 0,
    const std::uint64_t ruleId = 443) {
    auto rule = dropTcpDst443(priority, order, ruleId);
    rule.reasonId = 45;
    rule.action = Policy::L4RuleAction::Allow;
    return rule;
}

Policy::StatelessPacketPolicySnapshot snapshotWith(
    Policy::PacketPolicySubjectView subject) {
    return Policy::StatelessPacketPolicySnapshot(
        std::vector<Policy::PacketPolicySubjectView>{std::move(subject)},
        kRevision);
}

void expectPass(const Policy::PacketPolicyDecision &decision) {
    EXPECT_EQ(decision.verdict, Policy::PacketPolicyVerdict::PASS_NEXT);
    EXPECT_EQ(decision.stage, Policy::PacketPolicyStage::None);
}

TEST(PacketPolicyTest, MissingSubjectViewPassesNext) {
    const Policy::StatelessPacketPolicySnapshot snapshot(
        std::vector<Policy::PacketPolicySubjectView>{
            Policy::PacketPolicySubjectView{.linuxUid = kUid + 1}},
        kRevision);

    expectPass(snapshot.evaluate(ipv4TcpFacts()));
}

TEST(PacketPolicyTest, NetworkGateDropShortCircuitsBeforeL4Drop) {
    const auto snapshot = snapshotWith(Policy::PacketPolicySubjectView{
        .linuxUid = kUid,
        .networkGate = Policy::NetworkGateView{
            .blockedNetworkContextBits = 1ULL << 2U,
            .reasonId = 10,
            .ruleId = 100,
        },
        .l4Rules = {dropTcpDst443(0, 0, 200)},
    });

    const auto decision = snapshot.evaluate(ipv4TcpFacts());
    EXPECT_EQ(decision.verdict, Policy::PacketPolicyVerdict::DROP);
    EXPECT_EQ(decision.stage, Policy::PacketPolicyStage::NetworkGate);
    EXPECT_EQ(decision.reasonId, 10U);
    EXPECT_EQ(decision.ruleId, 100U);
    EXPECT_EQ(decision.revision, kRevision);
}

TEST(PacketPolicyTest, OpenGateAndNoL4MatchPassesNext) {
    const auto snapshot = snapshotWith(Policy::PacketPolicySubjectView{
        .linuxUid = kUid,
        .l4Rules = {
            Policy::L4Rule{
                .ruleId = 80,
                .reasonId = 80,
                .priority = 0,
                .order = 0,
                .action = Policy::L4RuleAction::Drop,
                .match = Policy::L4RuleMatch{
                    .family = AddressFamily::Ipv4,
                    .direction = DevicePacketDirection::Output,
                    .ipProtocol = kTcp,
                    .destinationPorts = Policy::PortRange::exact(80),
                },
            },
        },
    });

    expectPass(snapshot.evaluate(ipv4TcpFacts()));
}

TEST(PacketPolicyTest, Ipv4TcpExactDestinationPortDropsAtL4) {
    const auto snapshot = snapshotWith(Policy::PacketPolicySubjectView{
        .linuxUid = kUid,
        .l4Rules = {dropTcpDst443(0, 0, 443)},
    });

    const auto decision = snapshot.evaluate(ipv4TcpFacts());
    EXPECT_EQ(decision.verdict, Policy::PacketPolicyVerdict::DROP);
    EXPECT_EQ(decision.stage, Policy::PacketPolicyStage::L4);
    EXPECT_EQ(decision.reasonId, 44U);
    EXPECT_EQ(decision.ruleId, 443U);
    EXPECT_EQ(decision.revision, kRevision);
}

TEST(PacketPolicyTest, Ipv6UdpDestinationPortRangeDropsAtL4) {
    const auto snapshot = snapshotWith(Policy::PacketPolicySubjectView{
        .linuxUid = kUid,
        .l4Rules = {
            Policy::L4Rule{
                .ruleId = 5353,
                .reasonId = 53,
                .priority = 0,
                .order = 0,
                .action = Policy::L4RuleAction::Drop,
                .match = Policy::L4RuleMatch{
                    .family = AddressFamily::Ipv6,
                    .direction = DevicePacketDirection::Output,
                    .ipProtocol = kUdp,
                    .networkContexts = {65},
                    .destinationPorts = Policy::PortRange::inclusive(5300, 5400),
                },
            },
        },
    });

    const auto decision = snapshot.evaluate(ipv6UdpFacts());
    EXPECT_EQ(decision.verdict, Policy::PacketPolicyVerdict::DROP);
    EXPECT_EQ(decision.stage, Policy::PacketPolicyStage::L4);
    EXPECT_EQ(decision.reasonId, 53U);
    EXPECT_EQ(decision.ruleId, 5353U);
}

TEST(PacketPolicyTest, PortsUnavailableDoesNotMatchPortPredicates) {
    const auto snapshot = snapshotWith(Policy::PacketPolicySubjectView{
        .linuxUid = kUid,
        .l4Rules = {dropTcpDst443()},
    });
    auto facts = ipv4TcpFacts();
    facts.portsAvailable = false;

    expectPass(snapshot.evaluate(facts));
}

TEST(PacketPolicyTest, LowerPriorityNumberWinsBeforeHigherPriorityAllow) {
    const auto snapshot = snapshotWith(Policy::PacketPolicySubjectView{
        .linuxUid = kUid,
        .l4Rules = {
            allowTcpDst443(20, 0, 1),
            dropTcpDst443(10, 0, 2),
        },
    });

    const auto decision = snapshot.evaluate(ipv4TcpFacts());
    EXPECT_EQ(decision.verdict, Policy::PacketPolicyVerdict::DROP);
    EXPECT_EQ(decision.stage, Policy::PacketPolicyStage::L4);
    EXPECT_EQ(decision.ruleId, 2U);
}

TEST(PacketPolicyTest, SamePriorityUsesExplicitOrder) {
    auto allowFirst = snapshotWith(Policy::PacketPolicySubjectView{
        .linuxUid = kUid,
        .l4Rules = {
            dropTcpDst443(0, 20, 2),
            allowTcpDst443(0, 10, 1),
        },
    });
    expectPass(allowFirst.evaluate(ipv4TcpFacts()));

    auto dropFirst = snapshotWith(Policy::PacketPolicySubjectView{
        .linuxUid = kUid,
        .l4Rules = {
            allowTcpDst443(0, 20, 1),
            dropTcpDst443(0, 10, 2),
        },
    });
    const auto decision = dropFirst.evaluate(ipv4TcpFacts());
    EXPECT_EQ(decision.verdict, Policy::PacketPolicyVerdict::DROP);
    EXPECT_EQ(decision.ruleId, 2U);
}

TEST(PacketPolicyTest, SamePriorityAndOrderUsesStableRuleId) {
    auto lowerAllowRuleId = snapshotWith(Policy::PacketPolicySubjectView{
        .linuxUid = kUid,
        .l4Rules = {
            dropTcpDst443(0, 0, 11),
            allowTcpDst443(0, 0, 10),
        },
    });
    expectPass(lowerAllowRuleId.evaluate(ipv4TcpFacts()));

    auto lowerDropRuleId = snapshotWith(Policy::PacketPolicySubjectView{
        .linuxUid = kUid,
        .l4Rules = {
            allowTcpDst443(0, 0, 10),
            dropTcpDst443(0, 0, 9),
        },
    });
    const auto decision = lowerDropRuleId.evaluate(ipv4TcpFacts());
    EXPECT_EQ(decision.verdict, Policy::PacketPolicyVerdict::DROP);
    EXPECT_EQ(decision.ruleId, 9U);
}

TEST(PacketPolicyTest, L4AllowDoesNotReopenNetworkGateDrop) {
    const auto snapshot = snapshotWith(Policy::PacketPolicySubjectView{
        .linuxUid = kUid,
        .networkGate = Policy::NetworkGateView{
            .blockedNetworkContexts = {2},
            .reasonId = 10,
            .ruleId = 100,
        },
        .l4Rules = {allowTcpDst443(0, 0, 1)},
    });

    const auto decision = snapshot.evaluate(ipv4TcpFacts());
    EXPECT_EQ(decision.verdict, Policy::PacketPolicyVerdict::DROP);
    EXPECT_EQ(decision.stage, Policy::PacketPolicyStage::NetworkGate);
    EXPECT_EQ(decision.ruleId, 100U);
}

} // namespace
