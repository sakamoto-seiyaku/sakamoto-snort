/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueueHookPlan.hpp>
#include <NfqueueHookInstaller.hpp>
#include <NfqueuePassThrough.hpp>
#include <NfqueuePassThroughRuntime.hpp>

#include <NfqueueTopology.hpp>

#include <atomic>
#include <optional>
#include <vector>

#include <gtest/gtest.h>

namespace {

class RecordingVerdictSink final : public SnortDatapath::Nfqueue::VerdictSink {
public:
    bool sendVerdict(const std::uint32_t packetId, const std::uint32_t verdict) override {
        verdicts.push_back(SnortDatapath::Nfqueue::SentVerdict{
            .packetId = packetId,
            .verdict = verdict,
        });
        return true;
    }

    std::vector<SnortDatapath::Nfqueue::SentVerdict> verdicts;
};

class FailingVerdictSink final : public SnortDatapath::Nfqueue::VerdictSink {
public:
    bool sendVerdict(const std::uint32_t packetId, const std::uint32_t verdict) override {
        attempts.push_back(SnortDatapath::Nfqueue::SentVerdict{
            .packetId = packetId,
            .verdict = verdict,
        });
        return false;
    }

    std::vector<SnortDatapath::Nfqueue::SentVerdict> attempts;
};

class RecordingHookExecutor final : public SnortDatapath::Nfqueue::HookCommandExecutor {
public:
    bool execute(const SnortDatapath::Nfqueue::IptablesCommand &command) override {
        commands.push_back(command);
        return true;
    }

    std::vector<SnortDatapath::Nfqueue::IptablesCommand> commands;
};

} // namespace

TEST(NfqueueIpv4PassThroughTest, BuildsIpv4PassThroughHookPlan) {
    const auto queuePlan = makeNfqueueQueuePlan(NfqueueTopology::SplitInOut, 0, 4);
    const auto plan = SnortDatapath::Nfqueue::makeIpv4PassThroughHookPlan(
        SnortDatapath::Nfqueue::HookPlanConfig{
            .inputChain = "sucre-snort_INPUT",
            .outputChain = "sucre-snort_OUTPUT",
            .queuePlan = queuePlan,
        });

    const std::vector<SnortDatapath::Nfqueue::IptablesCommand> expected{
        {"/system/bin/iptables", {"-w", "-N", "sucre-snort_INPUT"}},
        {"/system/bin/iptables", {"-w", "-N", "sucre-snort_OUTPUT"}},
        {"/system/bin/iptables", {"-w", "-F", "sucre-snort_INPUT"}},
        {"/system/bin/iptables", {"-w", "-F", "sucre-snort_OUTPUT"}},
        {"/system/bin/iptables", {"-w", "-D", "INPUT", "-j", "sucre-snort_INPUT"}},
        {"/system/bin/iptables", {"-w", "-D", "OUTPUT", "-j", "sucre-snort_OUTPUT"}},
        {"/system/bin/iptables", {"-w", "-A", "INPUT", "-j", "sucre-snort_INPUT"}},
        {"/system/bin/iptables", {"-w", "-A", "OUTPUT", "-j", "sucre-snort_OUTPUT"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_INPUT", "-i", "lo", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_OUTPUT", "-o", "lo", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_INPUT", "-p", "udp", "--sport", "53", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_OUTPUT", "-p", "udp", "--dport", "53", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_INPUT", "-p", "tcp", "--sport", "53", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_OUTPUT", "-p", "tcp", "--dport", "53", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_INPUT", "-p", "udp", "--sport", "853", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_OUTPUT", "-p", "udp", "--dport", "853", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_INPUT", "-p", "tcp", "--sport", "853", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_OUTPUT", "-p", "tcp", "--dport", "853", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_INPUT", "-p", "udp", "--sport", "5353", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_OUTPUT", "-p", "udp", "--dport", "5353", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_INPUT", "-p", "tcp", "--sport", "5353", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_OUTPUT", "-p", "tcp", "--dport", "5353", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_INPUT", "-j", "NFQUEUE", "--queue-bypass", "--queue-balance", "0:1"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_OUTPUT", "-j", "NFQUEUE", "--queue-bypass", "--queue-balance", "2:3"}},
    };

    EXPECT_EQ(plan.commands, expected);
}

TEST(NfqueueDualStackPassThroughTest, BuildsSharedDualStackHookPlan) {
    const auto plan = SnortDatapath::Nfqueue::makeDualStackPassThroughHookPlan(
        SnortDatapath::Nfqueue::DualStackHookPlanConfig{
            .inputChain = "sucre-snort_INPUT",
            .outputChain = "sucre-snort_OUTPUT",
            .topology = NfqueueTopology::SplitInOut,
            .ipv4FirstQueue = 0,
            .ipv6FirstQueue = 4,
            .queuesPerFamily = 4,
        });

    const std::vector<SnortDatapath::Nfqueue::IptablesCommand> expected{
        {"/system/bin/iptables", {"-w", "-N", "sucre-snort_INPUT"}},
        {"/system/bin/iptables", {"-w", "-N", "sucre-snort_OUTPUT"}},
        {"/system/bin/iptables", {"-w", "-F", "sucre-snort_INPUT"}},
        {"/system/bin/iptables", {"-w", "-F", "sucre-snort_OUTPUT"}},
        {"/system/bin/iptables", {"-w", "-D", "INPUT", "-j", "sucre-snort_INPUT"}},
        {"/system/bin/iptables", {"-w", "-D", "OUTPUT", "-j", "sucre-snort_OUTPUT"}},
        {"/system/bin/iptables", {"-w", "-A", "INPUT", "-j", "sucre-snort_INPUT"}},
        {"/system/bin/iptables", {"-w", "-A", "OUTPUT", "-j", "sucre-snort_OUTPUT"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_INPUT", "-i", "lo", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_OUTPUT", "-o", "lo", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_INPUT", "-p", "udp", "--sport", "53", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_OUTPUT", "-p", "udp", "--dport", "53", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_INPUT", "-p", "tcp", "--sport", "53", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_OUTPUT", "-p", "tcp", "--dport", "53", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_INPUT", "-p", "udp", "--sport", "853", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_OUTPUT", "-p", "udp", "--dport", "853", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_INPUT", "-p", "tcp", "--sport", "853", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_OUTPUT", "-p", "tcp", "--dport", "853", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_INPUT", "-p", "udp", "--sport", "5353", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_OUTPUT", "-p", "udp", "--dport", "5353", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_INPUT", "-p", "tcp", "--sport", "5353", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_OUTPUT", "-p", "tcp", "--dport", "5353", "-j", "RETURN"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_INPUT", "-j", "NFQUEUE", "--queue-bypass", "--queue-balance", "0:1"}},
        {"/system/bin/iptables", {"-w", "-A", "sucre-snort_OUTPUT", "-j", "NFQUEUE", "--queue-bypass", "--queue-balance", "2:3"}},
        {"/system/bin/ip6tables", {"-w", "-N", "sucre-snort_INPUT"}},
        {"/system/bin/ip6tables", {"-w", "-N", "sucre-snort_OUTPUT"}},
        {"/system/bin/ip6tables", {"-w", "-F", "sucre-snort_INPUT"}},
        {"/system/bin/ip6tables", {"-w", "-F", "sucre-snort_OUTPUT"}},
        {"/system/bin/ip6tables", {"-w", "-D", "INPUT", "-j", "sucre-snort_INPUT"}},
        {"/system/bin/ip6tables", {"-w", "-D", "OUTPUT", "-j", "sucre-snort_OUTPUT"}},
        {"/system/bin/ip6tables", {"-w", "-A", "INPUT", "-j", "sucre-snort_INPUT"}},
        {"/system/bin/ip6tables", {"-w", "-A", "OUTPUT", "-j", "sucre-snort_OUTPUT"}},
        {"/system/bin/ip6tables", {"-w", "-A", "sucre-snort_INPUT", "-i", "lo", "-j", "RETURN"}},
        {"/system/bin/ip6tables", {"-w", "-A", "sucre-snort_OUTPUT", "-o", "lo", "-j", "RETURN"}},
        {"/system/bin/ip6tables", {"-w", "-A", "sucre-snort_INPUT", "-p", "udp", "--sport", "53", "-j", "RETURN"}},
        {"/system/bin/ip6tables", {"-w", "-A", "sucre-snort_OUTPUT", "-p", "udp", "--dport", "53", "-j", "RETURN"}},
        {"/system/bin/ip6tables", {"-w", "-A", "sucre-snort_INPUT", "-p", "tcp", "--sport", "53", "-j", "RETURN"}},
        {"/system/bin/ip6tables", {"-w", "-A", "sucre-snort_OUTPUT", "-p", "tcp", "--dport", "53", "-j", "RETURN"}},
        {"/system/bin/ip6tables", {"-w", "-A", "sucre-snort_INPUT", "-p", "udp", "--sport", "853", "-j", "RETURN"}},
        {"/system/bin/ip6tables", {"-w", "-A", "sucre-snort_OUTPUT", "-p", "udp", "--dport", "853", "-j", "RETURN"}},
        {"/system/bin/ip6tables", {"-w", "-A", "sucre-snort_INPUT", "-p", "tcp", "--sport", "853", "-j", "RETURN"}},
        {"/system/bin/ip6tables", {"-w", "-A", "sucre-snort_OUTPUT", "-p", "tcp", "--dport", "853", "-j", "RETURN"}},
        {"/system/bin/ip6tables", {"-w", "-A", "sucre-snort_INPUT", "-p", "udp", "--sport", "5353", "-j", "RETURN"}},
        {"/system/bin/ip6tables", {"-w", "-A", "sucre-snort_OUTPUT", "-p", "udp", "--dport", "5353", "-j", "RETURN"}},
        {"/system/bin/ip6tables", {"-w", "-A", "sucre-snort_INPUT", "-p", "tcp", "--sport", "5353", "-j", "RETURN"}},
        {"/system/bin/ip6tables", {"-w", "-A", "sucre-snort_OUTPUT", "-p", "tcp", "--dport", "5353", "-j", "RETURN"}},
        {"/system/bin/ip6tables", {"-w", "-A", "sucre-snort_INPUT", "-j", "NFQUEUE", "--queue-bypass", "--queue-balance", "4:5"}},
        {"/system/bin/ip6tables", {"-w", "-A", "sucre-snort_OUTPUT", "-j", "NFQUEUE", "--queue-bypass", "--queue-balance", "6:7"}},
    };

    EXPECT_EQ(plan.commands, expected);
}

TEST(NfqueueIpv4PassThroughTest, AcceptsNormalQueueEventExactlyOnce) {
    RecordingVerdictSink sink;

    const auto result = SnortDatapath::Nfqueue::acceptPassThroughEvent(
        SnortDatapath::Nfqueue::QueueEvent{.packetId = 42}, sink);

    EXPECT_EQ(result, SnortDatapath::Nfqueue::PassThroughResult::VerdictAccepted);
    ASSERT_EQ(sink.verdicts.size(), 1U);
    EXPECT_EQ(sink.verdicts[0],
              (SnortDatapath::Nfqueue::SentVerdict{
                  .packetId = 42,
                  .verdict = SnortDatapath::Nfqueue::kNfAcceptVerdict,
              }));
}

TEST(NfqueuePassThroughTest, QueueEventDirectionComesFromNfqueueHook) {
    const auto input = SnortDatapath::Nfqueue::makeQueueEventFromHook(
        42, kNfqueueHookLocalIn);
    ASSERT_TRUE(input.has_value());
    EXPECT_EQ(input->packetId, 42U);
    EXPECT_EQ(input->direction, NfqueuePacketDirection::Input);

    const auto output = SnortDatapath::Nfqueue::makeQueueEventFromHook(
        43, kNfqueueHookLocalOut);
    ASSERT_TRUE(output.has_value());
    EXPECT_EQ(output->packetId, 43U);
    EXPECT_EQ(output->direction, NfqueuePacketDirection::Output);

    EXPECT_FALSE(SnortDatapath::Nfqueue::makeQueueEventFromHook(
                     44, kNfqueueHookForward)
                     .has_value());
}

TEST(NfqueuePassThroughTest, UnsupportedHookWithPacketIdAcceptsFailOpenExactlyOnce) {
    RecordingVerdictSink sink;

    const auto result = SnortDatapath::Nfqueue::acceptPassThroughMetadata(
        SnortDatapath::Nfqueue::PassThroughMetadata{
            .packetId = 77,
            .hook = kNfqueueHookForward,
        },
        sink);

    EXPECT_EQ(result, SnortDatapath::Nfqueue::PassThroughResult::VerdictAccepted);
    ASSERT_EQ(sink.verdicts.size(), 1U);
    EXPECT_EQ(sink.verdicts[0],
              (SnortDatapath::Nfqueue::SentVerdict{
                  .packetId = 77,
                  .verdict = SnortDatapath::Nfqueue::kNfAcceptVerdict,
              }));
}

TEST(NfqueuePassThroughTest, MissingPacketHeaderDoesNotSendVerdictOrRequirePayload) {
    RecordingVerdictSink sink;

    const auto result = SnortDatapath::Nfqueue::acceptPassThroughPacketHeader(
        SnortDatapath::Nfqueue::PassThroughPacketHeader{
            .packetId = std::nullopt,
            .hook = kNfqueueHookLocalIn,
        },
        sink);

    EXPECT_EQ(result, SnortDatapath::Nfqueue::PassThroughResult::NoPacketId);
    EXPECT_TRUE(sink.verdicts.empty());
}

TEST(NfqueuePassThroughTest, VerdictFailureOnUnsupportedHookIsReported) {
    FailingVerdictSink sink;

    const auto result = SnortDatapath::Nfqueue::acceptPassThroughMetadata(
        SnortDatapath::Nfqueue::PassThroughMetadata{
            .packetId = 88,
            .hook = kNfqueueHookForward,
        },
        sink);

    EXPECT_EQ(result, SnortDatapath::Nfqueue::PassThroughResult::VerdictSendFailed);
    ASSERT_EQ(sink.attempts.size(), 1U);
    EXPECT_EQ(sink.attempts[0],
              (SnortDatapath::Nfqueue::SentVerdict{
                  .packetId = 88,
                  .verdict = SnortDatapath::Nfqueue::kNfAcceptVerdict,
              }));
}

TEST(NfqueueIpv4PassThroughTest, InstallerExecutesIpv4HookPlan) {
    RecordingHookExecutor executor;
    const auto queuePlan = makeNfqueueQueuePlan(NfqueueTopology::SplitInOut, 0, 2);

    const bool installed = SnortDatapath::Nfqueue::installIpv4PassThroughHooks(
        SnortDatapath::Nfqueue::HookPlanConfig{
            .inputChain = "sucre-snort_INPUT",
            .outputChain = "sucre-snort_OUTPUT",
            .queuePlan = queuePlan,
        },
        executor);

    EXPECT_TRUE(installed);
    ASSERT_GE(executor.commands.size(), 2U);
    EXPECT_EQ(executor.commands.front(),
              (SnortDatapath::Nfqueue::IptablesCommand{
                  .executable = "/system/bin/iptables",
                  .args = {"-w", "-N", "sucre-snort_INPUT"},
              }));
    EXPECT_EQ(executor.commands.back(),
              (SnortDatapath::Nfqueue::IptablesCommand{
                  .executable = "/system/bin/iptables",
                  .args = {"-w", "-A", "sucre-snort_OUTPUT", "-j", "NFQUEUE", "--queue-bypass",
                           "--queue-num", "1"},
              }));
}

TEST(NfqueueDualStackPassThroughTest, InstallerExecutesDualStackHookPlan) {
    RecordingHookExecutor executor;

    const bool installed = SnortDatapath::Nfqueue::installDualStackPassThroughHooks(
        SnortDatapath::Nfqueue::DualStackHookPlanConfig{
            .inputChain = "sucre-snort_INPUT",
            .outputChain = "sucre-snort_OUTPUT",
            .topology = NfqueueTopology::SharedFlowPool,
            .ipv4FirstQueue = 0,
            .ipv6FirstQueue = 2,
            .queuesPerFamily = 2,
        },
        executor);

    EXPECT_TRUE(installed);
    ASSERT_GE(executor.commands.size(), 4U);
    EXPECT_EQ(executor.commands.front(),
              (SnortDatapath::Nfqueue::IptablesCommand{
                  .executable = "/system/bin/iptables",
                  .args = {"-w", "-N", "sucre-snort_INPUT"},
              }));
    EXPECT_EQ(executor.commands.back(),
              (SnortDatapath::Nfqueue::IptablesCommand{
                  .executable = "/system/bin/ip6tables",
                  .args = {"-w", "-A", "sucre-snort_OUTPUT", "-j", "NFQUEUE", "--queue-bypass",
                           "--queue-balance", "2:3"},
              }));
}

TEST(NfqueueDualStackPassThroughTest, RuntimePlanStartsEveryIpv4AndIpv6ListenerQueue) {
    const auto plan = SnortDatapath::Nfqueue::makeDualStackPassThroughRuntimePlan(
        SnortDatapath::Nfqueue::DualStackPassThroughRuntimeConfig{
            .inputChain = "sucre-snort_INPUT",
            .outputChain = "sucre-snort_OUTPUT",
            .topology = NfqueueTopology::SplitInOut,
            .firstQueue = 10,
            .queuesPerFamily = 4,
        });

    EXPECT_EQ(plan.hookPlan.ipv4FirstQueue, 10U);
    EXPECT_EQ(plan.hookPlan.ipv6FirstQueue, 14U);
    EXPECT_EQ(plan.hookPlan.queuesPerFamily, 4U);
    EXPECT_EQ(plan.listeners,
              (std::vector<SnortDatapath::Nfqueue::PassThroughListenerPlan>{
                  {SnortDatapath::Nfqueue::NfqueueAddressFamily::Ipv4, 10},
                  {SnortDatapath::Nfqueue::NfqueueAddressFamily::Ipv4, 11},
                  {SnortDatapath::Nfqueue::NfqueueAddressFamily::Ipv4, 12},
                  {SnortDatapath::Nfqueue::NfqueueAddressFamily::Ipv4, 13},
                  {SnortDatapath::Nfqueue::NfqueueAddressFamily::Ipv6, 14},
                  {SnortDatapath::Nfqueue::NfqueueAddressFamily::Ipv6, 15},
                  {SnortDatapath::Nfqueue::NfqueueAddressFamily::Ipv6, 16},
                  {SnortDatapath::Nfqueue::NfqueueAddressFamily::Ipv6, 17},
              }));
}

TEST(NfqueuePassThroughLifecycleTest, WorkerGroupJoinsAndReleasesWorkers) {
    SnortDatapath::Nfqueue::PassThroughWorkerGroup workers;
    std::atomic_uint completed{0};

    workers.start([&completed] { completed.fetch_add(1, std::memory_order_relaxed); });
    workers.start([&completed] { completed.fetch_add(1, std::memory_order_relaxed); });

    EXPECT_EQ(workers.workerCount(), 2U);
    workers.join();

    EXPECT_EQ(completed.load(std::memory_order_relaxed), 2U);
    EXPECT_EQ(workers.workerCount(), 0U);
}
