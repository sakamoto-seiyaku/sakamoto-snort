/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueueHookPlan.hpp>
#include <NfqueueHookInstaller.hpp>
#include <NfqueuePassThrough.hpp>

#include <NfqueueTopology.hpp>

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
