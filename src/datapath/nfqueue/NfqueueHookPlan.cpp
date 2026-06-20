/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueueHookPlan.hpp>

#include <cstdint>
#include <iterator>
#include <string>
#include <utility>

namespace {

constexpr const char *kIpv4Iptables = "/system/bin/iptables";
constexpr const char *kIpv6Iptables = "/system/bin/ip6tables";

void addCommand(SnortDatapath::Nfqueue::HookPlan &plan, const char *executable,
                std::vector<std::string> args) {
    plan.commands.push_back(SnortDatapath::Nfqueue::IptablesCommand{
        .executable = executable,
        .args = std::move(args),
    });
}

void addDnsBypass(SnortDatapath::Nfqueue::HookPlan &plan, const std::string &inputChain,
                  const std::string &outputChain, const char *executable, const char *port) {
    addCommand(plan, executable,
               {"-w", "-A", inputChain, "-p", "udp", "--sport", port, "-j", "RETURN"});
    addCommand(plan, executable,
               {"-w", "-A", outputChain, "-p", "udp", "--dport", port, "-j", "RETURN"});
    addCommand(plan, executable,
               {"-w", "-A", inputChain, "-p", "tcp", "--sport", port, "-j", "RETURN"});
    addCommand(plan, executable,
               {"-w", "-A", outputChain, "-p", "tcp", "--dport", port, "-j", "RETURN"});
}

void addQueueRule(SnortDatapath::Nfqueue::HookPlan &plan, const std::string &chain,
                  const NfqueueRange range, const char *executable) {
    std::vector<std::string> args{"-w", "-A", chain, "-j", "NFQUEUE", "--queue-bypass"};
    if (range.count == 1) {
        args.emplace_back("--queue-num");
        args.emplace_back(std::to_string(range.first));
    } else {
        args.emplace_back("--queue-balance");
        args.emplace_back(std::to_string(range.first) + ":" +
                          std::to_string(range.first + range.count - 1));
    }
    addCommand(plan, executable, std::move(args));
}

SnortDatapath::Nfqueue::HookPlan makePassThroughHookPlanForExecutable(
    const SnortDatapath::Nfqueue::HookPlanConfig &config, const char *executable) {
    SnortDatapath::Nfqueue::HookPlan plan;

    addCommand(plan, executable, {"-w", "-N", config.inputChain});
    addCommand(plan, executable, {"-w", "-N", config.outputChain});
    addCommand(plan, executable, {"-w", "-F", config.inputChain});
    addCommand(plan, executable, {"-w", "-F", config.outputChain});
    addCommand(plan, executable, {"-w", "-D", "INPUT", "-j", config.inputChain});
    addCommand(plan, executable, {"-w", "-D", "OUTPUT", "-j", config.outputChain});
    addCommand(plan, executable, {"-w", "-A", "INPUT", "-j", config.inputChain});
    addCommand(plan, executable, {"-w", "-A", "OUTPUT", "-j", config.outputChain});
    addCommand(plan, executable, {"-w", "-A", config.inputChain, "-i", "lo", "-j", "RETURN"});
    addCommand(plan, executable, {"-w", "-A", config.outputChain, "-o", "lo", "-j", "RETURN"});

    for (const char *port : {"53", "853", "5353"}) {
        addDnsBypass(plan, config.inputChain, config.outputChain, executable, port);
    }

    addQueueRule(plan, config.inputChain, config.queuePlan.input, executable);
    addQueueRule(plan, config.outputChain, config.queuePlan.output, executable);

    return plan;
}

void appendPlan(SnortDatapath::Nfqueue::HookPlan &target,
                SnortDatapath::Nfqueue::HookPlan source) {
    target.commands.insert(target.commands.end(), std::make_move_iterator(source.commands.begin()),
                           std::make_move_iterator(source.commands.end()));
}

} // namespace

namespace SnortDatapath::Nfqueue {

HookPlan makeIpv4PassThroughHookPlan(const HookPlanConfig &config) {
    return makePassThroughHookPlanForExecutable(config, kIpv4Iptables);
}

HookPlan makeDualStackPassThroughHookPlan(const DualStackHookPlanConfig &config) {
    HookPlan plan;
    appendPlan(plan, makePassThroughHookPlanForExecutable(
                         HookPlanConfig{
                             .inputChain = config.inputChain,
                             .outputChain = config.outputChain,
                             .queuePlan = makeNfqueueQueuePlan(config.topology,
                                                               config.ipv4FirstQueue,
                                                               config.queuesPerFamily),
                         },
                         kIpv4Iptables));
    appendPlan(plan, makePassThroughHookPlanForExecutable(
                         HookPlanConfig{
                             .inputChain = config.inputChain,
                             .outputChain = config.outputChain,
                             .queuePlan = makeNfqueueQueuePlan(config.topology,
                                                               config.ipv6FirstQueue,
                                                               config.queuesPerFamily),
                         },
                         kIpv6Iptables));
    return plan;
}

} // namespace SnortDatapath::Nfqueue
