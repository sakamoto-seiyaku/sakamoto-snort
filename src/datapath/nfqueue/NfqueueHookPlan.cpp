/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <NfqueueHookPlan.hpp>

#include <cstdint>
#include <string>
#include <utility>

namespace {

constexpr const char *kIpv4Iptables = "/system/bin/iptables";

void addCommand(SnortDatapath::Nfqueue::HookPlan &plan, std::vector<std::string> args) {
    plan.commands.push_back(SnortDatapath::Nfqueue::IptablesCommand{
        .executable = kIpv4Iptables,
        .args = std::move(args),
    });
}

void addDnsBypass(SnortDatapath::Nfqueue::HookPlan &plan, const std::string &inputChain,
                  const std::string &outputChain, const char *port) {
    addCommand(plan, {"-w", "-A", inputChain, "-p", "udp", "--sport", port, "-j", "RETURN"});
    addCommand(plan, {"-w", "-A", outputChain, "-p", "udp", "--dport", port, "-j", "RETURN"});
    addCommand(plan, {"-w", "-A", inputChain, "-p", "tcp", "--sport", port, "-j", "RETURN"});
    addCommand(plan, {"-w", "-A", outputChain, "-p", "tcp", "--dport", port, "-j", "RETURN"});
}

void addQueueRule(SnortDatapath::Nfqueue::HookPlan &plan, const std::string &chain,
                  const NfqueueRange range) {
    std::vector<std::string> args{"-w", "-A", chain, "-j", "NFQUEUE", "--queue-bypass"};
    if (range.count == 1) {
        args.emplace_back("--queue-num");
        args.emplace_back(std::to_string(range.first));
    } else {
        args.emplace_back("--queue-balance");
        args.emplace_back(std::to_string(range.first) + ":" +
                          std::to_string(range.first + range.count - 1));
    }
    addCommand(plan, std::move(args));
}

} // namespace

namespace SnortDatapath::Nfqueue {

HookPlan makeIpv4PassThroughHookPlan(const HookPlanConfig &config) {
    HookPlan plan;

    addCommand(plan, {"-w", "-N", config.inputChain});
    addCommand(plan, {"-w", "-N", config.outputChain});
    addCommand(plan, {"-w", "-F", config.inputChain});
    addCommand(plan, {"-w", "-F", config.outputChain});
    addCommand(plan, {"-w", "-D", "INPUT", "-j", config.inputChain});
    addCommand(plan, {"-w", "-D", "OUTPUT", "-j", config.outputChain});
    addCommand(plan, {"-w", "-A", "INPUT", "-j", config.inputChain});
    addCommand(plan, {"-w", "-A", "OUTPUT", "-j", config.outputChain});
    addCommand(plan, {"-w", "-A", config.inputChain, "-i", "lo", "-j", "RETURN"});
    addCommand(plan, {"-w", "-A", config.outputChain, "-o", "lo", "-j", "RETURN"});

    for (const char *port : {"53", "853", "5353"}) {
        addDnsBypass(plan, config.inputChain, config.outputChain, port);
    }

    addQueueRule(plan, config.inputChain, config.queuePlan.input);
    addQueueRule(plan, config.outputChain, config.queuePlan.output);

    return plan;
}

} // namespace SnortDatapath::Nfqueue
