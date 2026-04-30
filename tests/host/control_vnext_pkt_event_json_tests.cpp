/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlVNextStreamJson.hpp>
#include <ControlVNextStreamManager.hpp>
#include <Domain.hpp>
#include <Settings.hpp>

#include <gtest/gtest.h>

#include <netinet/in.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// Provide the global Settings instance normally defined in src/sucre-snort.cpp.
Settings settings;

namespace {

const rapidjson::Value &requireExplain(const rapidjson::Document &doc, const char *kind) {
    EXPECT_TRUE(doc.HasMember("explain"));
    EXPECT_TRUE(doc["explain"].IsObject());
    const auto &explain = doc["explain"];
    EXPECT_TRUE(explain.HasMember("version"));
    EXPECT_EQ(explain["version"].GetUint(), 1u);
    EXPECT_TRUE(explain.HasMember("kind"));
    EXPECT_STREQ(explain["kind"].GetString(), kind);
    EXPECT_TRUE(explain.HasMember("inputs"));
    EXPECT_TRUE(explain.HasMember("final"));
    EXPECT_TRUE(explain.HasMember("stages"));
    EXPECT_TRUE(explain["stages"].IsArray());
    return explain;
}

std::vector<std::string> stageNames(const rapidjson::Value &stages) {
    std::vector<std::string> out;
    out.reserve(stages.Size());
    for (const auto &stage : stages.GetArray()) {
        out.emplace_back(stage["name"].GetString());
    }
    return out;
}

} // namespace

TEST(ControlVNextPktEventJson, L4StatusAlwaysPresentAndPortsZeroWhenNotKnownL4) {
    ControlVNextStreamManager::PktEvent ev{};
    ev.timestamp = timespec{.tv_sec = 1710000000, .tv_nsec = 123};
    ev.uid = 12345;
    ev.userId = 0;
    ev.app = std::make_shared<const std::string>("com.example.app");
    ev.ipVersion = 4;
    ev.proto = IPPROTO_TCP;
    ev.length = 100;
    ev.input = true;
    ev.accepted = true;

    ev.l4Status = L4Status::KNOWN_L4;
    ev.srcPort = 1234;
    ev.dstPort = 80;

    {
        const auto doc = ControlVNextStreamJson::makePktEvent(ev);
        ASSERT_TRUE(doc.IsObject());
        ASSERT_TRUE(doc.HasMember("l4Status"));
        ASSERT_TRUE(doc["l4Status"].IsString());
        EXPECT_STREQ(doc["l4Status"].GetString(), "known-l4");

        ASSERT_TRUE(doc.HasMember("srcPort"));
        ASSERT_TRUE(doc.HasMember("dstPort"));
        EXPECT_EQ(doc["srcPort"].GetUint(), 1234u);
        EXPECT_EQ(doc["dstPort"].GetUint(), 80u);
    }

    // When L4 is not known, ports must be forced to 0 in stream output.
    ev.l4Status = L4Status::FRAGMENT;
    ev.srcPort = 5555;
    ev.dstPort = 6666;
    {
        const auto doc = ControlVNextStreamJson::makePktEvent(ev);
        ASSERT_TRUE(doc.IsObject());
        ASSERT_TRUE(doc.HasMember("l4Status"));
        ASSERT_TRUE(doc["l4Status"].IsString());
        EXPECT_STREQ(doc["l4Status"].GetString(), "fragment");

        ASSERT_TRUE(doc.HasMember("srcPort"));
        ASSERT_TRUE(doc.HasMember("dstPort"));
        EXPECT_EQ(doc["srcPort"].GetUint(), 0u);
        EXPECT_EQ(doc["dstPort"].GetUint(), 0u);
    }
}

TEST(ControlVNextStreamEventJson, DnsExplainV1HasInputsFinalAndOrderedStages) {
    ControlVNextStreamManager::DnsEvent ev{};
    ev.timestamp = timespec{.tv_sec = 1710000000, .tv_nsec = 456};
    ev.uid = 12345;
    ev.userId = 0;
    ev.app = std::make_shared<const std::string>("com.example.app");
    ev.domain = std::make_shared<Domain>(std::string("blocked.example"));
    ev.domMask = 1;
    ev.appMask = 1;
    ev.blocked = true;
    ev.getips = false;
    ev.useCustomList = true;
    ev.policySource = DomainPolicySource::CUSTOM_RULE_BLACK;
    ev.ruleId = 42;

    ControlVNextStreamExplain::DnsExplainSnapshot explain{};
    explain.inputs = ControlVNextStreamExplain::DnsInputs{
        .blockEnabled = true,
        .tracked = true,
        .domainCustomEnabled = true,
        .useCustomList = true,
        .domain = "blocked.example",
        .domMask = 1,
        .appMask = 1,
    };
    explain.final = ControlVNextStreamExplain::DnsFinal{
        .blocked = true,
        .getips = false,
        .policySource = DomainPolicySource::CUSTOM_RULE_BLACK,
        .scope = "APP",
        .ruleId = 42,
    };
    for (const auto name : {
             ControlVNextStreamExplain::kDnsStageAppAllowList,
             ControlVNextStreamExplain::kDnsStageAppBlockList,
             ControlVNextStreamExplain::kDnsStageAppAllowRules,
             ControlVNextStreamExplain::kDnsStageAppBlockRules,
             ControlVNextStreamExplain::kDnsStageDeviceAllow,
             ControlVNextStreamExplain::kDnsStageDeviceBlock,
             ControlVNextStreamExplain::kDnsStageMaskFallback,
         }) {
        explain.stages.push_back(ControlVNextStreamExplain::DnsStageSnapshot{
            .name = std::string(name),
            .enabled = true,
            .evaluated = true,
            .matched = name == ControlVNextStreamExplain::kDnsStageAppBlockRules,
            .outcome = name == ControlVNextStreamExplain::kDnsStageAppBlockRules ? "block" : "none",
            .winner = name == ControlVNextStreamExplain::kDnsStageAppBlockRules,
        });
    }
    explain.stages[3].ruleIds = {42};
    explain.stages[3].ruleSnapshots = {ControlVNextStreamExplain::DnsRuleSnapshot{
        .ruleId = 42,
        .type = "domain",
        .pattern = "blocked.example",
        .scope = "APP",
        .action = "block",
    }};
    ev.explain = std::move(explain);

    const auto doc = ControlVNextStreamJson::makeDnsEvent(ev);
    const auto &out = requireExplain(doc, "dns-policy");
    EXPECT_TRUE(out["inputs"]["tracked"].GetBool());
    EXPECT_TRUE(out["final"]["blocked"].GetBool());
    EXPECT_EQ(out["final"]["ruleId"].GetUint(), 42u);
    EXPECT_EQ(stageNames(out["stages"]),
              (std::vector<std::string>{
                  "app.custom.allowList",
                  "app.custom.blockList",
                  "app.custom.allowRules",
                  "app.custom.blockRules",
                  "deviceWide.allow",
                  "deviceWide.block",
                  "maskFallback",
              }));
    ASSERT_TRUE(out["stages"][3].HasMember("ruleSnapshots"));
    EXPECT_EQ(out["stages"][3]["ruleSnapshots"][0]["ruleId"].GetUint(), 42u);
}

TEST(ControlVNextStreamEventJson, PktExplainV1HasInputsFinalAndOrderedStages) {
    ControlVNextStreamManager::PktEvent ev{};
    ev.timestamp = timespec{.tv_sec = 1710000000, .tv_nsec = 789};
    ev.uid = 12345;
    ev.userId = 0;
    ev.app = std::make_shared<const std::string>("com.example.app");
    ev.ipVersion = 4;
    ev.proto = IPPROTO_TCP;
    ev.length = 100;
    ev.input = false;
    ev.accepted = false;
    ev.reasonId = PacketReasonId::IP_RULE_BLOCK;
    ev.ruleId = 7;

    ControlVNextStreamExplain::PktExplainSnapshot explain{};
    explain.inputs = ControlVNextStreamExplain::PktInputs{
        .blockEnabled = true,
        .iprulesEnabled = true,
        .direction = "out",
        .ipVersion = 4,
        .protocol = "tcp",
        .l4Status = "known-l4",
        .ifindex = 3,
        .ifaceKindBit = 1,
        .ifaceKind = "wifi",
    };
    explain.final = ControlVNextStreamExplain::PktFinal{
        .accepted = false,
        .reasonId = PacketReasonId::IP_RULE_BLOCK,
        .ruleId = 7,
    };
    for (const auto name : {
             ControlVNextStreamExplain::kPktStageIfaceBlock,
             ControlVNextStreamExplain::kPktStageIpRulesEnforce,
             ControlVNextStreamExplain::kPktStageDomainIpLeak,
             ControlVNextStreamExplain::kPktStageIpRulesWould,
         }) {
        explain.stages.push_back(ControlVNextStreamExplain::PktStageSnapshot{
            .name = std::string(name),
            .enabled = true,
            .evaluated = true,
            .matched = name == ControlVNextStreamExplain::kPktStageIpRulesEnforce,
            .outcome = name == ControlVNextStreamExplain::kPktStageIpRulesEnforce ? "block" : "none",
            .winner = name == ControlVNextStreamExplain::kPktStageIpRulesEnforce,
        });
    }
    explain.stages[1].ruleIds = {7};
    explain.stages[1].ruleSnapshots = {ControlVNextStreamExplain::IpRulesRuleSnapshot{
        .ruleId = 7,
        .clientRuleId = "client-7",
        .matchKey = "mk2|family=ipv4|dir=out|iface=any|ifindex=0|proto=tcp|ctstate=any|ctdir=any|src=any|dst=any|sport=any|dport=443",
        .action = "block",
        .enforce = true,
        .log = false,
        .family = "ipv4",
        .dir = "out",
        .iface = "any",
        .ifindex = 0,
        .proto = "tcp",
        .ctState = "any",
        .ctDirection = "any",
        .src = "any",
        .dst = "any",
        .sport = "any",
        .dport = "443",
        .priority = 10,
    }};
    ev.explain = std::move(explain);

    const auto doc = ControlVNextStreamJson::makePktEvent(ev);
    const auto &out = requireExplain(doc, "packet-verdict");
    EXPECT_FALSE(out["final"]["accepted"].GetBool());
    EXPECT_STREQ(out["final"]["reasonId"].GetString(), "IP_RULE_BLOCK");
    EXPECT_EQ(stageNames(out["stages"]),
              (std::vector<std::string>{
                  "ifaceBlock",
                  "iprules.enforce",
                  "domainIpLeak",
                  "iprules.would",
              }));
    ASSERT_TRUE(out["stages"][1].HasMember("ruleSnapshots"));
    EXPECT_STREQ(out["stages"][1]["ruleSnapshots"][0]["matchKey"].GetString(),
                 "mk2|family=ipv4|dir=out|iface=any|ifindex=0|proto=tcp|ctstate=any|ctdir=any|src=any|dst=any|sport=any|dport=443");
}

TEST(ControlVNextStreamEventJson, ActivityAndNoticesDoNotGainExplain) {
    ControlVNextStreamManager::ActivityEvent activity{};
    activity.timestamp = timespec{.tv_sec = 1710000000, .tv_nsec = 1};
    activity.blockEnabled = true;
    EXPECT_FALSE(ControlVNextStreamJson::makeActivityEvent(activity).HasMember("explain"));
    EXPECT_FALSE(ControlVNextStreamJson::makeStartedNotice(
                     ControlVNextStreamManager::Type::Dns, 0, 0)
                     .HasMember("explain"));
    EXPECT_FALSE(ControlVNextStreamJson::makeSuppressedNotice(
                     ControlVNextStreamManager::Type::Pkt, 1000, TrafficSnapshot{})
                     .HasMember("explain"));
    EXPECT_FALSE(ControlVNextStreamJson::makeDroppedNotice(
                     ControlVNextStreamManager::Type::Pkt, 1000, 1)
                     .HasMember("explain"));
}

TEST(ControlVNextStreamEventJson, CandidateSnapshotsAreCappedAndWinnerIsRetained) {
    std::vector<ControlVNextStreamExplain::DnsRuleSnapshot> snapshots;
    snapshots.reserve(70);
    for (std::uint32_t ruleId = 1; ruleId <= 70; ++ruleId) {
        snapshots.push_back(ControlVNextStreamExplain::DnsRuleSnapshot{
            .ruleId = ruleId,
            .type = "domain",
            .pattern = "example.test",
            .scope = "APP",
            .action = "block",
        });
    }

    bool truncated = false;
    std::optional<std::uint32_t> omitted;
    ControlVNextStreamExplain::capCandidateSnapshots(
        snapshots, 70, [](const auto &snapshot) { return snapshot.ruleId; }, truncated, omitted);

    EXPECT_TRUE(truncated);
    ASSERT_TRUE(omitted.has_value());
    EXPECT_EQ(*omitted, 6u);
    ASSERT_EQ(snapshots.size(), ControlVNextStreamExplain::maxExplainCandidatesPerStage);
    EXPECT_EQ(snapshots.front().ruleId, 1u);
    EXPECT_EQ(snapshots.back().ruleId, 70u);
}
