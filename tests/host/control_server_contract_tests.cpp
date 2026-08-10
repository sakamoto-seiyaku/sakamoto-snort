/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlServer.hpp>
#include <ControlVNextCodec.hpp>
#include <PacketPolicy.hpp>
#include <RuntimeControl.hpp>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

namespace Flow = SnortDatapath::Flow;
namespace Policy = SnortDatapath::Policy;

class FakeRuntimeControl final : public SnortRuntime::BaseRuntimeControl {
public:
    bool nfqueuePassThroughReady() const noexcept override { return ready; }
    bool resetBaseRuntime() noexcept override {
        ++resetCount;
        return resetResult;
    }
    bool packetPolicyControlReady() const noexcept override { return policyReady; }
    Policy::PacketPolicySnapshotStatus packetPolicyStatus() const noexcept override {
        return policy.status();
    }
    Policy::PacketPolicyDecision evaluatePacketPolicy(
        const Flow::PacketFacts &facts) const noexcept override {
        return policy.evaluate(facts);
    }
    bool applyPacketPolicy(std::vector<Policy::PacketPolicySubjectView> subjects,
                           const std::uint64_t revision) noexcept override {
        ++policyApplyCount;
        try {
            policy.apply(std::move(subjects), revision);
        } catch (...) {
            return false;
        }
        return policyApplyResult;
    }

    bool ready = true;
    bool resetResult = true;
    bool policyReady = false;
    bool policyApplyResult = true;
    int resetCount = 0;
    int policyApplyCount = 0;
    Policy::RuntimePacketPolicySnapshot policy;
};

bool writeAll(const int fd, const std::string_view data) {
    std::size_t offset = 0;
    while (offset < data.size()) {
        const ssize_t n = ::write(fd, data.data() + offset, data.size() - offset);
        if (n > 0) {
            offset += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

class ControlServerHarness {
public:
    explicit ControlServerHarness(FakeRuntimeControl &runtime) {
        int fds[2]{-1, -1};
        if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) != 0) {
            throw std::runtime_error(std::string("socketpair failed: ") + std::strerror(errno));
        }

        clientFd_ = fds[1];
        serverThread_ = std::thread([serverFd = fds[0], &runtime] {
            SnortControlVNext::ControlServer server(runtime);
            server.serveClient(serverFd);
            ::close(serverFd);
        });
    }

    ~ControlServerHarness() {
        if (clientFd_ >= 0) {
            ::close(clientFd_);
        }
        if (serverThread_.joinable()) {
            serverThread_.join();
        }
    }

    rapidjson::Document call(const std::uint32_t id, const std::string_view cmd,
                             const std::string_view args = "{}") {
        const std::string frame = ControlVNext::encodeNetstring(
            std::string("{\"id\":") + std::to_string(id) + ",\"cmd\":\"" + std::string(cmd) +
            "\",\"args\":" + std::string(args) + "}");
        if (!writeAll(clientFd_, frame)) {
            throw std::runtime_error("write failed");
        }
        return readOneResponse();
    }

private:
    rapidjson::Document readOneResponse() {
        std::array<std::byte, 4096> buffer{};
        for (;;) {
            if (const auto payload = decoder_.pop(); payload.has_value()) {
                rapidjson::Document doc;
                ControlVNext::JsonError error;
                if (!ControlVNext::parseStrictJsonObject(*payload, doc, error)) {
                    throw std::runtime_error(error.message);
                }
                return doc;
            }

            const ssize_t n = ::read(clientFd_, buffer.data(), buffer.size());
            if (n == 0) {
                throw std::runtime_error("connection closed");
            }
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                throw std::runtime_error(std::string("read failed: ") + std::strerror(errno));
            }
            const auto bytes = std::span<const std::byte>(buffer.data(), static_cast<size_t>(n));
            if (const auto err = decoder_.feed(bytes); err.has_value()) {
                throw std::runtime_error(err->message);
            }
        }
    }

    int clientFd_ = -1;
    std::thread serverThread_;
    ControlVNext::NetstringDecoder decoder_{16 * 1024 * 1024};
};

std::vector<std::string_view> capabilityStrings(const rapidjson::Value &capabilities) {
    std::vector<std::string_view> out;
    for (const auto &capability : capabilities.GetArray()) {
        out.emplace_back(capability.GetString(), capability.GetStringLength());
    }
    return out;
}

} // namespace

TEST(ControlServerContract, HelloAdvertisesPassThroughCapabilityWhenRuntimeReady) {
    FakeRuntimeControl runtime;
    runtime.ready = true;
    ControlServerHarness harness(runtime);

    const rapidjson::Document response = harness.call(1, "HELLO");

    ASSERT_TRUE(response["ok"].GetBool());
    const auto &result = response["result"];
    const auto capabilities = capabilityStrings(result["capabilities"]);
    EXPECT_NE(std::find(capabilities.begin(), capabilities.end(), "snort10-base"),
              capabilities.end());
    EXPECT_NE(std::find(capabilities.begin(), capabilities.end(), "nfqueue-pass-through"),
              capabilities.end());
}

TEST(ControlServerContract, HelloOmitsPassThroughCapabilityBeforeRuntimeReady) {
    FakeRuntimeControl runtime;
    runtime.ready = false;
    ControlServerHarness harness(runtime);

    const rapidjson::Document response = harness.call(4, "HELLO");

    ASSERT_TRUE(response["ok"].GetBool());
    const auto capabilities = capabilityStrings(response["result"]["capabilities"]);
    EXPECT_NE(std::find(capabilities.begin(), capabilities.end(), "snort10-base"),
              capabilities.end());
    EXPECT_EQ(std::find(capabilities.begin(), capabilities.end(), "nfqueue-pass-through"),
              capabilities.end());
}

TEST(ControlServerContract, ResetAllReinstallsOnlyBaseRuntimeState) {
    FakeRuntimeControl runtime;
    ControlServerHarness harness(runtime);

    const rapidjson::Document response = harness.call(2, "RESETALL");

    ASSERT_TRUE(response["ok"].GetBool());
    EXPECT_EQ(runtime.resetCount, 1);
}

TEST(ControlServerContract, LegacyControlCommandsRemainUnsupported) {
    FakeRuntimeControl runtime;
    ControlServerHarness harness(runtime);

    const rapidjson::Document response = harness.call(3, "APPS.LIST");

    ASSERT_FALSE(response["ok"].GetBool());
    ASSERT_TRUE(response.HasMember("error"));
    ASSERT_TRUE(response["error"].HasMember("code"));
    EXPECT_STREQ(response["error"]["code"].GetString(), "UNSUPPORTED_COMMAND");
    EXPECT_EQ(runtime.resetCount, 0);
}

TEST(ControlServerContract, HelloAdvertisesPolicyCapabilityOnlyWhenRuntimeSupportsIt) {
    FakeRuntimeControl runtime;
    runtime.policyReady = true;
    ControlServerHarness harness(runtime);

    const rapidjson::Document response = harness.call(5, "HELLO");

    ASSERT_TRUE(response["ok"].GetBool());
    const auto capabilities = capabilityStrings(response["result"]["capabilities"]);
    EXPECT_NE(std::find(capabilities.begin(), capabilities.end(), "packet-policy-control"),
              capabilities.end());
}

TEST(ControlServerContract, PolicyStatusStartsEmptyAtRevisionZero) {
    FakeRuntimeControl runtime;
    runtime.policyReady = true;
    ControlServerHarness harness(runtime);

    const rapidjson::Document response = harness.call(10, "POLICY.STATUS");

    ASSERT_TRUE(response["ok"].GetBool());
    const auto &result = response["result"];
    EXPECT_EQ(result["revision"].GetUint64(), 0U);
    EXPECT_EQ(result["subjectCount"].GetUint64(), 0U);
    EXPECT_EQ(result["ruleCount"].GetUint64(), 0U);
    EXPECT_EQ(result["networkGateRuleCount"].GetUint64(), 0U);
    EXPECT_EQ(result["l4RuleCount"].GetUint64(), 0U);
}

TEST(ControlServerContract, PolicyApplyGateBlockAndEvaluateWinner) {
    FakeRuntimeControl runtime;
    runtime.policyReady = true;
    ControlServerHarness harness(runtime);

    const auto apply = harness.call(
        11, "POLICY.APPLY",
        R"({"revision":7,"subjects":[{"linuxUid":10001,"networkGate":{"blockedNetworkContexts":[2],"reasonId":10,"ruleId":100},"l4Rules":[]}]})");
    ASSERT_TRUE(apply["ok"].GetBool());
    EXPECT_EQ(apply["result"]["revision"].GetUint64(), 7U);
    EXPECT_EQ(apply["result"]["subjectCount"].GetUint64(), 1U);
    EXPECT_EQ(apply["result"]["networkGateRuleCount"].GetUint64(), 1U);

    const auto eval = harness.call(
        12, "POLICY.EVALUATE",
        R"({"linuxUid":10001,"networkContext":2,"family":"ipv4","direction":"input","ipProtocol":6,"sourcePort":40000,"destinationPort":443,"portsAvailable":true})");

    ASSERT_TRUE(eval["ok"].GetBool());
    const auto &decision = eval["result"];
    EXPECT_STREQ(decision["verdict"].GetString(), "DROP");
    EXPECT_STREQ(decision["stage"].GetString(), "NetworkGate");
    EXPECT_EQ(decision["reasonId"].GetUint(), 10U);
    EXPECT_EQ(decision["ruleId"].GetUint64(), 100U);
    EXPECT_EQ(decision["revision"].GetUint64(), 7U);
}

TEST(ControlServerContract, PolicyApplyL4OrderingAndRevisionSurviveControl) {
    FakeRuntimeControl runtime;
    runtime.policyReady = true;
    ControlServerHarness harness(runtime);

    const auto apply = harness.call(
        13, "POLICY.APPLY",
        R"({"revision":9,"subjects":[{"linuxUid":10001,"networkGate":{},"l4Rules":[{"ruleId":1,"reasonId":1,"priority":20,"order":0,"action":"allow","match":{"family":"ipv4","direction":"input","ipProtocol":6,"destinationPorts":{"first":443,"last":443}}},{"ruleId":2,"reasonId":44,"priority":10,"order":0,"action":"drop","match":{"family":"ipv4","direction":"input","ipProtocol":6,"destinationPorts":{"first":443,"last":443}}}]}]})");
    ASSERT_TRUE(apply["ok"].GetBool());
    EXPECT_EQ(apply["result"]["l4RuleCount"].GetUint64(), 2U);

    const auto eval = harness.call(
        14, "POLICY.EVALUATE",
        R"({"linuxUid":10001,"networkContext":2,"family":"ipv4","direction":"input","ipProtocol":6,"sourcePort":40000,"destinationPort":443,"portsAvailable":true})");

    ASSERT_TRUE(eval["ok"].GetBool());
    const auto &decision = eval["result"];
    EXPECT_STREQ(decision["verdict"].GetString(), "DROP");
    EXPECT_STREQ(decision["stage"].GetString(), "L4");
    EXPECT_EQ(decision["reasonId"].GetUint(), 44U);
    EXPECT_EQ(decision["ruleId"].GetUint64(), 2U);
    EXPECT_EQ(decision["revision"].GetUint64(), 9U);
}

TEST(ControlServerContract, PolicyGateDropWinsOverL4Allow) {
    FakeRuntimeControl runtime;
    runtime.policyReady = true;
    ControlServerHarness harness(runtime);

    const auto apply = harness.call(
        15, "POLICY.APPLY",
        R"({"revision":10,"subjects":[{"linuxUid":10001,"networkGate":{"blockedNetworkContextBits":4,"reasonId":10,"ruleId":100},"l4Rules":[{"ruleId":1,"reasonId":1,"priority":0,"order":0,"action":"allow","match":{"family":"ipv4","direction":"input","ipProtocol":6,"destinationPorts":{"first":443,"last":443}}}]}]})");
    ASSERT_TRUE(apply["ok"].GetBool());

    const auto eval = harness.call(
        16, "POLICY.EVALUATE",
        R"({"linuxUid":10001,"networkContext":2,"family":"ipv4","direction":"input","ipProtocol":6,"sourcePort":40000,"destinationPort":443,"portsAvailable":true})");

    ASSERT_TRUE(eval["ok"].GetBool());
    EXPECT_STREQ(eval["result"]["verdict"].GetString(), "DROP");
    EXPECT_STREQ(eval["result"]["stage"].GetString(), "NetworkGate");
    EXPECT_EQ(eval["result"]["ruleId"].GetUint64(), 100U);
}

TEST(ControlServerContract, MalformedPolicyApplyDoesNotReplaceOldSnapshot) {
    FakeRuntimeControl runtime;
    runtime.policyReady = true;
    ControlServerHarness harness(runtime);

    const auto baseline = harness.call(
        17, "POLICY.APPLY",
        R"({"revision":5,"subjects":[{"linuxUid":10001,"networkGate":{"blockedNetworkContexts":[2],"reasonId":10,"ruleId":100},"l4Rules":[]}]})");
    ASSERT_TRUE(baseline["ok"].GetBool());
    EXPECT_EQ(runtime.policyApplyCount, 1);

    const auto malformed = harness.call(
        18, "POLICY.APPLY",
        R"({"revision":6,"subjects":[{"linuxUid":10001,"unexpected":true}]})");
    ASSERT_FALSE(malformed["ok"].GetBool());
    ASSERT_TRUE(malformed.HasMember("error"));
    EXPECT_STREQ(malformed["error"]["code"].GetString(), "INVALID_ARGUMENT");
    EXPECT_EQ(runtime.policyApplyCount, 1);

    const auto eval = harness.call(
        19, "POLICY.EVALUATE",
        R"({"linuxUid":10001,"networkContext":2,"family":"ipv4","direction":"input","ipProtocol":6,"sourcePort":40000,"destinationPort":443,"portsAvailable":true})");
    ASSERT_TRUE(eval["ok"].GetBool());
    EXPECT_EQ(eval["result"]["revision"].GetUint64(), 5U);
    EXPECT_EQ(eval["result"]["ruleId"].GetUint64(), 100U);
}

TEST(ControlServerContract, PolicyCommandsAreUnsupportedWithoutRuntimeCapability) {
    FakeRuntimeControl runtime;
    runtime.policyReady = false;
    ControlServerHarness harness(runtime);

    const rapidjson::Document response = harness.call(20, "POLICY.STATUS");

    ASSERT_FALSE(response["ok"].GetBool());
    EXPECT_STREQ(response["error"]["code"].GetString(), "UNSUPPORTED_COMMAND");
}
