/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <ControlServer.hpp>
#include <ControlVNextCodec.hpp>
#include <PacketPolicy.hpp>
#include <RuntimeControl.hpp>
#include <VpnTunFdRuntime.hpp>

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
namespace Tun = SnortDatapath::Tun;

class UniqueFd final {
public:
    UniqueFd() = default;
    explicit UniqueFd(const int fd) noexcept : fd_(fd) {}
    ~UniqueFd() {
        reset();
    }

    UniqueFd(const UniqueFd &) = delete;
    UniqueFd &operator=(const UniqueFd &) = delete;

    UniqueFd(UniqueFd &&other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
    UniqueFd &operator=(UniqueFd &&other) noexcept {
        if (this != &other) {
            reset(std::exchange(other.fd_, -1));
        }
        return *this;
    }

    [[nodiscard]] int get() const noexcept { return fd_; }
    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }

    void reset(const int fd = -1) noexcept {
        if (fd_ >= 0) {
            ::close(fd_);
        }
        fd_ = fd;
    }

private:
    int fd_ = -1;
};

class FakeRuntimeControl final : public SnortRuntime::BaseRuntimeControl {
public:
    ~FakeRuntimeControl() override {
        if (attachedTunFd >= 0) {
            ::close(attachedTunFd);
        }
        if (attachedTransportFd >= 0) {
            ::close(attachedTransportFd);
        }
    }

    bool nfqueuePassThroughReady() const noexcept override { return ready; }
    bool packetAdapterReady() const noexcept override { return adapterReady; }
    std::string_view packetAdapterName() const noexcept override { return adapterName; }
    bool vpnTunFdHandoffReady() const noexcept override { return vpnTunHandoffReady; }
    bool vpnTunTransportFdHandoffReady() const noexcept override {
        return vpnTransportHandoffReady;
    }
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
    SnortRuntime::VpnTunFdAttachResult attachVpnTunFd(
        const int tunFd, const bool enableIpv6) noexcept override {
        ++vpnTunAttachCount;
        vpnTunAttachIpv6 = enableIpv6;
        if (!vpnTunAttachResult) {
            ::close(tunFd);
            return SnortRuntime::VpnTunFdAttachResult::error(
                "VPN_TUN_ATTACH_FAILED", "fake attach failed");
        }
        if (attachedTunFd >= 0) {
            ::close(attachedTunFd);
        }
        attachedTunFd = tunFd;
        return SnortRuntime::VpnTunFdAttachResult::accepted();
    }
    SnortRuntime::VpnTunFdAttachResult attachVpnTransportFd(
        const int transportFd) noexcept override {
        ++vpnTransportAttachCount;
        if (!vpnTransportAttachResult) {
            ::close(transportFd);
            return SnortRuntime::VpnTunFdAttachResult::error(
                "VPN_TRANSPORT_ATTACH_FAILED", "fake transport attach failed");
        }
        if (attachedTransportFd >= 0) {
            ::close(attachedTransportFd);
        }
        attachedTransportFd = transportFd;
        return SnortRuntime::VpnTunFdAttachResult::accepted();
    }

    bool ready = true;
    bool resetResult = true;
    bool policyReady = false;
    bool nfqueueCountersReady = false;
    bool vpnTunCountersReady = false;
    bool adapterReady = false;
    bool vpnTunHandoffReady = false;
    bool vpnTransportHandoffReady = false;
    bool vpnTunAttachResult = true;
    bool vpnTransportAttachResult = true;
    bool vpnTunAttachIpv6 = false;
    bool policyApplyResult = true;
    int resetCount = 0;
    int policyApplyCount = 0;
    int vpnTunAttachCount = 0;
    int vpnTransportAttachCount = 0;
    int attachedTunFd = -1;
    int attachedTransportFd = -1;
    Policy::RuntimePacketPolicySnapshot policy;
    SnortRuntime::NfqueueRuntimeCounters nfqueueCounters;
    SnortRuntime::VpnTunRuntimeCounters vpnTunCounters;
    std::string adapterName;

    bool nfqueueRuntimeCountersReady() const noexcept override {
        return nfqueueCountersReady;
    }
    SnortRuntime::NfqueueRuntimeCounters nfqueueRuntimeCounters() const noexcept override {
        return nfqueueCounters;
    }
    bool vpnTunRuntimeCountersReady() const noexcept override {
        return vpnTunCountersReady;
    }
    SnortRuntime::VpnTunRuntimeCounters vpnTunRuntimeCounters() const noexcept override {
        return vpnTunCounters;
    }
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

bool writeAllWithFd(const int fd, const std::string_view data, const int fdToSend) {
    if (data.empty()) {
        return true;
    }

    std::array<char, CMSG_SPACE(sizeof(int))> control{};
    iovec iov{
        .iov_base = const_cast<char *>(data.data()),
        .iov_len = data.size(),
    };
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.data();
    msg.msg_controllen = control.size();

    cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(cmsg), &fdToSend, sizeof(int));
    msg.msg_controllen = CMSG_SPACE(sizeof(int));

    const ssize_t n = ::sendmsg(fd, &msg, 0);
    if (n < 0) {
        return false;
    }
    const auto sent = static_cast<std::size_t>(n);
    if (sent > data.size()) {
        return false;
    }
    if (sent == data.size()) {
        return true;
    }
    return writeAll(fd, data.substr(sent));
}

class ControlServerHarness {
public:
    explicit ControlServerHarness(SnortRuntime::BaseRuntimeControl &runtime) {
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

    rapidjson::Document callWithFd(const std::uint32_t id, const std::string_view cmd,
                                   const std::string_view args, const int fdToSend) {
        const std::string frame = ControlVNext::encodeNetstring(
            std::string("{\"id\":") + std::to_string(id) + ",\"cmd\":\"" + std::string(cmd) +
            "\",\"args\":" + std::string(args) + "}");
        if (!writeAllWithFd(clientFd_, frame, fdToSend)) {
            throw std::runtime_error("write-with-fd failed");
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

TEST(ControlServerContract, HelloAdvertisesGenericPacketAdapterCapabilityWhenReady) {
    FakeRuntimeControl runtime;
    runtime.adapterReady = true;
    runtime.adapterName = "root-nfqueue";
    ControlServerHarness harness(runtime);

    const rapidjson::Document response = harness.call(41, "HELLO");

    ASSERT_TRUE(response["ok"].GetBool());
    const auto capabilities = capabilityStrings(response["result"]["capabilities"]);
    EXPECT_NE(std::find(capabilities.begin(), capabilities.end(), "packet-adapter-root-nfqueue"),
              capabilities.end());
}

TEST(ControlServerContract, HelloAdvertisesVpnTunFdHandoffOnlyWhenRuntimeSupportsIt) {
    FakeRuntimeControl runtime;
    runtime.vpnTunHandoffReady = true;
    ControlServerHarness harness(runtime);

    const rapidjson::Document response = harness.call(42, "HELLO");

    ASSERT_TRUE(response["ok"].GetBool());
    const auto capabilities = capabilityStrings(response["result"]["capabilities"]);
    EXPECT_NE(std::find(capabilities.begin(), capabilities.end(), "vpn-tun-fd-handoff"),
              capabilities.end());
}

TEST(ControlServerContract, HelloAdvertisesVpnTransportFdHandoffOnlyWhenRuntimeSupportsIt) {
    FakeRuntimeControl runtime;
    runtime.vpnTransportHandoffReady = true;
    ControlServerHarness harness(runtime);

    const rapidjson::Document response = harness.call(46, "HELLO");

    ASSERT_TRUE(response["ok"].GetBool());
    const auto capabilities = capabilityStrings(response["result"]["capabilities"]);
    EXPECT_NE(std::find(capabilities.begin(), capabilities.end(),
                        "vpn-tun-transport-fd-handoff"),
              capabilities.end());
}

TEST(ControlServerContract, RealVpnTunRuntimeAdvertisesAttachLaterBeforeFdAndAcceptsTunFd) {
    Tun::VpnTunFdRuntime runtime{-1, true};
    ASSERT_TRUE(runtime.start());
    ASSERT_FALSE(runtime.packetAdapterReady());
    ControlServerHarness harness(runtime);

    const rapidjson::Document hello = harness.call(50, "HELLO");

    ASSERT_TRUE(hello["ok"].GetBool());
    const auto capabilities = capabilityStrings(hello["result"]["capabilities"]);
    EXPECT_NE(std::find(capabilities.begin(), capabilities.end(), "vpn-tun-fd-handoff"),
              capabilities.end());
    EXPECT_NE(std::find(capabilities.begin(), capabilities.end(),
                        "vpn-tun-transport-fd-handoff"),
              capabilities.end());
    EXPECT_NE(std::find(capabilities.begin(), capabilities.end(), "vpn-tun-runtime-counters"),
              capabilities.end());
    EXPECT_NE(std::find(capabilities.begin(), capabilities.end(), "packet-policy-control"),
              capabilities.end());
    EXPECT_EQ(std::find(capabilities.begin(), capabilities.end(),
                        "packet-adapter-vpn-tun-hev"),
              capabilities.end());

    int pipeFds[2]{-1, -1};
    ASSERT_EQ(::pipe(pipeFds), 0) << std::strerror(errno);
    UniqueFd tunRead{pipeFds[0]};
    UniqueFd tunWrite{pipeFds[1]};

    const rapidjson::Document attach =
        harness.callWithFd(51, "VPN_TUN.ATTACH", "{\"enableIpv6\":true}", tunRead.get());
    tunRead.reset();

    ASSERT_TRUE(attach["ok"].GetBool());
    ASSERT_TRUE(attach.HasMember("result"));
    EXPECT_TRUE(attach["result"]["fdAttached"].GetBool());
    EXPECT_TRUE(attach["result"]["ipv6Enabled"].GetBool());
    EXPECT_STREQ(attach["result"]["adapter"].GetString(), "vpn-tun-hev");
    EXPECT_FALSE(runtime.packetAdapterReady());

    const rapidjson::Document status = harness.call(52, "VPN_TUN.STATUS");

    ASSERT_TRUE(status["ok"].GetBool());
    EXPECT_EQ(status["result"]["packetsSeen"].GetUint64(), 0U);
}

TEST(ControlServerContract, RealVpnTunRuntimeAdvertisesPacketAdapterAfterBothFdHandoffs) {
    Tun::VpnTunFdRuntime runtime{-1, true};
    ASSERT_TRUE(runtime.start());
    ControlServerHarness harness(runtime);

    int tunPipeFds[2]{-1, -1};
    ASSERT_EQ(::pipe(tunPipeFds), 0) << std::strerror(errno);
    UniqueFd tunRead{tunPipeFds[0]};
    UniqueFd tunWrite{tunPipeFds[1]};
    ASSERT_TRUE(tunRead.valid());
    ASSERT_TRUE(tunWrite.valid());

    const rapidjson::Document tunAttach =
        harness.callWithFd(53, "VPN_TUN.ATTACH", "{\"enableIpv6\":true}", tunRead.get());
    tunRead.reset();
    ASSERT_TRUE(tunAttach["ok"].GetBool());

    int transportPipeFds[2]{-1, -1};
    ASSERT_EQ(::pipe(transportPipeFds), 0) << std::strerror(errno);
    UniqueFd transportRead{transportPipeFds[0]};
    UniqueFd transportWrite{transportPipeFds[1]};
    ASSERT_TRUE(transportRead.valid());
    ASSERT_TRUE(transportWrite.valid());

    const rapidjson::Document transportAttach =
        harness.callWithFd(54, "VPN_TRANSPORT.ATTACH", "{}", transportRead.get());
    transportRead.reset();
    ASSERT_TRUE(transportAttach["ok"].GetBool());
    ASSERT_TRUE(transportAttach.HasMember("result"));
    EXPECT_TRUE(transportAttach["result"]["transportFdAttached"].GetBool());

    for (int attempt = 0; attempt < 50 && !runtime.packetAdapterReady(); ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    ASSERT_TRUE(runtime.packetAdapterReady());

    const rapidjson::Document hello = harness.call(55, "HELLO");

    ASSERT_TRUE(hello["ok"].GetBool());
    const auto capabilities = capabilityStrings(hello["result"]["capabilities"]);
    EXPECT_NE(std::find(capabilities.begin(), capabilities.end(),
                        "packet-adapter-vpn-tun-hev"),
              capabilities.end());
}

TEST(ControlServerContract, VpnTunAttachRejectsMissingScmRightsFd) {
    FakeRuntimeControl runtime;
    runtime.vpnTunHandoffReady = true;
    ControlServerHarness harness(runtime);

    const rapidjson::Document response =
        harness.call(43, "VPN_TUN.ATTACH", "{\"enableIpv6\":true}");

    ASSERT_FALSE(response["ok"].GetBool());
    EXPECT_STREQ(response["error"]["code"].GetString(), "INVALID_ARGUMENT");
    EXPECT_EQ(runtime.vpnTunAttachCount, 0);
}

TEST(ControlServerContract, VpnTransportAttachRejectsMissingScmRightsFd) {
    FakeRuntimeControl runtime;
    runtime.vpnTransportHandoffReady = true;
    ControlServerHarness harness(runtime);

    const rapidjson::Document response =
        harness.call(47, "VPN_TRANSPORT.ATTACH");

    ASSERT_FALSE(response["ok"].GetBool());
    EXPECT_STREQ(response["error"]["code"].GetString(), "INVALID_ARGUMENT");
    EXPECT_EQ(runtime.vpnTransportAttachCount, 0);
}

TEST(ControlServerContract, VpnTransportAttachTransfersOneScmRightsFdToRuntime) {
    FakeRuntimeControl runtime;
    runtime.vpnTransportHandoffReady = true;
    ControlServerHarness harness(runtime);
    int pipeFds[2]{-1, -1};
    ASSERT_EQ(::pipe(pipeFds), 0) << std::strerror(errno);

    const rapidjson::Document response =
        harness.callWithFd(48, "VPN_TRANSPORT.ATTACH", "{}", pipeFds[0]);
    ::close(pipeFds[0]);
    pipeFds[0] = -1;

    ASSERT_TRUE(response["ok"].GetBool());
    ASSERT_TRUE(response.HasMember("result"));
    EXPECT_TRUE(response["result"]["transportFdAttached"].GetBool());
    EXPECT_EQ(runtime.vpnTransportAttachCount, 1);
    ASSERT_GE(runtime.attachedTransportFd, 0);

    const char expected = 't';
    ASSERT_EQ(::write(pipeFds[1], &expected, 1), 1);
    ::close(pipeFds[1]);
    pipeFds[1] = -1;
    char actual = '\0';
    EXPECT_EQ(::read(runtime.attachedTransportFd, &actual, 1), 1);
    EXPECT_EQ(actual, expected);
}

TEST(ControlServerContract, VpnTransportAttachIsUnsupportedWithoutRuntimeCapability) {
    FakeRuntimeControl runtime;
    ControlServerHarness harness(runtime);
    int pipeFds[2]{-1, -1};
    ASSERT_EQ(::pipe(pipeFds), 0) << std::strerror(errno);

    const rapidjson::Document response =
        harness.callWithFd(49, "VPN_TRANSPORT.ATTACH", "{}", pipeFds[0]);
    ::close(pipeFds[0]);
    ::close(pipeFds[1]);

    ASSERT_FALSE(response["ok"].GetBool());
    EXPECT_STREQ(response["error"]["code"].GetString(), "UNSUPPORTED_COMMAND");
    EXPECT_EQ(runtime.vpnTransportAttachCount, 0);
}

TEST(ControlServerContract, VpnTunAttachTransfersOneScmRightsFdToRuntime) {
    FakeRuntimeControl runtime;
    runtime.vpnTunHandoffReady = true;
    ControlServerHarness harness(runtime);
    int pipeFds[2]{-1, -1};
    ASSERT_EQ(::pipe(pipeFds), 0) << std::strerror(errno);

    const rapidjson::Document response =
        harness.callWithFd(44, "VPN_TUN.ATTACH", "{\"enableIpv6\":true}", pipeFds[0]);
    ::close(pipeFds[0]);
    pipeFds[0] = -1;

    ASSERT_TRUE(response["ok"].GetBool());
    ASSERT_TRUE(response.HasMember("result"));
    EXPECT_TRUE(response["result"]["fdAttached"].GetBool());
    EXPECT_TRUE(response["result"]["ipv6Enabled"].GetBool());
    EXPECT_EQ(runtime.vpnTunAttachCount, 1);
    EXPECT_TRUE(runtime.vpnTunAttachIpv6);
    ASSERT_GE(runtime.attachedTunFd, 0);

    const char expected = 'x';
    ASSERT_EQ(::write(pipeFds[1], &expected, 1), 1);
    ::close(pipeFds[1]);
    pipeFds[1] = -1;
    char actual = '\0';
    EXPECT_EQ(::read(runtime.attachedTunFd, &actual, 1), 1);
    EXPECT_EQ(actual, expected);
}

TEST(ControlServerContract, VpnTunAttachIsUnsupportedWithoutRuntimeCapability) {
    FakeRuntimeControl runtime;
    ControlServerHarness harness(runtime);
    int pipeFds[2]{-1, -1};
    ASSERT_EQ(::pipe(pipeFds), 0) << std::strerror(errno);

    const rapidjson::Document response =
        harness.callWithFd(45, "VPN_TUN.ATTACH", "{\"enableIpv6\":true}", pipeFds[0]);
    ::close(pipeFds[0]);
    ::close(pipeFds[1]);

    ASSERT_FALSE(response["ok"].GetBool());
    EXPECT_STREQ(response["error"]["code"].GetString(), "UNSUPPORTED_COMMAND");
    EXPECT_EQ(runtime.vpnTunAttachCount, 0);
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

TEST(ControlServerContract, HelloOmitsNfqueueCountersCapabilityWhenUnsupported) {
    FakeRuntimeControl runtime;
    runtime.nfqueueCountersReady = false;
    ControlServerHarness harness(runtime);

    const rapidjson::Document response = harness.call(6, "HELLO");

    ASSERT_TRUE(response["ok"].GetBool());
    const auto capabilities = capabilityStrings(response["result"]["capabilities"]);
    EXPECT_EQ(std::find(capabilities.begin(), capabilities.end(), "nfqueue-runtime-counters"),
              capabilities.end());
}

TEST(ControlServerContract, NfqueueStatusIsUnsupportedWithoutRuntimeCapability) {
    FakeRuntimeControl runtime;
    runtime.nfqueueCountersReady = false;
    ControlServerHarness harness(runtime);

    const rapidjson::Document response = harness.call(7, "NFQUEUE.STATUS");

    ASSERT_FALSE(response["ok"].GetBool());
    EXPECT_STREQ(response["error"]["code"].GetString(), "UNSUPPORTED_COMMAND");
}

TEST(ControlServerContract, NfqueueStatusReturnsExactRuntimeCounters) {
    FakeRuntimeControl runtime;
    runtime.nfqueueCountersReady = true;
    runtime.nfqueueCounters.packetsSeen = 101;
    runtime.nfqueueCounters.acceptedPackets = 91;
    runtime.nfqueueCounters.droppedPackets = 7;
    runtime.nfqueueCounters.parsePassThroughPackets = 2;
    runtime.nfqueueCounters.capacityPassThroughPackets = 3;
    runtime.nfqueueCounters.ownerFaultPassThroughPackets = 4;
    runtime.nfqueueCounters.verdictSendFailures = 5;
    runtime.nfqueueCounters.fragmentBufferedPackets = 6;
    runtime.nfqueueCounters.fragmentReassembledPackets = 8;
    runtime.nfqueueCounters.uidMetadataPresentPackets = 9;
    runtime.nfqueueCounters.uidMetadataMissingPackets = 10;
    runtime.nfqueueCounters.lastObservedLinuxUid = 12546;
    runtime.nfqueueCounters.lastObservedUidKnown = true;
    runtime.nfqueueCounters.lastObservedNetworkContext = 7;
    runtime.nfqueueCounters.lastObservedHook = 3;
    runtime.nfqueueCounters.lastObservedInputInterfaceIndex = 11;
    runtime.nfqueueCounters.lastObservedOutputInterfaceIndex = 22;
    runtime.nfqueueCounters.lastObservedResult = "FlowAccepted";
    ControlServerHarness harness(runtime);

    const rapidjson::Document hello = harness.call(8, "HELLO");
    ASSERT_TRUE(hello["ok"].GetBool());
    const auto capabilities = capabilityStrings(hello["result"]["capabilities"]);
    EXPECT_NE(std::find(capabilities.begin(), capabilities.end(), "nfqueue-runtime-counters"),
              capabilities.end());

    const rapidjson::Document response = harness.call(9, "NFQUEUE.STATUS");

    ASSERT_TRUE(response["ok"].GetBool());
    const auto &result = response["result"];
    EXPECT_EQ(result["packetsSeen"].GetUint64(), 101U);
    EXPECT_EQ(result["acceptedPackets"].GetUint64(), 91U);
    EXPECT_EQ(result["droppedPackets"].GetUint64(), 7U);
    EXPECT_EQ(result["parsePassThroughPackets"].GetUint64(), 2U);
    EXPECT_EQ(result["capacityPassThroughPackets"].GetUint64(), 3U);
    EXPECT_EQ(result["ownerFaultPassThroughPackets"].GetUint64(), 4U);
    EXPECT_EQ(result["verdictSendFailures"].GetUint64(), 5U);
    EXPECT_EQ(result["fragmentBufferedPackets"].GetUint64(), 6U);
    EXPECT_EQ(result["fragmentReassembledPackets"].GetUint64(), 8U);
    EXPECT_EQ(result["uidMetadataPresentPackets"].GetUint64(), 9U);
    EXPECT_EQ(result["uidMetadataMissingPackets"].GetUint64(), 10U);
    EXPECT_EQ(result["lastObservedLinuxUid"].GetUint(), 12546U);
    EXPECT_TRUE(result["lastObservedUidKnown"].GetBool());
    EXPECT_EQ(result["lastObservedNetworkContext"].GetUint(), 7U);
    EXPECT_EQ(result["lastObservedHook"].GetUint(), 3U);
    EXPECT_EQ(result["lastObservedInputInterfaceIndex"].GetUint(), 11U);
    EXPECT_EQ(result["lastObservedOutputInterfaceIndex"].GetUint(), 22U);
    EXPECT_STREQ(result["lastObservedResult"].GetString(), "FlowAccepted");
}

TEST(ControlServerContract, HelloOmitsVpnTunCountersCapabilityWhenUnsupported) {
    FakeRuntimeControl runtime;
    runtime.vpnTunCountersReady = false;
    ControlServerHarness harness(runtime);

    const rapidjson::Document response = harness.call(46, "HELLO");

    ASSERT_TRUE(response["ok"].GetBool());
    const auto capabilities = capabilityStrings(response["result"]["capabilities"]);
    EXPECT_EQ(std::find(capabilities.begin(), capabilities.end(),
                        "vpn-tun-runtime-counters"),
              capabilities.end());
}

TEST(ControlServerContract, VpnTunStatusIsUnsupportedWithoutRuntimeCapability) {
    FakeRuntimeControl runtime;
    runtime.vpnTunCountersReady = false;
    ControlServerHarness harness(runtime);

    const rapidjson::Document response = harness.call(47, "VPN_TUN.STATUS");

    ASSERT_FALSE(response["ok"].GetBool());
    EXPECT_STREQ(response["error"]["code"].GetString(), "UNSUPPORTED_COMMAND");
}

TEST(ControlServerContract, VpnTunStatusReturnsExactRuntimeCounters) {
    FakeRuntimeControl runtime;
    runtime.vpnTunCountersReady = true;
    runtime.vpnTunCounters.packetsSeen = 201;
    runtime.vpnTunCounters.normalizedPackets = 202;
    runtime.vpnTunCounters.forwardedPackets = 191;
    runtime.vpnTunCounters.droppedPackets = 7;
    runtime.vpnTunCounters.parsePolicyBypassPackets = 2;
    runtime.vpnTunCounters.capacityPolicyBypassPackets = 3;
    runtime.vpnTunCounters.ownerFaultRuntimeDrops = 4;
    runtime.vpnTunCounters.fragmentBufferedPackets = 5;
    runtime.vpnTunCounters.fragmentReassembledPackets = 6;
    runtime.vpnTunCounters.uidAttributionHitPackets = 197;
    runtime.vpnTunCounters.uidUnknownFallbackPackets = 4;
    runtime.vpnTunCounters.outboundPackets = 111;
    runtime.vpnTunCounters.transportReturnPackets = 90;
    runtime.vpnTunCounters.transportSucceededPackets = 81;
    runtime.vpnTunCounters.transportFailedPackets = 8;
    runtime.vpnTunCounters.transportUnsupportedPackets = 1;
    runtime.vpnTunCounters.directPackets = 198;
    runtime.vpnTunCounters.ownerGuardPasses = 198;
    runtime.vpnTunCounters.ownerGuardMismatches = 0;
    runtime.vpnTunCounters.lastObservedLinuxUid = 12546;
    runtime.vpnTunCounters.lastObservedUidKnown = true;
    runtime.vpnTunCounters.lastObservedNetworkContext = 7;
    runtime.vpnTunCounters.lastObservedInterfaceIndex = 9;
    runtime.vpnTunCounters.lastObservedDirection = "transport-return";
    runtime.vpnTunCounters.lastObservedResult = "FlowForwarded";
    ControlServerHarness harness(runtime);

    const rapidjson::Document hello = harness.call(48, "HELLO");
    ASSERT_TRUE(hello["ok"].GetBool());
    const auto capabilities = capabilityStrings(hello["result"]["capabilities"]);
    EXPECT_NE(std::find(capabilities.begin(), capabilities.end(),
                        "vpn-tun-runtime-counters"),
              capabilities.end());

    const rapidjson::Document response = harness.call(49, "VPN_TUN.STATUS");

    ASSERT_TRUE(response["ok"].GetBool());
    const auto &result = response["result"];
    EXPECT_EQ(result["packetsSeen"].GetUint64(), 201U);
    EXPECT_EQ(result["normalizedPackets"].GetUint64(), 202U);
    EXPECT_EQ(result["forwardedPackets"].GetUint64(), 191U);
    EXPECT_EQ(result["droppedPackets"].GetUint64(), 7U);
    EXPECT_EQ(result["parsePolicyBypassPackets"].GetUint64(), 2U);
    EXPECT_EQ(result["capacityPolicyBypassPackets"].GetUint64(), 3U);
    EXPECT_EQ(result["ownerFaultRuntimeDrops"].GetUint64(), 4U);
    EXPECT_EQ(result["fragmentBufferedPackets"].GetUint64(), 5U);
    EXPECT_EQ(result["fragmentReassembledPackets"].GetUint64(), 6U);
    EXPECT_EQ(result["uidAttributionHitPackets"].GetUint64(), 197U);
    EXPECT_EQ(result["uidUnknownFallbackPackets"].GetUint64(), 4U);
    EXPECT_EQ(result["outboundPackets"].GetUint64(), 111U);
    EXPECT_EQ(result["transportReturnPackets"].GetUint64(), 90U);
    EXPECT_EQ(result["transportSucceededPackets"].GetUint64(), 81U);
    EXPECT_EQ(result["transportFailedPackets"].GetUint64(), 8U);
    EXPECT_EQ(result["transportUnsupportedPackets"].GetUint64(), 1U);
    EXPECT_EQ(result["directPackets"].GetUint64(), 198U);
    EXPECT_EQ(result["ownerGuardPasses"].GetUint64(), 198U);
    EXPECT_EQ(result["ownerGuardMismatches"].GetUint64(), 0U);
    EXPECT_EQ(result["lastObservedLinuxUid"].GetUint(), 12546U);
    EXPECT_TRUE(result["lastObservedUidKnown"].GetBool());
    EXPECT_EQ(result["lastObservedNetworkContext"].GetUint(), 7U);
    EXPECT_EQ(result["lastObservedInterfaceIndex"].GetUint(), 9U);
    EXPECT_STREQ(result["lastObservedDirection"].GetString(), "transport-return");
    EXPECT_STREQ(result["lastObservedResult"].GetString(), "FlowForwarded");
}

TEST(ControlServerContract, PolicyUnknownApplicationSubjectMatchesUidUnknownFacts) {
    FakeRuntimeControl runtime;
    runtime.policyReady = true;
    ControlServerHarness harness(runtime);

    const auto apply = harness.call(
        21, "POLICY.APPLY",
        R"({"revision":68,"subjects":[{"uidKnown":false,"networkGate":{},"l4Rules":[{"ruleId":500,"reasonId":50,"priority":0,"order":0,"action":"drop","match":{"family":"ipv4","direction":"input","ipProtocol":6,"destinationPorts":{"first":443,"last":443}}}]}]})");
    ASSERT_TRUE(apply["ok"].GetBool());

    const auto eval = harness.call(
        22, "POLICY.EVALUATE",
        R"({"uidKnown":false,"networkContext":2,"family":"ipv4","direction":"input","ipProtocol":6,"sourcePort":40000,"destinationPort":443,"portsAvailable":true})");

    ASSERT_TRUE(eval["ok"].GetBool());
    EXPECT_STREQ(eval["result"]["verdict"].GetString(), "DROP");
    EXPECT_STREQ(eval["result"]["stage"].GetString(), "L4");
    EXPECT_EQ(eval["result"]["reasonId"].GetUint(), 50U);
    EXPECT_EQ(eval["result"]["ruleId"].GetUint64(), 500U);
    EXPECT_EQ(eval["result"]["revision"].GetUint64(), 68U);
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
    EXPECT_FALSE(result.HasMember("runtimeCounters"));
    EXPECT_FALSE(result.HasMember("packetsSeen"));
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
