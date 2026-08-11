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

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <algorithm>
#include <cerrno>
#include <chrono>
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
namespace Protocol = SnortDatapath::Protocol;
namespace Catalog = sucre::protocol;

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

void makePacketSocketPair(int (&fds)[2]) {
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, fds), 0)
        << std::strerror(errno);
}

bool writePacket(const int fd, const std::span<const std::uint8_t> packet) {
    const ssize_t written = ::write(fd, packet.data(), packet.size());
    return written == static_cast<ssize_t>(packet.size());
}

std::vector<std::uint8_t> readPacketFromFd(const int fd) {
    std::array<std::uint8_t, 2048> buffer{};
    const ssize_t bytes = ::read(fd, buffer.data(), buffer.size());
    if (bytes <= 0) {
        return {};
    }
    return std::vector<std::uint8_t>(
        buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(bytes));
}

std::vector<std::uint8_t> readPacketFromFdWithDeadline(
    const int fd,
    const std::chrono::milliseconds deadline = std::chrono::milliseconds{1000}) {
    const auto stopAt = std::chrono::steady_clock::now() + deadline;
    while (std::chrono::steady_clock::now() < stopAt) {
        pollfd target{
            .fd = fd,
            .events = POLLIN | POLLERR | POLLHUP,
            .revents = 0,
        };
        const int pollResult = ::poll(&target, 1, 10);
        if (pollResult < 0 && errno == EINTR) {
            continue;
        }
        if (pollResult <= 0) {
            continue;
        }
        if ((target.revents & POLLIN) != 0) {
            return readPacketFromFd(fd);
        }
        return {};
    }
    return {};
}

void putU16(std::span<std::uint8_t> bytes, const std::size_t offset,
            const std::uint16_t value) noexcept {
    bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 1] = static_cast<std::uint8_t>(value & 0xffU);
}

std::array<std::uint8_t, 40> ipv4TcpPacket(const bool reverse = false) {
    std::array<std::uint8_t, 40> packet{};
    packet[0] = 0x45;
    putU16(packet, 2, 40);
    packet[8] = 64;
    packet[9] = 6;
    const std::array<std::uint8_t, 4> source = reverse
        ? std::array<std::uint8_t, 4>{192, 0, 2, 1}
        : std::array<std::uint8_t, 4>{10, 0, 0, 1};
    const std::array<std::uint8_t, 4> destination = reverse
        ? std::array<std::uint8_t, 4>{10, 0, 0, 1}
        : std::array<std::uint8_t, 4>{192, 0, 2, 1};
    for (std::size_t index = 0; index < 4; ++index) {
        packet[12 + index] = source[index];
        packet[16 + index] = destination[index];
    }
    putU16(packet, 20, reverse ? 443 : 40000);
    putU16(packet, 22, reverse ? 40000 : 443);
    packet[32] = 0x50;
    return packet;
}

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

rapidjson::Document waitForVpnTunPacketsSeen(ControlServerHarness &harness,
                                             const std::uint64_t packetsSeen,
                                             std::uint32_t &id) {
    rapidjson::Document latest;
    for (std::size_t attempt = 0; attempt < 100; ++attempt) {
        latest = harness.call(id++, "VPN_TUN.STATUS");
        if (latest["ok"].GetBool()
            && latest["result"]["packetsSeen"].GetUint64() >= packetsSeen) {
            return latest;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    return latest;
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

TEST(ControlServerContract, RealVpnTunRuntimeControlRelayForwardsAllowedOutboundPacket) {
    Tun::VpnTunFdRuntime runtime{-1, true};
    ASSERT_TRUE(runtime.start());
    ControlServerHarness harness(runtime);

    int tunFds[2]{-1, -1};
    int transportFds[2]{-1, -1};
    makePacketSocketPair(tunFds);
    makePacketSocketPair(transportFds);
    UniqueFd tunRuntime{tunFds[0]};
    UniqueFd tunPeer{tunFds[1]};
    UniqueFd transportRuntime{transportFds[0]};
    UniqueFd transportPeer{transportFds[1]};

    const rapidjson::Document tunAttach =
        harness.callWithFd(56, "VPN_TUN.ATTACH", "{\"enableIpv6\":true}", tunRuntime.get());
    tunRuntime.reset();
    ASSERT_TRUE(tunAttach["ok"].GetBool());
    const rapidjson::Document transportAttach =
        harness.callWithFd(57, "VPN_TRANSPORT.ATTACH", "{}", transportRuntime.get());
    transportRuntime.reset();
    ASSERT_TRUE(transportAttach["ok"].GetBool());

    for (int attempt = 0; attempt < 50 && !runtime.packetAdapterReady(); ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    ASSERT_TRUE(runtime.packetAdapterReady());

    const auto packet = ipv4TcpPacket();
    ASSERT_TRUE(writePacket(tunPeer.get(), std::span<const std::uint8_t>{packet}));
    const auto transported = readPacketFromFdWithDeadline(transportPeer.get());

    ASSERT_EQ(transported.size(), packet.size());
    EXPECT_TRUE(std::equal(packet.begin(), packet.end(), transported.begin()));

    std::uint32_t statusId = 58;
    const rapidjson::Document status = waitForVpnTunPacketsSeen(harness, 1, statusId);
    ASSERT_TRUE(status["ok"].GetBool());
    EXPECT_EQ(status["result"]["forwardedPackets"].GetUint64(), 1U);
    EXPECT_EQ(status["result"]["droppedPackets"].GetUint64(), 0U);
    EXPECT_EQ(status["result"]["transportSucceededPackets"].GetUint64(), 1U);
    EXPECT_EQ(status["result"]["uidUnknownFallbackPackets"].GetUint64(), 1U);
    EXPECT_STREQ(status["result"]["lastObservedResult"].GetString(), "FlowForwarded");
}

TEST(ControlServerContract, RealVpnTunRuntimeLateAttributionReevaluatesNextUnknownPacket) {
    Tun::VpnTunFdRuntime runtime{-1, true};
    ASSERT_TRUE(runtime.start());
    ControlServerHarness harness(runtime);

    const rapidjson::Document hello = harness.call(58, "HELLO");
    ASSERT_TRUE(hello["ok"].GetBool());
    const auto capabilities = capabilityStrings(hello["result"]["capabilities"]);
    EXPECT_NE(std::find(capabilities.begin(), capabilities.end(),
                        "vpn-tun-attribution-control"),
              capabilities.end());

    const rapidjson::Document policy = harness.call(
        59, "POLICY.APPLY",
        R"({"revision":5600,"subjects":[{"linuxUid":20002,"networkGate":{},"l4Rules":[{"ruleId":5601,"reasonId":56,"priority":0,"order":0,"action":"drop","match":{"family":"ipv4","direction":"output","ipProtocol":6,"destinationPorts":{"first":443,"last":443}}}]}]})");
    ASSERT_TRUE(policy["ok"].GetBool());

    int tunFds[2]{-1, -1};
    int transportFds[2]{-1, -1};
    makePacketSocketPair(tunFds);
    makePacketSocketPair(transportFds);
    UniqueFd tunRuntime{tunFds[0]};
    UniqueFd tunPeer{tunFds[1]};
    UniqueFd transportRuntime{transportFds[0]};
    UniqueFd transportPeer{transportFds[1]};

    ASSERT_TRUE(harness.callWithFd(
                    60, "VPN_TUN.ATTACH", "{\"enableIpv6\":true}", tunRuntime.get())["ok"]
                    .GetBool());
    tunRuntime.reset();
    ASSERT_TRUE(harness.callWithFd(
                    61, "VPN_TRANSPORT.ATTACH", "{}", transportRuntime.get())["ok"]
                    .GetBool());
    transportRuntime.reset();

    for (int attempt = 0; attempt < 50 && !runtime.packetAdapterReady(); ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    ASSERT_TRUE(runtime.packetAdapterReady());

    const auto packet = ipv4TcpPacket();
    ASSERT_TRUE(writePacket(tunPeer.get(), std::span<const std::uint8_t>{packet}));
    const auto firstTransported = readPacketFromFdWithDeadline(transportPeer.get());
    ASSERT_EQ(firstTransported.size(), packet.size());

    const rapidjson::Document attribution = harness.call(
        62, "VPN_TUN.ATTRIBUTION.APPLY",
        R"({"uidKnown":false,"networkContext":0,"family":"ipv4","direction":"output","ipProtocol":6,"sourceIp":"10.0.0.1","destinationIp":"192.0.2.1","sourcePort":40000,"destinationPort":443,"portsAvailable":true,"resolvedLinuxUid":20002})");
    ASSERT_TRUE(attribution["ok"].GetBool());
    EXPECT_TRUE(attribution["result"]["found"].GetBool());
    EXPECT_TRUE(attribution["result"]["updated"].GetBool());
    EXPECT_FALSE(attribution["result"]["previousUidKnown"].GetBool());
    EXPECT_EQ(attribution["result"]["currentLinuxUid"].GetUint(), 20002U);
    EXPECT_TRUE(attribution["result"]["currentUidKnown"].GetBool());

    ASSERT_TRUE(writePacket(tunPeer.get(), std::span<const std::uint8_t>{packet}));
    std::uint32_t statusId = 63;
    const rapidjson::Document status = waitForVpnTunPacketsSeen(harness, 2, statusId);

    ASSERT_TRUE(status["ok"].GetBool());
    EXPECT_EQ(status["result"]["forwardedPackets"].GetUint64(), 1U);
    EXPECT_EQ(status["result"]["droppedPackets"].GetUint64(), 1U);
    EXPECT_EQ(status["result"]["uidUnknownFallbackPackets"].GetUint64(), 2U);
    EXPECT_EQ(status["result"]["attributionUpdates"].GetUint64(), 1U);
    EXPECT_EQ(status["result"]["attributionMisses"].GetUint64(), 0U);
    EXPECT_EQ(status["result"]["attributionResolutions"].GetUint64(), 1U);
    EXPECT_STREQ(status["result"]["lastObservedResult"].GetString(), "FlowDropped");
    EXPECT_TRUE(readPacketFromFdWithDeadline(
                    transportPeer.get(), std::chrono::milliseconds{100})
                    .empty());
}

TEST(ControlServerContract, RealVpnTunRuntimeControlGateDropBlocksOutboundRelay) {
    Tun::VpnTunFdRuntime runtime{-1, true};
    ASSERT_TRUE(runtime.start());
    ControlServerHarness harness(runtime);

    int tunFds[2]{-1, -1};
    int transportFds[2]{-1, -1};
    makePacketSocketPair(tunFds);
    makePacketSocketPair(transportFds);
    UniqueFd tunRuntime{tunFds[0]};
    UniqueFd tunPeer{tunFds[1]};
    UniqueFd transportRuntime{transportFds[0]};
    UniqueFd transportPeer{transportFds[1]};

    const rapidjson::Document policy = harness.call(
        70, "POLICY.APPLY",
        R"({"revision":6900,"subjects":[{"uidKnown":false,"networkGate":{"blockedNetworkContexts":[0],"reasonId":6900,"ruleId":6900},"l4Rules":[]}]})");
    ASSERT_TRUE(policy["ok"].GetBool());
    EXPECT_EQ(policy["result"]["revision"].GetUint64(), 6900U);
    EXPECT_EQ(policy["result"]["networkGateRuleCount"].GetUint64(), 1U);

    const rapidjson::Document gateEval = harness.call(
        71, "POLICY.EVALUATE",
        R"({"uidKnown":false,"networkContext":0,"family":"ipv4","direction":"output","ipProtocol":6,"sourcePort":40000,"destinationPort":443,"portsAvailable":true})");
    ASSERT_TRUE(gateEval["ok"].GetBool());
    EXPECT_STREQ(gateEval["result"]["verdict"].GetString(), "DROP");
    EXPECT_STREQ(gateEval["result"]["stage"].GetString(), "NetworkGate");
    EXPECT_EQ(gateEval["result"]["reasonId"].GetUint(), 6900U);
    EXPECT_EQ(gateEval["result"]["ruleId"].GetUint64(), 6900U);

    ASSERT_TRUE(harness.callWithFd(
                    72, "VPN_TUN.ATTACH", "{\"enableIpv6\":true}", tunRuntime.get())["ok"]
                    .GetBool());
    tunRuntime.reset();
    ASSERT_TRUE(harness.callWithFd(
                    73, "VPN_TRANSPORT.ATTACH", "{}", transportRuntime.get())["ok"]
                    .GetBool());
    transportRuntime.reset();

    for (int attempt = 0; attempt < 50 && !runtime.packetAdapterReady(); ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    ASSERT_TRUE(runtime.packetAdapterReady());

    const auto packet = ipv4TcpPacket();
    ASSERT_TRUE(writePacket(tunPeer.get(), std::span<const std::uint8_t>{packet}));
    std::uint32_t statusId = 74;
    const rapidjson::Document status = waitForVpnTunPacketsSeen(harness, 1, statusId);

    ASSERT_TRUE(status["ok"].GetBool());
    EXPECT_EQ(status["result"]["forwardedPackets"].GetUint64(), 0U);
    EXPECT_EQ(status["result"]["droppedPackets"].GetUint64(), 1U);
    EXPECT_EQ(status["result"]["transportSucceededPackets"].GetUint64(), 0U);
    EXPECT_EQ(status["result"]["uidUnknownFallbackPackets"].GetUint64(), 1U);
    EXPECT_STREQ(status["result"]["lastObservedResult"].GetString(), "FlowDropped");
    EXPECT_TRUE(readPacketFromFdWithDeadline(
                    transportPeer.get(), std::chrono::milliseconds{100})
                    .empty());
}

TEST(ControlServerContract, RealVpnTunRuntimeControlL4DropBlocksOutboundRelay) {
    Tun::VpnTunFdRuntime runtime{-1, true};
    ASSERT_TRUE(runtime.start());
    ControlServerHarness harness(runtime);

    int tunFds[2]{-1, -1};
    int transportFds[2]{-1, -1};
    makePacketSocketPair(tunFds);
    makePacketSocketPair(transportFds);
    UniqueFd tunRuntime{tunFds[0]};
    UniqueFd tunPeer{tunFds[1]};
    UniqueFd transportRuntime{transportFds[0]};
    UniqueFd transportPeer{transportFds[1]};

    const rapidjson::Document policy = harness.call(
        80, "POLICY.APPLY",
        R"({"revision":6901,"subjects":[{"uidKnown":false,"networkGate":{},"l4Rules":[{"ruleId":6901,"reasonId":6901,"priority":0,"order":0,"action":"drop","match":{"family":"ipv4","direction":"output","ipProtocol":6,"destinationPorts":{"first":443,"last":443}}}]}]})");
    ASSERT_TRUE(policy["ok"].GetBool());
    EXPECT_EQ(policy["result"]["revision"].GetUint64(), 6901U);
    EXPECT_EQ(policy["result"]["l4RuleCount"].GetUint64(), 1U);

    const rapidjson::Document l4Eval = harness.call(
        81, "POLICY.EVALUATE",
        R"({"uidKnown":false,"networkContext":0,"family":"ipv4","direction":"output","ipProtocol":6,"sourcePort":40000,"destinationPort":443,"portsAvailable":true})");
    ASSERT_TRUE(l4Eval["ok"].GetBool());
    EXPECT_STREQ(l4Eval["result"]["verdict"].GetString(), "DROP");
    EXPECT_STREQ(l4Eval["result"]["stage"].GetString(), "L4");
    EXPECT_EQ(l4Eval["result"]["reasonId"].GetUint(), 6901U);
    EXPECT_EQ(l4Eval["result"]["ruleId"].GetUint64(), 6901U);

    ASSERT_TRUE(harness.callWithFd(
                    82, "VPN_TUN.ATTACH", "{\"enableIpv6\":true}", tunRuntime.get())["ok"]
                    .GetBool());
    tunRuntime.reset();
    ASSERT_TRUE(harness.callWithFd(
                    83, "VPN_TRANSPORT.ATTACH", "{}", transportRuntime.get())["ok"]
                    .GetBool());
    transportRuntime.reset();

    for (int attempt = 0; attempt < 50 && !runtime.packetAdapterReady(); ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    ASSERT_TRUE(runtime.packetAdapterReady());

    const auto packet = ipv4TcpPacket();
    ASSERT_TRUE(writePacket(tunPeer.get(), std::span<const std::uint8_t>{packet}));
    std::uint32_t statusId = 84;
    const rapidjson::Document status = waitForVpnTunPacketsSeen(harness, 1, statusId);

    ASSERT_TRUE(status["ok"].GetBool());
    EXPECT_EQ(status["result"]["forwardedPackets"].GetUint64(), 0U);
    EXPECT_EQ(status["result"]["droppedPackets"].GetUint64(), 1U);
    EXPECT_EQ(status["result"]["transportSucceededPackets"].GetUint64(), 0U);
    EXPECT_EQ(status["result"]["uidUnknownFallbackPackets"].GetUint64(), 1U);
    EXPECT_STREQ(status["result"]["lastObservedResult"].GetString(), "FlowDropped");
    EXPECT_TRUE(readPacketFromFdWithDeadline(
                    transportPeer.get(), std::chrono::milliseconds{100})
                    .empty());
}

TEST(ControlServerContract, RealVpnTunRuntimeControlRelayReturnsAllowedTransportPacket) {
    Tun::VpnTunFdRuntime runtime{-1, true};
    ASSERT_TRUE(runtime.start());
    ControlServerHarness harness(runtime);

    int tunFds[2]{-1, -1};
    int transportFds[2]{-1, -1};
    makePacketSocketPair(tunFds);
    makePacketSocketPair(transportFds);
    UniqueFd tunRuntime{tunFds[0]};
    UniqueFd tunPeer{tunFds[1]};
    UniqueFd transportRuntime{transportFds[0]};
    UniqueFd transportPeer{transportFds[1]};

    ASSERT_TRUE(harness.callWithFd(
                    90, "VPN_TUN.ATTACH", "{\"enableIpv6\":true}", tunRuntime.get())["ok"]
                    .GetBool());
    tunRuntime.reset();
    ASSERT_TRUE(harness.callWithFd(
                    91, "VPN_TRANSPORT.ATTACH", "{}", transportRuntime.get())["ok"]
                    .GetBool());
    transportRuntime.reset();

    for (int attempt = 0; attempt < 50 && !runtime.packetAdapterReady(); ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    ASSERT_TRUE(runtime.packetAdapterReady());

    const auto packet = ipv4TcpPacket(true);
    ASSERT_TRUE(writePacket(transportPeer.get(), std::span<const std::uint8_t>{packet}));
    const auto returned = readPacketFromFdWithDeadline(tunPeer.get());

    ASSERT_EQ(returned.size(), packet.size());
    EXPECT_TRUE(std::equal(packet.begin(), packet.end(), returned.begin()));

    std::uint32_t statusId = 92;
    const rapidjson::Document status = waitForVpnTunPacketsSeen(harness, 1, statusId);
    ASSERT_TRUE(status["ok"].GetBool());
    EXPECT_EQ(status["result"]["forwardedPackets"].GetUint64(), 1U);
    EXPECT_EQ(status["result"]["droppedPackets"].GetUint64(), 0U);
    EXPECT_EQ(status["result"]["transportReturnPackets"].GetUint64(), 1U);
    EXPECT_EQ(status["result"]["transportSucceededPackets"].GetUint64(), 1U);
    EXPECT_EQ(status["result"]["uidUnknownFallbackPackets"].GetUint64(), 1U);
    EXPECT_STREQ(status["result"]["lastObservedDirection"].GetString(), "transport-return");
    EXPECT_STREQ(status["result"]["lastObservedResult"].GetString(), "FlowForwarded");
}

TEST(ControlServerContract, RealVpnTunRuntimeControlGateDropBlocksTransportReturnRelay) {
    Tun::VpnTunFdRuntime runtime{-1, true};
    ASSERT_TRUE(runtime.start());
    ControlServerHarness harness(runtime);

    int tunFds[2]{-1, -1};
    int transportFds[2]{-1, -1};
    makePacketSocketPair(tunFds);
    makePacketSocketPair(transportFds);
    UniqueFd tunRuntime{tunFds[0]};
    UniqueFd tunPeer{tunFds[1]};
    UniqueFd transportRuntime{transportFds[0]};
    UniqueFd transportPeer{transportFds[1]};

    const rapidjson::Document policy = harness.call(
        100, "POLICY.APPLY",
        R"({"revision":6902,"subjects":[{"uidKnown":false,"networkGate":{"blockedNetworkContexts":[0],"reasonId":6902,"ruleId":6902},"l4Rules":[]}]})");
    ASSERT_TRUE(policy["ok"].GetBool());
    EXPECT_EQ(policy["result"]["revision"].GetUint64(), 6902U);
    EXPECT_EQ(policy["result"]["networkGateRuleCount"].GetUint64(), 1U);

    const rapidjson::Document gateEval = harness.call(
        101, "POLICY.EVALUATE",
        R"({"uidKnown":false,"networkContext":0,"family":"ipv4","direction":"input","ipProtocol":6,"sourcePort":443,"destinationPort":40000,"portsAvailable":true})");
    ASSERT_TRUE(gateEval["ok"].GetBool());
    EXPECT_STREQ(gateEval["result"]["verdict"].GetString(), "DROP");
    EXPECT_STREQ(gateEval["result"]["stage"].GetString(), "NetworkGate");
    EXPECT_EQ(gateEval["result"]["reasonId"].GetUint(), 6902U);
    EXPECT_EQ(gateEval["result"]["ruleId"].GetUint64(), 6902U);

    ASSERT_TRUE(harness.callWithFd(
                    102, "VPN_TUN.ATTACH", "{\"enableIpv6\":true}", tunRuntime.get())["ok"]
                    .GetBool());
    tunRuntime.reset();
    ASSERT_TRUE(harness.callWithFd(
                    103, "VPN_TRANSPORT.ATTACH", "{}", transportRuntime.get())["ok"]
                    .GetBool());
    transportRuntime.reset();

    for (int attempt = 0; attempt < 50 && !runtime.packetAdapterReady(); ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    ASSERT_TRUE(runtime.packetAdapterReady());

    const auto packet = ipv4TcpPacket(true);
    ASSERT_TRUE(writePacket(transportPeer.get(), std::span<const std::uint8_t>{packet}));
    std::uint32_t statusId = 104;
    const rapidjson::Document status = waitForVpnTunPacketsSeen(harness, 1, statusId);

    ASSERT_TRUE(status["ok"].GetBool());
    EXPECT_EQ(status["result"]["forwardedPackets"].GetUint64(), 0U);
    EXPECT_EQ(status["result"]["droppedPackets"].GetUint64(), 1U);
    EXPECT_EQ(status["result"]["transportReturnPackets"].GetUint64(), 1U);
    EXPECT_EQ(status["result"]["transportSucceededPackets"].GetUint64(), 0U);
    EXPECT_EQ(status["result"]["uidUnknownFallbackPackets"].GetUint64(), 1U);
    EXPECT_STREQ(status["result"]["lastObservedDirection"].GetString(), "transport-return");
    EXPECT_STREQ(status["result"]["lastObservedResult"].GetString(), "FlowDropped");
    EXPECT_TRUE(readPacketFromFdWithDeadline(
                    tunPeer.get(), std::chrono::milliseconds{100})
                    .empty());
}

TEST(ControlServerContract, RealVpnTunRuntimeControlL4DropBlocksTransportReturnRelay) {
    Tun::VpnTunFdRuntime runtime{-1, true};
    ASSERT_TRUE(runtime.start());
    ControlServerHarness harness(runtime);

    int tunFds[2]{-1, -1};
    int transportFds[2]{-1, -1};
    makePacketSocketPair(tunFds);
    makePacketSocketPair(transportFds);
    UniqueFd tunRuntime{tunFds[0]};
    UniqueFd tunPeer{tunFds[1]};
    UniqueFd transportRuntime{transportFds[0]};
    UniqueFd transportPeer{transportFds[1]};

    const rapidjson::Document policy = harness.call(
        110, "POLICY.APPLY",
        R"({"revision":6903,"subjects":[{"uidKnown":false,"networkGate":{},"l4Rules":[{"ruleId":6903,"reasonId":6903,"priority":0,"order":0,"action":"drop","match":{"family":"ipv4","direction":"input","ipProtocol":6,"destinationPorts":{"first":40000,"last":40000}}}]}]})");
    ASSERT_TRUE(policy["ok"].GetBool());
    EXPECT_EQ(policy["result"]["revision"].GetUint64(), 6903U);
    EXPECT_EQ(policy["result"]["l4RuleCount"].GetUint64(), 1U);

    const rapidjson::Document l4Eval = harness.call(
        111, "POLICY.EVALUATE",
        R"({"uidKnown":false,"networkContext":0,"family":"ipv4","direction":"input","ipProtocol":6,"sourcePort":443,"destinationPort":40000,"portsAvailable":true})");
    ASSERT_TRUE(l4Eval["ok"].GetBool());
    EXPECT_STREQ(l4Eval["result"]["verdict"].GetString(), "DROP");
    EXPECT_STREQ(l4Eval["result"]["stage"].GetString(), "L4");
    EXPECT_EQ(l4Eval["result"]["reasonId"].GetUint(), 6903U);
    EXPECT_EQ(l4Eval["result"]["ruleId"].GetUint64(), 6903U);

    ASSERT_TRUE(harness.callWithFd(
                    112, "VPN_TUN.ATTACH", "{\"enableIpv6\":true}", tunRuntime.get())["ok"]
                    .GetBool());
    tunRuntime.reset();
    ASSERT_TRUE(harness.callWithFd(
                    113, "VPN_TRANSPORT.ATTACH", "{}", transportRuntime.get())["ok"]
                    .GetBool());
    transportRuntime.reset();

    for (int attempt = 0; attempt < 50 && !runtime.packetAdapterReady(); ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds{2});
    }
    ASSERT_TRUE(runtime.packetAdapterReady());

    const auto packet = ipv4TcpPacket(true);
    ASSERT_TRUE(writePacket(transportPeer.get(), std::span<const std::uint8_t>{packet}));
    std::uint32_t statusId = 114;
    const rapidjson::Document status = waitForVpnTunPacketsSeen(harness, 1, statusId);

    ASSERT_TRUE(status["ok"].GetBool());
    EXPECT_EQ(status["result"]["forwardedPackets"].GetUint64(), 0U);
    EXPECT_EQ(status["result"]["droppedPackets"].GetUint64(), 1U);
    EXPECT_EQ(status["result"]["transportReturnPackets"].GetUint64(), 1U);
    EXPECT_EQ(status["result"]["transportSucceededPackets"].GetUint64(), 0U);
    EXPECT_EQ(status["result"]["uidUnknownFallbackPackets"].GetUint64(), 1U);
    EXPECT_STREQ(status["result"]["lastObservedDirection"].GetString(), "transport-return");
    EXPECT_STREQ(status["result"]["lastObservedResult"].GetString(), "FlowDropped");
    EXPECT_TRUE(readPacketFromFdWithDeadline(
                    tunPeer.get(), std::chrono::milliseconds{100})
                    .empty());
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
    runtime.nfqueueCounters.queueCapacity = 64;
    runtime.nfqueueCounters.queueHighWatermark = 4;
    runtime.nfqueueCounters.queueCompletionCapacity = 64;
    runtime.nfqueueCounters.queueCompletionHighWatermark = 7;
    runtime.nfqueueCounters.flowTableEntries = 9;
    runtime.nfqueueCounters.flowTableCapacity = 64;
    runtime.nfqueueCounters.flowTableHighWatermark = 12;
    runtime.nfqueueCounters.flowTableCapacityMisses = 2;
    runtime.nfqueueCounters.lpiProvider = Protocol::LpiProviderStatus{
        .available = true,
        .providerName = "fake-lpi",
        .counters = Protocol::LpiProviderCounters{
            .packetsObserved = 14,
            .payloadEligiblePackets = 11,
            .terminalSkippedPackets = 1,
            .providerUnavailablePackets = 0,
            .packetsSubmittedToProvider = 10,
            .providerNoResultPackets = 6,
            .providerFactPackets = 4,
        },
    };
    runtime.nfqueueCounters.uidMetadataPresentPackets = 9;
    runtime.nfqueueCounters.uidMetadataMissingPackets = 10;
    runtime.nfqueueCounters.lastObservedLinuxUid = 12546;
    runtime.nfqueueCounters.lastObservedUidKnown = true;
    runtime.nfqueueCounters.lastObservedNetworkContext = 7;
    runtime.nfqueueCounters.lastObservedHook = 3;
    runtime.nfqueueCounters.lastObservedInputInterfaceIndex = 11;
    runtime.nfqueueCounters.lastObservedOutputInterfaceIndex = 22;
    runtime.nfqueueCounters.lastObservedResult = "FlowAccepted";
    runtime.nfqueueCounters.policyDropActivity.record(
        Policy::PacketPolicyDecision::drop(
            17, 42, 7, Policy::PacketPolicyStage::NetworkGate),
        12546, true, 7);
    runtime.nfqueueCounters.allowedFlowActivity.record(
        Flow::PacketFacts{
            .source = Flow::IpAddress::v4({10, 0, 0, 1}),
            .destination = Flow::IpAddress::v4({192, 0, 2, 1}),
            .ipProtocol = 6,
            .sourcePort = 40000,
            .destinationPort = 443,
            .portsAvailable = true,
            .parseStatus = Flow::ParseStatus::Ready,
            .deviceDirection = Flow::DevicePacketDirection::Output,
            .originalLength = 1500,
            .boundedPrefixLength = 40,
            .domain = Flow::FlowDomain{
                .linuxUid = 12546,
                .uidKnown = true,
                .networkContext = 7,
            },
        },
        Flow::FlowEntryObservation{
            .relativeDirection = Flow::FlowRelativeDirection::Orig,
            .flowOriginDir = Flow::DevicePacketDirection::Output,
            .created = true,
            .linuxUid = 12546,
            .uidKnown = true,
            .decisionStateValid = true,
            .policyRevision = 11,
            .packets = 3,
            .bytes = 4500,
            .lpiRecognition = Flow::LpiRecognitionState{
                .payloadPacketsSubmitted = 4,
                .terminalState = Flow::LpiRecognitionTerminalState::Done,
                .mappedResults = {
                    Flow::LpiRecognitionResult{
                        .protocolId = Catalog::ApplicationProtocolId::HTTP,
                        .firstPayloadPacketSequence = 1,
                        .direction = Flow::FlowRelativeDirection::Orig,
                    },
                    Flow::LpiRecognitionResult{
                        .protocolId = Catalog::ApplicationProtocolId::QUIC,
                        .firstPayloadPacketSequence = 4,
                        .direction = Flow::FlowRelativeDirection::Reply,
                    },
                },
            },
        });
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
    EXPECT_EQ(result["queueCapacity"].GetUint64(), 64U);
    EXPECT_EQ(result["queueHighWatermark"].GetUint64(), 4U);
    EXPECT_EQ(result["queueCompletionCapacity"].GetUint64(), 64U);
    EXPECT_EQ(result["queueCompletionHighWatermark"].GetUint64(), 7U);
    EXPECT_EQ(result["flowTableEntries"].GetUint64(), 9U);
    EXPECT_EQ(result["flowTableCapacity"].GetUint64(), 64U);
    EXPECT_EQ(result["flowTableHighWatermark"].GetUint64(), 12U);
    EXPECT_EQ(result["flowTableCapacityMisses"].GetUint64(), 2U);
    ASSERT_TRUE(result["lpiProvider"].IsObject());
    const auto &lpiProvider = result["lpiProvider"];
    EXPECT_TRUE(lpiProvider["available"].GetBool());
    EXPECT_STREQ(lpiProvider["name"].GetString(), "fake-lpi");
    EXPECT_EQ(lpiProvider["packetsObserved"].GetUint64(), 14U);
    EXPECT_EQ(lpiProvider["payloadEligiblePackets"].GetUint64(), 11U);
    EXPECT_EQ(lpiProvider["terminalSkippedPackets"].GetUint64(), 1U);
    EXPECT_EQ(lpiProvider["providerUnavailablePackets"].GetUint64(), 0U);
    EXPECT_EQ(lpiProvider["packetsSubmittedToProvider"].GetUint64(), 10U);
    EXPECT_EQ(lpiProvider["providerNoResultPackets"].GetUint64(), 6U);
    EXPECT_EQ(lpiProvider["providerFactPackets"].GetUint64(), 4U);
    EXPECT_EQ(result["uidMetadataPresentPackets"].GetUint64(), 9U);
    EXPECT_EQ(result["uidMetadataMissingPackets"].GetUint64(), 10U);
    EXPECT_EQ(result["lastObservedLinuxUid"].GetUint(), 12546U);
    EXPECT_TRUE(result["lastObservedUidKnown"].GetBool());
    EXPECT_EQ(result["lastObservedNetworkContext"].GetUint(), 7U);
    EXPECT_EQ(result["lastObservedHook"].GetUint(), 3U);
    EXPECT_EQ(result["lastObservedInputInterfaceIndex"].GetUint(), 11U);
    EXPECT_EQ(result["lastObservedOutputInterfaceIndex"].GetUint(), 22U);
    EXPECT_STREQ(result["lastObservedResult"].GetString(), "FlowAccepted");
    ASSERT_TRUE(result["policyDropActivity"].IsObject());
    const auto &activity = result["policyDropActivity"];
    EXPECT_EQ(activity["capacity"].GetUint(), 8U);
    EXPECT_EQ(activity["records"].GetUint64(), 1U);
    EXPECT_EQ(activity["totalRecords"].GetUint64(), 1U);
    EXPECT_EQ(activity["evictedRecords"].GetUint64(), 0U);
    EXPECT_TRUE(activity["hasLastRecord"].GetBool());
    EXPECT_EQ(activity["lastLinuxUid"].GetUint(), 12546U);
    EXPECT_TRUE(activity["lastUidKnown"].GetBool());
    EXPECT_EQ(activity["lastNetworkContext"].GetUint(), 7U);
    EXPECT_STREQ(activity["lastStage"].GetString(), "NetworkGate");
    EXPECT_EQ(activity["lastReasonId"].GetUint(), 17U);
    EXPECT_EQ(activity["lastRuleId"].GetUint64(), 42U);
    EXPECT_EQ(activity["lastRevision"].GetUint64(), 7U);
    ASSERT_TRUE(result["allowedFlowActivity"].IsObject());
    const auto &allowed = result["allowedFlowActivity"];
    EXPECT_EQ(allowed["capacity"].GetUint(), 8U);
    EXPECT_EQ(allowed["records"].GetUint64(), 1U);
    EXPECT_EQ(allowed["totalRecords"].GetUint64(), 1U);
    EXPECT_EQ(allowed["evictedRecords"].GetUint64(), 0U);
    EXPECT_TRUE(allowed["hasLastRecord"].GetBool());
    EXPECT_STREQ(allowed["lastSourceAddress"].GetString(), "10.0.0.1");
    EXPECT_STREQ(allowed["lastDestinationAddress"].GetString(), "192.0.2.1");
    EXPECT_EQ(allowed["lastIpProtocol"].GetUint(), 6U);
    EXPECT_EQ(allowed["lastSourcePort"].GetUint(), 40000U);
    EXPECT_EQ(allowed["lastDestinationPort"].GetUint(), 443U);
    EXPECT_TRUE(allowed["lastPortsAvailable"].GetBool());
    EXPECT_STREQ(allowed["lastDeviceDirection"].GetString(), "output");
    EXPECT_STREQ(allowed["lastFlowDirection"].GetString(), "orig");
    EXPECT_EQ(allowed["lastLinuxUid"].GetUint(), 12546U);
    EXPECT_TRUE(allowed["lastUidKnown"].GetBool());
    EXPECT_EQ(allowed["lastNetworkContext"].GetUint(), 7U);
    EXPECT_EQ(allowed["lastPolicyRevision"].GetUint64(), 11U);
    EXPECT_EQ(allowed["lastPackets"].GetUint64(), 3U);
    EXPECT_EQ(allowed["lastBytes"].GetUint64(), 4500U);
    EXPECT_STREQ(allowed["lastProtocolRecognitionState"].GetString(), "identified");
    EXPECT_STREQ(allowed["lastApplicationProtocolKey"].GetString(), "quic");
    EXPECT_STREQ(allowed["lastApplicationProtocolCategory"].GetString(), "web");
    EXPECT_STREQ(allowed["lastProtocolRecognitionSequence"].GetString(),
                 "1:http:orig,4:quic:reply");
    EXPECT_EQ(allowed["lastProtocolPayloadPackets"].GetUint(), 4U);
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

TEST(ControlServerContract, VpnTunAttributionApplyIsUnsupportedWithoutRuntimeCapability) {
    FakeRuntimeControl runtime;
    ControlServerHarness harness(runtime);

    const rapidjson::Document response = harness.call(
        50, "VPN_TUN.ATTRIBUTION.APPLY",
        R"({"uidKnown":false,"networkContext":0,"family":"ipv4","direction":"output","ipProtocol":6,"sourcePort":40000,"destinationPort":443,"portsAvailable":true,"resolvedLinuxUid":20002})");

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
    runtime.vpnTunCounters.flowTableEntries = 13;
    runtime.vpnTunCounters.flowTableCapacity = 64;
    runtime.vpnTunCounters.flowTableHighWatermark = 21;
    runtime.vpnTunCounters.flowTableCapacityMisses = 3;
    runtime.vpnTunCounters.lpiProvider = Protocol::LpiProviderStatus{
        .available = false,
        .providerName = "disabled",
        .counters = Protocol::LpiProviderCounters{
            .packetsObserved = 9,
            .payloadEligiblePackets = 7,
            .terminalSkippedPackets = 2,
            .providerUnavailablePackets = 5,
            .packetsSubmittedToProvider = 0,
            .providerNoResultPackets = 0,
            .providerFactPackets = 0,
        },
    };
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
    runtime.vpnTunCounters.attributionUpdates = 11;
    runtime.vpnTunCounters.attributionMisses = 12;
    runtime.vpnTunCounters.attributionResolutions = 13;
    runtime.vpnTunCounters.lastObservedLinuxUid = 12546;
    runtime.vpnTunCounters.lastObservedUidKnown = true;
    runtime.vpnTunCounters.lastObservedNetworkContext = 7;
    runtime.vpnTunCounters.lastObservedInterfaceIndex = 9;
    runtime.vpnTunCounters.lastObservedDirection = "transport-return";
    runtime.vpnTunCounters.lastObservedResult = "FlowForwarded";
    runtime.vpnTunCounters.policyDropActivity.record(
        Policy::PacketPolicyDecision::drop(
            91, 7001, 69, Policy::PacketPolicyStage::NetworkGate),
        12546, true, 7);
    runtime.vpnTunCounters.allowedFlowActivity.record(
        Flow::PacketFacts{
            .source = Flow::IpAddress::v4({192, 0, 2, 1}),
            .destination = Flow::IpAddress::v4({10, 0, 0, 1}),
            .ipProtocol = 17,
            .sourcePort = 53,
            .destinationPort = 53000,
            .portsAvailable = true,
            .parseStatus = Flow::ParseStatus::Ready,
            .deviceDirection = Flow::DevicePacketDirection::Input,
            .originalLength = 1200,
            .boundedPrefixLength = 28,
            .domain = Flow::FlowDomain{
                .adapter = Flow::AdapterKind::VpnTun,
                .linuxUid = 12546,
                .uidKnown = true,
                .networkContext = 7,
                .runtimeProfile = 1,
                .interfaceIndex = 9,
            },
        },
        Flow::FlowEntryObservation{
            .relativeDirection = Flow::FlowRelativeDirection::Reply,
            .flowOriginDir = Flow::DevicePacketDirection::Output,
            .linuxUid = 12546,
            .uidKnown = true,
            .decisionStateValid = true,
            .policyRevision = 70,
            .packets = 2,
            .bytes = 2400,
        });
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
    EXPECT_EQ(result["flowTableEntries"].GetUint64(), 13U);
    EXPECT_EQ(result["flowTableCapacity"].GetUint64(), 64U);
    EXPECT_EQ(result["flowTableHighWatermark"].GetUint64(), 21U);
    EXPECT_EQ(result["flowTableCapacityMisses"].GetUint64(), 3U);
    ASSERT_TRUE(result["lpiProvider"].IsObject());
    const auto &lpiProvider = result["lpiProvider"];
    EXPECT_FALSE(lpiProvider["available"].GetBool());
    EXPECT_STREQ(lpiProvider["name"].GetString(), "disabled");
    EXPECT_EQ(lpiProvider["packetsObserved"].GetUint64(), 9U);
    EXPECT_EQ(lpiProvider["payloadEligiblePackets"].GetUint64(), 7U);
    EXPECT_EQ(lpiProvider["terminalSkippedPackets"].GetUint64(), 2U);
    EXPECT_EQ(lpiProvider["providerUnavailablePackets"].GetUint64(), 5U);
    EXPECT_EQ(lpiProvider["packetsSubmittedToProvider"].GetUint64(), 0U);
    EXPECT_EQ(lpiProvider["providerNoResultPackets"].GetUint64(), 0U);
    EXPECT_EQ(lpiProvider["providerFactPackets"].GetUint64(), 0U);
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
    EXPECT_EQ(result["attributionUpdates"].GetUint64(), 11U);
    EXPECT_EQ(result["attributionMisses"].GetUint64(), 12U);
    EXPECT_EQ(result["attributionResolutions"].GetUint64(), 13U);
    EXPECT_EQ(result["lastObservedLinuxUid"].GetUint(), 12546U);
    EXPECT_TRUE(result["lastObservedUidKnown"].GetBool());
    EXPECT_EQ(result["lastObservedNetworkContext"].GetUint(), 7U);
    EXPECT_EQ(result["lastObservedInterfaceIndex"].GetUint(), 9U);
    EXPECT_STREQ(result["lastObservedDirection"].GetString(), "transport-return");
    EXPECT_STREQ(result["lastObservedResult"].GetString(), "FlowForwarded");
    ASSERT_TRUE(result["policyDropActivity"].IsObject());
    const auto &activity = result["policyDropActivity"];
    EXPECT_EQ(activity["capacity"].GetUint(), 8U);
    EXPECT_EQ(activity["records"].GetUint64(), 1U);
    EXPECT_EQ(activity["totalRecords"].GetUint64(), 1U);
    EXPECT_EQ(activity["evictedRecords"].GetUint64(), 0U);
    EXPECT_TRUE(activity["hasLastRecord"].GetBool());
    EXPECT_EQ(activity["lastLinuxUid"].GetUint(), 12546U);
    EXPECT_TRUE(activity["lastUidKnown"].GetBool());
    EXPECT_EQ(activity["lastNetworkContext"].GetUint(), 7U);
    EXPECT_STREQ(activity["lastStage"].GetString(), "NetworkGate");
    EXPECT_EQ(activity["lastReasonId"].GetUint(), 91U);
    EXPECT_EQ(activity["lastRuleId"].GetUint64(), 7001U);
    EXPECT_EQ(activity["lastRevision"].GetUint64(), 69U);
    ASSERT_TRUE(result["allowedFlowActivity"].IsObject());
    const auto &allowed = result["allowedFlowActivity"];
    EXPECT_EQ(allowed["capacity"].GetUint(), 8U);
    EXPECT_EQ(allowed["records"].GetUint64(), 1U);
    EXPECT_EQ(allowed["totalRecords"].GetUint64(), 1U);
    EXPECT_EQ(allowed["evictedRecords"].GetUint64(), 0U);
    EXPECT_TRUE(allowed["hasLastRecord"].GetBool());
    EXPECT_STREQ(allowed["lastSourceAddress"].GetString(), "192.0.2.1");
    EXPECT_STREQ(allowed["lastDestinationAddress"].GetString(), "10.0.0.1");
    EXPECT_EQ(allowed["lastIpProtocol"].GetUint(), 17U);
    EXPECT_EQ(allowed["lastSourcePort"].GetUint(), 53U);
    EXPECT_EQ(allowed["lastDestinationPort"].GetUint(), 53000U);
    EXPECT_TRUE(allowed["lastPortsAvailable"].GetBool());
    EXPECT_STREQ(allowed["lastDeviceDirection"].GetString(), "input");
    EXPECT_STREQ(allowed["lastFlowDirection"].GetString(), "reply");
    EXPECT_EQ(allowed["lastLinuxUid"].GetUint(), 12546U);
    EXPECT_TRUE(allowed["lastUidKnown"].GetBool());
    EXPECT_EQ(allowed["lastNetworkContext"].GetUint(), 7U);
    EXPECT_EQ(allowed["lastPolicyRevision"].GetUint64(), 70U);
    EXPECT_EQ(allowed["lastPackets"].GetUint64(), 2U);
    EXPECT_EQ(allowed["lastBytes"].GetUint64(), 2400U);
    EXPECT_STREQ(allowed["lastProtocolRecognitionState"].GetString(), "");
    EXPECT_STREQ(allowed["lastApplicationProtocolKey"].GetString(), "");
    EXPECT_STREQ(allowed["lastApplicationProtocolCategory"].GetString(), "");
    EXPECT_STREQ(allowed["lastProtocolRecognitionSequence"].GetString(), "");
    EXPECT_EQ(allowed["lastProtocolPayloadPackets"].GetUint(), 0U);
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

TEST(ControlServerContract, PolicyApplyNetworkGateContextRulesKeepRuleAttribution) {
    FakeRuntimeControl runtime;
    runtime.policyReady = true;
    ControlServerHarness harness(runtime);

    const auto apply = harness.call(
        101, "POLICY.APPLY",
        R"({"revision":51,"subjects":[{"linuxUid":10001,"networkGate":{"rules":[{"networkContext":1,"reasonId":5101,"ruleId":51001},{"networkContext":3,"reasonId":5103,"ruleId":51003}]},"l4Rules":[{"ruleId":443,"reasonId":44,"priority":10,"order":0,"action":"drop","match":{"family":"ipv4","direction":"input","ipProtocol":6,"destinationPorts":{"first":443,"last":443}}}]}]})");
    ASSERT_TRUE(apply["ok"].GetBool());
    EXPECT_EQ(apply["result"]["networkGateRuleCount"].GetUint64(), 2U);

    const auto mobile = harness.call(
        102, "POLICY.EVALUATE",
        R"({"linuxUid":10001,"networkContext":1,"family":"ipv4","direction":"input","ipProtocol":6,"sourcePort":40000,"destinationPort":443,"portsAvailable":true})");
    ASSERT_TRUE(mobile["ok"].GetBool());
    EXPECT_STREQ(mobile["result"]["verdict"].GetString(), "DROP");
    EXPECT_STREQ(mobile["result"]["stage"].GetString(), "NetworkGate");
    EXPECT_EQ(mobile["result"]["reasonId"].GetUint(), 5101U);
    EXPECT_EQ(mobile["result"]["ruleId"].GetUint64(), 51001U);

    const auto vpn = harness.call(
        103, "POLICY.EVALUATE",
        R"({"linuxUid":10001,"networkContext":3,"family":"ipv4","direction":"input","ipProtocol":6,"sourcePort":40000,"destinationPort":443,"portsAvailable":true})");
    ASSERT_TRUE(vpn["ok"].GetBool());
    EXPECT_STREQ(vpn["result"]["stage"].GetString(), "NetworkGate");
    EXPECT_EQ(vpn["result"]["reasonId"].GetUint(), 5103U);
    EXPECT_EQ(vpn["result"]["ruleId"].GetUint64(), 51003U);

    const auto wifi = harness.call(
        104, "POLICY.EVALUATE",
        R"({"linuxUid":10001,"networkContext":2,"family":"ipv4","direction":"input","ipProtocol":6,"sourcePort":40000,"destinationPort":443,"portsAvailable":true})");
    ASSERT_TRUE(wifi["ok"].GetBool());
    EXPECT_STREQ(wifi["result"]["stage"].GetString(), "L4");
    EXPECT_EQ(wifi["result"]["ruleId"].GetUint64(), 443U);
}

TEST(ControlServerContract, PolicyApplyRejectsDuplicateNetworkGateContextRules) {
    FakeRuntimeControl runtime;
    runtime.policyReady = true;
    ControlServerHarness harness(runtime);

    const auto apply = harness.call(
        105, "POLICY.APPLY",
        R"({"revision":52,"subjects":[{"linuxUid":10001,"networkGate":{"rules":[{"networkContext":1,"reasonId":5101,"ruleId":51001},{"networkContext":1,"reasonId":5102,"ruleId":51002}]},"l4Rules":[]}]} )");
    ASSERT_FALSE(apply["ok"].GetBool());
    ASSERT_TRUE(apply.HasMember("error"));
    EXPECT_STREQ(apply["error"]["code"].GetString(), "INVALID_ARGUMENT");
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

TEST(ControlServerContract, PolicyApplyL4CidrMatchAndDefaultPassNext) {
    FakeRuntimeControl runtime;
    runtime.policyReady = true;
    ControlServerHarness harness(runtime);

    const auto apply = harness.call(
        113, "POLICY.APPLY",
        R"({"revision":52,"subjects":[{"linuxUid":10001,"networkGate":{},"l4Rules":[{"ruleId":5201,"reasonId":52,"priority":0,"order":0,"action":"drop","match":{"family":"ipv4","sourceCidr":"10.0.0.0/8","destinationCidr":"192.0.2.0/24","direction":"input","ipProtocol":6,"destinationPorts":{"first":443,"last":443}}}]}]})");
    ASSERT_TRUE(apply["ok"].GetBool());
    EXPECT_EQ(apply["result"]["l4RuleCount"].GetUint64(), 1U);

    const auto matched = harness.call(
        114, "POLICY.EVALUATE",
        R"({"linuxUid":10001,"networkContext":2,"family":"ipv4","sourceIp":"10.12.0.4","destinationIp":"192.0.2.44","direction":"input","ipProtocol":6,"sourcePort":40000,"destinationPort":443,"portsAvailable":true})");
    ASSERT_TRUE(matched["ok"].GetBool());
    EXPECT_STREQ(matched["result"]["verdict"].GetString(), "DROP");
    EXPECT_STREQ(matched["result"]["stage"].GetString(), "L4");
    EXPECT_EQ(matched["result"]["ruleId"].GetUint64(), 5201U);

    const auto defaultPass = harness.call(
        115, "POLICY.EVALUATE",
        R"({"linuxUid":10001,"networkContext":2,"family":"ipv4","sourceIp":"10.12.0.4","destinationIp":"198.51.100.44","direction":"input","ipProtocol":6,"sourcePort":40000,"destinationPort":443,"portsAvailable":true})");
    ASSERT_TRUE(defaultPass["ok"].GetBool());
    EXPECT_STREQ(defaultPass["result"]["verdict"].GetString(), "PASS_NEXT");
    EXPECT_STREQ(defaultPass["result"]["stage"].GetString(), "None");
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
