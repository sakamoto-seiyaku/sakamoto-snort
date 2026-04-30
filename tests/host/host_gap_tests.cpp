#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <memory>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <vector>

#include <Activity.hpp>
#include <ActivityManager.hpp>
#include <AppManager.hpp>
#include <CmdLine.hpp>
#include <DnsRequest.hpp>
#include <HostManager.hpp>
#include <PacketManager.hpp>
#include <RulesManager.hpp>
#include <Saver.hpp>
#include <Settings.hpp>
#include <SocketIO.hpp>
#include <Streamable.hpp>
#include <Timer.hpp>

// Provide the globals normally defined in src/sucre-snort.cpp.
Settings settings;
DomainManager domManager;
RulesManager rulesManager;
AppManager appManager;
HostManager hostManager;
ActivityManager activityManager;
PacketManager pktManager;
FlowTelemetry flowTelemetry;
std::shared_mutex mutexListeners;

namespace {

std::string readAllBytes(const int fd) {
    std::string out;
    std::array<char, 4096> buf{};
    while (true) {
        const ssize_t n = ::read(fd, buf.data(), buf.size());
        if (n > 0) {
            out.append(buf.data(), static_cast<size_t>(n));
            continue;
        }
        if (n == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        break;
    }
    return out;
}

std::vector<std::string> splitNulStrings(const std::string &bytes) {
    std::vector<std::string> parts;
    std::string cur;
    cur.reserve(bytes.size());
    for (const unsigned char c : bytes) {
        if (c == '\0') {
            if (!cur.empty()) {
                parts.push_back(cur);
                cur.clear();
            }
            continue;
        }
        cur.push_back(static_cast<char>(c));
    }
    if (!cur.empty()) {
        parts.push_back(cur);
    }
    return parts;
}

std::string makeTmpPath(const std::string &stem) {
    const auto dir = std::filesystem::temp_directory_path();
    const auto pid = static_cast<long long>(::getpid());
    const auto path = dir / (stem + "_" + std::to_string(pid) + ".bin");
    return path.string();
}

class HostGapTest : public ::testing::Test {
protected:
    void SetUp() override {
        settings.reset();
        domManager.reset();
        rulesManager.reset();
        appManager.reset();
        hostManager.reset();
        pktManager.reset();
        activityManager.reset();
    }
};

TEST_F(HostGapTest, SaverRoundtripAndRemove) {
    const std::string path = makeTmpPath("sucre_snort_saver");
    std::remove(path.c_str());
    std::remove((path + ".tmp").c_str());

    Saver saver(path);
    saver.save([&] {
        saver.write<uint32_t>(123U);
        saver.write(std::string("hello"));
    });

    bool ran = false;
    Saver reader(path);
    reader.restore([&] {
        const auto val = reader.read<uint32_t>();
        std::string str;
        reader.read(str);
        EXPECT_EQ(val, 123U);
        EXPECT_EQ(str, "hello");
        ran = true;
    });
    EXPECT_TRUE(ran);

    reader.remove();
    std::ifstream in(path);
    EXPECT_FALSE(in.is_open());
}

TEST_F(HostGapTest, SaverRejectsOverlongStringPayload) {
    const std::string path = makeTmpPath("sucre_snort_saver_bad");
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    const uint32_t len = 5001; // > default max=1000
    out.write(reinterpret_cast<const char *>(&len), sizeof(len));
    out.close();

    bool ran = false;
    Saver reader(path);
    reader.restore([&] {
        std::string str;
        reader.read(str);
        ran = true;
    });
    EXPECT_FALSE(ran);

    reader.remove();
}

TEST_F(HostGapTest, TimerSetAndGetDoesNotCrash) {
    Timer::set("t1", "msg");
    Timer::get("t1", "msg");
    Timer::get("t1");
    Timer::get("missing");
    SUCCEED();
}

TEST_F(HostGapTest, SocketIOWritesTrailingNulAndPrettyFormats) {
    int fds[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    {
        SocketIO sock(fds[0]);
        std::stringstream out;
        out << "{\"a\":1,\"b\":2}";
        ASSERT_TRUE(sock.print(out, false));
    }
    if (fds[0] >= 0) {
        ::close(fds[0]);
        fds[0] = -1;
    }

    const std::string bytes = readAllBytes(fds[1]);
    ASSERT_FALSE(bytes.empty());
    EXPECT_EQ(bytes.back(), '\0');
    EXPECT_EQ(bytes.substr(0, bytes.size() - 1), "{\"a\":1,\"b\":2}");

    if (fds[1] >= 0) {
        ::close(fds[1]);
        fds[1] = -1;
    }

    int fds2[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds2), 0);

    {
        SocketIO sock(fds2[0]);
        std::stringstream out;
        out << "{\"a\":1,\"b\":2}";
        ASSERT_TRUE(sock.print(out, true));
    }
    if (fds2[0] >= 0) {
        ::close(fds2[0]);
        fds2[0] = -1;
    }

    const std::string prettyBytes = readAllBytes(fds2[1]);
    ASSERT_FALSE(prettyBytes.empty());
    EXPECT_EQ(prettyBytes.back(), '\0');
    const std::string pretty = prettyBytes.substr(0, prettyBytes.size() - 1);
    EXPECT_NE(pretty.find("\r\n"), std::string::npos);
    EXPECT_NE(pretty.find("\t"), std::string::npos);
    EXPECT_NE(pretty.find(": "), std::string::npos);

    if (fds2[1] >= 0) {
        ::close(fds2[1]);
        fds2[1] = -1;
    }
}

TEST_F(HostGapTest, DnsRequestPrintHorizonExpireAndRestore) {
    const auto domain = domManager.make("example.com");
    ASSERT_NE(domain, nullptr);

    const App::Uid uid = 42;
    appManager.install(uid, App::NamesVec{"com.example.app"});
    const auto app = appManager.find(uid);
    ASSERT_NE(app, nullptr);

    timespec now{};
    ::timespec_get(&now, TIME_UTC);
    const timespec oldTs{now.tv_sec - static_cast<std::time_t>(settings.dnsStreamMaxHorizon) - 1, 0};

    auto oldReq = std::make_shared<DnsRequest>(app, domain, Stats::GREY, false, oldTs);
    auto newReq = std::make_shared<DnsRequest>(app, domain, Stats::GREY, false, now);

    EXPECT_TRUE(oldReq->expired(newReq));
    EXPECT_FALSE(newReq->expired(oldReq));
    EXPECT_TRUE(newReq->inHorizon(10U, timespec{now.tv_sec + 1, 0}));
    EXPECT_FALSE(oldReq->inHorizon(10U, timespec{now.tv_sec, 0}));

    std::stringstream printed;
    newReq->print(printed);
    const std::string s = printed.str();
    EXPECT_NE(s.find("\"app\""), std::string::npos);
    EXPECT_NE(s.find("\"domain\""), std::string::npos);
    EXPECT_NE(s.find("example.com"), std::string::npos);

    const std::string path = makeTmpPath("sucre_snort_dnsreq");
    std::remove(path.c_str());
    std::remove((path + ".tmp").c_str());

    Saver saver(path);
    saver.save([&] { newReq->save(saver); });

    DnsRequest::Ptr restored = nullptr;
    bool restoredRan = false;
    Saver reader(path);
    reader.restore([&] {
        restored = DnsRequest::restore(reader);
        restoredRan = true;
    });
    EXPECT_TRUE(restoredRan);
    ASSERT_NE(restored, nullptr);
    std::stringstream printed2;
    restored->print(printed2);
    EXPECT_NE(printed2.str().find("com.example.app"), std::string::npos);

    reader.remove();
}

TEST_F(HostGapTest, LegacyStreamableIsFrozenNoOp) {
    const auto domain1 = domManager.make("a.example.com");
    const auto domain2 = domManager.make("b.example.com");
    ASSERT_NE(domain1, nullptr);
    ASSERT_NE(domain2, nullptr);

    auto app = std::make_shared<App>(0, "root");

    timespec now{};
    ::timespec_get(&now, TIME_UTC);

    const timespec ts1{now.tv_sec - 2000, 0};
    const timespec ts2{now.tv_sec - 1000, 0};
    auto req1 = std::make_shared<DnsRequest>(app, domain1, Stats::GREY, false, ts1);
    auto req2 = std::make_shared<DnsRequest>(app, domain2, Stats::GREY, false, ts2);

    Streamable<DnsRequest> stream;
    stream.stream(req1);
    stream.stream(req2);

    int fds[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    auto sockio = std::make_shared<SocketIO>(fds[0]);

    stream.startStream(sockio, false, /*horizon*/ 10, /*minSize*/ 1);
    sockio.reset();
    if (fds[0] >= 0) {
        ::close(fds[0]);
        fds[0] = -1;
    }

    const auto messages = splitNulStrings(readAllBytes(fds[1]));
    EXPECT_TRUE(messages.empty());

    if (fds[1] >= 0) {
        ::close(fds[1]);
        fds[1] = -1;
    }

    const timespec veryOldTs{
        now.tv_sec - static_cast<std::time_t>(settings.dnsStreamMaxHorizon) - 1, 0};
    auto veryOldReq = std::make_shared<DnsRequest>(app, domain1, Stats::GREY, false, veryOldTs);
    auto freshReq = std::make_shared<DnsRequest>(app, domain2, Stats::GREY, false, now);
    Streamable<DnsRequest> stream2;
    stream2.stream(veryOldReq);
    stream2.stream(freshReq);

    int fds2[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds2), 0);
    auto sockio2 = std::make_shared<SocketIO>(fds2[0]);
    stream2.startStream(sockio2, false, /*horizon*/ 1000, /*minSize*/ 0);
    sockio2.reset();
    if (fds2[0] >= 0) {
        ::close(fds2[0]);
        fds2[0] = -1;
    }

    const auto messages2 = splitNulStrings(readAllBytes(fds2[1]));
    EXPECT_TRUE(messages2.empty());

    if (fds2[1] >= 0) {
        ::close(fds2[1]);
        fds2[1] = -1;
    }
}

TEST_F(HostGapTest, AppManagerSupportsAnonymousUpgradeAndPerUserSnapshot) {
    const App::Uid uid0 = 123;
    const App::Uid uid1 = 100000 + 456;

    const auto anon = appManager.make(uid0);
    ASSERT_NE(anon, nullptr);
    EXPECT_TRUE(anon->isAnonymous());

    appManager.install(uid0, App::NamesVec{"u0.app"});
    const auto upgraded = appManager.findByName("u0.app", 0);
    ASSERT_EQ(upgraded, anon);
    EXPECT_FALSE(upgraded->isAnonymous());

    appManager.install(uid1, App::NamesVec{"u1.app"});
    const auto snapAll = appManager.snapshotByUid();
    const auto snapU0 = appManager.snapshotByUid(0);
    const auto snapU1 = appManager.snapshotByUid(1);

    EXPECT_EQ(snapAll.size(), 2U);
    EXPECT_EQ(snapU0.size(), 1U);
    EXPECT_EQ(snapU1.size(), 1U);
    EXPECT_EQ(snapU0[0]->userId(), 0U);
    EXPECT_EQ(snapU1[0]->userId(), 1U);

    appManager.remove(uid0, App::NamesVec{"u0.app"});
    EXPECT_EQ(appManager.find(uid0), nullptr);
}

TEST_F(HostGapTest, HostManagerMakeNoReverseDnsDeduplicatesAndResets) {
    const uint8_t raw[4] = {8, 8, 8, 8};
    const Address<IPv4> ip(raw);

    const auto h1 = hostManager.makeNoReverseDns(ip);
    const auto h2 = hostManager.makeNoReverseDns(ip);
    ASSERT_NE(h1, nullptr);
    ASSERT_EQ(h1, h2);

    std::stringstream out;
    hostManager.printHosts(out, "");
    const std::string s = out.str();
    EXPECT_NE(s.find("\"ipv4\""), std::string::npos);

    hostManager.reset();
    const auto h3 = hostManager.makeNoReverseDns(ip);
    ASSERT_NE(h3, nullptr);
    EXPECT_NE(h1, h3);
}

TEST_F(HostGapTest, PacketPrintIncludesReasonAndRuleFields) {
    const uint8_t srcRaw[4] = {127, 0, 0, 1};
    const uint8_t dstRaw[4] = {8, 8, 8, 8};
    const Address<IPv4> srcIp(srcRaw);
    const Address<IPv4> dstIp(dstRaw);

    auto host = std::make_shared<Host>();
    host->name("remote.example");

    auto app = std::make_shared<App>(0, "root");

    const timespec ts{123, 456};
    Packet<IPv4> pkt(srcIp, dstIp, host, app, /*input*/ true, /*iface*/ 0, ts, IPPROTO_TCP, 1, 2,
                     1500, /*accepted*/ true, PacketReasonId::ALLOW_DEFAULT, 123U, 456U);

    std::stringstream out;
    pkt.print(out);
    const std::string s = out.str();
    EXPECT_NE(s.find("\"ipVersion\":4"), std::string::npos);
    EXPECT_NE(s.find("\"reasonId\":\"ALLOW_DEFAULT\""), std::string::npos);
    EXPECT_NE(s.find("\"ruleId\":123"), std::string::npos);
    EXPECT_NE(s.find("\"wouldRuleId\":456"), std::string::npos);
    EXPECT_NE(s.find("\"wouldDrop\":1"), std::string::npos);
    EXPECT_NE(s.find("\"host\":\"remote.example\""), std::string::npos);
}

TEST_F(HostGapTest, PacketManagerIfaceBlockAndAllowDefaultUpdateReasonMetrics) {
    PacketManager mgr;

    const uint8_t srcRaw[4] = {10, 0, 0, 1};
    const uint8_t dstRaw[4] = {10, 0, 0, 2};
    const Address<IPv4> srcIp(srcRaw);
    const Address<IPv4> dstIp(dstRaw);
    auto host = std::make_shared<Host>();
    auto app = std::make_shared<App>(0, "root");

    timespec ts{};
    ::timespec_get(&ts, TIME_UTC);

    // IFACE_BLOCK
    app->blockIface(1);
    bool trackedSnapshot = true;
    L4ParseResult l4{};
    l4.l4Status = L4Status::KNOWN_L4;
    l4.proto = IPPROTO_TCP;
    l4.srcPort = 1;
    l4.dstPort = 2;
    l4.portsAvailable = 1;

    const bool verdictBlock = mgr.make<IPv4>(srcIp, dstIp, app, host, true, 0, ts, l4,
                                             100, /*ifaceKindBit*/ 1, /*ifaceBlockedSnapshot*/ false,
                                             /*ctPktV4*/ nullptr, /*ctPktV6*/ nullptr,
                                             /*streamEventOut*/ nullptr,
                                             /*trackedSnapshotOut*/ &trackedSnapshot);
    EXPECT_FALSE(verdictBlock);
    EXPECT_FALSE(trackedSnapshot);

    // ALLOW_DEFAULT
    app->blockIface(0);
    const bool verdictAllow = mgr.make<IPv4>(srcIp, dstIp, app, host, true, 0, ts, l4,
                                             100, /*ifaceKindBit*/ 0, /*ifaceBlockedSnapshot*/ false);
    EXPECT_TRUE(verdictAllow);

    const auto snap = mgr.reasonMetricsSnapshot();
    EXPECT_EQ(snap.reasons[static_cast<size_t>(PacketReasonId::IFACE_BLOCK)].packets, 1U);
    EXPECT_EQ(snap.reasons[static_cast<size_t>(PacketReasonId::ALLOW_DEFAULT)].packets, 1U);
}

TEST_F(HostGapTest, PacketManagerIpv6ConntrackGatingIsPerFamily) {
    PacketManager mgr;
    settings.ipRulesEnabled(true);

    const uint32_t uid = 10000;
    auto app = std::make_shared<App>(uid, "u0.app");
    auto host = std::make_shared<Host>();

    // v4 uses conntrack, v6 does not. We will evaluate an IPv6 packet and ensure
    // conntrack metrics remain unchanged (i.e. v4 mask bit MUST NOT leak to v6).
    IpRulesEngine::ApplyRule v4{};
    v4.clientRuleId = "v4";
    v4.family = IpRulesEngine::Family::IPV4;
    v4.action = IpRulesEngine::Action::ALLOW;
    v4.priority = 1;
    v4.proto = IpRulesEngine::Proto::TCP;
    v4.ctState = IpRulesEngine::CtState::NEW;

    IpRulesEngine::ApplyRule v6{};
    v6.clientRuleId = "v6";
    v6.family = IpRulesEngine::Family::IPV6;
    v6.action = IpRulesEngine::Action::ALLOW;
    v6.priority = 1;
    v6.proto = IpRulesEngine::Proto::TCP;

    ASSERT_TRUE(mgr.ipRules().replaceRulesForUid(uid, {v4, v6}).ok);

    const auto snap = mgr.ipRules().hotSnapshot();
    ASSERT_TRUE(snap.valid());
    ASSERT_NE(snap.rulesEpoch(), 0u);
    EXPECT_TRUE(snap.uidUsesCt(uid, IpRulesEngine::Family::IPV4));
    EXPECT_FALSE(snap.uidUsesCt(uid, IpRulesEngine::Family::IPV6));

    const std::array<std::uint8_t, 16> a = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                           0,    0,    0,    0,    0, 0, 0, 1};
    const std::array<std::uint8_t, 16> b = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                           0,    0,    0,    0,    0, 0, 0, 2};
    const Address<IPv6> srcIp(a.data());
    const Address<IPv6> dstIp(b.data());

    timespec ts{};
    ::timespec_get(&ts, TIME_UTC);

    L4ParseResult l4{};
    l4.l4Status = L4Status::KNOWN_L4;
    l4.proto = IPPROTO_TCP;
    l4.srcPort = 12345;
    l4.dstPort = 443;
    l4.portsAvailable = 1;

    Conntrack::PacketV6 ctPkt{};
    ctPkt.tsNs = 1;
    ctPkt.uid = uid;
    ctPkt.srcIp = a;
    ctPkt.dstIp = b;
    ctPkt.proto = IPPROTO_TCP;
    ctPkt.ipPayloadLen = 20;
    ctPkt.srcPort = 12345;
    ctPkt.dstPort = 443;
    ctPkt.hasTcp = true;
    ctPkt.tcp.dataOffsetWords = 5;
    ctPkt.tcp.flags = TH_SYN;

    const auto before = mgr.conntrackMetricsSnapshot();

    const bool verdict = mgr.make<IPv6>(srcIp, dstIp, app, host, /*input*/ true, /*iface*/ 0, ts,
                                        l4, /*len*/ 100,
                                        /*ifaceKindBit*/ 0, /*ifaceBlockedSnapshot*/ false,
                                        /*ctPktV4*/ nullptr, /*ctPktV6*/ &ctPkt);
    EXPECT_TRUE(verdict);

    const auto after = mgr.conntrackMetricsSnapshot();
    EXPECT_EQ(after.totalEntries, before.totalEntries);
    EXPECT_EQ(after.creates, before.creates);
    EXPECT_EQ(after.byFamily.ipv6.totalEntries, before.byFamily.ipv6.totalEntries);
    EXPECT_EQ(after.byFamily.ipv6.creates, before.byFamily.ipv6.creates);
}

TEST_F(HostGapTest, ActivityAndActivityManagerCurrentNoOpSemantics) {
    auto app = std::make_shared<App>(0, "root");
    Activity activity(app);
    EXPECT_FALSE(activity.expired(std::make_shared<Activity>(app)));
    activity.streamed(true);
    EXPECT_TRUE(activity.expired(std::make_shared<Activity>(app)));
    EXPECT_TRUE(activity.inHorizon(1U, timespec{0, 0}));

    int fds[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    auto sockio = std::make_shared<SocketIO>(fds[0]);

    ActivityManager mgr;
    mgr.make(app);
    mgr.startStream(sockio, false, /*horizon*/ 0, /*minSize*/ 0);
    sockio.reset();
    if (fds[0] >= 0) {
        ::close(fds[0]);
        fds[0] = -1;
    }

    const auto messages = splitNulStrings(readAllBytes(fds[1]));
    EXPECT_TRUE(messages.empty());

    if (fds[1] >= 0) {
        ::close(fds[1]);
        fds[1] = -1;
    }
}

TEST_F(HostGapTest, ActivityManagerResetReleasesTopApp) {
    ActivityManager mgr;
    auto app = std::make_shared<App>(0, "root");
    std::weak_ptr<App> weakApp = app;

    mgr.make(app);
    app.reset();
    EXPECT_FALSE(weakApp.expired());

    mgr.reset();
    EXPECT_TRUE(weakApp.expired());
}

TEST_F(HostGapTest, CmdLineExecNoCrash) {
    CmdLine cmd("/bin/true");
    cmd.exec();

    CmdLine copy(cmd);
    copy.exec();

    SUCCEED();
}

} // namespace
