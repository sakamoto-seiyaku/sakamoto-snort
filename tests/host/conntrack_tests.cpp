#include <Conntrack.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <thread>

#include <netinet/in.h>
#include <netinet/tcp.h>

TEST(ConntrackTest, TcpPayloadLenUsesDataOffset) {
    Conntrack ct;
    Conntrack::PacketV4 pkt{};
    pkt.proto = IPPROTO_TCP;
    pkt.hasTcp = true;
    pkt.ipPayloadLen = 60; // bytes after IPv4 header
    pkt.tcp.dataOffsetWords = 10; // 40-byte TCP header (20 bytes options)

    std::uint16_t payloadLen = 0;
    ASSERT_TRUE(Conntrack::computeTcpPayloadLen(pkt, payloadLen));
    EXPECT_EQ(payloadLen, 20u);

    (void)ct;
}

TEST(ConntrackTest, Ipv4FragmentsAreInvalid) {
    Conntrack ct;
    Conntrack::PacketV4 pkt{};
    pkt.isFragment = true;

    const auto r = ct.update(pkt);
    EXPECT_EQ(r.state, Conntrack::CtState::INVALID);
    EXPECT_EQ(r.direction, Conntrack::CtDirection::ANY);
}

TEST(ConntrackTest, TcpNewThenReplyBecomesEstablished) {
    Conntrack ct;

    Conntrack::PacketV4 orig{};
    orig.tsNs = 1;
    orig.uid = 1000;
    orig.srcIp = 0x01020304;
    orig.dstIp = 0x05060708;
    orig.proto = IPPROTO_TCP;
    orig.srcPort = 12345;
    orig.dstPort = 443;
    orig.ipPayloadLen = 20;
    orig.hasTcp = true;
    orig.tcp.dataOffsetWords = 5;
    orig.tcp.flags = TH_SYN;

    auto r1 = ct.update(orig);
    EXPECT_EQ(r1.state, Conntrack::CtState::NEW);
    EXPECT_EQ(r1.direction, Conntrack::CtDirection::ORIG);

    Conntrack::PacketV4 reply = orig;
    reply.tsNs = 2;
    std::swap(reply.srcIp, reply.dstIp);
    std::swap(reply.srcPort, reply.dstPort);
    reply.tcp.flags = static_cast<std::uint8_t>(TH_SYN | TH_ACK);

    auto r2 = ct.update(reply);
    EXPECT_EQ(r2.state, Conntrack::CtState::ESTABLISHED);
    EXPECT_EQ(r2.direction, Conntrack::CtDirection::REPLY);

    orig.tsNs = 3;
    orig.tcp.flags = TH_ACK;
    auto r3 = ct.update(orig);
    EXPECT_EQ(r3.state, Conntrack::CtState::ESTABLISHED);
    EXPECT_EQ(r3.direction, Conntrack::CtDirection::ORIG);
}

TEST(ConntrackTest, TcpSecondPacketIsEstablishedEvenWithoutReply) {
    Conntrack ct;

    Conntrack::PacketV4 orig{};
    orig.tsNs = 1;
    orig.uid = 1000;
    orig.srcIp = 0x01020304;
    orig.dstIp = 0x05060708;
    orig.proto = IPPROTO_TCP;
    orig.srcPort = 12345;
    orig.dstPort = 443;
    orig.ipPayloadLen = 20;
    orig.hasTcp = true;
    orig.tcp.dataOffsetWords = 5;
    orig.tcp.flags = TH_SYN;

    auto r1 = ct.update(orig);
    EXPECT_EQ(r1.state, Conntrack::CtState::NEW);

    orig.tsNs = 2;
    orig.tcp.flags = TH_SYN; // retransmit
    auto r2 = ct.update(orig);
    EXPECT_EQ(r2.state, Conntrack::CtState::ESTABLISHED);
    EXPECT_EQ(r2.direction, Conntrack::CtDirection::ORIG);
}

TEST(ConntrackTest, PolicyPreviewDoesNotCreateEntryUntilAccepted) {
    Conntrack ct;

    Conntrack::PacketV4 orig{};
    orig.tsNs = 1;
    orig.uid = 1000;
    orig.srcIp = 0x01020304;
    orig.dstIp = 0x05060708;
    orig.proto = IPPROTO_TCP;
    orig.srcPort = 12345;
    orig.dstPort = 443;
    orig.ipPayloadLen = 20;
    orig.hasTcp = true;
    orig.tcp.dataOffsetWords = 5;
    orig.tcp.flags = TH_SYN;

    auto preview1 = ct.inspectForPolicy(orig);
    EXPECT_EQ(preview1.result.state, Conntrack::CtState::NEW);
    EXPECT_EQ(preview1.result.direction, Conntrack::CtDirection::ORIG);
    EXPECT_TRUE(preview1.createOnAccept);

    orig.tsNs = 2;
    auto preview2 = ct.inspectForPolicy(orig);
    EXPECT_EQ(preview2.result.state, Conntrack::CtState::NEW);
    EXPECT_EQ(preview2.result.direction, Conntrack::CtDirection::ORIG);
    EXPECT_TRUE(preview2.createOnAccept);

    ct.commitAccepted(orig, preview2);

    orig.tsNs = 3;
    auto r3 = ct.update(orig);
    EXPECT_EQ(r3.state, Conntrack::CtState::ESTABLISHED);
    EXPECT_EQ(r3.direction, Conntrack::CtDirection::ORIG);
}

#ifdef SUCRE_SNORT_TESTING
TEST(ConntrackTest, ResetRebindsThreadEpochSlotToNewLifetime) {
    Conntrack ct;

    Conntrack::PacketV4 pkt{};
    pkt.tsNs = 1;
    pkt.uid = 1000;
    pkt.srcIp = 0x01020304;
    pkt.dstIp = 0x05060708;
    pkt.proto = IPPROTO_UDP;
    pkt.srcPort = 12345;
    pkt.dstPort = 443;

    EXPECT_EQ(ct.debugEpochUsedSlots(), 0u);
    const std::uint64_t epoch1 = ct.debugEpochInstanceId();
    ASSERT_NE(epoch1, 0u);

    (void)ct.update(pkt);
    EXPECT_EQ(ct.debugEpochUsedSlots(), 1u);

    ct.reset();

    const std::uint64_t epoch2 = ct.debugEpochInstanceId();
    EXPECT_NE(epoch2, 0u);
    EXPECT_NE(epoch2, epoch1);
    EXPECT_EQ(ct.debugEpochUsedSlots(), 0u);

    pkt.tsNs = 2;
    (void)ct.update(pkt);
    EXPECT_EQ(ct.debugEpochUsedSlots(), 1u);
}
#endif

TEST(ConntrackTest, UdpNewThenReplyBecomesEstablished) {
    Conntrack ct;

    Conntrack::PacketV4 orig{};
    orig.tsNs = 1;
    orig.uid = 1000;
    orig.srcIp = 0x0A000001;
    orig.dstIp = 0x0A000002;
    orig.proto = IPPROTO_UDP;
    orig.srcPort = 11111;
    orig.dstPort = 22222;

    auto r1 = ct.update(orig);
    EXPECT_EQ(r1.state, Conntrack::CtState::NEW);
    EXPECT_EQ(r1.direction, Conntrack::CtDirection::ORIG);

    Conntrack::PacketV4 reply = orig;
    reply.tsNs = 2;
    std::swap(reply.srcIp, reply.dstIp);
    std::swap(reply.srcPort, reply.dstPort);

    auto r2 = ct.update(reply);
    EXPECT_EQ(r2.state, Conntrack::CtState::ESTABLISHED);
    EXPECT_EQ(r2.direction, Conntrack::CtDirection::REPLY);
}

TEST(ConntrackTest, UdpSecondPacketWithoutReplyStaysNew) {
    Conntrack ct;

    Conntrack::PacketV4 orig{};
    orig.tsNs = 1;
    orig.uid = 1000;
    orig.srcIp = 0x0A000001;
    orig.dstIp = 0x0A000002;
    orig.proto = IPPROTO_UDP;
    orig.srcPort = 11111;
    orig.dstPort = 22222;

    auto r1 = ct.update(orig);
    EXPECT_EQ(r1.state, Conntrack::CtState::NEW);

    orig.tsNs = 2;
    auto r2 = ct.update(orig);
    EXPECT_EQ(r2.state, Conntrack::CtState::NEW);
    EXPECT_EQ(r2.direction, Conntrack::CtDirection::ORIG);
}

TEST(ConntrackTest, OtherProtoTransitionsToEstablishedOnReply) {
    Conntrack ct;

    Conntrack::PacketV4 orig{};
    orig.tsNs = 1;
    orig.uid = 1000;
    orig.srcIp = 0x0A000001;
    orig.dstIp = 0x0A000002;
    orig.proto = 47; // GRE (no ports)

    auto r1 = ct.update(orig);
    EXPECT_EQ(r1.state, Conntrack::CtState::NEW);
    EXPECT_EQ(r1.direction, Conntrack::CtDirection::ORIG);

    orig.tsNs = 2;
    auto r2 = ct.update(orig);
    EXPECT_EQ(r2.state, Conntrack::CtState::NEW);

    Conntrack::PacketV4 reply = orig;
    reply.tsNs = 3;
    std::swap(reply.srcIp, reply.dstIp);

    auto r3 = ct.update(reply);
    EXPECT_EQ(r3.state, Conntrack::CtState::ESTABLISHED);
    EXPECT_EQ(r3.direction, Conntrack::CtDirection::REPLY);
}

TEST(ConntrackTest, IcmpEchoRequestReplyBecomesEstablished) {
    Conntrack ct;

    Conntrack::PacketV4 req{};
    req.tsNs = 1;
    req.uid = 1000;
    req.srcIp = 0x0A000001;
    req.dstIp = 0x0A000002;
    req.proto = IPPROTO_ICMP;
    req.hasIcmp = true;
    req.icmp.type = 8;
    req.icmp.code = 0;
    req.icmp.id = 0xBEEF;

    auto r1 = ct.update(req);
    EXPECT_EQ(r1.state, Conntrack::CtState::NEW);
    EXPECT_EQ(r1.direction, Conntrack::CtDirection::ORIG);

    Conntrack::PacketV4 rep = req;
    rep.tsNs = 2;
    std::swap(rep.srcIp, rep.dstIp);
    rep.icmp.type = 0;

    auto r2 = ct.update(rep);
    EXPECT_EQ(r2.state, Conntrack::CtState::ESTABLISHED);
    EXPECT_EQ(r2.direction, Conntrack::CtDirection::REPLY);
}

TEST(ConntrackTest, UnsupportedL4InputsAreInvalid) {
    Conntrack ct;

    Conntrack::PacketV4 badTcp{};
    badTcp.tsNs = 1;
    badTcp.uid = 1000;
    badTcp.srcIp = 1;
    badTcp.dstIp = 2;
    badTcp.proto = IPPROTO_TCP;
    badTcp.srcPort = 0;
    badTcp.dstPort = 443;
    badTcp.hasTcp = true;

    auto r1 = ct.update(badTcp);
    EXPECT_EQ(r1.state, Conntrack::CtState::INVALID);
    EXPECT_EQ(r1.direction, Conntrack::CtDirection::ANY);

    Conntrack::PacketV4 badIcmp{};
    badIcmp.tsNs = 1;
    badIcmp.uid = 1000;
    badIcmp.srcIp = 1;
    badIcmp.dstIp = 2;
    badIcmp.proto = IPPROTO_ICMP;
    badIcmp.hasIcmp = true;
    badIcmp.icmp.type = 3; // Dest unreachable (error) is invalid in phase-1.
    badIcmp.icmp.code = 0;
    badIcmp.icmp.id = 0;

    auto r2 = ct.update(badIcmp);
    EXPECT_EQ(r2.state, Conntrack::CtState::INVALID);
    EXPECT_EQ(r2.direction, Conntrack::CtDirection::ANY);
}

TEST(ConntrackTest, IcmpReplyCannotCreateNewEntry) {
    Conntrack ct;

    Conntrack::PacketV4 rep{};
    rep.tsNs = 1;
    rep.uid = 1000;
    rep.srcIp = 0x0A000001;
    rep.dstIp = 0x0A000002;
    rep.proto = IPPROTO_ICMP;
    rep.hasIcmp = true;
    rep.icmp.type = 0; // echo reply
    rep.icmp.code = 0;
    rep.icmp.id = 0xBEEF;

    auto r = ct.update(rep);
    EXPECT_EQ(r.state, Conntrack::CtState::INVALID);
    EXPECT_EQ(r.direction, Conntrack::CtDirection::ANY);
}

TEST(ConntrackTest, TcpSynAckCannotCreateNewEntry) {
    Conntrack ct;

    Conntrack::PacketV4 synAck{};
    synAck.tsNs = 1;
    synAck.uid = 1000;
    synAck.srcIp = 1;
    synAck.dstIp = 2;
    synAck.proto = IPPROTO_TCP;
    synAck.srcPort = 12345;
    synAck.dstPort = 443;
    synAck.ipPayloadLen = 20;
    synAck.hasTcp = true;
    synAck.tcp.dataOffsetWords = 5;
    synAck.tcp.flags = static_cast<std::uint8_t>(TH_SYN | TH_ACK);

    auto r = ct.update(synAck);
    EXPECT_EQ(r.state, Conntrack::CtState::INVALID);
    EXPECT_EQ(r.direction, Conntrack::CtDirection::ANY);
}

TEST(ConntrackTest, TcpInvalidFlagsCannotCreateNewEntry) {
    Conntrack ct;

    Conntrack::PacketV4 bad{};
    bad.tsNs = 1;
    bad.uid = 1000;
    bad.srcIp = 1;
    bad.dstIp = 2;
    bad.proto = IPPROTO_TCP;
    bad.srcPort = 12345;
    bad.dstPort = 443;
    bad.ipPayloadLen = 20;
    bad.hasTcp = true;
    bad.tcp.dataOffsetWords = 5;
    bad.tcp.flags = TH_FIN; // FIN without ACK/RST is invalid in OVS-grade validation.

    auto r = ct.update(bad);
    EXPECT_EQ(r.state, Conntrack::CtState::INVALID);
    EXPECT_EQ(r.direction, Conntrack::CtDirection::ANY);
}

TEST(ConntrackTest, OverflowReturnsInvalid) {
    Conntrack::Options opt{};
    opt.maxEntries = 1;
    opt.shards = 1;
    opt.bucketsPerShard = 16;
    Conntrack ct(opt);

    Conntrack::PacketV4 a{};
    a.tsNs = 1;
    a.uid = 1000;
    a.srcIp = 1;
    a.dstIp = 2;
    a.proto = IPPROTO_UDP;
    a.srcPort = 10000;
    a.dstPort = 20000;
    auto r1 = ct.update(a);
    EXPECT_EQ(r1.state, Conntrack::CtState::NEW);

    Conntrack::PacketV4 b = a;
    b.tsNs = 2;
    b.srcIp = 3;
    b.dstIp = 4;
    b.srcPort = 30000;
    b.dstPort = 40000;
    auto r2 = ct.update(b);
    EXPECT_EQ(r2.state, Conntrack::CtState::INVALID);
    EXPECT_EQ(r2.direction, Conntrack::CtDirection::ANY);
}

TEST(ConntrackTest, SweepRemovesExpiredEntriesToRespectCap) {
    Conntrack::Options opt{};
    opt.maxEntries = 1;
    opt.shards = 1;
    opt.bucketsPerShard = 1; // deterministic: everything lands in bucket 0
    opt.sweepMaxBuckets = 1;
    opt.sweepMaxEntries = 16;
    opt.sweepMinIntervalMs = 0; // disable hot-path sweep throttling for the test
    Conntrack ct(opt);

    Conntrack::PacketV4 a{};
    a.tsNs = 1;
    a.uid = 1000;
    a.srcIp = 1;
    a.dstIp = 2;
    a.proto = IPPROTO_UDP;
    a.srcPort = 10000;
    a.dstPort = 20000;
    auto r1 = ct.update(a);
    EXPECT_EQ(r1.state, Conntrack::CtState::NEW);

    // udpFirst default is 60s; advance beyond expiration.
    Conntrack::PacketV4 b = a;
    b.tsNs = 61ULL * 1000ULL * 1000ULL * 1000ULL;
    b.srcIp = 3;
    b.dstIp = 4;
    b.srcPort = 30000;
    b.dstPort = 40000;

    auto r2 = ct.update(b);
    EXPECT_EQ(r2.state, Conntrack::CtState::NEW);
    EXPECT_EQ(r2.direction, Conntrack::CtDirection::ORIG);
}

TEST(ConntrackConcurrencyTest, ConcurrentBidirectionalUpdatesSameFlowAreSafe) {
    Conntrack::Options opt{};
    opt.shards = 1;
    opt.bucketsPerShard = 1;
    opt.sweepMaxBuckets = 1;
    opt.sweepMaxEntries = 64;
    opt.sweepMinIntervalMs = 0;
    Conntrack ct(opt);

    Conntrack::PacketV4 orig{};
    orig.uid = 1000;
    orig.srcIp = 0x0A000001;
    orig.dstIp = 0x0A000002;
    orig.proto = IPPROTO_UDP;
    orig.srcPort = 11111;
    orig.dstPort = 22222;
    orig.tsNs = 1;
    (void)ct.update(orig);

    Conntrack::PacketV4 reply = orig;
    std::swap(reply.srcIp, reply.dstIp);
    std::swap(reply.srcPort, reply.dstPort);

    constexpr int kIters = 50'000;
    std::atomic<bool> start{false};
    std::atomic<int> invalid{0};
    std::atomic<int> wrongDir{0};

    auto worker = [&](Conntrack::PacketV4 pkt, const bool expectReplyDir) {
        while (!start.load(std::memory_order_acquire)) {
        }
        for (int i = 0; i < kIters; ++i) {
            pkt.tsNs = static_cast<std::uint64_t>(2 + i);
            const auto r = ct.update(pkt);
            if (r.state == Conntrack::CtState::INVALID || r.direction == Conntrack::CtDirection::ANY) {
                invalid.fetch_add(1, std::memory_order_relaxed);
            }
            if (expectReplyDir && r.direction != Conntrack::CtDirection::REPLY) {
                wrongDir.fetch_add(1, std::memory_order_relaxed);
            }
            if (!expectReplyDir && r.direction != Conntrack::CtDirection::ORIG) {
                wrongDir.fetch_add(1, std::memory_order_relaxed);
            }
        }
    };

    std::thread t1(worker, orig, false);
    std::thread t2(worker, reply, true);
    start.store(true, std::memory_order_release);
    t1.join();
    t2.join();

    EXPECT_EQ(invalid.load(std::memory_order_relaxed), 0);
    EXPECT_EQ(wrongDir.load(std::memory_order_relaxed), 0);
    EXPECT_EQ(ct.update(orig).state, Conntrack::CtState::ESTABLISHED);
    EXPECT_EQ(ct.update(reply).state, Conntrack::CtState::ESTABLISHED);
}

TEST(ConntrackConcurrencyTest, ConcurrentSweepsAndReclaimsDoNotCrash) {
    Conntrack::Options opt{};
    opt.maxEntries = 256;
    opt.shards = 1;
    opt.bucketsPerShard = 1;
    opt.sweepMaxBuckets = 1;
    opt.sweepMaxEntries = 256;
    opt.sweepMinIntervalMs = 0;
    Conntrack ct(opt);

    constexpr int kIters = 5000;
    constexpr std::uint64_t kStepNs = 61ULL * 1000ULL * 1000ULL * 1000ULL;
    std::atomic<bool> start{false};

    auto gen = [&](const std::uint16_t portBase) {
        Conntrack::PacketV4 pkt{};
        pkt.uid = 1000;
        pkt.srcIp = 0x0A000001;
        pkt.dstIp = 0x0A000002;
        pkt.proto = IPPROTO_UDP;
        pkt.dstPort = 22222;
        while (!start.load(std::memory_order_acquire)) {
        }
        for (int i = 0; i < kIters; ++i) {
            pkt.tsNs = static_cast<std::uint64_t>(i) * kStepNs;
            pkt.srcPort = static_cast<std::uint16_t>(portBase + (i % 1024));
            (void)ct.update(pkt);
        }
    };

    std::thread t1(gen, 10000);
    std::thread t2(gen, 20000);
    start.store(true, std::memory_order_release);
    t1.join();
    t2.join();
}
