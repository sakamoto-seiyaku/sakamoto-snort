#include <Conntrack.hpp>
#include <FlowTelemetryAbi.hpp>
#include <FlowTelemetryRecords.hpp>
#include <L4ParseResult.hpp>
#include <sucre-snort.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <array>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>

FlowTelemetry flowTelemetry;

namespace {

std::array<std::byte, 4> ipv4AddrBytes(const std::uint32_t ip) noexcept {
    return {
        static_cast<std::byte>((ip >> 24) & 0xFFu),
        static_cast<std::byte>((ip >> 16) & 0xFFu),
        static_cast<std::byte>((ip >> 8) & 0xFFu),
        static_cast<std::byte>(ip & 0xFFu),
    };
}

std::array<std::byte, 16> ipv6AddrBytes(const std::array<std::uint8_t, 16> &ip) noexcept {
    std::array<std::byte, 16> out{};
    for (std::size_t i = 0; i < ip.size(); ++i) {
        out[i] = static_cast<std::byte>(ip[i]);
    }
    return out;
}

bool readFlowPayloadU64(const FlowTelemetry::OpenResult &open, const std::uint64_t ticket,
                        const std::size_t payloadOffset, std::uint64_t &outValue) {
    std::vector<std::byte> slot(static_cast<std::size_t>(open.slotBytes));
    const off_t offset =
        static_cast<off_t>((ticket % open.slotCount) * static_cast<std::uint64_t>(open.slotBytes));
    const ssize_t n = ::pread(open.sharedMemoryFd, slot.data(), slot.size(), offset);
    if (n != static_cast<ssize_t>(slot.size())) {
        return false;
    }

    const std::span<const std::byte> slotSpan(slot.data(), slot.size());
    const auto state = static_cast<FlowTelemetryAbi::SlotState>(
        FlowTelemetryAbi::readU32Le(slotSpan, FlowTelemetryAbi::kSlotOffsetState));
    if (state != FlowTelemetryAbi::SlotState::Committed) {
        return false;
    }
    const auto recordType = static_cast<FlowTelemetryAbi::RecordType>(
        FlowTelemetryAbi::readU16Le(slotSpan, FlowTelemetryAbi::kSlotOffsetRecordType));
    if (recordType != FlowTelemetryAbi::RecordType::Flow) {
        return false;
    }
    const std::uint32_t payloadSize =
        FlowTelemetryAbi::readU32Le(slotSpan, FlowTelemetryAbi::kSlotOffsetPayloadSize);
    if (payloadSize < FlowTelemetryRecords::kFlowV1Bytes ||
        payloadOffset + sizeof(std::uint64_t) > payloadSize) {
        return false;
    }

    const std::span<const std::byte> payload(
        slot.data() + FlowTelemetryAbi::kSlotHeaderBytes, payloadSize);
    outValue = FlowTelemetryAbi::readU64Le(payload, payloadOffset);
    return true;
}

bool readFlowPayload(const FlowTelemetry::OpenResult &open, const std::uint64_t ticket,
                     std::vector<std::byte> &outPayload) {
    std::vector<std::byte> slot(static_cast<std::size_t>(open.slotBytes));
    const off_t offset =
        static_cast<off_t>((ticket % open.slotCount) * static_cast<std::uint64_t>(open.slotBytes));
    const ssize_t n = ::pread(open.sharedMemoryFd, slot.data(), slot.size(), offset);
    if (n != static_cast<ssize_t>(slot.size())) {
        return false;
    }

    const std::span<const std::byte> slotSpan(slot.data(), slot.size());
    const auto state = static_cast<FlowTelemetryAbi::SlotState>(
        FlowTelemetryAbi::readU32Le(slotSpan, FlowTelemetryAbi::kSlotOffsetState));
    if (state != FlowTelemetryAbi::SlotState::Committed) {
        return false;
    }
    const auto recordType = static_cast<FlowTelemetryAbi::RecordType>(
        FlowTelemetryAbi::readU16Le(slotSpan, FlowTelemetryAbi::kSlotOffsetRecordType));
    if (recordType != FlowTelemetryAbi::RecordType::Flow) {
        return false;
    }
    const std::uint32_t payloadSize =
        FlowTelemetryAbi::readU32Le(slotSpan, FlowTelemetryAbi::kSlotOffsetPayloadSize);
    if (payloadSize < FlowTelemetryRecords::kFlowV1Bytes) {
        return false;
    }
    outPayload.assign(slot.begin() + FlowTelemetryAbi::kSlotHeaderBytes,
                      slot.begin() + FlowTelemetryAbi::kSlotHeaderBytes + payloadSize);
    return true;
}

bool writeSlotState(const FlowTelemetry::OpenResult &open, const std::uint64_t ticket,
                    const FlowTelemetryAbi::SlotState state) {
    std::array<std::byte, sizeof(std::uint32_t)> stateBytes{};
    FlowTelemetryAbi::writeU32Le(
        std::span<std::byte>(stateBytes.data(), stateBytes.size()), 0,
        static_cast<std::uint32_t>(state));
    const off_t offset = static_cast<off_t>(
        (ticket % open.slotCount) * static_cast<std::uint64_t>(open.slotBytes) +
        FlowTelemetryAbi::kSlotOffsetState);
    return ::pwrite(open.sharedMemoryFd, stateBytes.data(), stateBytes.size(), offset) ==
        static_cast<ssize_t>(stateBytes.size());
}

bool openTelemetryForConntrackTest(void *owner, const std::uint32_t slotBytes,
                                   const std::uint64_t ringDataBytes,
                                   FlowTelemetry::OpenResult &out) {
    FlowTelemetry::Config cfg{};
    cfg.slotBytes = slotBytes;
    cfg.ringDataBytes = ringDataBytes;
    cfg.packetsThreshold = 1;
    cfg.bytesThreshold = 1;
    cfg.maxExportIntervalMs = 1;

    std::string err;
    const std::unique_lock<std::shared_mutex> lock(mutexListeners);
    return flowTelemetry.open(owner, true, FlowTelemetry::Level::Flow, cfg, out, err);
}

bool openTelemetryForConntrackTest(void *owner, const std::uint32_t slotBytes,
                                   FlowTelemetry::OpenResult &out) {
    return openTelemetryForConntrackTest(owner, slotBytes, slotBytes, out);
}

bool readFlowRecordSeq(const FlowTelemetry::OpenResult &open, const std::uint64_t ticket,
                       std::uint64_t &outSeq) {
    return readFlowPayloadU64(open, ticket, FlowTelemetryRecords::kFlowV1OffsetRecordSeq, outSeq);
}

bool readFlowInstanceId(const FlowTelemetry::OpenResult &open, const std::uint64_t ticket,
                        std::uint64_t &outFlowInstanceId) {
    return readFlowPayloadU64(open, ticket, FlowTelemetryRecords::kFlowV1OffsetFlowInstanceId,
                              outFlowInstanceId);
}

void closeTelemetryForConntrackTest(void *owner) {
    const std::unique_lock<std::shared_mutex> lock(mutexListeners);
    flowTelemetry.close(owner);
}

Conntrack::TelemetryPacketFacts telemetryFacts(std::span<const std::byte> src,
                                               std::span<const std::byte> dst,
                                               const std::uint32_t packetBytes = 60,
                                               const FlowTelemetryRecords::FlowPacketDirection dir =
                                                   FlowTelemetryRecords::FlowPacketDirection::In,
                                               const PacketReasonId reason =
                                                   PacketReasonId::ALLOW_DEFAULT,
                                               const std::optional<std::uint32_t> &ruleId =
                                                   std::nullopt) {
    Conntrack::TelemetryPacketFacts facts{};
    facts.packetDir = dir;
    facts.verdict = reason == PacketReasonId::ALLOW_DEFAULT || reason == PacketReasonId::IP_RULE_ALLOW
        ? FlowTelemetryRecords::FlowVerdict::Allow
        : FlowTelemetryRecords::FlowVerdict::Block;
    facts.ifaceKindBit = 0;
    facts.l4Status = static_cast<std::uint8_t>(L4Status::KNOWN_L4);
    facts.uidKnown = true;
    facts.ifindexKnown = true;
    facts.portsAvailable = true;
    facts.userId = 0;
    facts.ifindex = 7;
    facts.reasonId = reason;
    facts.ruleId = ruleId;
    facts.srcAddrNet = src;
    facts.dstAddrNet = dst;
    facts.packetBytes = packetBytes;
    return facts;
}

Conntrack::TelemetryPacketFacts zeroPackedDecisionFacts(std::span<const std::byte> src,
                                                        std::span<const std::byte> dst,
                                                        const std::uint32_t packetBytes = 60) {
    Conntrack::TelemetryPacketFacts facts{};
    facts.packetDir = FlowTelemetryRecords::FlowPacketDirection::In;
    facts.verdict = FlowTelemetryRecords::FlowVerdict::Unknown;
    facts.ifaceKindBit = 0;
    facts.l4Status = static_cast<std::uint8_t>(L4Status::KNOWN_L4);
    facts.uidKnown = true;
    facts.ifindexKnown = true;
    facts.portsAvailable = true;
    facts.userId = 0;
    facts.ifindex = 7;
    facts.reasonId = PacketReasonId::IFACE_BLOCK;
    facts.srcAddrNet = src;
    facts.dstAddrNet = dst;
    facts.packetBytes = packetBytes;
    return facts;
}

} // namespace

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

TEST(ConntrackTest, FlowTelemetryRecordSeqAdvancesOnlyAfterSuccessfulConntrackExport) {
    int owner = 0;
    flowTelemetry.resetAll();

    Conntrack ct;
    Conntrack::PacketV4 pkt{};
    pkt.tsNs = 1'000'000;
    pkt.uid = 2000;
    pkt.srcIp = 0x0A000001u;
    pkt.dstIp = 0x0A000002u;
    pkt.proto = IPPROTO_TCP;
    pkt.srcPort = 12345;
    pkt.dstPort = 443;
    pkt.ipPayloadLen = 20;
    pkt.hasTcp = true;
    pkt.tcp.dataOffsetWords = 5;
    pkt.tcp.flags = TH_SYN;

    const auto src = ipv4AddrBytes(pkt.srcIp);
    const auto dst = ipv4AddrBytes(pkt.dstIp);
    FlowTelemetry::OpenResult open{};
    ASSERT_TRUE(openTelemetryForConntrackTest(&owner, FlowTelemetryAbi::kSlotBytes,
                                              FlowTelemetryAbi::kSlotBytes * 2ull, open));

    ct.observeFlowTelemetry(pkt,
                            Conntrack::Result{.state = Conntrack::CtState::NEW,
                                              .direction = Conntrack::CtDirection::ORIG},
                            flowTelemetry.hotPathFlow(),
                            telemetryFacts(std::span<const std::byte>(src.data(), src.size()),
                                           std::span<const std::byte>(dst.data(), dst.size())));

    std::uint64_t seq = 0;
    ASSERT_TRUE(readFlowRecordSeq(open, /*ticket=*/0, seq));
    EXPECT_EQ(seq, 1ull);

    std::array<std::byte, sizeof(std::uint32_t)> writingState{};
    FlowTelemetryAbi::writeU32Le(
        std::span<std::byte>(writingState.data(), writingState.size()), 0,
        static_cast<std::uint32_t>(FlowTelemetryAbi::SlotState::Writing));
    const off_t slot1StateOffset = static_cast<off_t>(
        FlowTelemetryAbi::kSlotBytes + FlowTelemetryAbi::kSlotOffsetState);
    ASSERT_EQ(::pwrite(open.sharedMemoryFd, writingState.data(), writingState.size(), slot1StateOffset),
              static_cast<ssize_t>(writingState.size()));

    pkt.tsNs += 1'000'000;
    pkt.tcp.flags = TH_ACK;
    ct.observeFlowTelemetry(pkt,
                            Conntrack::Result{.state = Conntrack::CtState::ESTABLISHED,
                                              .direction = Conntrack::CtDirection::ORIG},
                            flowTelemetry.hotPathFlow(),
                            telemetryFacts(std::span<const std::byte>(src.data(), src.size()),
                                           std::span<const std::byte>(dst.data(), dst.size())));

    const auto dropped = flowTelemetry.healthSnapshot();
    EXPECT_EQ(dropped.recordsDropped, 1ull);
    EXPECT_EQ(dropped.lastDropReason, FlowTelemetryRing::DropReason::SlotBusy);

    pkt.tsNs += 1'000'000;
    ct.observeFlowTelemetry(pkt,
                            Conntrack::Result{.state = Conntrack::CtState::ESTABLISHED,
                                              .direction = Conntrack::CtDirection::ORIG},
                            flowTelemetry.hotPathFlow(),
                            telemetryFacts(std::span<const std::byte>(src.data(), src.size()),
                                           std::span<const std::byte>(dst.data(), dst.size())));

    ASSERT_TRUE(readFlowRecordSeq(open, /*ticket=*/2, seq));
    EXPECT_EQ(seq, 2ull);

    closeTelemetryForConntrackTest(&owner);
    flowTelemetry.resetAll();
}

TEST(ConntrackTest, FlowTelemetryResourcePressureExportsResourceEvictedEndWhenFlowTableIsFull) {
    int owner = 0;
    flowTelemetry.resetAll();

    FlowTelemetry::Config cfg{};
    cfg.slotBytes = FlowTelemetryAbi::kSlotBytes;
    cfg.ringDataBytes = FlowTelemetryAbi::kSlotBytes * 4ull;
    cfg.packetsThreshold = 1;
    cfg.bytesThreshold = 1;
    cfg.maxExportIntervalMs = 1;
    cfg.maxFlowEntries = 1;

    FlowTelemetry::OpenResult open{};
    std::string err;
    {
        const std::unique_lock<std::shared_mutex> lock(mutexListeners);
        ASSERT_TRUE(flowTelemetry.open(&owner, true, FlowTelemetry::Level::Flow, cfg, open, err)) << err;
    }

    Conntrack::Options opt{};
    opt.shards = 1;
    opt.bucketsPerShard = 1;
    opt.sweepMaxBuckets = 1;
    opt.sweepMaxEntries = 8;
    Conntrack ct(opt);
    Conntrack::PacketV4 first{};
    first.tsNs = 1'000'000;
    first.uid = 2000;
    first.srcIp = 0x0A000001u;
    first.dstIp = 0x0A000002u;
    first.proto = IPPROTO_TCP;
    first.srcPort = 12345;
    first.dstPort = 443;
    first.ipPayloadLen = 20;
    first.hasTcp = true;
    first.tcp.dataOffsetWords = 5;
    first.tcp.flags = TH_SYN;

    const auto firstSrc = ipv4AddrBytes(first.srcIp);
    const auto firstDst = ipv4AddrBytes(first.dstIp);
    ct.observeFlowTelemetry(first,
                            Conntrack::Result{.state = Conntrack::CtState::NEW,
                                              .direction = Conntrack::CtDirection::ORIG},
                            flowTelemetry.hotPathFlow(),
                            telemetryFacts(std::span<const std::byte>(firstSrc.data(), firstSrc.size()),
                                           std::span<const std::byte>(firstDst.data(), firstDst.size())));

    Conntrack::PacketV4 second = first;
    second.tsNs += 1'000'000;
    second.srcIp = 0x0A000003u;
    second.srcPort = 23456;
    const auto secondSrc = ipv4AddrBytes(second.srcIp);
    const auto secondDst = ipv4AddrBytes(second.dstIp);
    ct.observeFlowTelemetry(second,
                            Conntrack::Result{.state = Conntrack::CtState::NEW,
                                              .direction = Conntrack::CtDirection::ORIG},
                            flowTelemetry.hotPathFlow(),
                            telemetryFacts(std::span<const std::byte>(secondSrc.data(), secondSrc.size()),
                                           std::span<const std::byte>(secondDst.data(), secondDst.size())));

    std::vector<std::byte> evictedPayload{};
    ASSERT_TRUE(readFlowPayload(open, /*ticket=*/1, evictedPayload));
    const std::span<const std::byte> evicted(evictedPayload.data(), evictedPayload.size());
    EXPECT_EQ(static_cast<std::uint8_t>(evicted[FlowTelemetryRecords::kFlowV1OffsetKind]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowRecordKind::End));
    EXPECT_EQ(static_cast<std::uint8_t>(evicted[FlowTelemetryRecords::kFlowV1OffsetEndReason]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowEndReason::ResourceEvicted));

    std::vector<std::byte> secondPayload{};
    ASSERT_TRUE(readFlowPayload(open, /*ticket=*/2, secondPayload));
    EXPECT_EQ(static_cast<std::uint8_t>(secondPayload[FlowTelemetryRecords::kFlowV1OffsetKind]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowRecordKind::Begin));

    closeTelemetryForConntrackTest(&owner);
    flowTelemetry.resetAll();
}

TEST(ConntrackTest, FlowTelemetryDisabledCleanupExportsEndReason) {
    int owner = 0;
    flowTelemetry.resetAll();

    Conntrack::Options opt{};
    opt.shards = 1;
    opt.bucketsPerShard = 1;
    opt.sweepMaxBuckets = 1;
    opt.sweepMaxEntries = 8;
    Conntrack ct(opt);
    FlowTelemetry::OpenResult open{};
    ASSERT_TRUE(openTelemetryForConntrackTest(&owner, FlowTelemetryAbi::kSlotBytes,
                                              FlowTelemetryAbi::kSlotBytes * 3ull, open));

    Conntrack::PacketV4 pkt{};
    pkt.tsNs = 1'000'000;
    pkt.uid = 2000;
    pkt.srcIp = 0x0A000001u;
    pkt.dstIp = 0x0A000002u;
    pkt.proto = IPPROTO_TCP;
    pkt.srcPort = 12345;
    pkt.dstPort = 443;
    pkt.ipPayloadLen = 20;
    pkt.hasTcp = true;
    pkt.tcp.dataOffsetWords = 5;
    pkt.tcp.flags = TH_SYN;

    const auto src = ipv4AddrBytes(pkt.srcIp);
    const auto dst = ipv4AddrBytes(pkt.dstIp);
    ct.observeFlowTelemetry(pkt,
                            Conntrack::Result{.state = Conntrack::CtState::NEW,
                                              .direction = Conntrack::CtDirection::ORIG},
                            flowTelemetry.hotPathFlow(),
                            telemetryFacts(std::span<const std::byte>(src.data(), src.size()),
                                           std::span<const std::byte>(dst.data(), dst.size())));

    EXPECT_EQ(ct.exportTelemetryDisabledEnds(/*nowNs=*/2'000'000), 1u);

    std::vector<std::byte> payload{};
    ASSERT_TRUE(readFlowPayload(open, /*ticket=*/1, payload));
    const std::span<const std::byte> bytes(payload.data(), payload.size());
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetKind]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowRecordKind::End));
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetEndReason]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowEndReason::TelemetryDisabled));
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetTimestampNs),
              2'000'000ull);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetLastSeenNs),
              pkt.tsNs);

    closeTelemetryForConntrackTest(&owner);
    flowTelemetry.resetAll();
}

TEST(ConntrackTest, FlowTelemetryDisabledCleanupPreservesRuleIdZeroOnEnd) {
    int owner = 0;
    flowTelemetry.resetAll();

    Conntrack::Options opt{};
    opt.shards = 1;
    opt.bucketsPerShard = 1;
    opt.sweepMaxBuckets = 1;
    opt.sweepMaxEntries = 8;
    Conntrack ct(opt);
    FlowTelemetry::OpenResult open{};
    ASSERT_TRUE(openTelemetryForConntrackTest(&owner, FlowTelemetryAbi::kSlotBytes,
                                              FlowTelemetryAbi::kSlotBytes * 3ull, open));

    Conntrack::PacketV4 pkt{};
    pkt.tsNs = 1'000'000;
    pkt.uid = 2000;
    pkt.srcIp = 0x0A000001u;
    pkt.dstIp = 0x0A000002u;
    pkt.proto = IPPROTO_TCP;
    pkt.srcPort = 12345;
    pkt.dstPort = 443;
    pkt.ipPayloadLen = 20;
    pkt.hasTcp = true;
    pkt.tcp.dataOffsetWords = 5;
    pkt.tcp.flags = TH_SYN;

    const auto src = ipv4AddrBytes(pkt.srcIp);
    const auto dst = ipv4AddrBytes(pkt.dstIp);
    ct.observeFlowTelemetry(pkt,
                            Conntrack::Result{.state = Conntrack::CtState::NEW,
                                              .direction = Conntrack::CtDirection::ORIG},
                            flowTelemetry.hotPathFlow(),
                            telemetryFacts(std::span<const std::byte>(src.data(), src.size()),
                                           std::span<const std::byte>(dst.data(), dst.size()),
                                           /*packetBytes=*/60,
                                           FlowTelemetryRecords::FlowPacketDirection::In,
                                           PacketReasonId::IP_RULE_BLOCK,
                                           std::optional<std::uint32_t>{0u}));

    std::vector<std::byte> beginPayload{};
    ASSERT_TRUE(readFlowPayload(open, /*ticket=*/0, beginPayload));
    std::span<const std::byte> begin(beginPayload.data(), beginPayload.size());
    EXPECT_NE(static_cast<std::uint8_t>(begin[FlowTelemetryRecords::kFlowV1OffsetFlags]) &
                  FlowTelemetryRecords::kFlowFlagHasRuleId,
              0u);
    EXPECT_EQ(FlowTelemetryAbi::readU32Le(begin, FlowTelemetryRecords::kFlowV1OffsetRuleId), 0u);

    EXPECT_EQ(ct.exportTelemetryDisabledEnds(/*nowNs=*/2'000'000), 1u);

    std::vector<std::byte> endPayload{};
    ASSERT_TRUE(readFlowPayload(open, /*ticket=*/1, endPayload));
    std::span<const std::byte> end(endPayload.data(), endPayload.size());
    EXPECT_EQ(static_cast<std::uint8_t>(end[FlowTelemetryRecords::kFlowV1OffsetKind]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowRecordKind::End));
    EXPECT_EQ(static_cast<std::uint8_t>(end[FlowTelemetryRecords::kFlowV1OffsetVerdict]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowVerdict::Block));
    EXPECT_EQ(static_cast<std::uint8_t>(end[FlowTelemetryRecords::kFlowV1OffsetReasonId]),
              static_cast<std::uint8_t>(PacketReasonId::IP_RULE_BLOCK));
    EXPECT_NE(static_cast<std::uint8_t>(end[FlowTelemetryRecords::kFlowV1OffsetFlags]) &
                  FlowTelemetryRecords::kFlowFlagHasRuleId,
              0u);
    EXPECT_EQ(FlowTelemetryAbi::readU32Le(end, FlowTelemetryRecords::kFlowV1OffsetRuleId), 0u);

    closeTelemetryForConntrackTest(&owner);
    flowTelemetry.resetAll();
}

TEST(ConntrackTest, FlowTelemetryDisabledCleanupStopsAtEntryBudgetWhenWritesFail) {
    int owner = 0;
    flowTelemetry.resetAll();

    FlowTelemetry::Config cfg{};
    cfg.slotBytes = FlowTelemetryAbi::kSlotBytes;
    cfg.ringDataBytes = FlowTelemetryAbi::kSlotBytes * 8ull;
    cfg.packetsThreshold = 1;
    cfg.bytesThreshold = 1;
    cfg.maxExportIntervalMs = 1;

    FlowTelemetry::OpenResult open{};
    std::string err;
    {
        const std::unique_lock<std::shared_mutex> lock(mutexListeners);
        ASSERT_TRUE(flowTelemetry.open(&owner, true, FlowTelemetry::Level::Flow, cfg, open, err)) << err;
    }

    Conntrack::Options opt{};
    opt.shards = 1;
    opt.bucketsPerShard = 1;
    opt.sweepMaxBuckets = 1;
    opt.sweepMaxEntries = 1;
    Conntrack ct(opt);

    for (std::uint32_t i = 0; i < 3; ++i) {
        Conntrack::PacketV4 pkt{};
        pkt.tsNs = 1'000'000 + i;
        pkt.uid = 2000;
        pkt.srcIp = 0x0A000001u + i;
        pkt.dstIp = 0x0A000002u;
        pkt.proto = IPPROTO_TCP;
        pkt.srcPort = static_cast<std::uint16_t>(12345u + i);
        pkt.dstPort = 443;
        pkt.ipPayloadLen = 20;
        pkt.hasTcp = true;
        pkt.tcp.dataOffsetWords = 5;
        pkt.tcp.flags = TH_SYN;

        const auto src = ipv4AddrBytes(pkt.srcIp);
        const auto dst = ipv4AddrBytes(pkt.dstIp);
        ct.observeFlowTelemetry(pkt,
                                Conntrack::Result{.state = Conntrack::CtState::NEW,
                                                  .direction = Conntrack::CtDirection::ORIG},
                                flowTelemetry.hotPathFlow(),
                                telemetryFacts(std::span<const std::byte>(src.data(), src.size()),
                                               std::span<const std::byte>(dst.data(), dst.size())));
    }

    const auto before = flowTelemetry.healthSnapshot();
    ASSERT_EQ(before.recordsWritten, 3ull);
    ASSERT_EQ(before.recordsDropped, 0ull);
    ASSERT_TRUE(writeSlotState(open, /*ticket=*/3,
                               FlowTelemetryAbi::SlotState::Writing));

    EXPECT_EQ(ct.exportTelemetryDisabledEnds(/*nowNs=*/2'000'000), 0u);

    const auto after = flowTelemetry.healthSnapshot();
    EXPECT_EQ(after.recordsWritten, before.recordsWritten);
    EXPECT_EQ(after.recordsDropped, before.recordsDropped + 1ull);
    EXPECT_EQ(after.lastDropReason, FlowTelemetryRing::DropReason::SlotBusy);

    closeTelemetryForConntrackTest(&owner);
    flowTelemetry.resetAll();
}

TEST(ConntrackTest, FlowTelemetryFlowInstanceIdIsUniqueAcrossIpv4AndIpv6) {
    int owner = 0;
    flowTelemetry.resetAll();

    Conntrack ct;
    FlowTelemetry::OpenResult open{};
    ASSERT_TRUE(openTelemetryForConntrackTest(&owner, FlowTelemetryAbi::kSlotBytes,
                                              FlowTelemetryAbi::kSlotBytes * 2ull, open));

    Conntrack::PacketV4 pkt4{};
    pkt4.tsNs = 1'000'000;
    pkt4.uid = 2000;
    pkt4.srcIp = 0x0A000001u;
    pkt4.dstIp = 0x0A000002u;
    pkt4.proto = IPPROTO_TCP;
    pkt4.srcPort = 12345;
    pkt4.dstPort = 443;
    pkt4.ipPayloadLen = 20;
    pkt4.hasTcp = true;
    pkt4.tcp.dataOffsetWords = 5;
    pkt4.tcp.flags = TH_SYN;

    const auto src4 = ipv4AddrBytes(pkt4.srcIp);
    const auto dst4 = ipv4AddrBytes(pkt4.dstIp);
    ct.observeFlowTelemetry(pkt4,
                            Conntrack::Result{.state = Conntrack::CtState::NEW,
                                              .direction = Conntrack::CtDirection::ORIG},
                            flowTelemetry.hotPathFlow(),
                            telemetryFacts(std::span<const std::byte>(src4.data(), src4.size()),
                                           std::span<const std::byte>(dst4.data(), dst4.size())));

    Conntrack::PacketV6 pkt6{};
    pkt6.tsNs = 2'000'000;
    pkt6.uid = 2000;
    pkt6.srcIp = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    pkt6.dstIp = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    pkt6.proto = IPPROTO_TCP;
    pkt6.srcPort = 23456;
    pkt6.dstPort = 443;
    pkt6.ipPayloadLen = 20;
    pkt6.hasTcp = true;
    pkt6.tcp.dataOffsetWords = 5;
    pkt6.tcp.flags = TH_SYN;

    const auto src6 = ipv6AddrBytes(pkt6.srcIp);
    const auto dst6 = ipv6AddrBytes(pkt6.dstIp);
    ct.observeFlowTelemetry(pkt6,
                            Conntrack::Result{.state = Conntrack::CtState::NEW,
                                              .direction = Conntrack::CtDirection::ORIG},
                            flowTelemetry.hotPathFlow(),
                            telemetryFacts(std::span<const std::byte>(src6.data(), src6.size()),
                                           std::span<const std::byte>(dst6.data(), dst6.size())));

    std::uint64_t id4 = 0;
    std::uint64_t id6 = 0;
    ASSERT_TRUE(readFlowInstanceId(open, /*ticket=*/0, id4));
    ASSERT_TRUE(readFlowInstanceId(open, /*ticket=*/1, id6));
    EXPECT_NE(id4, 0ull);
    EXPECT_NE(id6, 0ull);
    EXPECT_NE(id4, id6);

    closeTelemetryForConntrackTest(&owner);
    flowTelemetry.resetAll();
}

TEST(ConntrackTest, FlowTelemetryExportsRawFactsAndDirectionCounters) {
    int owner = 0;
    flowTelemetry.resetAll();

    Conntrack ct;
    FlowTelemetry::OpenResult open{};
    ASSERT_TRUE(openTelemetryForConntrackTest(&owner, FlowTelemetryAbi::kSlotBytes,
                                              FlowTelemetryAbi::kSlotBytes * 4ull, open));

    Conntrack::PacketV4 orig{};
    orig.tsNs = 1'000'000;
    orig.uid = 2000;
    orig.srcIp = 0x0A000001u;
    orig.dstIp = 0x0A000002u;
    orig.proto = IPPROTO_TCP;
    orig.srcPort = 12345;
    orig.dstPort = 443;
    orig.ipPayloadLen = 20;
    orig.hasTcp = true;
    orig.tcp.dataOffsetWords = 5;
    orig.tcp.flags = TH_SYN;
    const auto origSrc = ipv4AddrBytes(orig.srcIp);
    const auto origDst = ipv4AddrBytes(orig.dstIp);
    ct.observeFlowTelemetry(orig,
                            Conntrack::Result{.state = Conntrack::CtState::NEW,
                                              .direction = Conntrack::CtDirection::ORIG},
                            flowTelemetry.hotPathFlow(),
                            telemetryFacts(std::span<const std::byte>(origSrc.data(), origSrc.size()),
                                           std::span<const std::byte>(origDst.data(), origDst.size()),
                                           /*packetBytes=*/60,
                                           FlowTelemetryRecords::FlowPacketDirection::In));

    Conntrack::PacketV4 reply = orig;
    reply.tsNs = 2'000'000;
    reply.srcIp = orig.dstIp;
    reply.dstIp = orig.srcIp;
    reply.srcPort = orig.dstPort;
    reply.dstPort = orig.srcPort;
    reply.tcp.flags = TH_ACK;
    const auto replySrc = ipv4AddrBytes(reply.srcIp);
    const auto replyDst = ipv4AddrBytes(reply.dstIp);
    ct.observeFlowTelemetry(reply,
                            Conntrack::Result{.state = Conntrack::CtState::ESTABLISHED,
                                              .direction = Conntrack::CtDirection::REPLY},
                            flowTelemetry.hotPathFlow(),
                            telemetryFacts(std::span<const std::byte>(replySrc.data(), replySrc.size()),
                                           std::span<const std::byte>(replyDst.data(), replyDst.size()),
                                           /*packetBytes=*/80,
                                           FlowTelemetryRecords::FlowPacketDirection::Out));

    std::vector<std::byte> payload{};
    ASSERT_TRUE(readFlowPayload(open, /*ticket=*/1, payload));
    const std::span<const std::byte> bytes(payload.data(), payload.size());
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetPacketDir]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowPacketDirection::Out));
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetFlowOriginDir]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowPacketDirection::In));
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetVerdict]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowVerdict::Allow));
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetFirstSeenNs),
              1'000'000ull);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetLastSeenNs),
              2'000'000ull);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetTotalPackets), 2ull);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetTotalBytes), 140ull);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetInPackets), 1ull);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetInBytes), 60ull);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetOutPackets), 1ull);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetOutBytes), 80ull);
    const std::uint8_t flags = static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetFlags]);
    EXPECT_NE(flags & FlowTelemetryRecords::kFlowFlagUidKnown, 0u);
    EXPECT_NE(flags & FlowTelemetryRecords::kFlowFlagIfindexKnown, 0u);
    EXPECT_NE(flags & FlowTelemetryRecords::kFlowFlagPortsAvailable, 0u);

    closeTelemetryForConntrackTest(&owner);
    flowTelemetry.resetAll();
}

TEST(ConntrackTest, FlowTelemetryUsesConntrackFirstSeenAndMarksMidstreamPickup) {
    int owner = 0;
    flowTelemetry.resetAll();

    Conntrack ct;
    Conntrack::PacketV4 first{};
    first.tsNs = 1'000'000;
    first.uid = 2000;
    first.srcIp = 0x0A000001u;
    first.dstIp = 0x0A000002u;
    first.proto = IPPROTO_TCP;
    first.srcPort = 12345;
    first.dstPort = 443;
    first.ipPayloadLen = 20;
    first.hasTcp = true;
    first.tcp.dataOffsetWords = 5;
    first.tcp.flags = TH_SYN;

    const auto view = ct.inspectForPolicy(first);
    ASSERT_EQ(view.result.state, Conntrack::CtState::NEW);
    ASSERT_EQ(view.result.direction, Conntrack::CtDirection::ORIG);
    ASSERT_TRUE(view.createOnAccept);
    ct.commitAccepted(first, view);

    FlowTelemetry::OpenResult open{};
    ASSERT_TRUE(openTelemetryForConntrackTest(&owner, FlowTelemetryAbi::kSlotBytes, open));

    Conntrack::PacketV4 later = first;
    later.tsNs = 2'000'000;
    later.tcp.flags = TH_ACK;
    const auto src = ipv4AddrBytes(later.srcIp);
    const auto dst = ipv4AddrBytes(later.dstIp);
    ct.observeFlowTelemetry(later,
                            Conntrack::Result{.state = Conntrack::CtState::ESTABLISHED,
                                              .direction = Conntrack::CtDirection::ORIG},
                            flowTelemetry.hotPathFlow(),
                            telemetryFacts(std::span<const std::byte>(src.data(), src.size()),
                                           std::span<const std::byte>(dst.data(), dst.size()),
                                           /*packetBytes=*/80,
                                           FlowTelemetryRecords::FlowPacketDirection::Out));

    std::vector<std::byte> payload{};
    ASSERT_TRUE(readFlowPayload(open, /*ticket=*/0, payload));
    const std::span<const std::byte> bytes(payload.data(), payload.size());
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetKind]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowRecordKind::Begin));
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetPacketDir]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowPacketDirection::Out));
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetFlowOriginDir]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowPacketDirection::Out));
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetFirstSeenNs),
              1'000'000ull);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetLastSeenNs),
              2'000'000ull);
    const std::uint8_t flags = static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetFlags]);
    EXPECT_NE(flags & FlowTelemetryRecords::kFlowFlagPickedUpMidStream, 0u);

    closeTelemetryForConntrackTest(&owner);
    flowTelemetry.resetAll();
}

TEST(ConntrackTest, FlowTelemetryLooseAckOnlyNewTcpIsPickedUpAndUsesPickupTtl) {
    int owner = 0;
    flowTelemetry.resetAll();

    FlowTelemetry::Config cfg{};
    cfg.slotBytes = FlowTelemetryAbi::kSlotBytes;
    cfg.ringDataBytes = FlowTelemetryAbi::kSlotBytes * 4ull;
    cfg.packetsThreshold = 1;
    cfg.bytesThreshold = 1;
    cfg.maxExportIntervalMs = 1;
    cfg.pickupTtlMs = 1;

    FlowTelemetry::OpenResult open{};
    std::string err;
    {
        const std::unique_lock<std::shared_mutex> lock(mutexListeners);
        ASSERT_TRUE(flowTelemetry.open(&owner, true, FlowTelemetry::Level::Flow, cfg, open, err)) << err;
    }

    Conntrack::Options opt{};
    opt.shards = 1;
    opt.bucketsPerShard = 1;
    opt.sweepMaxBuckets = 1;
    opt.sweepMaxEntries = 8;
    Conntrack ct(opt);

    Conntrack::PacketV4 ackOnly{};
    ackOnly.tsNs = 1'000'000;
    ackOnly.uid = 2000;
    ackOnly.srcIp = 0x0A000001u;
    ackOnly.dstIp = 0x0A000002u;
    ackOnly.proto = IPPROTO_TCP;
    ackOnly.srcPort = 12345;
    ackOnly.dstPort = 443;
    ackOnly.ipPayloadLen = 20;
    ackOnly.hasTcp = true;
    ackOnly.tcp.dataOffsetWords = 5;
    ackOnly.tcp.flags = TH_ACK;

    const auto ackSrc = ipv4AddrBytes(ackOnly.srcIp);
    const auto ackDst = ipv4AddrBytes(ackOnly.dstIp);
    ct.observeFlowTelemetry(ackOnly,
                            Conntrack::Result{.state = Conntrack::CtState::NEW,
                                              .direction = Conntrack::CtDirection::ORIG},
                            flowTelemetry.hotPathFlow(),
                            telemetryFacts(std::span<const std::byte>(ackSrc.data(), ackSrc.size()),
                                           std::span<const std::byte>(ackDst.data(), ackDst.size())));

    std::vector<std::byte> beginPayload{};
    ASSERT_TRUE(readFlowPayload(open, /*ticket=*/0, beginPayload));
    std::span<const std::byte> begin(beginPayload.data(), beginPayload.size());
    EXPECT_EQ(static_cast<std::uint8_t>(begin[FlowTelemetryRecords::kFlowV1OffsetKind]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowRecordKind::Begin));
    EXPECT_NE(static_cast<std::uint8_t>(begin[FlowTelemetryRecords::kFlowV1OffsetFlags]) &
                  FlowTelemetryRecords::kFlowFlagPickedUpMidStream,
              0u);

    Conntrack::PacketV4 next = ackOnly;
    next.tsNs = ackOnly.tsNs + 1'000'001;
    next.srcIp = 0x0A000003u;
    next.srcPort = 23456;
    next.tcp.flags = TH_SYN;
    const auto nextSrc = ipv4AddrBytes(next.srcIp);
    const auto nextDst = ipv4AddrBytes(next.dstIp);
    ct.observeFlowTelemetry(next,
                            Conntrack::Result{.state = Conntrack::CtState::NEW,
                                              .direction = Conntrack::CtDirection::ORIG},
                            flowTelemetry.hotPathFlow(),
                            telemetryFacts(std::span<const std::byte>(nextSrc.data(), nextSrc.size()),
                                           std::span<const std::byte>(nextDst.data(), nextDst.size())));

    std::vector<std::byte> endPayload{};
    ASSERT_TRUE(readFlowPayload(open, /*ticket=*/1, endPayload));
    std::span<const std::byte> end(endPayload.data(), endPayload.size());
    EXPECT_EQ(static_cast<std::uint8_t>(end[FlowTelemetryRecords::kFlowV1OffsetKind]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowRecordKind::End));
    EXPECT_EQ(static_cast<std::uint8_t>(end[FlowTelemetryRecords::kFlowV1OffsetEndReason]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowEndReason::IdleTimeout));
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(end, FlowTelemetryRecords::kFlowV1OffsetTimestampNs),
              next.tsNs);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(end, FlowTelemetryRecords::kFlowV1OffsetLastSeenNs),
              ackOnly.tsNs);

    closeTelemetryForConntrackTest(&owner);
    flowTelemetry.resetAll();
}

TEST(ConntrackTest, FlowTelemetryExportsIcmpDetailsWithoutPorts) {
    int owner = 0;
    flowTelemetry.resetAll();

    Conntrack ct;
    FlowTelemetry::OpenResult open{};
    ASSERT_TRUE(openTelemetryForConntrackTest(&owner, FlowTelemetryAbi::kSlotBytes, open));

    Conntrack::PacketV4 pkt{};
    pkt.tsNs = 1'000'000;
    pkt.uid = 2000;
    pkt.srcIp = 0x0A000001u;
    pkt.dstIp = 0x0A000002u;
    pkt.proto = IPPROTO_ICMP;
    pkt.ipPayloadLen = 8;
    pkt.hasIcmp = true;
    pkt.icmp.type = 8;
    pkt.icmp.code = 0;
    pkt.icmp.id = 0x1234;
    const auto src = ipv4AddrBytes(pkt.srcIp);
    const auto dst = ipv4AddrBytes(pkt.dstIp);
    auto facts = telemetryFacts(std::span<const std::byte>(src.data(), src.size()),
                                std::span<const std::byte>(dst.data(), dst.size()));
    facts.portsAvailable = false;
    facts.icmpType = pkt.icmp.type;
    facts.icmpCode = pkt.icmp.code;
    facts.icmpId = pkt.icmp.id;
    ct.observeFlowTelemetry(pkt,
                            Conntrack::Result{.state = Conntrack::CtState::NEW,
                                              .direction = Conntrack::CtDirection::ORIG},
                            flowTelemetry.hotPathFlow(), facts);

    std::vector<std::byte> payload{};
    ASSERT_TRUE(readFlowPayload(open, /*ticket=*/0, payload));
    const std::span<const std::byte> bytes(payload.data(), payload.size());
    EXPECT_EQ(FlowTelemetryAbi::readU16Le(bytes, FlowTelemetryRecords::kFlowV1OffsetSrcPort), 0u);
    EXPECT_EQ(FlowTelemetryAbi::readU16Le(bytes, FlowTelemetryRecords::kFlowV1OffsetDstPort), 0u);
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetIcmpType]), 8u);
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetIcmpCode]), 0u);
    EXPECT_EQ(FlowTelemetryAbi::readU16Le(bytes, FlowTelemetryRecords::kFlowV1OffsetIcmpId), 0x1234u);
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetFlags]) &
                  FlowTelemetryRecords::kFlowFlagPortsAvailable,
              0u);

    closeTelemetryForConntrackTest(&owner);
    flowTelemetry.resetAll();
}

TEST(ConntrackTest, FlowTelemetryExportsL3ObservationForFragmentAndInvalidL4) {
    int owner = 0;
    flowTelemetry.resetAll();

    Conntrack ct;
    FlowTelemetry::OpenResult open{};
    ASSERT_TRUE(openTelemetryForConntrackTest(&owner, FlowTelemetryAbi::kSlotBytes,
                                              FlowTelemetryAbi::kSlotBytes * 2ull, open));

    Conntrack::PacketV4 fragment{};
    fragment.tsNs = 1'000'000;
    fragment.uid = 2000;
    fragment.srcIp = 0x0A000001u;
    fragment.dstIp = 0x0A000002u;
    fragment.proto = IPPROTO_TCP;
    fragment.isFragment = true;
    fragment.ipPayloadLen = 8;
    const auto fragSrc = ipv4AddrBytes(fragment.srcIp);
    const auto fragDst = ipv4AddrBytes(fragment.dstIp);
    auto fragFacts = telemetryFacts(std::span<const std::byte>(fragSrc.data(), fragSrc.size()),
                                    std::span<const std::byte>(fragDst.data(), fragDst.size()));
    fragFacts.l4Status = static_cast<std::uint8_t>(L4Status::FRAGMENT);
    fragFacts.portsAvailable = false;
    ct.observeFlowTelemetry(fragment,
                            Conntrack::Result{.state = Conntrack::CtState::INVALID,
                                              .direction = Conntrack::CtDirection::ANY},
                            flowTelemetry.hotPathFlow(), fragFacts);

    Conntrack::PacketV4 invalid = fragment;
    invalid.tsNs = 2'000'000;
    invalid.srcIp = 0x0A000003u;
    invalid.isFragment = false;
    const auto invSrc = ipv4AddrBytes(invalid.srcIp);
    const auto invDst = ipv4AddrBytes(invalid.dstIp);
    auto invalidFacts = telemetryFacts(std::span<const std::byte>(invSrc.data(), invSrc.size()),
                                       std::span<const std::byte>(invDst.data(), invDst.size()));
    invalidFacts.l4Status = static_cast<std::uint8_t>(L4Status::INVALID_OR_UNAVAILABLE_L4);
    invalidFacts.portsAvailable = false;
    ct.observeFlowTelemetry(invalid,
                            Conntrack::Result{.state = Conntrack::CtState::INVALID,
                                              .direction = Conntrack::CtDirection::ANY},
                            flowTelemetry.hotPathFlow(), invalidFacts);

    for (std::uint64_t ticket = 0; ticket < 2; ++ticket) {
        std::vector<std::byte> payload{};
        ASSERT_TRUE(readFlowPayload(open, ticket, payload));
        const std::span<const std::byte> bytes(payload.data(), payload.size());
        EXPECT_EQ(static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetObservationKind]),
                  static_cast<std::uint8_t>(FlowTelemetryRecords::FlowObservationKind::L3Observation));
        EXPECT_EQ(FlowTelemetryAbi::readU16Le(bytes, FlowTelemetryRecords::kFlowV1OffsetSrcPort), 0u);
        EXPECT_EQ(FlowTelemetryAbi::readU16Le(bytes, FlowTelemetryRecords::kFlowV1OffsetDstPort), 0u);
        EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetTotalPackets), 1ull);
    }
    std::vector<std::byte> fragPayload{};
    ASSERT_TRUE(readFlowPayload(open, /*ticket=*/0, fragPayload));
    EXPECT_EQ(static_cast<std::uint8_t>(fragPayload[FlowTelemetryRecords::kFlowV1OffsetL4Status]),
              static_cast<std::uint8_t>(L4Status::FRAGMENT));
    std::vector<std::byte> invalidPayload{};
    ASSERT_TRUE(readFlowPayload(open, /*ticket=*/1, invalidPayload));
    EXPECT_EQ(static_cast<std::uint8_t>(invalidPayload[FlowTelemetryRecords::kFlowV1OffsetL4Status]),
              static_cast<std::uint8_t>(L4Status::INVALID_OR_UNAVAILABLE_L4));

    closeTelemetryForConntrackTest(&owner);
    flowTelemetry.resetAll();
}

TEST(ConntrackTest, FlowTelemetryExpiredFlowExportsEndWithIdleReasonAndLastSeen) {
    int owner = 0;
    flowTelemetry.resetAll();

    Conntrack::Options opt{};
    opt.shards = 1;
    opt.bucketsPerShard = 1;
    opt.sweepMaxBuckets = 1;
    opt.sweepMaxEntries = 8;
    Conntrack ct(opt);
    FlowTelemetry::OpenResult open{};
    ASSERT_TRUE(openTelemetryForConntrackTest(&owner, FlowTelemetryAbi::kSlotBytes,
                                              FlowTelemetryAbi::kSlotBytes * 4ull, open));

    Conntrack::PacketV4 first{};
    first.tsNs = 1'000'000;
    first.uid = 2000;
    first.srcIp = 0x0A000001u;
    first.dstIp = 0x0A000002u;
    first.proto = IPPROTO_TCP;
    first.srcPort = 12345;
    first.dstPort = 443;
    first.ipPayloadLen = 20;
    first.hasTcp = true;
    first.tcp.dataOffsetWords = 5;
    first.tcp.flags = TH_SYN;
    const auto firstSrc = ipv4AddrBytes(first.srcIp);
    const auto firstDst = ipv4AddrBytes(first.dstIp);
    ct.observeFlowTelemetry(first,
                            Conntrack::Result{.state = Conntrack::CtState::NEW,
                                              .direction = Conntrack::CtDirection::ORIG},
                            flowTelemetry.hotPathFlow(),
                            telemetryFacts(std::span<const std::byte>(firstSrc.data(), firstSrc.size()),
                                           std::span<const std::byte>(firstDst.data(), firstDst.size())));

    Conntrack::PacketV4 second = first;
    second.tsNs = first.tsNs + 31ull * 1'000'000'000ull;
    second.srcIp = 0x0A000003u;
    second.srcPort = 23456;
    const auto secondSrc = ipv4AddrBytes(second.srcIp);
    const auto secondDst = ipv4AddrBytes(second.dstIp);
    ct.observeFlowTelemetry(second,
                            Conntrack::Result{.state = Conntrack::CtState::NEW,
                                              .direction = Conntrack::CtDirection::ORIG},
                            flowTelemetry.hotPathFlow(),
                            telemetryFacts(std::span<const std::byte>(secondSrc.data(), secondSrc.size()),
                                           std::span<const std::byte>(secondDst.data(), secondDst.size())));

    std::vector<std::byte> payload{};
    ASSERT_TRUE(readFlowPayload(open, /*ticket=*/1, payload));
    const std::span<const std::byte> bytes(payload.data(), payload.size());
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetKind]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowRecordKind::End));
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetEndReason]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowEndReason::IdleTimeout));
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetTimestampNs),
              second.tsNs);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetFirstSeenNs),
              first.tsNs);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetLastSeenNs),
              first.tsNs);

    closeTelemetryForConntrackTest(&owner);
    flowTelemetry.resetAll();
}

TEST(ConntrackTest, FlowTelemetryIpv4IdleSweepExportsEndForZeroPackedDecisionKey) {
    int owner = 0;
    flowTelemetry.resetAll();

    Conntrack::Options opt{};
    opt.shards = 1;
    opt.bucketsPerShard = 1;
    opt.sweepMaxBuckets = 1;
    opt.sweepMaxEntries = 8;
    Conntrack ct(opt);
    FlowTelemetry::OpenResult open{};
    ASSERT_TRUE(openTelemetryForConntrackTest(&owner, FlowTelemetryAbi::kSlotBytes,
                                              FlowTelemetryAbi::kSlotBytes * 4ull, open));

    Conntrack::PacketV4 first{};
    first.tsNs = 1'000'000;
    first.uid = 2000;
    first.srcIp = 0x0A000001u;
    first.dstIp = 0x0A000002u;
    first.proto = IPPROTO_UDP;
    first.srcPort = 12345;
    first.dstPort = 53;
    first.ipPayloadLen = 8;
    const auto firstSrc = ipv4AddrBytes(first.srcIp);
    const auto firstDst = ipv4AddrBytes(first.dstIp);
    ct.observeFlowTelemetry(
        first,
        Conntrack::Result{.state = Conntrack::CtState::ANY,
                          .direction = Conntrack::CtDirection::ANY},
        flowTelemetry.hotPathFlow(),
        zeroPackedDecisionFacts(std::span<const std::byte>(firstSrc.data(), firstSrc.size()),
                                std::span<const std::byte>(firstDst.data(), firstDst.size())));

    Conntrack::PacketV4 second = first;
    second.tsNs = first.tsNs + 11ull * 1'000'000'000ull;
    second.srcIp = 0x0A000003u;
    second.srcPort = 23456;
    const auto secondSrc = ipv4AddrBytes(second.srcIp);
    const auto secondDst = ipv4AddrBytes(second.dstIp);
    ct.observeFlowTelemetry(second,
                            Conntrack::Result{.state = Conntrack::CtState::NEW,
                                              .direction = Conntrack::CtDirection::ORIG},
                            flowTelemetry.hotPathFlow(),
                            telemetryFacts(std::span<const std::byte>(secondSrc.data(), secondSrc.size()),
                                           std::span<const std::byte>(secondDst.data(), secondDst.size())));

    std::vector<std::byte> payload{};
    ASSERT_TRUE(readFlowPayload(open, /*ticket=*/1, payload));
    const std::span<const std::byte> bytes(payload.data(), payload.size());
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetKind]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowRecordKind::End));
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetEndReason]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowEndReason::IdleTimeout));
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetVerdict]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowVerdict::Unknown));
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetTimestampNs),
              second.tsNs);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetFirstSeenNs),
              first.tsNs);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetLastSeenNs),
              first.tsNs);

    closeTelemetryForConntrackTest(&owner);
    flowTelemetry.resetAll();
}

TEST(ConntrackTest, FlowTelemetryIpv6IdleSweepExportsEndForZeroPackedDecisionKey) {
    int owner = 0;
    flowTelemetry.resetAll();

    Conntrack::Options opt{};
    opt.shards = 1;
    opt.bucketsPerShard = 1;
    opt.sweepMaxBuckets = 1;
    opt.sweepMaxEntries = 8;
    Conntrack ct(opt);
    FlowTelemetry::OpenResult open{};
    ASSERT_TRUE(openTelemetryForConntrackTest(&owner, FlowTelemetryAbi::kSlotBytes,
                                              FlowTelemetryAbi::kSlotBytes * 4ull, open));

    Conntrack::PacketV6 first{};
    first.tsNs = 1'000'000;
    first.uid = 2000;
    first.srcIp[15] = 1;
    first.dstIp[15] = 2;
    first.proto = IPPROTO_UDP;
    first.srcPort = 12345;
    first.dstPort = 53;
    first.ipPayloadLen = 8;
    const auto firstSrc = ipv6AddrBytes(first.srcIp);
    const auto firstDst = ipv6AddrBytes(first.dstIp);
    ct.observeFlowTelemetry(
        first,
        Conntrack::Result{.state = Conntrack::CtState::ANY,
                          .direction = Conntrack::CtDirection::ANY},
        flowTelemetry.hotPathFlow(),
        zeroPackedDecisionFacts(std::span<const std::byte>(firstSrc.data(), firstSrc.size()),
                                std::span<const std::byte>(firstDst.data(), firstDst.size())));

    Conntrack::PacketV6 second = first;
    second.tsNs = first.tsNs + 11ull * 1'000'000'000ull;
    second.srcIp[15] = 3;
    second.srcPort = 23456;
    const auto secondSrc = ipv6AddrBytes(second.srcIp);
    const auto secondDst = ipv6AddrBytes(second.dstIp);
    ct.observeFlowTelemetry(second,
                            Conntrack::Result{.state = Conntrack::CtState::NEW,
                                              .direction = Conntrack::CtDirection::ORIG},
                            flowTelemetry.hotPathFlow(),
                            telemetryFacts(std::span<const std::byte>(secondSrc.data(), secondSrc.size()),
                                           std::span<const std::byte>(secondDst.data(), secondDst.size())));

    std::vector<std::byte> payload{};
    ASSERT_TRUE(readFlowPayload(open, /*ticket=*/1, payload));
    const std::span<const std::byte> bytes(payload.data(), payload.size());
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetKind]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowRecordKind::End));
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetEndReason]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowEndReason::IdleTimeout));
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[FlowTelemetryRecords::kFlowV1OffsetVerdict]),
              static_cast<std::uint8_t>(FlowTelemetryRecords::FlowVerdict::Unknown));
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetTimestampNs),
              second.tsNs);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetFirstSeenNs),
              first.tsNs);
    EXPECT_EQ(FlowTelemetryAbi::readU64Le(bytes, FlowTelemetryRecords::kFlowV1OffsetLastSeenNs),
              first.tsNs);

    closeTelemetryForConntrackTest(&owner);
    flowTelemetry.resetAll();
}

TEST(ConntrackTest, Ipv4FragmentsAreInvalid) {
    Conntrack ct;
    Conntrack::PacketV4 pkt{};
    pkt.isFragment = true;

    const auto r = ct.update(pkt);
    EXPECT_EQ(r.state, Conntrack::CtState::INVALID);
    EXPECT_EQ(r.direction, Conntrack::CtDirection::ANY);
}

TEST(ConntrackTest, Ipv6FragmentsAreInvalid) {
    Conntrack ct;
    Conntrack::PacketV6 pkt{};
    pkt.isFragment = true;

    const auto r = ct.update(pkt);
    EXPECT_EQ(r.state, Conntrack::CtState::INVALID);
    EXPECT_EQ(r.direction, Conntrack::CtDirection::ANY);
}

TEST(ConntrackTest, TcpNewThenReplyBecomesEstablishedIpv6) {
    Conntrack ct;

    const std::array<std::uint8_t, 16> a = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                           0,    0,    0,    0,    0, 0, 0, 1};
    const std::array<std::uint8_t, 16> b = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                           0,    0,    0,    0,    0, 0, 0, 2};

    Conntrack::PacketV6 orig{};
    orig.tsNs = 1;
    orig.uid = 1000;
    orig.srcIp = a;
    orig.dstIp = b;
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

    Conntrack::PacketV6 reply = orig;
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

TEST(ConntrackTest, Icmp6EchoRequestReplyBecomesEstablished) {
    Conntrack ct;

    const std::array<std::uint8_t, 16> a = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                           0,    0,    0,    0,    0, 0, 0, 1};
    const std::array<std::uint8_t, 16> b = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                           0,    0,    0,    0,    0, 0, 0, 2};

    Conntrack::PacketV6 req{};
    req.tsNs = 1;
    req.uid = 1000;
    req.srcIp = a;
    req.dstIp = b;
    req.proto = IPPROTO_ICMPV6;
    req.hasIcmp = true;
    req.icmp.type = 128; // echo request
    req.icmp.code = 0;
    req.icmp.id = 0xBEEF;

    auto r1 = ct.update(req);
    EXPECT_EQ(r1.state, Conntrack::CtState::NEW);
    EXPECT_EQ(r1.direction, Conntrack::CtDirection::ORIG);

    Conntrack::PacketV6 rep = req;
    rep.tsNs = 2;
    std::swap(rep.srcIp, rep.dstIp);
    rep.icmp.type = 129; // echo reply

    auto r2 = ct.update(rep);
    EXPECT_EQ(r2.state, Conntrack::CtState::ESTABLISHED);
    EXPECT_EQ(r2.direction, Conntrack::CtDirection::REPLY);
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

TEST(ConntrackConcurrencyTest, ConcurrentPreviewCommitUpdatesAndReclaimStaySafe) {
    Conntrack::Options opt{};
    opt.maxEntries = 8192;
    opt.shards = 2;
    opt.bucketsPerShard = 1;
    opt.sweepMaxBuckets = 1;
    opt.sweepMaxEntries = 128;
    opt.sweepMinIntervalMs = 0;
    Conntrack ct(opt);

    constexpr int kThreads = 4;
    constexpr int kIters = 2000;
    constexpr std::uint64_t kStepNs = 61ULL * 1000ULL * 1000ULL * 1000ULL;
    std::atomic<bool> start{false};
    std::atomic<int> invalidExisting{0};

    auto worker = [&](const int workerId) {
        while (!start.load(std::memory_order_acquire)) {
        }
        for (int i = 0; i < kIters; ++i) {
            Conntrack::PacketV4 pkt{};
            pkt.tsNs = static_cast<std::uint64_t>(i + 1) * kStepNs;
            pkt.uid = static_cast<std::uint32_t>(1000 + (workerId % 2));
            pkt.srcIp = 0x0A000001u + static_cast<std::uint32_t>(workerId);
            pkt.dstIp = 0x0A000080u + static_cast<std::uint32_t>(i % 7);
            pkt.proto = IPPROTO_UDP;
            pkt.srcPort = static_cast<std::uint16_t>(10000 + ((i + workerId * 97) % 4096));
            pkt.dstPort = static_cast<std::uint16_t>(20000 + (i % 32));

            if ((i % 3) == 0) {
                auto preview = ct.inspectForPolicy(pkt);
                if (preview.createOnAccept) {
                    ct.commitAccepted(pkt, preview);
                }
            } else if ((i % 3) == 1) {
                const auto result = ct.update(pkt);
                if (result.state == Conntrack::CtState::INVALID) {
                    invalidExisting.fetch_add(1, std::memory_order_relaxed);
                }
            } else {
                Conntrack::PacketV4 reply = pkt;
                std::swap(reply.srcIp, reply.dstIp);
                std::swap(reply.srcPort, reply.dstPort);
                (void)ct.update(reply);
            }
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back(worker, i);
    }
    start.store(true, std::memory_order_release);
    for (auto &thread : threads) {
        thread.join();
    }

    const auto metrics = ct.metricsSnapshot();
    EXPECT_LE(metrics.totalEntries, opt.maxEntries);
    EXPECT_EQ(invalidExisting.load(std::memory_order_relaxed), 0);
}

TEST(ConntrackConcurrencyTest, ResetIsSafeWhenExternalListenersMutexExcludesReaders) {
    Conntrack::Options opt{};
    opt.maxEntries = 8192;
    opt.shards = 2;
    opt.bucketsPerShard = 16;
    opt.sweepMaxBuckets = 2;
    opt.sweepMaxEntries = 64;
    opt.sweepMinIntervalMs = 0;
    Conntrack ct(opt);

    constexpr int kThreads = 4;
    constexpr int kIters = 1500;
    constexpr int kResetRounds = 64;
    std::atomic<bool> start{false};
    std::atomic<int> invalid{0};

    auto reader = [&](const int workerId) {
        while (!start.load(std::memory_order_acquire)) {
        }
        for (int i = 0; i < kIters; ++i) {
            Conntrack::PacketV4 pkt{};
            pkt.tsNs = static_cast<std::uint64_t>(i + 1);
            pkt.uid = 1000;
            pkt.srcIp = 0x0A010001u + static_cast<std::uint32_t>(workerId);
            pkt.dstIp = 0x0A020001u + static_cast<std::uint32_t>(i % 8);
            pkt.proto = IPPROTO_UDP;
            pkt.srcPort = static_cast<std::uint16_t>(12000 + ((i + workerId * 31) % 2048));
            pkt.dstPort = 443;

            const std::shared_lock<std::shared_mutex> lock(mutexListeners);
            const auto preview = ct.inspectForPolicy(pkt);
            if (preview.result.state == Conntrack::CtState::INVALID) {
                invalid.fetch_add(1, std::memory_order_relaxed);
                continue;
            }
            if (preview.createOnAccept) {
                ct.commitAccepted(pkt, preview);
            }
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back(reader, i);
    }
    start.store(true, std::memory_order_release);

    for (int i = 0; i < kResetRounds; ++i) {
        const std::unique_lock<std::shared_mutex> lock(mutexListeners);
        ct.reset();
    }

    for (auto &thread : threads) {
        thread.join();
    }

    EXPECT_EQ(invalid.load(std::memory_order_relaxed), 0);
    EXPECT_LE(ct.metricsSnapshot().totalEntries, opt.maxEntries);
}
