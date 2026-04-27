#include <Ipv6L4Walker.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

namespace {

std::array<std::uint8_t, sizeof(tcphdr)> makeTcpHdr(const std::uint16_t srcPort,
                                                    const std::uint16_t dstPort,
                                                    const std::uint8_t doffWords) {
    tcphdr tcp{};
    tcp.source = htons(srcPort);
    tcp.dest = htons(dstPort);
    tcp.doff = doffWords;

    std::array<std::uint8_t, sizeof(tcphdr)> bytes{};
    std::memcpy(bytes.data(), &tcp, sizeof(tcp));
    return bytes;
}

} // namespace

TEST(Ipv6L4WalkerTest, SkipHopoptsThenParseTcp) {
    const auto tcp = makeTcpHdr(12345, 443, 5);

    std::array<std::uint8_t, 8 + sizeof(tcphdr)> buf{};
    // ip6_ext header: 8 bytes total when ip6e_len=0. First two bytes are nxt/len.
    buf[0] = IPPROTO_TCP; // next
    buf[1] = 0;           // (len+1)*8 => 8 bytes
    std::memcpy(buf.data() + 8, tcp.data(), tcp.size());

    const auto r = parseIpv6L4(IPPROTO_HOPOPTS, buf.data(), buf.size());
    EXPECT_EQ(r.l4Status, L4Status::KNOWN_L4);
    EXPECT_EQ(r.proto, IPPROTO_TCP);
    EXPECT_EQ(r.srcPort, 12345);
    EXPECT_EQ(r.dstPort, 443);
    EXPECT_EQ(r.portsAvailable, 1u);
}

TEST(Ipv6L4WalkerTest, FragmentClassifiesAndStops) {
    ip6_frag frag{};
    frag.ip6f_nxt = IPPROTO_TCP;

    std::array<std::uint8_t, sizeof(ip6_frag)> buf{};
    std::memcpy(buf.data(), &frag, sizeof(frag));

    const auto r = parseIpv6L4(IPPROTO_FRAGMENT, buf.data(), buf.size());
    EXPECT_EQ(r.l4Status, L4Status::FRAGMENT);
    EXPECT_EQ(r.proto, IPPROTO_TCP);
    EXPECT_EQ(r.srcPort, 0u);
    EXPECT_EQ(r.dstPort, 0u);
    EXPECT_EQ(r.portsAvailable, 0u);
}

TEST(Ipv6L4WalkerTest, OtherTerminalNoNextHeader) {
    std::array<std::uint8_t, 1> buf{};
    const auto r = parseIpv6L4(IPPROTO_NONE, buf.data(), 0);
    EXPECT_EQ(r.l4Status, L4Status::OTHER_TERMINAL);
    EXPECT_EQ(r.proto, IPPROTO_NONE);
    EXPECT_EQ(r.portsAvailable, 0u);
}

TEST(Ipv6L4WalkerTest, OtherTerminalEsp) {
    std::array<std::uint8_t, 4> buf{};
    const auto r = parseIpv6L4(IPPROTO_ESP, buf.data(), buf.size());
    EXPECT_EQ(r.l4Status, L4Status::OTHER_TERMINAL);
    EXPECT_EQ(r.proto, IPPROTO_ESP);
    EXPECT_EQ(r.portsAvailable, 0u);
}

TEST(Ipv6L4WalkerTest, BudgetExceededBecomesInvalid) {
    constexpr std::size_t kHeaders = 9; // > max 8
    const auto tcp = makeTcpHdr(1000, 2000, 5);

    std::array<std::uint8_t, kHeaders * 8 + sizeof(tcphdr)> buf{};
    for (std::size_t i = 0; i < kHeaders; ++i) {
        const std::size_t off = i * 8;
        const std::uint8_t nxt = (i + 1 == kHeaders) ? static_cast<std::uint8_t>(IPPROTO_TCP)
                                                      : static_cast<std::uint8_t>(IPPROTO_HOPOPTS);
        buf[off + 0] = nxt; // ip6e_nxt
        buf[off + 1] = 0;   // 8 bytes
    }
    std::memcpy(buf.data() + kHeaders * 8, tcp.data(), tcp.size());

    const auto r = parseIpv6L4(IPPROTO_HOPOPTS, buf.data(), buf.size());
    EXPECT_EQ(r.l4Status, L4Status::INVALID_OR_UNAVAILABLE_L4);
    EXPECT_EQ(r.proto, IPPROTO_TCP);
    EXPECT_EQ(r.portsAvailable, 0u);
}

TEST(Ipv6L4WalkerTest, MalformedTcpMapsToInvalid) {
    auto tcp = makeTcpHdr(1, 2, 4); // doff < 5 -> invalid

    const auto r = parseIpv6L4(IPPROTO_TCP, tcp.data(), tcp.size());
    EXPECT_EQ(r.l4Status, L4Status::INVALID_OR_UNAVAILABLE_L4);
    EXPECT_EQ(r.proto, IPPROTO_TCP);
    EXPECT_EQ(r.portsAvailable, 0u);
}
