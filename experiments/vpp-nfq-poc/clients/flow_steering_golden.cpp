/* SPDX-License-Identifier: AGPL-3.0-or-later */

// Throwaway POC oracle: validate the fixed Android/C hash vector through the
// production OwnerSelector.  The coprime worker counts have an LCM larger than
// 2^64, so matching every remainder uniquely validates the 64-bit hash value.

#include <FlowSteering.hpp>

#include <array>
#include <cstdint>
#include <iostream>

using namespace SnortDatapath::Flow;

namespace {

constexpr std::uint64_t kSeed = 0x1234;
constexpr std::uint64_t kExpectedHash = 6363941064820286797ULL;
constexpr std::array<std::uint32_t, 3> kWorkerCounts{
    2U,
    4294967291U,
    4294967279U,
};

PacketFacts packet(const bool reverse) {
    PacketFacts facts{
        .source = IpAddress::v4({192, 0, 2, 1}),
        .destination = IpAddress::v4({198, 51, 100, 2}),
        .ipProtocol = 17,
        .sourcePort = 12345,
        .destinationPort = 443,
        .portsAvailable = true,
        .fragmented = false,
        .parseStatus = ParseStatus::Ready,
        .originalLength = 64,
        .boundedPrefixLength = 64,
    };
    if (reverse) {
        std::swap(facts.source, facts.destination);
        std::swap(facts.sourcePort, facts.destinationPort);
    }
    return facts;
}

} // namespace

int main() {
    const auto forward = CanonicalFlowKey::from(packet(false));
    const auto reverse = CanonicalFlowKey::from(packet(true));
    if (!forward || !reverse || *forward != *reverse) {
        std::cerr << "production canonicalization mismatch\n";
        return 1;
    }
    for (const auto workers : kWorkerCounts) {
        const OwnerSelector selector(WorkerLayout{workers, kSeed});
        const auto expected = static_cast<std::uint32_t>(kExpectedHash % workers);
        if (selector.ownerFor(*forward) != expected || selector.ownerFor(*reverse) != expected) {
            std::cerr << "production hash remainder mismatch workers=" << workers << '\n';
            return 1;
        }
    }
    std::cout << "production-golden version=1 seed=" << kSeed
              << " hash=" << kExpectedHash << " exact=1 reverse=1\n";
    return 0;
}
