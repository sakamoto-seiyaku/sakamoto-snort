/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <NfqueueTopology.hpp>

#include <cstdint>
#include <string>

namespace SnortDatapath::Nfqueue {

struct Ipv4PassThroughRuntimeConfig {
    std::string inputChain = "sucre-snort_INPUT";
    std::string outputChain = "sucre-snort_OUTPUT";
    NfqueueTopology topology = NfqueueTopology::SplitInOut;
    std::uint32_t firstQueue = 0;
    std::uint32_t queueCount = 4;
};

class Ipv4PassThroughRuntime {
public:
    explicit Ipv4PassThroughRuntime(Ipv4PassThroughRuntimeConfig config = {});

    [[nodiscard]] bool start();

private:
    Ipv4PassThroughRuntimeConfig config_;
};

} // namespace SnortDatapath::Nfqueue
