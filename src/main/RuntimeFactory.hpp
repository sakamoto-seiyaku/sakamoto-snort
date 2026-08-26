/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <RuntimeControl.hpp>
#include <RuntimeFactoryPlan.hpp>

#include <memory>
#include <string_view>

namespace SnortDatapath::Tun {
class VpnHevLwipDriver;
} // namespace SnortDatapath::Tun

namespace SnortRuntime {

struct RuntimeFactoryStartOptions {
    std::string_view vpnTunFdSource;
    VpnFlowStackRuntimeBackend preferredVpnFlowStackBackend =
        VpnFlowStackRuntimeBackend::FdCompatibility;
    SnortDatapath::Tun::VpnHevLwipDriver *vpnHevLwipDriver = nullptr;
};

struct RuntimeFactoryResult {
    RuntimeFactoryPlan plan;
    std::unique_ptr<BaseRuntimeControl> runtime;
};

[[nodiscard]] RuntimeFactoryResult createStartedRuntime(
    RuntimeProfileSelection selection);
[[nodiscard]] RuntimeFactoryResult createStartedRuntime(
    RuntimeProfileSelection selection,
    const char *vpnTunFdSource);
[[nodiscard]] RuntimeFactoryResult createStartedRuntime(
    RuntimeProfileSelection selection,
    RuntimeFactoryStartOptions options);

} // namespace SnortRuntime
