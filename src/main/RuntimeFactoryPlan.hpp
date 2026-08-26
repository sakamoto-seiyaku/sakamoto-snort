/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <RuntimeProfile.hpp>

#include <string_view>

namespace SnortRuntime {

enum class RuntimeFactoryAction {
    CreateRootNfqueue,
    CreateVpnTunFdHandoff,
    CreateVpnTunHevLwip,
    RejectProfile,
};

enum class VpnFlowStackRuntimeBackend {
    None,
    FdCompatibility,
    HevLwipFacade,
};

struct RuntimeFactoryOptions {
    std::string_view vpnTunFdSource;
    VpnFlowStackRuntimeBackend preferredVpnFlowStackBackend =
        VpnFlowStackRuntimeBackend::FdCompatibility;
    bool vpnHevLwipDriverAvailable = false;
};

struct RuntimeFactoryPlan {
    RuntimeFactoryAction action = RuntimeFactoryAction::RejectProfile;
    bool launchable = false;
    int exitCode = 2;
    std::string_view errorCode;
    std::string_view adapterName;
    VpnFlowStackRuntimeBackend vpnFlowStackBackend =
        VpnFlowStackRuntimeBackend::None;
    bool usingCompatibilityFallback = false;
};

[[nodiscard]] RuntimeFactoryPlan planRuntimeFactory(
    RuntimeProfileSelection selection) noexcept;
[[nodiscard]] RuntimeFactoryPlan planRuntimeFactory(
    RuntimeProfileSelection selection,
    std::string_view vpnTunFdSource) noexcept;
[[nodiscard]] RuntimeFactoryPlan planRuntimeFactory(
    RuntimeProfileSelection selection,
    RuntimeFactoryOptions options) noexcept;

} // namespace SnortRuntime
