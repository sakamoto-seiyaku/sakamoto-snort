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
    RejectProfile,
    RejectVpnTunFdMissing,
};

struct RuntimeFactoryPlan {
    RuntimeFactoryAction action = RuntimeFactoryAction::RejectProfile;
    bool launchable = false;
    int exitCode = 2;
    std::string_view errorCode;
    std::string_view adapterName;
};

[[nodiscard]] RuntimeFactoryPlan planRuntimeFactory(
    RuntimeProfileSelection selection) noexcept;
[[nodiscard]] RuntimeFactoryPlan planRuntimeFactory(
    RuntimeProfileSelection selection,
    std::string_view vpnTunFdSource) noexcept;

} // namespace SnortRuntime
