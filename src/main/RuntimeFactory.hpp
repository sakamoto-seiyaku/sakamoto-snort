/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <RuntimeControl.hpp>
#include <RuntimeFactoryPlan.hpp>

#include <memory>

namespace SnortRuntime {

struct RuntimeFactoryResult {
    RuntimeFactoryPlan plan;
    std::unique_ptr<BaseRuntimeControl> runtime;
};

[[nodiscard]] RuntimeFactoryResult createStartedRuntime(
    RuntimeProfileSelection selection);
[[nodiscard]] RuntimeFactoryResult createStartedRuntime(
    RuntimeProfileSelection selection,
    const char *vpnTunFdSource);

} // namespace SnortRuntime
