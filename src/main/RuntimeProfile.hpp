/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <string_view>

namespace SnortRuntime {

enum class RuntimeProfile {
    Root,
    Vpn,
};

struct RuntimeProfileSelection {
    RuntimeProfile profile = RuntimeProfile::Root;
    bool ok = false;
    std::string_view errorCode;
};

[[nodiscard]] RuntimeProfileSelection parseRuntimeProfile(std::string_view value) noexcept;
[[nodiscard]] RuntimeProfileSelection runtimeProfileFromEnv(const char *value) noexcept;
[[nodiscard]] std::string_view runtimeProfileName(RuntimeProfile profile) noexcept;

} // namespace SnortRuntime
