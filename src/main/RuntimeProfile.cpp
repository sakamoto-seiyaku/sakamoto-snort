/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <RuntimeProfile.hpp>

namespace SnortRuntime {

RuntimeProfileSelection parseRuntimeProfile(const std::string_view value) noexcept {
    if (value == "root") {
        return RuntimeProfileSelection{.profile = RuntimeProfile::Root, .ok = true};
    }
    if (value == "vpn") {
        return RuntimeProfileSelection{.profile = RuntimeProfile::Vpn, .ok = true};
    }
    return RuntimeProfileSelection{
        .profile = RuntimeProfile::Root,
        .ok = false,
        .errorCode = value.empty() ? "runtime_profile_missing" : "runtime_profile_unknown",
    };
}

RuntimeProfileSelection runtimeProfileFromEnv(const char *value) noexcept {
    if (value == nullptr || std::string_view{value}.empty()) {
        return RuntimeProfileSelection{.profile = RuntimeProfile::Root, .ok = true};
    }
    return parseRuntimeProfile(std::string_view{value});
}

std::string_view runtimeProfileName(const RuntimeProfile profile) noexcept {
    switch (profile) {
    case RuntimeProfile::Root:
        return "root";
    case RuntimeProfile::Vpn:
        return "vpn";
    }
    return "unknown";
}

} // namespace SnortRuntime
