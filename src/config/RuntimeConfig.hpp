/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace SnortConfig {

inline constexpr const char *kControlVNextSocketName = "sucre-snort-control-vnext";
inline constexpr std::uint32_t kControlProtocolVersion = 1;
inline constexpr std::size_t kControlMaxRequestBytes = 16U * 1024U * 1024U;
inline constexpr std::size_t kControlMaxResponseBytes = 16U * 1024U * 1024U;
inline constexpr int kControlListenBacklog = 16;

} // namespace SnortConfig
