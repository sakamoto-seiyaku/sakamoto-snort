/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

namespace SnortRuntime {

void installSignalHandlers();
[[nodiscard]] bool installParentDeathGuard() noexcept;
void joinParentDeathMonitor() noexcept;
void requestShutdown() noexcept;
bool shutdownRequested() noexcept;

} // namespace SnortRuntime
