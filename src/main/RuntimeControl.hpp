/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

namespace SnortRuntime {

class BaseRuntimeControl {
public:
    virtual ~BaseRuntimeControl() = default;

    [[nodiscard]] virtual bool nfqueuePassThroughReady() const noexcept = 0;
    [[nodiscard]] virtual bool resetBaseRuntime() noexcept = 0;
};

} // namespace SnortRuntime
