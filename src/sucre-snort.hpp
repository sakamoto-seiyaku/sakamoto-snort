/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <android-base/logging.h>
#include <cstdint>
#include <iomanip>
#include <map>
#include <shared_mutex>

#define JSS(s) "\"" << s << "\""
#define JSF(s) JSS(s) << ":"
#define JSB(b) (b ? 1 : 0)

#define when(first, stm)                                                                           \
    if (first) {                                                                                   \
        first = false;                                                                             \
    } else {                                                                                       \
        stm;                                                                                       \
    }

// Removed custom injection of std::shared_lock<std::shared_mutex> to avoid undefined behavior.

extern std::shared_mutex mutexListeners;

std::uint64_t snortResetEpoch() noexcept;
bool snortResetEpochIsStable(std::uint64_t epoch) noexcept;
bool snortResetEpochStillCurrent(std::uint64_t epoch) noexcept;
void snortBeginResetEpoch() noexcept;
void snortEndResetEpoch() noexcept;

void snortSave(bool quit = false);
void snortResetAll();
