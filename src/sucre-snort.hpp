/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <android-base/logging.h>
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

namespace std {
template <class Mutex> class shared_lock_guard {
private:
    Mutex &_mutex;

public:
    explicit shared_lock_guard(Mutex &mutex)
        : _mutex(mutex) {
        mutex.lock_shared();
    }

    ~shared_lock_guard() { _mutex.unlock_shared(); }
};
} // namespace std

extern std::shared_mutex mutexListeners;

void snortSave(bool quit = false);
