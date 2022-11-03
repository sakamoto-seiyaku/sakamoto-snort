/*
 * Copyright 2019 - 2022, iodé Technologies
 *
 * This file is part of the iode-snort project.
 *
 * iode-snort is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * iode-snort is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with iode-snort. If not, see <https://www.gnu.org/licenses/>.
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
