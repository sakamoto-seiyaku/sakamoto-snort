/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <AndroidInitSocket.hpp>

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <string>

int snort_get_control_socket(const char *const name) noexcept {
    if (name == nullptr || *name == '\0') {
        return -1;
    }

    const std::string envName = std::string("ANDROID_SOCKET_") + name;
    const char *const value = std::getenv(envName.c_str());
    if (value == nullptr || *value == '\0') {
        return -1;
    }

    errno = 0;
    char *end = nullptr;
    const long fd = std::strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || fd < 0 || fd > INT_MAX) {
        return -1;
    }

    return static_cast<int>(fd);
}
