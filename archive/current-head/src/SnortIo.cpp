/*
 * SPDX-FileCopyrightText: 2024-2028 sucré Technologies
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include <sucre-snort.hpp>

#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

bool snortWriteAllWithDeadline(const int fd, const void *data, const std::size_t len,
                               const std::chrono::milliseconds deadline) noexcept {
    if (len == 0) {
        return true;
    }

    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }

    const bool restoreBlocking = (flags & O_NONBLOCK) == 0;
    if (restoreBlocking && fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return false;
    }

    struct RestoreFlags {
        int fd = -1;
        int flags = 0;
        bool restore = false;
        ~RestoreFlags() {
            if (restore) {
                (void)fcntl(fd, F_SETFL, flags);
            }
        }
    } restore{fd, flags, restoreBlocking};

    const auto end = std::chrono::steady_clock::now() + deadline;
    const auto *buf = static_cast<const char *>(data);
    std::size_t offset = 0;

    while (offset < len) {
        const ssize_t n = write(fd, buf + offset, len - offset);
        if (n > 0) {
            offset += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= end) {
                return false;
            }
            const auto remaining =
                std::chrono::duration_cast<std::chrono::milliseconds>(end - now).count();
            pollfd pfd{.fd = fd, .events = POLLOUT | POLLHUP, .revents = 0};
            const int rc = poll(&pfd, 1, static_cast<int>(std::max<std::int64_t>(1, remaining)));
            if (rc < 0 && errno == EINTR) {
                continue;
            }
            if (rc <= 0 || (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))) {
                return false;
            }
            continue;
        }
        return false;
    }

    return true;
}
